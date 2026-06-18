mod audit;
mod config;
mod detect;
mod domain;
mod gateway;
mod pin;
mod policy;
mod protocol;

use std::process::Stdio;
use tokio::io::{self, AsyncBufReadExt, AsyncWriteExt};
use tokio::process::Command;

fn init_telemetry() {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_telemetry();

    let args: Vec<String> = std::env::args().skip(1).collect();

    if args.first().map(String::as_str) == Some("verify") {
        let path = args.get(1).map(String::as_str).unwrap_or("vex-audit.log");
        let count = audit::verify_chain(path)?;
        println!("chain intact: {count} record(s) verified in `{path}`");
        return Ok(());
    }

    let config_path = std::env::var("VEX_CONFIG").unwrap_or_else(|_| "vex.toml".to_owned());
    let cfg = config::load(&config_path)?;

    let server_id = domain::ServerId::parse(cfg.server_id)
        .map_err(|e| anyhow::anyhow!("invalid server id in config: {e}"))?;
    let pin_store = pin::PinStore::load(&cfg.pin_store_path).map_err(|e| anyhow::anyhow!("{e}"))?;
    let audit_log = audit::AuditLog::open(&cfg.audit_log_path)
        .map_err(|e| anyhow::anyhow!("could not open audit log: {e}"))?;

    let mut gw = gateway::Gateway::new(server_id, cfg.policy, pin_store, audit_log);

    let (command, command_args) = args
        .split_first()
        .ok_or_else(|| anyhow::anyhow!("usage: vex-mcp <command> [args...]"))?;

    tracing::info!(?command, ?command_args, "spawning child server");

    let mut child = Command::new(command)
        .args(command_args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;

    let mut child_stdin = Some(child.stdin.take().expect("child stdin was piped"));
    let child_stdout = child.stdout.take().expect("child stdout was piped");

    let stdin = io::stdin();
    let mut stdout = io::stdout();

    let mut client_lines = io::BufReader::new(stdin).lines();
    let mut server_lines = io::BufReader::new(child_stdout).lines();

    let mut client_done = false;
    let mut server_done = false;

    while !(client_done && server_done) {
        tokio::select! {
            line = client_lines.next_line(), if !client_done => {
                match line? {
                    Some(line) => {
                        match gw.handle_client_line(&line) {
                            gateway::Disposition::Forward => {
                                if let Some(child_stdin) = child_stdin.as_mut() {
                                    child_stdin.write_all(line.as_bytes()).await?;
                                    child_stdin.write_all(b"\n").await?;
                                    child_stdin.flush().await?;
                                }
                            }
                            gateway::Disposition::Refusal(json) => {
                                stdout.write_all(json.as_bytes()).await?;
                                stdout.write_all(b"\n").await?;
                                stdout.flush().await?;
                            }
                            gateway::Disposition::Drop => {}
                        }
                    }
                    None => {
                        client_done = true;
                        drop(child_stdin.take());
                    }
                }
            }
            line = server_lines.next_line(), if !server_done => {
                match line? {
                    Some(line) => {
                        match gw.handle_server_line(&line) {
                            gateway::Disposition::Forward => {
                                stdout.write_all(line.as_bytes()).await?;
                                stdout.write_all(b"\n").await?;
                                stdout.flush().await?;
                            }
                            // Server messages are never refused back to the client;
                            // Drop suppresses poisoned tool-list responses silently.
                            gateway::Disposition::Refusal(_) | gateway::Disposition::Drop => {}
                        }
                    }
                    None => server_done = true,
                }
            }
        }
    }

    child.wait().await?;

    Ok(())
}
