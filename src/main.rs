mod audit;
mod config;
mod detect;
mod domain;
mod gateway;
mod pin;
mod policy;
mod protocol;
mod rate_limit;
mod transport;

fn init_telemetry() {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();
}

fn print_help() {
    println!(
        "\
{name} {version} — a transparent MCP security gateway

USAGE:
    vex-mcp <server-command> [server-args...]
    vex-mcp verify [audit-log-path]
    vex-mcp --help | --version

The primary form spawns <server-command> as a child MCP server and proxies
JSON-RPC between your client and that server, inspecting tool descriptions,
detecting definition drift, and enforcing the capability policy.

SUBCOMMANDS:
    verify    Verify the audit-log hash chain (default: vex-audit.log)

ENVIRONMENT:
    VEX_CONFIG    Path to the config file (default: vex.toml)",
        name = env!("CARGO_PKG_NAME"),
        version = env!("CARGO_PKG_VERSION"),
    );
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();

    match args.first().map(String::as_str) {
        Some("--help" | "-h") => {
            print_help();
            return Ok(());
        }
        Some("--version" | "-V") => {
            println!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        _ => {}
    }

    init_telemetry();

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

    let rate_limiter = cfg.rate_limit.map(rate_limit::RateLimiter::new);
    let gateway = gateway::Gateway::new(server_id, cfg.policy, pin_store, audit_log, rate_limiter);

    let (command, command_args) = args
        .split_first()
        .ok_or_else(|| anyhow::anyhow!("usage: vex-mcp <command> [args...]"))?;

    transport::Application {
        gateway,
        command: command.clone(),
        command_args: command_args.to_vec(),
    }
    .run()
    .await
}
