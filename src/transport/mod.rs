use std::process::Stdio;

use tokio::io::{self, AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt};
use tokio::process::Command;

use crate::gateway::{Disposition, Gateway};

pub struct Application {
    pub gateway: Gateway,
    pub command: String,
    pub command_args: Vec<String>,
}

impl Application {
    pub async fn run(mut self) -> anyhow::Result<()> {
        tracing::info!(command = %self.command, args = ?self.command_args, "spawning child server");

        let mut child = Command::new(&self.command)
            .args(&self.command_args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?;

        let child_stdin = child.stdin.take().expect("child stdin was piped");
        let child_stdout = child.stdout.take().expect("child stdout was piped");

        run_proxy(
            &mut self.gateway,
            io::BufReader::new(io::stdin()),
            io::BufReader::new(child_stdout),
            io::stdout(),
            child_stdin,
        )
        .await?;

        // run_proxy returns once the client disconnects. A server that ignores its
        // closed stdin would otherwise keep us alive, so terminate the child.
        child.start_kill().ok();
        child.wait().await?;
        Ok(())
    }
}

/// Routes client↔server lines through the gateway and dispatches each `Disposition`
/// to the correct pipe. Generic over the four streams so tests drive it with
/// in-memory pipes instead of a spawned child.
pub async fn run_proxy<CR, SR, CW, SW>(
    gateway: &mut Gateway,
    client_in: CR,
    server_in: SR,
    mut client_out: CW,
    mut server_out: SW,
) -> anyhow::Result<()>
where
    CR: AsyncBufRead + Unpin,
    SR: AsyncBufRead + Unpin,
    CW: AsyncWrite + Unpin,
    SW: AsyncWrite + Unpin,
{
    let mut client_lines = client_in.lines();
    let mut server_lines = server_in.lines();

    let mut server_done = false;

    loop {
        tokio::select! {
            line = client_lines.next_line() => {
                match line? {
                    Some(line) => match gateway.handle_client_line(&line) {
                        Disposition::Forward => write_line(&mut server_out, &line).await?,
                        Disposition::Refusal(json) => write_line(&mut client_out, &json).await?,
                        Disposition::Drop => {}
                    },
                    // The client disconnected: the session is over. Close the child's
                    // stdin and stop - don't wait on a server that may never close
                    // its own stdout.
                    None => {
                        server_out.shutdown().await?;
                        break;
                    }
                }
            }
            line = server_lines.next_line(), if !server_done => {
                match line? {
                    Some(line) => match gateway.handle_server_line(&line) {
                        Disposition::Forward => write_line(&mut client_out, &line).await?,
                        // Server messages are never refused to the client; Drop suppresses a poisoned catalog.
                        Disposition::Refusal(_) | Disposition::Drop => {}
                    },
                    None => server_done = true,
                }
            }
        }
    }

    Ok(())
}

async fn write_line<W: AsyncWrite + Unpin>(w: &mut W, line: &str) -> anyhow::Result<()> {
    w.write_all(line.as_bytes()).await?;
    w.write_all(b"\n").await?;
    w.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{audit, domain, pin, policy};

    fn test_gateway() -> Gateway {
        let pin_dir = tempfile::tempdir().unwrap();
        let audit_file = tempfile::NamedTempFile::new().unwrap();
        let server_id = domain::ServerId::parse("test-server".to_owned()).unwrap();
        let policy = policy::Policy {
            default_action: policy::DefaultAction::Allow,
            allowed_tools: vec![],
            blocked_tools: vec![domain::ToolPattern::parse("shell.exec".to_owned()).unwrap()],
            confirmation_required: vec![],
        };
        let pin_store = pin::PinStore::load(pin_dir.path().join("pins.json")).unwrap();
        let audit_log = audit::AuditLog::open(audit_file.path().to_str().unwrap()).unwrap();
        Gateway::new(server_id, policy, pin_store, audit_log, None)
    }

    fn tool_call(id: u64, tool: &str) -> String {
        serde_json::json!({
            "jsonrpc": "2.0", "id": id, "method": "tools/call",
            "params": { "name": tool, "arguments": {} }
        })
        .to_string()
    }

    async fn drive(gateway: &mut Gateway, client_input: &str) -> (String, String) {
        let mut to_client: Vec<u8> = Vec::new();
        let mut to_server: Vec<u8> = Vec::new();
        run_proxy(
            gateway,
            io::BufReader::new(client_input.as_bytes()),
            io::BufReader::new(&b""[..]),
            &mut to_client,
            &mut to_server,
        )
        .await
        .unwrap();
        (
            String::from_utf8(to_client).unwrap(),
            String::from_utf8(to_server).unwrap(),
        )
    }

    #[tokio::test]
    async fn allowed_client_call_is_forwarded_to_server() {
        let mut gw = test_gateway();
        let input = format!("{}\n", tool_call(1, "safe_tool"));
        let (to_client, to_server) = drive(&mut gw, &input).await;
        assert!(to_server.contains("safe_tool"));
        assert!(to_client.is_empty());
    }

    #[tokio::test]
    async fn blocked_client_call_refuses_to_client_and_not_to_server() {
        let mut gw = test_gateway();
        let input = format!("{}\n", tool_call(1, "shell.exec"));
        let (to_client, to_server) = drive(&mut gw, &input).await;
        assert!(to_client.contains("error"));
        assert!(to_server.is_empty());
    }
}
