mod detect;
mod domain;
mod protocol;

use std::collections::HashMap;
use std::process::Stdio;
use tokio::io::{self, AsyncBufReadExt, AsyncWriteExt};
use tokio::process::Command;

fn init_telemetry() {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();
}

fn classify_and_record(
    direction: &'static str,
    line: &str,
    pending: &mut HashMap<domain::RequestId, String>,
) -> domain::MessageClass {
    if let Ok(req) = serde_json::from_str::<protocol::RawJsonRpcRequest>(line) {
        let class = domain::classify_request(&req.method);

        if let Some(id) = req
            .id
            .as_ref()
            .and_then(|id| domain::RequestId::parse(id).ok())
        {
            pending.insert(id, req.method.clone());
        }

        tracing::info!(%direction, method = %req.method, class = ?class, "request");
        return class;
    }

    if let Ok(resp) = serde_json::from_str::<protocol::RawJsonRpcResponse>(line) {
        let id = resp
            .id
            .as_ref()
            .and_then(|id| domain::RequestId::parse(id).ok());
        let class = domain::classify_response(id.as_ref(), pending);

        if let Some(id) = id {
            pending.remove(&id);
        }

        tracing::info!(%direction, class = ?class, "response");
        return class;
    }

    tracing::warn!(
        %direction,
        bytes = line.len(),
        "message did not parse as a known request or response shape"
    );
    domain::MessageClass::Unknown
}

fn inspect_tool_list_response(line: &str) {
    let Ok(resp) = serde_json::from_str::<protocol::RawJsonRpcResponse>(line) else {
        tracing::warn!("tools/list response could not be re-parsed for inspection");
        return;
    };

    let Some(result) = resp.result else {
        tracing::warn!("tools/list response has no result field");
        return;
    };

    let Some(tools) = result.get("tools").and_then(|t| t.as_array()) else {
        tracing::warn!("tools/list result has no tools array");
        return;
    };

    for tool in tools {
        let name = tool.get("name").and_then(|n| n.as_str()).unwrap_or("<unknown>");
        let Some(desc_str) = tool.get("description").and_then(|d| d.as_str()) else {
            tracing::debug!(tool = %name, "tool has no description, skipping");
            continue;
        };

        let desc = match domain::ToolDescription::parse(desc_str.to_owned()) {
            Ok(d) => d,
            Err(e) => {
                tracing::debug!(tool = %name, error = %e, "tool description invalid, skipping");
                continue;
            }
        };

        let findings = detect::poisoning::scan_tool_description(&desc);
        if findings.is_empty() {
            tracing::debug!(tool = %name, "tool description clean");
        } else {
            for finding in &findings {
                tracing::warn!(
                    tool = %name,
                    rule_id = finding.rule_id,
                    severity = ?finding.severity,
                    message = %finding.message,
                    "FINDING: tool description flagged",
                );
            }
        }
    }
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    init_telemetry();

    let args: Vec<String> = std::env::args().skip(1).collect();
    let (command, command_args) = args
        .split_first()
        .expect("usage: vex-mcp <command> [args...]");

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

    let mut pending: HashMap<domain::RequestId, String> = HashMap::new();
    let mut client_lines = io::BufReader::new(stdin).lines();
    let mut server_lines = io::BufReader::new(child_stdout).lines();

    let mut client_done = false;
    let mut server_done = false;

    while !(client_done && server_done) {
        tokio::select! {
            line = client_lines.next_line(), if !client_done => {
                match line? {
                    Some(line) => {
                        classify_and_record("client_to_server", &line, &mut pending);
                        if let Some(child_stdin) = child_stdin.as_mut() {
                            child_stdin.write_all(line.as_bytes()).await?;
                            child_stdin.write_all(b"\n").await?;
                            child_stdin.flush().await?;
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
                        let class = classify_and_record("server_to_client", &line, &mut pending);
                        if class == domain::MessageClass::ToolListResponse {
                            inspect_tool_list_response(&line);
                        }
                        stdout.write_all(line.as_bytes()).await?;
                        stdout.write_all(b"\n").await?;
                        stdout.flush().await?;
                    }
                    None => server_done = true,
                }
            }
        }
    }

    child.wait().await?;

    Ok(())
}
