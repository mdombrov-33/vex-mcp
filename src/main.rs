mod detect;
mod domain;
mod pin;
mod policy;
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
) -> (domain::MessageClass, Option<protocol::RawJsonRpcResponse>) {
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
        return (class, None);
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
        return (class, Some(resp));
    }

    tracing::warn!(
        %direction,
        bytes = line.len(),
        "message did not parse as a known request or response shape"
    );
    (domain::MessageClass::Unknown, None)
}

fn inspect_tool_list_response(
    resp: &protocol::RawJsonRpcResponse,
    server_id: &domain::ServerId,
    pin_store: &pin::PinStore,
) -> Vec<detect::ToolInspection> {
    let Some(result) = resp.result.as_ref() else {
        tracing::warn!("tools/list response has no result field");
        return vec![];
    };

    let Some(tools) = result.get("tools").and_then(|t| t.as_array()) else {
        tracing::warn!("tools/list result has no tools array");
        return vec![];
    };

    let mut inspections = Vec::new();

    for tool in tools {
        let name_str = tool
            .get("name")
            .and_then(|n| n.as_str())
            .unwrap_or("<unknown>");

        let tool_name = match domain::ToolName::parse(name_str.to_owned()) {
            Ok(n) => n,
            Err(e) => {
                tracing::debug!(tool = %name_str, error = %e, "tool name invalid, skipping");
                continue;
            }
        };

        let Some(desc_str) = tool.get("description").and_then(|d| d.as_str()) else {
            tracing::debug!(tool = %name_str, "tool has no description, skipping");
            continue;
        };

        let desc = match domain::ToolDescription::parse(desc_str.to_owned()) {
            Ok(d) => d,
            Err(e) => {
                tracing::debug!(tool = %name_str, error = %e, "tool description invalid, skipping");
                continue;
            }
        };

        let input_schema = tool
            .get("inputSchema")
            .cloned()
            .unwrap_or(serde_json::Value::Null);

        let def = domain::ToolDefinition {
            name: tool_name,
            description: desc,
            input_schema,
        };

        let mut findings = detect::poisoning::scan_tool_description(&def.description);
        findings.extend(detect::drift::detect_drift(&def, server_id, pin_store));

        inspections.push(detect::ToolInspection {
            new_hash: def.hash(),
            name: def.name,
            findings,
        });
    }

    inspections
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

    let server_id =
        domain::ServerId::parse(command.clone()).expect("command name must be a valid server id");

    let pin_store_path = std::env::var("VEX_PIN_STORE").unwrap_or_else(|_| "pins.json".to_owned());
    let mut pin_store = pin::PinStore::load(&pin_store_path).expect("failed to load pin store");

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
                        let _ = classify_and_record("client_to_server", &line, &mut pending);
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
                        let (class, parsed) = classify_and_record("server_to_client", &line, &mut pending);
                        if class == domain::MessageClass::ToolListResponse {
                            let inspections = parsed
                                .as_ref()
                                .map(|resp| inspect_tool_list_response(resp, &server_id, &pin_store))
                                .unwrap_or_default();
                            for inspection in &inspections {
                                let tool = inspection.name.as_ref();
                                let verdict = policy::decide(class, &inspection.findings);
                                match verdict {
                                    domain::Verdict::Allow => {
                                        tracing::debug!(%tool, "tool clean");
                                    }
                                    domain::Verdict::Flag => {
                                        for f in &inspection.findings {
                                            tracing::warn!(%tool, rule_id = f.rule_id, severity = ?f.severity, message = %f.message, verdict = "Flag", "FINDING");
                                        }
                                    }
                                    domain::Verdict::Block | domain::Verdict::RequireConfirmation => {
                                        for f in &inspection.findings {
                                            tracing::error!(%tool, rule_id = f.rule_id, severity = ?f.severity, message = %f.message, verdict = "Block", "FINDING");
                                        }
                                        // M4 will synthesize a JSON-RPC error and skip forwarding.
                                    }
                                }
                                pin_store.upsert(&server_id, &inspection.name, inspection.new_hash.clone());
                            }
                            if !inspections.is_empty() && let Err(e) = pin_store.save() {
                                tracing::warn!(error = %e, "failed to persist pin store");
                            }
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
