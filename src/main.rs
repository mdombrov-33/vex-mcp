mod audit;
mod config;
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
) -> (
    domain::MessageClass,
    Option<protocol::RawJsonRpcRequest>,
    Option<protocol::RawJsonRpcResponse>,
) {
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
        return (class, Some(req), None);
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
        return (class, None, Some(resp));
    }

    tracing::warn!(
        %direction,
        bytes = line.len(),
        "message did not parse as a known request or response shape"
    );
    (domain::MessageClass::Unknown, None, None)
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

async fn synthesize_refusal(
    id: Option<&serde_json::Value>,
    reason: &str,
    stdout: &mut io::Stdout,
) -> std::io::Result<()> {
    let id_json = id.cloned().unwrap_or(serde_json::Value::Null);
    let payload = serde_json::json!({
        "jsonrpc": "2.0",
        "id": id_json,
        "error": {
            "code": -32600,
            "message": reason,
        }
    });
    let line = serde_json::to_string(&payload).expect("refusal payload is always serializable");
    stdout.write_all(line.as_bytes()).await?;
    stdout.write_all(b"\n").await?;
    stdout.flush().await
}

fn verdict_label(v: &domain::Verdict) -> String {
    match v {
        domain::Verdict::Allow => "allow",
        domain::Verdict::Flag { .. } => "flag",
        domain::Verdict::Block { .. } => "block",
        domain::Verdict::RequireConfirmation { .. } => "require_confirmation",
    }
    .to_owned()
}

fn message_class_label(c: domain::MessageClass) -> String {
    match c {
        domain::MessageClass::ToolCallRequest => "tool_call_request",
        domain::MessageClass::ToolListResponse => "tool_list_response",
        domain::MessageClass::KnownSafeRequest => "known_safe_request",
        domain::MessageClass::PassiveResponse => "passive_response",
        domain::MessageClass::Unknown => "unknown",
    }
    .to_owned()
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn try_append(log: &mut audit::AuditLog, record: audit::AuditRecord) {
    if let Err(e) = log.append(record) {
        tracing::warn!(error = %e, "failed to write audit record");
    }
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
    let mut pin_store =
        pin::PinStore::load(&cfg.pin_store_path).map_err(|e| anyhow::anyhow!("{e}"))?;
    let policy = cfg.policy;
    let mut audit_log = audit::AuditLog::open(&cfg.audit_log_path)
        .map_err(|e| anyhow::anyhow!("could not open audit log: {e}"))?;

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
                        let (class, req, _resp) =
                            classify_and_record("client_to_server", &line, &mut pending);

                        if class == domain::MessageClass::ToolCallRequest
                            && let Some(ref req) = req
                        {
                            let tool_name_str = req.params
                                .get("name")
                                .and_then(|v| v.as_str())
                                .unwrap_or("");
                            match domain::ToolName::parse(tool_name_str.to_owned()) {
                                Ok(tool_name) => {
                                    let verdict = policy::decide_tool_call(&policy, &tool_name);
                                    let param_shape = req.params
                                        .get("arguments")
                                        .map(audit::parameter_shape);
                                    try_append(&mut audit_log, audit::AuditRecord {
                                        timestamp: unix_now(),
                                        direction: audit::Direction::ClientToServer,
                                        message_class: "tool_call_request".to_owned(),
                                        server_id: server_id.as_ref().to_owned(),
                                        tool_name: Some(tool_name.as_ref().to_owned()),
                                        verdict: verdict_label(&verdict),
                                        findings_count: 0,
                                        param_shape,
                                        chain_hash: String::new(),
                                    });
                                    let action = policy::GatewayAction::from(verdict);
                                    match action {
                                        policy::GatewayAction::ForwardUnchanged => {}
                                        policy::GatewayAction::ForwardWithWarning { ref warning } => {
                                            tracing::warn!(tool = %tool_name_str, %warning, "forwarding with warning");
                                        }
                                        policy::GatewayAction::SynthesizeRefusal { ref reason } => {
                                            tracing::error!(tool = %tool_name_str, %reason, "BLOCKED tool call");
                                            synthesize_refusal(req.id.as_ref(), reason, &mut stdout).await?;
                                            continue;
                                        }
                                        policy::GatewayAction::PauseForConfirmation { ref reason } => {
                                            tracing::error!(tool = %tool_name_str, %reason, "BLOCKED (confirmation not yet implemented)");
                                            synthesize_refusal(req.id.as_ref(), reason, &mut stdout).await?;
                                            continue;
                                        }
                                    }
                                }
                                Err(e) => {
                                    tracing::warn!(tool = %tool_name_str, error = %e, "could not parse tool name; blocking");
                                    try_append(&mut audit_log, audit::AuditRecord {
                                        timestamp: unix_now(),
                                        direction: audit::Direction::ClientToServer,
                                        message_class: "tool_call_request".to_owned(),
                                        server_id: server_id.as_ref().to_owned(),
                                        tool_name: Some(tool_name_str.to_owned()),
                                        verdict: "block".to_owned(),
                                        findings_count: 0,
                                        param_shape: None,
                                        chain_hash: String::new(),
                                    });
                                    synthesize_refusal(req.id.as_ref(), "invalid tool name", &mut stdout).await?;
                                    continue;
                                }
                            }
                        } else {
                            try_append(&mut audit_log, audit::AuditRecord {
                                timestamp: unix_now(),
                                direction: audit::Direction::ClientToServer,
                                message_class: message_class_label(class),
                                server_id: server_id.as_ref().to_owned(),
                                tool_name: None,
                                verdict: "allow".to_owned(),
                                findings_count: 0,
                                param_shape: None,
                                chain_hash: String::new(),
                            });
                        }

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
                        let (class, _req, resp) =
                            classify_and_record("server_to_client", &line, &mut pending);

                        if class == domain::MessageClass::ToolListResponse {
                            let inspections = resp
                                .as_ref()
                                .map(|r| inspect_tool_list_response(r, &server_id, &pin_store))
                                .unwrap_or_default();

                            let mut should_block_response = false;

                            for inspection in &inspections {
                                let tool = inspection.name.as_ref();
                                let verdict = policy::decide_findings(class, &inspection.findings);
                                try_append(&mut audit_log, audit::AuditRecord {
                                    timestamp: unix_now(),
                                    direction: audit::Direction::ServerToClient,
                                    message_class: "tool_list_response".to_owned(),
                                    server_id: server_id.as_ref().to_owned(),
                                    tool_name: Some(tool.to_owned()),
                                    verdict: verdict_label(&verdict),
                                    findings_count: inspection.findings.len(),
                                    param_shape: None,
                                    chain_hash: String::new(),
                                });
                                match verdict {
                                    domain::Verdict::Allow => {
                                        tracing::debug!(%tool, "tool clean");
                                    }
                                    domain::Verdict::Flag { ref reason } => {
                                        tracing::warn!(%tool, %reason, "FINDING flagged");
                                        for f in &inspection.findings {
                                            tracing::warn!(%tool, rule_id = f.rule_id, severity = ?f.severity, message = %f.message, "detail");
                                        }
                                    }
                                    domain::Verdict::Block { ref reason }
                                    | domain::Verdict::RequireConfirmation { ref reason } => {
                                        tracing::error!(%tool, %reason, "FINDING blocked");
                                        for f in &inspection.findings {
                                            tracing::error!(%tool, rule_id = f.rule_id, severity = ?f.severity, message = %f.message, "detail");
                                        }
                                        should_block_response = true;
                                    }
                                }
                                pin_store.upsert(
                                    &server_id,
                                    &inspection.name,
                                    inspection.new_hash.clone(),
                                );
                            }

                            if !inspections.is_empty() && let Err(e) = pin_store.save() {
                                tracing::warn!(error = %e, "failed to persist pin store");
                            }

                            if should_block_response {
                                tracing::error!("suppressing poisoned tools/list response");
                                continue;
                            }
                        } else {
                            try_append(&mut audit_log, audit::AuditRecord {
                                timestamp: unix_now(),
                                direction: audit::Direction::ServerToClient,
                                message_class: message_class_label(class),
                                server_id: server_id.as_ref().to_owned(),
                                tool_name: None,
                                verdict: "allow".to_owned(),
                                findings_count: 0,
                                param_shape: None,
                                chain_hash: String::new(),
                            });
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
