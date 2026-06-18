pub mod drift;
pub mod poisoning;

use crate::domain;

pub fn inspect_tool_list(
    result: Option<&serde_json::Value>,
    server_id: &domain::ServerId,
    pin_store: &crate::pin::PinStore,
) -> Vec<ToolInspection> {
    let Some(result) = result else {
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

        let mut findings = poisoning::scan_tool_description(&def.description);
        findings.extend(drift::detect_drift(&def, server_id, pin_store));

        inspections.push(ToolInspection {
            new_hash: def.hash(),
            name: def.name,
            findings,
        });
    }

    inspections
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub rule_id: &'static str,
    pub severity: Severity,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Severity {
    #[allow(dead_code)]
    Low,
    #[allow(dead_code)]
    Medium,
    High,
    Critical,
}

#[derive(Debug)]
pub struct ToolInspection {
    pub name: domain::ToolName,
    pub findings: Vec<Finding>,
    pub new_hash: domain::ToolDefinitionHash,
}
