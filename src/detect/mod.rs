pub mod drift;
pub mod poisoning;

use crate::domain;

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
