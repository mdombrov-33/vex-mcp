use crate::detect::{Finding, Severity};
use crate::domain::{self, MessageClass, ToolName, Verdict};

// GatewayAction

pub enum GatewayAction {
    ForwardUnchanged,
    ForwardWithWarning {
        warning: String,
    },
    SynthesizeRefusal {
        reason: String,
    },
    // reserved for ADR-0003; currently routed to SynthesizeRefusal
    #[allow(dead_code)]
    PauseForConfirmation {
        reason: String,
    },
}

impl From<Verdict> for GatewayAction {
    fn from(verdict: Verdict) -> Self {
        match verdict {
            Verdict::Allow => GatewayAction::ForwardUnchanged,
            Verdict::Flag { reason } => GatewayAction::ForwardWithWarning { warning: reason },
            Verdict::Block { reason } => GatewayAction::SynthesizeRefusal { reason },
            // ADR-0003: no confirmation channel yet — treat as Block
            Verdict::RequireConfirmation { reason } => GatewayAction::SynthesizeRefusal { reason },
        }
    }
}

// Policy

#[derive(Debug, Clone)]
pub enum DefaultAction {
    Allow,
    Deny,
}

#[derive(Debug, Clone)]
pub struct Policy {
    pub default_action: DefaultAction,
    pub blocked_tools: Vec<ToolName>,
    pub confirmation_required: Vec<ToolName>,
}

pub fn decide_tool_call(policy: &Policy, tool_name: &ToolName) -> Verdict {
    if policy.blocked_tools.contains(tool_name) {
        return Verdict::Block {
            reason: format!("tool `{}` is forbidden by policy", tool_name.as_ref()),
        };
    }
    if policy.confirmation_required.contains(tool_name) {
        return Verdict::RequireConfirmation {
            reason: format!("tool `{}` requires confirmation", tool_name.as_ref()),
        };
    }
    match policy.default_action {
        DefaultAction::Allow => Verdict::Allow,
        DefaultAction::Deny => Verdict::Block {
            reason: format!(
                "tool `{}` is not explicitly allowed (default-deny)",
                tool_name.as_ref()
            ),
        },
    }
}

pub fn decide_findings(class: MessageClass, findings: &[Finding]) -> Verdict {
    if findings.is_empty() {
        return Verdict::Allow;
    }
    if findings.iter().any(|f| f.severity == Severity::Critical) {
        return match domain::failure_mode_for(class) {
            domain::FailureMode::Closed => Verdict::Block {
                reason: "critical detector finding on fail-closed message class".into(),
            },
            domain::FailureMode::Open => Verdict::Flag {
                reason: "critical detector finding on fail-open message class".into(),
            },
        };
    }
    match domain::failure_mode_for(class) {
        domain::FailureMode::Closed => Verdict::Block {
            reason: "detector finding on fail-closed message class".into(),
        },
        domain::FailureMode::Open => Verdict::Flag {
            reason: "detector finding on fail-open message class".into(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::Severity;

    fn make_policy(default_action: DefaultAction, blocked: &[&str], confirm: &[&str]) -> Policy {
        Policy {
            default_action,
            blocked_tools: blocked
                .iter()
                .map(|s| ToolName::parse(s.to_string()).unwrap())
                .collect(),
            confirmation_required: confirm
                .iter()
                .map(|s| ToolName::parse(s.to_string()).unwrap())
                .collect(),
        }
    }

    fn tool(name: &str) -> ToolName {
        ToolName::parse(name.to_string()).unwrap()
    }

    fn finding(severity: Severity) -> Finding {
        Finding {
            rule_id: "TEST",
            severity,
            message: "test".into(),
        }
    }

    // decide_tool_call

    #[test]
    fn blocked_tool_is_blocked() {
        let policy = make_policy(DefaultAction::Allow, &["shell.exec"], &[]);
        assert!(matches!(
            decide_tool_call(&policy, &tool("shell.exec")),
            Verdict::Block { .. }
        ));
    }

    #[test]
    fn confirmation_tool_requires_confirmation() {
        let policy = make_policy(DefaultAction::Allow, &[], &["email.send"]);
        assert!(matches!(
            decide_tool_call(&policy, &tool("email.send")),
            Verdict::RequireConfirmation { .. }
        ));
    }

    #[test]
    fn default_allow_lets_unknown_tool_through() {
        let policy = make_policy(DefaultAction::Allow, &[], &[]);
        assert_eq!(decide_tool_call(&policy, &tool("anything")), Verdict::Allow);
    }

    #[test]
    fn default_deny_blocks_unlisted_tool() {
        let policy = make_policy(DefaultAction::Deny, &[], &[]);
        assert!(matches!(
            decide_tool_call(&policy, &tool("anything")),
            Verdict::Block { .. }
        ));
    }

    #[test]
    fn blocklist_takes_precedence_over_default_allow() {
        let policy = make_policy(DefaultAction::Allow, &["shell.exec"], &[]);
        assert!(matches!(
            decide_tool_call(&policy, &tool("shell.exec")),
            Verdict::Block { .. }
        ));
    }

    // decide_findings

    #[test]
    fn no_findings_always_allow() {
        assert_eq!(
            decide_findings(MessageClass::ToolCallRequest, &[]),
            Verdict::Allow
        );
        assert_eq!(
            decide_findings(MessageClass::PassiveResponse, &[]),
            Verdict::Allow
        );
    }

    #[test]
    fn findings_on_closed_class_block() {
        assert!(matches!(
            decide_findings(MessageClass::ToolListResponse, &[finding(Severity::High)]),
            Verdict::Block { .. }
        ));
        assert!(matches!(
            decide_findings(MessageClass::ToolCallRequest, &[finding(Severity::High)]),
            Verdict::Block { .. }
        ));
    }

    #[test]
    fn findings_on_open_class_flag() {
        assert!(matches!(
            decide_findings(MessageClass::PassiveResponse, &[finding(Severity::High)]),
            Verdict::Flag { .. }
        ));
    }

    // GatewayAction conversion

    #[test]
    fn allow_maps_to_forward_unchanged() {
        assert!(matches!(
            GatewayAction::from(Verdict::Allow),
            GatewayAction::ForwardUnchanged
        ));
    }

    #[test]
    fn block_maps_to_synthesize_refusal() {
        assert!(matches!(
            GatewayAction::from(Verdict::Block { reason: "x".into() }),
            GatewayAction::SynthesizeRefusal { .. }
        ));
    }

    #[test]
    fn require_confirmation_maps_to_synthesize_refusal_until_adr0003() {
        assert!(matches!(
            GatewayAction::from(Verdict::RequireConfirmation { reason: "x".into() }),
            GatewayAction::SynthesizeRefusal { .. }
        ));
    }
}
