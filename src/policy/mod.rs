use crate::detect::{Finding, Severity};
use crate::domain::{self, MessageClass, ToolName, ToolPattern, Verdict};

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

#[derive(Debug, Clone)]
pub enum DefaultAction {
    Allow,
    Deny,
}

#[derive(Debug, Clone)]
pub struct Policy {
    pub default_action: DefaultAction,
    pub allowed_tools: Vec<ToolPattern>,
    pub blocked_tools: Vec<ToolPattern>,
    pub confirmation_required: Vec<ToolPattern>,
}

pub fn decide_tool_call(policy: &Policy, tool_name: &ToolName) -> Verdict {
    // An explicit block always wins, even over the allow-list.
    if policy.blocked_tools.iter().any(|p| p.matches(tool_name)) {
        return Verdict::Block {
            reason: format!("tool `{}` is forbidden by policy", tool_name.as_ref()),
        };
    }
    // Under default-deny, a tool must match the allow-list to proceed.
    if matches!(policy.default_action, DefaultAction::Deny)
        && !policy.allowed_tools.iter().any(|p| p.matches(tool_name))
    {
        return Verdict::Block {
            reason: format!(
                "tool `{}` is not in the allow-list (default-deny)",
                tool_name.as_ref()
            ),
        };
    }
    if policy
        .confirmation_required
        .iter()
        .any(|p| p.matches(tool_name))
    {
        return Verdict::RequireConfirmation {
            reason: format!("tool `{}` requires confirmation", tool_name.as_ref()),
        };
    }
    Verdict::Allow
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

    fn patterns(names: &[&str]) -> Vec<ToolPattern> {
        names
            .iter()
            .map(|s| ToolPattern::parse(s.to_string()).unwrap())
            .collect()
    }

    fn make_policy(default_action: DefaultAction, blocked: &[&str], confirm: &[&str]) -> Policy {
        Policy {
            default_action,
            allowed_tools: Vec::new(),
            blocked_tools: patterns(blocked),
            confirmation_required: patterns(confirm),
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
    fn default_deny_allows_listed_tool() {
        let policy = Policy {
            default_action: DefaultAction::Deny,
            allowed_tools: patterns(&["fs.read_file"]),
            blocked_tools: vec![],
            confirmation_required: vec![],
        };
        assert_eq!(
            decide_tool_call(&policy, &tool("fs.read_file")),
            Verdict::Allow
        );
        assert!(matches!(
            decide_tool_call(&policy, &tool("fs.delete")),
            Verdict::Block { .. }
        ));
    }

    #[test]
    fn allow_list_matches_the_bare_wire_name() {
        let bare = Policy {
            default_action: DefaultAction::Deny,
            allowed_tools: patterns(&["read_file"]),
            blocked_tools: vec![],
            confirmation_required: vec![],
        };
        assert_eq!(decide_tool_call(&bare, &tool("read_file")), Verdict::Allow);

        let namespaced = Policy {
            default_action: DefaultAction::Deny,
            allowed_tools: patterns(&["filesystem.read_file"]),
            blocked_tools: vec![],
            confirmation_required: vec![],
        };
        assert!(matches!(
            decide_tool_call(&namespaced, &tool("read_file")),
            Verdict::Block { .. }
        ));
    }

    #[test]
    fn default_deny_allow_list_honors_globs() {
        let policy = Policy {
            default_action: DefaultAction::Deny,
            allowed_tools: patterns(&["fs.*"]),
            blocked_tools: vec![],
            confirmation_required: vec![],
        };
        assert_eq!(decide_tool_call(&policy, &tool("fs.read")), Verdict::Allow);
        assert_eq!(decide_tool_call(&policy, &tool("fs.write")), Verdict::Allow);
        assert!(matches!(
            decide_tool_call(&policy, &tool("shell.exec")),
            Verdict::Block { .. }
        ));
    }

    #[test]
    fn blocklist_takes_precedence_over_allow_list() {
        let policy = Policy {
            default_action: DefaultAction::Deny,
            allowed_tools: patterns(&["fs.*"]),
            blocked_tools: patterns(&["fs.delete"]),
            confirmation_required: vec![],
        };
        assert!(matches!(
            decide_tool_call(&policy, &tool("fs.delete")),
            Verdict::Block { .. }
        ));
    }

    #[test]
    fn allow_list_tool_can_still_require_confirmation() {
        let policy = Policy {
            default_action: DefaultAction::Deny,
            allowed_tools: patterns(&["github.create_pr"]),
            blocked_tools: vec![],
            confirmation_required: patterns(&["github.create_pr"]),
        };
        assert!(matches!(
            decide_tool_call(&policy, &tool("github.create_pr")),
            Verdict::RequireConfirmation { .. }
        ));
    }

    #[test]
    fn allow_list_is_ignored_under_default_allow() {
        // allowed_tools only gates default-deny; under default-allow everything passes.
        let policy = Policy {
            default_action: DefaultAction::Allow,
            allowed_tools: patterns(&["fs.read"]),
            blocked_tools: vec![],
            confirmation_required: vec![],
        };
        assert_eq!(
            decide_tool_call(&policy, &tool("anything.else")),
            Verdict::Allow
        );
    }

    #[test]
    fn blocklist_takes_precedence_over_default_allow() {
        let policy = make_policy(DefaultAction::Allow, &["shell.exec"], &[]);
        assert!(matches!(
            decide_tool_call(&policy, &tool("shell.exec")),
            Verdict::Block { .. }
        ));
    }

    #[test]
    fn glob_pattern_blocks_matching_family() {
        let policy = make_policy(DefaultAction::Allow, &["shell.*"], &[]);
        assert!(matches!(
            decide_tool_call(&policy, &tool("shell.exec")),
            Verdict::Block { .. }
        ));
        assert!(matches!(
            decide_tool_call(&policy, &tool("shell.run")),
            Verdict::Block { .. }
        ));
    }

    #[test]
    fn glob_pattern_does_not_block_unrelated_tool() {
        let policy = make_policy(DefaultAction::Allow, &["shell.*"], &[]);
        assert_eq!(decide_tool_call(&policy, &tool("fs.read")), Verdict::Allow);
    }

    #[test]
    fn exact_name_still_matches_literally() {
        // `.` is a literal in globset, so an exact name matches only itself.
        let policy = make_policy(DefaultAction::Allow, &["shell.exec"], &[]);
        assert_eq!(
            decide_tool_call(&policy, &tool("shellxexec")),
            Verdict::Allow
        );
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
