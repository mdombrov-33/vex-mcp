use crate::detect::Finding;
use crate::domain::{self, MessageClass, Verdict};

/// Converts detector findings and message class into a single `Verdict`.
///
/// M4 will extend this with allowlist / capability-policy rules that can
/// produce `Block` or `RequireConfirmation` even for finding-free messages.
/// For now: no findings → Allow; findings on a fail-closed class → Block;
/// findings on a fail-open class → Flag (forward with warning).
pub fn decide(class: MessageClass, findings: &[Finding]) -> Verdict {
    if findings.is_empty() {
        return Verdict::Allow;
    }
    match domain::failure_mode_for(class) {
        domain::FailureMode::Closed => Verdict::Block,
        domain::FailureMode::Open => Verdict::Flag,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::{Finding, Severity};

    fn finding() -> Finding {
        Finding {
            rule_id: "TEST",
            severity: Severity::High,
            message: "test".into(),
        }
    }

    #[test]
    fn no_findings_always_allow() {
        assert_eq!(decide(MessageClass::ToolCallRequest, &[]), Verdict::Allow);
        assert_eq!(decide(MessageClass::PassiveResponse, &[]), Verdict::Allow);
    }

    #[test]
    fn findings_on_closed_class_block() {
        assert_eq!(
            decide(MessageClass::ToolListResponse, &[finding()]),
            Verdict::Block
        );
        assert_eq!(
            decide(MessageClass::ToolCallRequest, &[finding()]),
            Verdict::Block
        );
        assert_eq!(
            decide(MessageClass::Unknown, &[finding()]),
            Verdict::Block
        );
    }

    #[test]
    fn findings_on_open_class_flag() {
        assert_eq!(
            decide(MessageClass::PassiveResponse, &[finding()]),
            Verdict::Flag
        );
        assert_eq!(
            decide(MessageClass::KnownSafeRequest, &[finding()]),
            Verdict::Flag
        );
    }
}
