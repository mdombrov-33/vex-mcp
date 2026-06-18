use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageClass {
    ToolCallRequest,
    ToolListResponse,
    KnownSafeRequest,
    PassiveResponse,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureMode {
    Open,
    Closed,
}

/// The single decision policy reaches for a message. See CONTEXT.md.
/// `RequireConfirmation` behaves as `Block` until a confirmation channel exists (ADR-0003).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    Flag { reason: String },
    Block { reason: String },
    // reserved for ADR-0003; behaves as Block until a confirmation channel exists
    RequireConfirmation { reason: String },
}

impl std::fmt::Display for MessageClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MessageClass::ToolCallRequest => f.write_str("tool_call_request"),
            MessageClass::ToolListResponse => f.write_str("tool_list_response"),
            MessageClass::KnownSafeRequest => f.write_str("known_safe_request"),
            MessageClass::PassiveResponse => f.write_str("passive_response"),
            MessageClass::Unknown => f.write_str("unknown"),
        }
    }
}

impl std::fmt::Display for Verdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Verdict::Allow => f.write_str("allow"),
            Verdict::Flag { .. } => f.write_str("flag"),
            Verdict::Block { .. } => f.write_str("block"),
            Verdict::RequireConfirmation { .. } => f.write_str("require_confirmation"),
        }
    }
}

pub fn failure_mode_for(class: MessageClass) -> FailureMode {
    match class {
        // Privileged actions and the tool catalog that controls them: fail closed.
        MessageClass::ToolCallRequest => FailureMode::Closed,
        MessageClass::ToolListResponse => FailureMode::Closed,
        // Unrecognized request methods: fail closed (ADR-0002).
        MessageClass::Unknown => FailureMode::Closed,
        // Non-privileged handshake/listing requests and passive data responses: fail open.
        MessageClass::KnownSafeRequest => FailureMode::Open,
        MessageClass::PassiveResponse => FailureMode::Open,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RequestId(String);

impl RequestId {
    pub fn parse(value: &serde_json::Value) -> Result<Self, String> {
        match value {
            serde_json::Value::String(s) => Ok(Self(s.clone())),
            serde_json::Value::Number(n) => Ok(Self(n.to_string())),
            other => Err(format!("Invalid request id: {other}")),
        }
    }
}

pub fn classify_request(method: &str) -> MessageClass {
    match method {
        "tools/call" => MessageClass::ToolCallRequest,
        "initialize" | "ping" | "tools/list" => MessageClass::KnownSafeRequest,
        m if m.starts_with("resources/") || m.starts_with("prompts/") => {
            MessageClass::KnownSafeRequest
        }
        _ => MessageClass::Unknown,
    }
}

pub fn classify_response(
    id: Option<&RequestId>,
    pending: &HashMap<RequestId, String>,
) -> MessageClass {
    match id.and_then(|id| pending.get(id)) {
        Some(method) if method == "tools/list" => MessageClass::ToolListResponse,
        _ => MessageClass::PassiveResponse,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolDescription(String);

impl ToolDescription {
    pub fn parse(raw: String) -> Result<Self, String> {
        if raw.is_empty() {
            return Err("tool description must not be empty".into());
        }
        Ok(Self(raw))
    }
}

impl AsRef<str> for ToolDescription {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ServerId(String);

impl ServerId {
    pub fn parse(value: String) -> Result<Self, String> {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return Err("server id cannot be empty".into());
        }
        Ok(Self(trimmed.to_owned()))
    }
}

impl AsRef<str> for ServerId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ToolName(String);

impl ToolName {
    pub fn parse(value: String) -> Result<Self, String> {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return Err("tool name cannot be empty".into());
        }
        if trimmed.len() > 128 {
            return Err("tool name is too long".into());
        }
        Ok(Self(trimmed.to_owned()))
    }
}

impl AsRef<str> for ToolName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// A policy pattern matched against a `ToolName`. Exact names match literally
/// (globset treats `.` as a literal); wildcards (`shell.*`, `fs.write*`) match a
/// family of tools. Distinct from `ToolName` so a glob can never masquerade as a
/// validated exact tool name.
#[derive(Debug, Clone)]
pub struct ToolPattern {
    raw: String,
    matcher: globset::GlobMatcher,
}

impl ToolPattern {
    pub fn parse(value: String) -> Result<Self, String> {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return Err("tool pattern cannot be empty".into());
        }
        let matcher = globset::Glob::new(trimmed)
            .map_err(|e| format!("invalid tool pattern `{trimmed}`: {e}"))?
            .compile_matcher();
        Ok(Self {
            raw: trimmed.to_owned(),
            matcher,
        })
    }

    pub fn matches(&self, name: &ToolName) -> bool {
        self.matcher.is_match(name.as_ref())
    }
}

impl AsRef<str> for ToolPattern {
    fn as_ref(&self) -> &str {
        &self.raw
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolDefinitionHash(String);

impl ToolDefinitionHash {
    pub fn from_hex(hex: String) -> Self {
        Self(hex)
    }
}

impl AsRef<str> for ToolDefinitionHash {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ToolDefinition {
    pub name: ToolName,
    pub description: ToolDescription,
    pub input_schema: serde_json::Value,
}

impl ToolDefinition {
    pub fn hash(&self) -> ToolDefinitionHash {
        use sha2::Digest;
        let bytes = serde_json::to_vec(self).expect("ToolDefinition is always serializable");
        let digest = sha2::Sha256::digest(&bytes);
        ToolDefinitionHash(hex::encode(digest))
    }
}

impl serde::Serialize for ToolName {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

impl serde::Serialize for ToolDescription {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_tool_call() {
        assert_eq!(
            classify_request("tools/call"),
            MessageClass::ToolCallRequest
        );
    }

    #[test]
    fn classifies_unknown_method_as_unknown() {
        assert_eq!(
            classify_request("some/future/method"),
            MessageClass::Unknown
        )
    }

    #[test]
    fn classifies_tools_list_request_as_known_safe() {
        assert_eq!(
            classify_request("tools/list"),
            MessageClass::KnownSafeRequest
        );
    }

    #[test]
    fn failure_mode_table() {
        assert_eq!(
            failure_mode_for(MessageClass::ToolCallRequest),
            FailureMode::Closed
        );
        assert_eq!(
            failure_mode_for(MessageClass::ToolListResponse),
            FailureMode::Closed
        );
        assert_eq!(failure_mode_for(MessageClass::Unknown), FailureMode::Closed);
        assert_eq!(
            failure_mode_for(MessageClass::KnownSafeRequest),
            FailureMode::Open
        );
        assert_eq!(
            failure_mode_for(MessageClass::PassiveResponse),
            FailureMode::Open
        );
    }
}

#[test]
fn parses_string_and_number_ids_consistently() {
    let from_number = RequestId::parse(&serde_json::json!(1)).unwrap();
    let from_string = RequestId::parse(&serde_json::json!("1")).unwrap();
    assert_eq!(from_number, from_string);
}

#[test]
fn rejects_non_string_non_number_id() {
    assert!(RequestId::parse(&serde_json::json!(null)).is_err());
}

#[test]
fn classifies_tools_list_response_via_pending_table() {
    let mut pending = HashMap::new();
    let id = RequestId::parse(&serde_json::json!(1)).unwrap();
    pending.insert(id.clone(), "tools/list".to_string());

    assert_eq!(
        classify_response(Some(&id), &pending),
        MessageClass::ToolListResponse
    );
}

#[test]
fn classifies_unmatched_id_as_passive() {
    let pending = HashMap::new();
    let id = RequestId::parse(&serde_json::json!(99)).unwrap();

    assert_eq!(
        classify_response(Some(&id), &pending),
        MessageClass::PassiveResponse
    );
}
