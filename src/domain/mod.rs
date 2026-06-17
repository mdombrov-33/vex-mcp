use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageClass {
    ToolCallRequest,
    ToolListResponse,
    KnownSafeRequest,
    PassiveResponse,
    Unknown,
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
