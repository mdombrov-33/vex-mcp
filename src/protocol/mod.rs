#[derive(Debug, serde::Deserialize)]
pub struct RawJsonRpcRequest {
    pub id: Option<serde_json::Value>,
    pub method: String,
    #[serde(default)]
    pub params: serde_json::Value,
}

#[derive(Debug, serde::Deserialize)]
pub struct RawJsonRpcResponse {
    pub id: Option<serde_json::Value>,
    #[serde(default)]
    pub result: Option<serde_json::Value>,
    #[allow(dead_code)]
    #[serde(default)]
    pub error: Option<serde_json::Value>,
}
