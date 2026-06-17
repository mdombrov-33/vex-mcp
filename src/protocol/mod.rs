#[derive(Debug, serde::Deserialize)]
pub struct RawJsonRpcRequest {
    // Not read yet at M1's scope; kept for wire-format fidelity per §10.2 and
    // because later milestones need them (e.g. M2 inspects `params`).
    #[allow(dead_code)]
    pub jsonrpc: String,
    pub id: Option<serde_json::Value>,
    pub method: String,
    #[allow(dead_code)]
    #[serde(default)]
    pub params: serde_json::Value,
}

#[derive(Debug, serde::Deserialize)]
pub struct RawJsonRpcResponse {
    // Not read yet at M1's scope; kept for wire-format fidelity per §10.2 and
    // because later milestones need them (e.g. M2 inspects `result`).
    #[allow(dead_code)]
    pub jsonrpc: String,
    pub id: Option<serde_json::Value>,
    #[serde(default)]
    pub result: Option<serde_json::Value>,
    #[allow(dead_code)]
    #[serde(default)]
    pub error: Option<serde_json::Value>,
}
