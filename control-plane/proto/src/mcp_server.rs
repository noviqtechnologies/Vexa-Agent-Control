use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SanitizedMcpServerMeta {
    pub ide_target: String,
    pub server_name: String,
    pub wrapped: bool,
    pub path_verified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpServerSnapshot {
    pub agent_id: String,
    pub servers: Vec<SanitizedMcpServerMeta>,
}
