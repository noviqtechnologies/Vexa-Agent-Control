//! Typed action requests for Vexa PDP evaluation (Gate 1.2).

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LlmRequestType {
    Chat,
    Completion,
    Embedding,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceAccessType {
    Read,
    List,
    Subscribe,
    Unsubscribe,
}

/// Strongly typed ActionRequest variant model for PDP evaluation
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ActionRequest {
    McpToolCall {
        tool_name: String,
        arguments: Value,
        server_id: Option<String>,
    },
    LlmRequest {
        provider: String,
        model: String,
        request_type: LlmRequestType,
    },
    ResourceAccess {
        resource_uri: String,
        access_type: ResourceAccessType,
    },
    PromptAccess {
        prompt_name: String,
        arguments: Option<Value>,
    },
}

impl ActionRequest {
    pub fn target_identifier(&self) -> &str {
        match self {
            Self::McpToolCall { tool_name, .. } => tool_name,
            Self::LlmRequest { model, .. } => model,
            Self::ResourceAccess { resource_uri, .. } => resource_uri,
            Self::PromptAccess { prompt_name, .. } => prompt_name,
        }
    }
}
