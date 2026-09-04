//! Pipeline Hook Framework (AR-1)
//!
//! Provides extensible lifecycle hooks across pre-route, pre-execution, and post-execution stages
//! for both HTTP body inspection and structured MCP tool calls.

use async_trait::async_trait;
use hyper::HeaderMap;
use serde_json::Value;
use std::sync::Arc;

use crate::proxy::pipeline::RequestContext;

/// Outcome returned by a pipeline hook.
#[derive(Clone, Debug, PartialEq)]
pub enum HookOutcome {
    /// Proceed to the next hook in the pipeline without modification.
    Continue,
    /// In-place mutation of structured JSON payload (e.g. MCP tool parameters or DLP redaction).
    ModifyJson(Value),
    /// In-place replacement of raw HTTP body or streaming bytes.
    ModifyBytes(Vec<u8>),
    /// Terminate request immediately and fail closed with HTTP status and reason.
    Block { status: u16, reason: String },
}

/// Execution stage of the pipeline lifecycle.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HookStage {
    /// Evaluated prior to upstream routing or provider dispatch.
    PreRoute,
    /// Evaluated immediately prior to tool execution or LLM call.
    PreExecute,
    /// Evaluated on response payload or streaming response chunks.
    PostExecute,
}

/// Pluggable pipeline hook contract.
#[async_trait]
pub trait PipelineHook: Send + Sync {
    /// Unique diagnostic identifier for the hook.
    fn name(&self) -> &'static str;

    /// Lifecycle stage at which the hook operates.
    fn stage(&self) -> HookStage;

    /// Intercept and inspect/mutate raw HTTP requests.
    async fn on_http_request(
        &self,
        _headers: &HeaderMap,
        _body: &[u8],
        _ctx: &mut RequestContext,
    ) -> HookOutcome {
        HookOutcome::Continue
    }

    /// Intercept and inspect/mutate structured MCP tool calls.
    async fn on_mcp_tool_call(
        &self,
        _tool_name: &str,
        _params: &mut Value,
        _ctx: &mut RequestContext,
    ) -> HookOutcome {
        HookOutcome::Continue
    }

    /// Intercept and inspect/mutate streaming response chunks.
    async fn on_response_stream_chunk(
        &self,
        _chunk: &[u8],
        _ctx: &mut RequestContext,
    ) -> HookOutcome {
        HookOutcome::Continue
    }
}

/// Central registry managing sequential execution of pipeline hooks.
#[derive(Clone, Default)]
pub struct HookRegistry {
    hooks: Vec<Arc<dyn PipelineHook>>,
}

impl HookRegistry {
    pub fn new() -> Self {
        Self { hooks: Vec::new() }
    }

    /// Initialize standard hook registry with compiled DLP scanner.
    pub fn with_default_scanners(dlp_scanner: Arc<crate::policy::dlp::DlpScanner>) -> Self {
        let mut registry = Self::new();
        registry.register(Arc::new(DlpMcpHook::new(dlp_scanner.clone())));
        registry.register(Arc::new(HttpDlpInspectionHook::new(dlp_scanner)));
        registry
    }

    /// Register a hook into the registry.
    pub fn register(&mut self, hook: Arc<dyn PipelineHook>) {
        self.hooks.push(hook);
    }

    /// Number of registered hooks.
    pub fn len(&self) -> usize {
        self.hooks.len()
    }

    pub fn is_empty(&self) -> bool {
        self.hooks.is_empty()
    }

    /// Execute all registered hooks matching the given stage on an MCP tool call.
    pub async fn execute_mcp_tool_hooks(
        &self,
        stage: HookStage,
        tool_name: &str,
        params: &mut Value,
        ctx: &mut RequestContext,
    ) -> HookOutcome {
        let mut modified = false;

        for hook in &self.hooks {
            if hook.stage() == stage {
                match hook.on_mcp_tool_call(tool_name, params, ctx).await {
                    HookOutcome::Continue => {}
                    HookOutcome::ModifyJson(new_params) => {
                        *params = new_params;
                        modified = true;
                    }
                    HookOutcome::Block { status, reason } => {
                        return HookOutcome::Block { status, reason };
                    }
                    HookOutcome::ModifyBytes(_) => {}
                }
            }
        }

        if modified {
            HookOutcome::ModifyJson(params.clone())
        } else {
            HookOutcome::Continue
        }
    }

    /// Execute all registered hooks matching the given stage on an HTTP request.
    pub async fn execute_http_request_hooks(
        &self,
        stage: HookStage,
        headers: &HeaderMap,
        body: &[u8],
        ctx: &mut RequestContext,
    ) -> HookOutcome {
        let mut current_body = body.to_vec();
        let mut modified = false;

        for hook in &self.hooks {
            if hook.stage() == stage {
                match hook.on_http_request(headers, &current_body, ctx).await {
                    HookOutcome::Continue => {}
                    HookOutcome::ModifyBytes(new_body) => {
                        current_body = new_body;
                        modified = true;
                    }
                    HookOutcome::Block { status, reason } => {
                        return HookOutcome::Block { status, reason };
                    }
                    HookOutcome::ModifyJson(_) => {}
                }
            }
        }

        if modified {
            HookOutcome::ModifyBytes(current_body)
        } else {
            HookOutcome::Continue
        }
    }

    /// Execute all registered hooks matching the given stage on a response stream chunk.
    pub async fn execute_stream_chunk_hooks(
        &self,
        stage: HookStage,
        chunk: &[u8],
        ctx: &mut RequestContext,
    ) -> HookOutcome {
        let mut current_chunk = chunk.to_vec();
        let mut modified = false;

        for hook in &self.hooks {
            if hook.stage() == stage {
                match hook.on_response_stream_chunk(&current_chunk, ctx).await {
                    HookOutcome::Continue => {}
                    HookOutcome::ModifyBytes(new_chunk) => {
                        current_chunk = new_chunk;
                        modified = true;
                    }
                    HookOutcome::Block { status, reason } => {
                        return HookOutcome::Block { status, reason };
                    }
                    HookOutcome::ModifyJson(_) => {}
                }
            }
        }

        if modified {
            HookOutcome::ModifyBytes(current_chunk)
        } else {
            HookOutcome::Continue
        }
    }
}

// ── Built-in Hook Implementations ────────────────────────────────────────────

/// Built-in hook enforcing DLP redaction on structured MCP tool call parameters.
pub struct DlpMcpHook {
    dlp_scanner: Arc<crate::policy::dlp::DlpScanner>,
}

impl DlpMcpHook {
    pub fn new(dlp_scanner: Arc<crate::policy::dlp::DlpScanner>) -> Self {
        Self { dlp_scanner }
    }
}

#[async_trait]
impl PipelineHook for DlpMcpHook {
    fn name(&self) -> &'static str {
        "dlp_mcp_redaction"
    }

    fn stage(&self) -> HookStage {
        HookStage::PreExecute
    }

    async fn on_mcp_tool_call(
        &self,
        _tool_name: &str,
        params: &mut Value,
        _ctx: &mut RequestContext,
    ) -> HookOutcome {
        let original = params.clone();
        self.dlp_scanner.redact_value(params);
        if *params != original {
            HookOutcome::ModifyJson(params.clone())
        } else {
            HookOutcome::Continue
        }
    }
}

/// Built-in hook enforcing DLP redaction on HTTP request bodies.
pub struct HttpDlpInspectionHook {
    dlp_scanner: Arc<crate::policy::dlp::DlpScanner>,
}

impl HttpDlpInspectionHook {
    pub fn new(dlp_scanner: Arc<crate::policy::dlp::DlpScanner>) -> Self {
        Self { dlp_scanner }
    }
}

#[async_trait]
impl PipelineHook for HttpDlpInspectionHook {
    fn name(&self) -> &'static str {
        "dlp_http_inspection"
    }

    fn stage(&self) -> HookStage {
        HookStage::PreRoute
    }

    async fn on_http_request(
        &self,
        _headers: &HeaderMap,
        body: &[u8],
        _ctx: &mut RequestContext,
    ) -> HookOutcome {
        if let Ok(text) = std::str::from_utf8(body) {
            let redacted = self.dlp_scanner.redact_text(text);
            if redacted != text {
                return HookOutcome::ModifyBytes(redacted.into_bytes());
            }
        }
        HookOutcome::Continue
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    struct BlockingHook;

    #[async_trait]
    impl PipelineHook for BlockingHook {
        fn name(&self) -> &'static str {
            "test_block"
        }
        fn stage(&self) -> HookStage {
            HookStage::PreExecute
        }
        async fn on_mcp_tool_call(
            &self,
            tool_name: &str,
            _params: &mut Value,
            _ctx: &mut RequestContext,
        ) -> HookOutcome {
            if tool_name == "blocked_tool" {
                HookOutcome::Block {
                    status: 403,
                    reason: "tool execution denied by hook".to_string(),
                }
            } else {
                HookOutcome::Continue
            }
        }
    }

    #[tokio::test]
    async fn test_mcp_tool_call_redaction_mutation() {
        let dlp = Arc::new(crate::policy::dlp::DlpScanner::new(None).unwrap());
        let mut registry = HookRegistry::new();
        registry.register(Arc::new(DlpMcpHook::new(dlp)));

        let mut params = json!({
            "command": "echo AKIAIOSFODNN7EXAMPLE",
            "safe": "hello"
        });
        let mut ctx = RequestContext::for_session("test-session");

        let outcome = registry
            .execute_mcp_tool_hooks(HookStage::PreExecute, "bash", &mut params, &mut ctx)
            .await;

        match outcome {
            HookOutcome::ModifyJson(p) => {
                assert!(p["command"].as_str().unwrap().contains("[REDACTED:"));
                assert_eq!(p["safe"], "hello");
            }
            _ => panic!("expected ModifyJson outcome"),
        }
    }

    #[tokio::test]
    async fn test_mcp_tool_blocking() {
        let mut registry = HookRegistry::new();
        registry.register(Arc::new(BlockingHook));

        let mut params = json!({});
        let mut ctx = RequestContext::for_session("test-session");

        let outcome = registry
            .execute_mcp_tool_hooks(HookStage::PreExecute, "blocked_tool", &mut params, &mut ctx)
            .await;

        match outcome {
            HookOutcome::Block { status, reason } => {
                assert_eq!(status, 403);
                assert!(reason.contains("tool execution denied"));
            }
            _ => panic!("expected Block outcome"),
        }
    }

    #[tokio::test]
    async fn test_http_request_redaction_mutation() {
        let dlp = Arc::new(crate::policy::dlp::DlpScanner::new(None).unwrap());
        let mut registry = HookRegistry::new();
        registry.register(Arc::new(HttpDlpInspectionHook::new(dlp)));

        let body = b"{\"key\": \"AKIAIOSFODNN7EXAMPLE\"}";
        let headers = HeaderMap::new();
        let mut ctx = RequestContext::for_session("test-session");

        let outcome = registry
            .execute_http_request_hooks(HookStage::PreRoute, &headers, body, &mut ctx)
            .await;

        match outcome {
            HookOutcome::ModifyBytes(b) => {
                let s = String::from_utf8(b).unwrap();
                assert!(s.contains("[REDACTED:"));
            }
            _ => panic!("expected ModifyBytes outcome"),
        }
    }
}
