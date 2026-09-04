use agentcontrol::proxy::hooks::{HookOutcome, HookRegistry, HookStage, PipelineHook};
use agentcontrol::proxy::pipeline::RequestContext;
use async_trait::async_trait;
use serde_json::{json, Value};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

struct TrackingHook {
    name: &'static str,
    stage: HookStage,
    calls: Arc<AtomicUsize>,
}

#[async_trait]
impl PipelineHook for TrackingHook {
    fn name(&self) -> &'static str {
        self.name
    }
    fn stage(&self) -> HookStage {
        self.stage
    }
    async fn on_mcp_tool_call(
        &self,
        _tool_name: &str,
        _params: &mut Value,
        _ctx: &mut RequestContext,
    ) -> HookOutcome {
        self.calls.fetch_add(1, Ordering::SeqCst);
        HookOutcome::Continue
    }
    async fn on_response_stream_chunk(
        &self,
        chunk: &[u8],
        _ctx: &mut RequestContext,
    ) -> HookOutcome {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let mut modified = chunk.to_vec();
        modified.extend_from_slice(b" [hook_appended]");
        HookOutcome::ModifyBytes(modified)
    }
}

#[tokio::test]
async fn test_hook_stage_filtering_and_order() {
    let pre_calls = Arc::new(AtomicUsize::new(0));
    let post_calls = Arc::new(AtomicUsize::new(0));

    let mut registry = HookRegistry::new();
    registry.register(Arc::new(TrackingHook {
        name: "pre_hook",
        stage: HookStage::PreExecute,
        calls: pre_calls.clone(),
    }));
    registry.register(Arc::new(TrackingHook {
        name: "post_hook",
        stage: HookStage::PostExecute,
        calls: post_calls.clone(),
    }));

    let mut params = json!({"foo": "bar"});
    let mut ctx = RequestContext::for_session("test-session");

    // Execute PreExecute stage
    let res = registry
        .execute_mcp_tool_hooks(HookStage::PreExecute, "custom_tool", &mut params, &mut ctx)
        .await;

    assert_eq!(res, HookOutcome::Continue);
    assert_eq!(pre_calls.load(Ordering::SeqCst), 1);
    assert_eq!(post_calls.load(Ordering::SeqCst), 0); // PostExecute must not fire

    // Execute PostExecute stream chunk
    let chunk_res = registry
        .execute_stream_chunk_hooks(HookStage::PostExecute, b"stream_data", &mut ctx)
        .await;

    match chunk_res {
        HookOutcome::ModifyBytes(b) => {
            let s = String::from_utf8(b).unwrap();
            assert!(s.contains("stream_data [hook_appended]"));
        }
        _ => panic!("expected ModifyBytes"),
    }
    assert_eq!(post_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn test_hook_chaining_sequential_json_mutation() {
    struct PrefixHook;
    #[async_trait]
    impl PipelineHook for PrefixHook {
        fn name(&self) -> &'static str { "prefix" }
        fn stage(&self) -> HookStage { HookStage::PreExecute }
        async fn on_mcp_tool_call(&self, _: &str, p: &mut Value, _: &mut RequestContext) -> HookOutcome {
            if let Some(text) = p.get("text").and_then(|v| v.as_str()) {
                p["text"] = json!(format!("prefixed: {}", text));
                HookOutcome::ModifyJson(p.clone())
            } else {
                HookOutcome::Continue
            }
        }
    }

    struct SuffixHook;
    #[async_trait]
    impl PipelineHook for SuffixHook {
        fn name(&self) -> &'static str { "suffix" }
        fn stage(&self) -> HookStage { HookStage::PreExecute }
        async fn on_mcp_tool_call(&self, _: &str, p: &mut Value, _: &mut RequestContext) -> HookOutcome {
            if let Some(text) = p.get("text").and_then(|v| v.as_str()) {
                p["text"] = json!(format!("{} :suffixed", text));
                HookOutcome::ModifyJson(p.clone())
            } else {
                HookOutcome::Continue
            }
        }
    }

    let mut registry = HookRegistry::new();
    registry.register(Arc::new(PrefixHook));
    registry.register(Arc::new(SuffixHook));

    let mut params = json!({"text": "core"});
    let mut ctx = RequestContext::for_session("test-session");

    let outcome = registry
        .execute_mcp_tool_hooks(HookStage::PreExecute, "test_tool", &mut params, &mut ctx)
        .await;

    match outcome {
        HookOutcome::ModifyJson(p) => {
            assert_eq!(p["text"], "prefixed: core :suffixed");
        }
        _ => panic!("expected chained ModifyJson outcome"),
    }
}
