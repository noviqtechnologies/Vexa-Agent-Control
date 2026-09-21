use agentcontrol::proxy::broker_client::BrokerLLMRequest;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use serde_json::json;

fn bench_broker_request_construction(c: &mut Criterion) {
    let mut group = c.benchmark_group("gateway_broker_preparation");

    let req = BrokerLLMRequest {
        schema_version: "3.0".to_string(),
        request_id: "req-bench-test-uuid-12345".to_string(),
        provider: "openai".to_string(),
        project_ref: "default".to_string(),
        model: "gpt-4o".to_string(),
        protocol: "openai_chat_completions".to_string(),
        stream: true,
        llm_mode: Some("central_enforce".to_string()),
        input_token_estimate: Some(150),
        max_output_tokens: Some(2048),
        virtual_key: Some("vx-live-testkey-12345".to_string()),
        payload: json!({
            "model": "gpt-4o",
            "messages": [
                {"role": "system", "content": "You are an AI coding assistant."},
                {"role": "user", "content": "Write an efficient sorting algorithm."}
            ],
            "stream": true
        }),
    };

    group.bench_function("serialize_broker_request", |b| {
        b.iter(|| {
            let serialized = serde_json::to_vec(black_box(&req)).unwrap();
            assert!(!serialized.is_empty());
        })
    });

    group.finish();
}

criterion_group!(benches, bench_broker_request_construction);
criterion_main!(benches);
