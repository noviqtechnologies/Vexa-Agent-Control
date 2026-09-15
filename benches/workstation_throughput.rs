use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use agentcontrol::mcp::policy::{inspect_jsonrpc_frame, scan_and_redact_text};
use serde_json::json;

fn bench_jsonrpc_frame_inspection(c: &mut Criterion) {
    let mut group = c.benchmark_group("workstation_mcp_inspection");

    // 1. Small tool call (4KB)
    let small_payload = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "read_file",
            "arguments": {
                "path": "/etc/config.json",
                "auth_header": "Bearer sk-1234567890abcdef1234567890abcdef"
            }
        }
    });
    let small_bytes = serde_json::to_vec(&small_payload).unwrap();
    group.throughput(Throughput::Bytes(small_bytes.len() as u64));
    group.bench_function("mcp_small_4kb", |b| {
        b.iter(|| {
            let res = inspect_jsonrpc_frame(black_box(&small_bytes), false);
            assert!(res.is_ok());
        })
    });

    // 2. Normal tool call (32KB)
    let normal_arg = "A".repeat(30 * 1024);
    let normal_payload = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "write_data",
            "arguments": {
                "data": normal_arg,
                "conn": "postgres://user:secret@localhost:5432/db"
            }
        }
    });
    let normal_bytes = serde_json::to_vec(&normal_payload).unwrap();
    group.throughput(Throughput::Bytes(normal_bytes.len() as u64));
    group.bench_function("mcp_normal_32kb", |b| {
        b.iter(|| {
            let res = inspect_jsonrpc_frame(black_box(&normal_bytes), false);
            assert!(res.is_ok());
        })
    });

    // 3. Coding LLM payload (256KB)
    let code_buffer = "fn compute() { println!(\"evaluating chunk\"); }\n".repeat(5000);
    let code_payload = json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "code_analysis",
            "arguments": {
                "code": code_buffer
            }
        }
    });
    let code_bytes = serde_json::to_vec(&code_payload).unwrap();
    group.throughput(Throughput::Bytes(code_bytes.len() as u64));
    group.bench_function("mcp_code_256kb", |b| {
        b.iter(|| {
            let res = inspect_jsonrpc_frame(black_box(&code_bytes), false);
            assert!(res.is_ok());
        })
    });

    group.finish();
}

fn bench_parameter_dlp_redaction(c: &mut Criterion) {
    let sample_text = "Deploying key sk-abcdef1234567890abcdef12345 to postgres://admin:pass@db.internal:5432/main with cert -----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...";
    c.bench_function("parameter_dlp_redact", |b| {
        b.iter(|| {
            let (redacted, findings) = scan_and_redact_text(black_box(sample_text));
            assert!(!findings.is_empty());
            assert!(!redacted.contains("sk-"));
        })
    });
}

criterion_group!(benches, bench_jsonrpc_frame_inspection, bench_parameter_dlp_redaction);
criterion_main!(benches);
