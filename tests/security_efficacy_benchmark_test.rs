//! Security Efficacy & Latency Benchmark Harness (SEC-004)
//! Measures Recall, Precision, False-Positive Rate, and Latency (p50/p95/p99)
//! against the versioned attack and benign test corpus.

use agentcontrol::policy::dlp::DlpScanner;
use agentcontrol::policy::injection::{InjectionScanner, ScanResult};
use serde::Deserialize;
use serde_json::json;
use std::fs;
use std::path::Path;
use std::time::Instant;

#[derive(Debug, Deserialize)]
struct TestCase {
    id: String,
    category: String,
    expected_decision: String,
    payload: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct Corpus {
    version: String,
    description: String,
    test_cases: Vec<TestCase>,
}

#[test]
fn test_security_efficacy_and_latency_benchmark() {
    let corpus_path = Path::new("tests/corpus/injection_test_corpus.json");
    assert!(
        corpus_path.exists(),
        "Corpus file must exist at tests/corpus/injection_test_corpus.json"
    );

    let data = fs::read_to_string(corpus_path).expect("Failed to read corpus file");
    let corpus: Corpus = serde_json::from_str(&data).expect("Invalid corpus JSON format");

    let injection_scanner = InjectionScanner::new().expect("Failed to compile injection scanner");
    let dlp_scanner = DlpScanner::new(None).expect("Failed to compile DLP scanner");

    let mut true_positives = 0;
    let mut false_positives = 0;
    let mut true_negatives = 0;
    let mut false_negatives = 0;

    let mut latencies_micros: Vec<u128> = Vec::new();

    for tc in &corpus.test_cases {
        let start = Instant::now();

        // 1. Scan for injection patterns
        let response_val = if tc.payload.starts_with('{') {
            serde_json::from_str(&tc.payload).unwrap_or_else(|_| {
                json!({
                    "content": [{"type": "text", "text": tc.payload}]
                })
            })
        } else {
            json!({
                "content": [{"type": "text", "text": tc.payload}]
            })
        };

        let tool_name = if tc.category == "tool_description_poisoning" {
            "tools/list"
        } else {
            "test_tool"
        };

        let injection_result =
            injection_scanner.scan_response(&response_val, tool_name, "bench-session", true);
        let injection_blocked = matches!(
            injection_result,
            ScanResult::Block { .. } | ScanResult::Warn { .. }
        );

        // 2. Scan for DLP secrets
        let dlp_findings = dlp_scanner.scan_content(&tc.payload);
        let dlp_blocked = !dlp_findings.is_empty();

        let is_detected = injection_blocked || dlp_blocked;
        let elapsed = start.elapsed().as_micros();
        latencies_micros.push(elapsed);

        let is_attack = tc.expected_decision == "block";

        if is_attack && is_detected {
            true_positives += 1;
        } else if is_attack && !is_detected {
            false_negatives += 1;
            println!(
                "[MISSED ATTACK] ID: {} Category: {} Payload: {}",
                tc.id, tc.category, tc.payload
            );
        } else if !is_attack && !is_detected {
            true_negatives += 1;
        } else if !is_attack && is_detected {
            false_positives += 1;
            println!(
                "[FALSE POSITIVE] ID: {} Category: {} Payload: {}",
                tc.id, tc.category, tc.payload
            );
        }
    }

    // Sort latencies for percentiles
    latencies_micros.sort_unstable();
    let n = latencies_micros.len();
    let p50 = latencies_micros[n * 50 / 100];
    let p95 = latencies_micros[n * 95 / 100];
    let p99 = latencies_micros[n * 99 / 100];

    let total_attacks = true_positives + false_negatives;
    let total_benign = true_negatives + false_positives;

    let recall = if total_attacks > 0 {
        (true_positives as f64) / (total_attacks as f64)
    } else {
        1.0
    };

    let precision = if (true_positives + false_positives) > 0 {
        (true_positives as f64) / ((true_positives + false_positives) as f64)
    } else {
        1.0
    };

    let fpr = if total_benign > 0 {
        (false_positives as f64) / (total_benign as f64)
    } else {
        0.0
    };

    println!("\n========================================================");
    println!(
        "  VEXA AGENT CONTROL — SECURITY BENCHMARK RESULTS (v{})",
        corpus.version
    );
    println!("========================================================");
    println!("  Total Cases Evaluated : {}", n);
    println!("  True Positives (TP)   : {}", true_positives);
    println!("  False Positives (FP)  : {}", false_positives);
    println!("  True Negatives (TN)   : {}", true_negatives);
    println!("  False Negatives (FN)  : {}", false_negatives);
    println!("--------------------------------------------------------");
    println!("  Recall Rate           : {:.2}%", recall * 100.0);
    println!("  Precision Rate        : {:.2}%", precision * 100.0);
    println!("  False Positive Rate   : {:.2}%", fpr * 100.0);
    println!("--------------------------------------------------------");
    println!(
        "  Latency p50           : {} µs ({:.3} ms)",
        p50,
        (p50 as f64) / 1000.0
    );
    println!(
        "  Latency p95           : {} µs ({:.3} ms)",
        p95,
        (p95 as f64) / 1000.0
    );
    println!(
        "  Latency p99           : {} µs ({:.3} ms)",
        p99,
        (p99 as f64) / 1000.0
    );
    println!("========================================================\n");

    // Efficacy Assertions (Baseline Gate A Quality Bars)
    assert!(
        recall >= 0.90,
        "Recall rate ({:.2}%) must meet or exceed 90%",
        recall * 100.0
    );
    assert!(
        precision >= 0.90,
        "Precision rate ({:.2}%) must meet or exceed 90%",
        precision * 100.0
    );
    assert!(
        fpr <= 0.05,
        "False positive rate ({:.2}%) must be 5% or lower",
        fpr * 100.0
    );
    assert!(p99 <= 15000, "p99 latency ({} µs) must be under 15ms", p99);
}
