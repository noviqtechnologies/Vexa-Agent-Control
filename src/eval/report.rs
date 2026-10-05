//! Phase 2: Disaggregated Detector Precision & Recall Reporting
//!
//! Generates per-detector-family evaluation metrics:
//! - Accuracy
//! - Precision (TP / (TP + FP))
//! - Recall    (TP / (TP + FN))
//! - False Positive Rate (FP / (FP + TN))
//! - False Negative Rate (FN / (TP + FN))
//!
//! Conforms to Plan Review Feedback v4 §Phase-2 "Disaggregated Detector Metrics".

use std::collections::HashMap;
use serde::{Deserialize, Serialize};

use crate::eval::replay::{ExpectedVerdict, ReplayVerdict};

// ─── Per-detector accumulator ─────────────────────────────────────────────────

/// Raw confusion matrix counts for a single detector family.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DetectorAccumulator {
    /// True Positive: expected Deny/Redact, got Deny/Redact
    pub tp: u64,
    /// True Negative: expected Allow, got Allow
    pub tn: u64,
    /// False Positive: expected Allow, got Deny/Redact
    pub fp: u64,
    /// False Negative: expected Deny/Redact, got Allow
    pub fn_: u64,
}

impl DetectorAccumulator {
    /// Record a single evaluation result into the confusion matrix.
    pub fn record(&mut self, expected: &ExpectedVerdict, actual: &ReplayVerdict) {
        let expected_positive = matches!(expected, ExpectedVerdict::Deny | ExpectedVerdict::Redact);
        let actual_positive = matches!(actual, ReplayVerdict::Deny | ReplayVerdict::Redact);

        match (expected_positive, actual_positive) {
            (true, true) => self.tp += 1,
            (true, false) => self.fn_ += 1,
            (false, true) => self.fp += 1,
            (false, false) => self.tn += 1,
        }
    }
}

// ─── Derived metrics ──────────────────────────────────────────────────────────

/// Computed precision/recall metrics for a single detector family.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectorMetrics {
    pub family: String,
    pub true_positives: u64,
    pub true_negatives: u64,
    pub false_positives: u64,
    pub false_negatives: u64,
    pub total: u64,
    /// TP / (TP + FP) — "what fraction of alerts are real threats?"
    pub precision: f64,
    /// TP / (TP + FN) — "what fraction of real threats were caught?"
    pub recall: f64,
    /// FP / (FP + TN) — "what fraction of benign events were incorrectly blocked?"
    pub false_positive_rate: f64,
    /// FN / (TP + FN) — "what fraction of threats slipped through?"
    pub false_negative_rate: f64,
    /// (TP + TN) / total
    pub accuracy: f64,
}

impl DetectorMetrics {
    /// Compute from raw accumulator counts.
    pub fn from_accumulator(family: impl Into<String>, acc: &DetectorAccumulator) -> Self {
        let tp = acc.tp as f64;
        let tn = acc.tn as f64;
        let fp = acc.fp as f64;
        let fn_ = acc.fn_ as f64;
        let total = tp + tn + fp + fn_;

        let precision = if tp + fp > 0.0 { tp / (tp + fp) } else { 1.0 };
        let recall = if tp + fn_ > 0.0 { tp / (tp + fn_) } else { 1.0 };
        let false_positive_rate = if fp + tn > 0.0 { fp / (fp + tn) } else { 0.0 };
        let false_negative_rate = if tp + fn_ > 0.0 { fn_ / (tp + fn_) } else { 0.0 };
        let accuracy = if total > 0.0 { (tp + tn) / total } else { 1.0 };

        Self {
            family: family.into(),
            true_positives: acc.tp,
            true_negatives: acc.tn,
            false_positives: acc.fp,
            false_negatives: acc.fn_,
            total: total as u64,
            precision,
            recall,
            false_positive_rate,
            false_negative_rate,
            accuracy,
        }
    }
}

// ─── Disaggregated report ─────────────────────────────────────────────────────

/// Full disaggregated metrics report across all detector families.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisaggregatedMetrics {
    pub by_family: Vec<DetectorMetrics>,
    /// Overall corpus-level bypass count (events expected Deny that got Allow).
    pub corpus_bypass_count: u64,
    /// Overall false positive count.
    pub corpus_false_positive_count: u64,
}

/// Build the disaggregated metrics from per-family accumulators.
pub fn build_disaggregated_metrics(
    accumulators: HashMap<String, DetectorAccumulator>,
) -> DisaggregatedMetrics {
    let mut by_family: Vec<DetectorMetrics> = accumulators
        .iter()
        .map(|(family, acc)| DetectorMetrics::from_accumulator(family.clone(), acc))
        .collect();
    by_family.sort_by(|a, b| a.family.cmp(&b.family));

    let corpus_bypass_count = accumulators.values().map(|a| a.fn_).sum();
    let corpus_false_positive_count = accumulators.values().map(|a| a.fp).sum();

    DisaggregatedMetrics {
        by_family,
        corpus_bypass_count,
        corpus_false_positive_count,
    }
}

// ─── Human-readable renderer ──────────────────────────────────────────────────

/// Render a human-readable table of disaggregated detector metrics.
pub fn render_metrics_table(metrics: &DisaggregatedMetrics) -> String {
    let mut out = String::new();
    out.push_str("\n╔══════════════════════════════════════════════════════════════════════════════╗\n");
    out.push_str("║        Vexa AgentControl — Disaggregated Detector Evaluation Report          ║\n");
    out.push_str("╚══════════════════════════════════════════════════════════════════════════════╝\n\n");

    out.push_str(&format!(
        "{:<20}  {:>7}  {:>7}  {:>8}  {:>8}  {:>9}  {:>9}\n",
        "Detector Family", "Precis.", "Recall", "FP Rate", "FN Rate", "Accuracy", "Events"
    ));
    out.push_str(&"─".repeat(82));
    out.push('\n');

    for m in &metrics.by_family {
        out.push_str(&format!(
            "{:<20}  {:>6.1}%  {:>6.1}%  {:>7.1}%  {:>7.1}%  {:>8.1}%  {:>7}\n",
            m.family,
            m.precision * 100.0,
            m.recall * 100.0,
            m.false_positive_rate * 100.0,
            m.false_negative_rate * 100.0,
            m.accuracy * 100.0,
            m.total,
        ));
    }

    out.push_str(&"─".repeat(82));
    out.push('\n');
    out.push_str(&format!(
        "\nCorpus bypasses (FN): {}    False positives (FP): {}\n",
        metrics.corpus_bypass_count,
        metrics.corpus_false_positive_count
    ));
    out
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_accumulator_tp() {
        let mut acc = DetectorAccumulator::default();
        acc.record(&ExpectedVerdict::Deny, &ReplayVerdict::Deny);
        assert_eq!(acc.tp, 1);
        assert_eq!(acc.tn, 0);
        assert_eq!(acc.fp, 0);
        assert_eq!(acc.fn_, 0);
    }

    #[test]
    fn test_accumulator_tn() {
        let mut acc = DetectorAccumulator::default();
        acc.record(&ExpectedVerdict::Allow, &ReplayVerdict::Allow);
        assert_eq!(acc.tn, 1);
    }

    #[test]
    fn test_accumulator_fp() {
        let mut acc = DetectorAccumulator::default();
        acc.record(&ExpectedVerdict::Allow, &ReplayVerdict::Deny);
        assert_eq!(acc.fp, 1);
    }

    #[test]
    fn test_accumulator_fn() {
        let mut acc = DetectorAccumulator::default();
        acc.record(&ExpectedVerdict::Deny, &ReplayVerdict::Allow);
        assert_eq!(acc.fn_, 1);
    }

    #[test]
    fn test_perfect_precision_recall() {
        let acc = DetectorAccumulator { tp: 10, tn: 10, fp: 0, fn_: 0 };
        let m = DetectorMetrics::from_accumulator("dlp", &acc);
        assert!((m.precision - 1.0).abs() < 1e-9);
        assert!((m.recall - 1.0).abs() < 1e-9);
        assert!((m.false_positive_rate - 0.0).abs() < 1e-9);
        assert!((m.false_negative_rate - 0.0).abs() < 1e-9);
        assert!((m.accuracy - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_zero_precision_on_all_fp() {
        let acc = DetectorAccumulator { tp: 0, tn: 0, fp: 5, fn_: 0 };
        let m = DetectorMetrics::from_accumulator("injection", &acc);
        assert!((m.precision - 0.0).abs() < 1e-9);
    }

    #[test]
    fn test_zero_recall_on_all_fn() {
        let acc = DetectorAccumulator { tp: 0, tn: 5, fp: 0, fn_: 5 };
        let m = DetectorMetrics::from_accumulator("injection", &acc);
        assert!((m.recall - 0.0).abs() < 1e-9);
        assert!((m.false_negative_rate - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_empty_accumulator_defaults_to_perfect() {
        // Empty corpus for a detector = no events = no penalties
        let acc = DetectorAccumulator::default();
        let m = DetectorMetrics::from_accumulator("egress", &acc);
        assert!((m.precision - 1.0).abs() < 1e-9);
        assert!((m.recall - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_build_disaggregated_metrics() {
        let mut map = HashMap::new();
        map.insert("dlp".to_string(), DetectorAccumulator { tp: 8, tn: 2, fp: 1, fn_: 0 });
        map.insert("injection".to_string(), DetectorAccumulator { tp: 5, tn: 5, fp: 0, fn_: 1 });
        let metrics = build_disaggregated_metrics(map);
        assert_eq!(metrics.by_family.len(), 2);
        assert_eq!(metrics.corpus_bypass_count, 1); // fn_ from injection
        assert_eq!(metrics.corpus_false_positive_count, 1); // fp from dlp
    }

    #[test]
    fn test_render_metrics_table_contains_header() {
        let metrics = DisaggregatedMetrics {
            by_family: vec![
                DetectorMetrics::from_accumulator("dlp", &DetectorAccumulator { tp: 5, tn: 5, fp: 0, fn_: 0 }),
            ],
            corpus_bypass_count: 0,
            corpus_false_positive_count: 0,
        };
        let table = render_metrics_table(&metrics);
        assert!(table.contains("Disaggregated Detector Evaluation Report"));
        assert!(table.contains("dlp"));
        assert!(table.contains("100.0%"));
    }
}
