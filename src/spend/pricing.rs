//! LLM model token cost pricing table loader and estimator.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// Cost rates per 1 million input and output tokens (in US cents).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelPrice {
    pub input_per_1m_cents: u64,
    pub output_per_1m_cents: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PricingTable {
    pub version: String,
    pub models: HashMap<String, ModelPrice>,
    pub fallback: ModelPrice,
}

impl PricingTable {
    pub fn load(override_path: Option<&Path>) -> Result<Self, String> {
        let bundled = include_str!("pricing_default.toml");
        let mut table: PricingTable = toml::from_str(bundled)
            .map_err(|e| format!("Failed to parse bundled pricing table: {}", e))?;

        if let Some(path) = override_path {
            if path.exists() {
                let custom_str = fs::read_to_string(path)
                    .map_err(|e| format!("Failed to read custom pricing table: {}", e))?;
                let custom_table: PricingTable = toml::from_str(&custom_str)
                    .map_err(|e| format!("Failed to parse custom pricing table: {}", e))?;

                // Merge overrides
                for (k, v) in custom_table.models {
                    table.models.insert(k, v);
                }
                table.version = custom_table.version; // Use custom version string
                table.fallback = custom_table.fallback;
            }
        }

        Ok(table)
    }

    pub fn estimate_cents(&self, model: &str, input_tokens: u64, output_tokens: u64) -> u64 {
        let price = self.models.get(model).unwrap_or(&self.fallback);

        let input_cost = (input_tokens as f64 / 1_000_000.0) * (price.input_per_1m_cents as f64);
        let output_cost = (output_tokens as f64 / 1_000_000.0) * (price.output_per_1m_cents as f64);

        // Ceil to ensure we don't undercharge fractions of a cent
        (input_cost + output_cost).ceil() as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bundled_pricing_table_loads_and_verifies_frontier_rates() {
        let table =
            PricingTable::load(None).expect("Bundled pricing table must load and parse cleanly");
        assert_eq!(table.version, "2026-09-01");

        // Verify Anthropic frontier
        assert!(table.models.contains_key("claude-fable-5.1"));
        assert!(table.models.contains_key("claude-fable-5"));
        assert!(table.models.contains_key("claude-opus-5"));
        assert!(table.models.contains_key("claude-sonnet-5"));
        assert!(table.models.contains_key("claude-haiku-4.5"));

        // Verify OpenAI frontier
        assert!(table.models.contains_key("gpt-6-astra"));
        assert!(table.models.contains_key("gpt-5.6-sol"));
        assert!(table.models.contains_key("o4-mini"));
        assert!(table.models.contains_key("o3"));

        // Verify Google frontier
        assert!(table.models.contains_key("gemini-3.8-flash"));
        assert!(table.models.contains_key("gemini-2.5-pro"));

        // Verify DeepSeek frontier
        assert!(table.models.contains_key("deepseek-v4-pro"));
        assert!(table.models.contains_key("deepseek-v4-flash"));

        // Test estimate calculation for gpt-6-astra: 1000 cents input / 5000 cents output per 1M
        // 10,000 in (10 cents), 2,000 out (10 cents) => 20 cents
        let cost = table.estimate_cents("gpt-6-astra", 10_000, 2_000);
        assert_eq!(cost, 20);

        // Test deepseek-v4-flash: 14 cents in / 28 cents out per 1M
        let ds_cost = table.estimate_cents("deepseek-v4-flash", 1_000_000, 1_000_000);
        assert_eq!(ds_cost, 42);
    }
}
