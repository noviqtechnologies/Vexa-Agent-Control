//! LLM model token cost pricing table loader and estimator.

use std::collections::HashMap;
use std::path::Path;
use std::fs;
use serde::{Deserialize, Serialize};

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
