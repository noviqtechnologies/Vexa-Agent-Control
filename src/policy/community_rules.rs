//! Community and custom regex DLP rule loader (FR-112).
//!
//! Extends built-in DLP secret detectors with custom user-defined regex patterns loaded from YAML.

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use regex::Regex;
use crate::policy::dlp::SecretCategory;

/// Custom community DLP detection rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommunityRule {
    pub name: String,
    pub category: SecretCategory,
    pub regex: String,
}

/// Container for loaded community DLP rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommunityRulesConfig {
    pub rules: Vec<CommunityRule>,
}

impl CommunityRulesConfig {
    /// Loads and validates a community rules YAML file from the specified path.
    ///
    /// # Errors
    /// Returns an error string if the file cannot be read, parsed, or contains invalid regexes.
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let path = path.as_ref();
        if !path.exists() {
            return Ok(CommunityRulesConfig { rules: Vec::new() });
        }

        let content = fs::read_to_string(path)
            .map_err(|e| format!("Failed to read community rules file {:?}: {}", path, e))?;

        let config: CommunityRulesConfig = serde_yaml::from_str(&content)
            .map_err(|e| format!("Failed to parse community rules YAML: {}", e))?;

        // Validate regexes
        for rule in &config.rules {
            if let Err(e) = Regex::new(&rule.regex) {
                return Err(format!("Invalid regex in community rule '{}': {}", rule.name, e));
            }
        }

        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    use std::io::Write;

    #[test]
    fn test_load_community_rules() {
        let yaml = r#"
rules:
  - name: "Custom Token"
    category: "Other"
    regex: "custom-[a-zA-Z0-9]{16}"
  - name: "Acme Corp Key"
    category: "Other"
    regex: "ACME-[0-9]{10}"
"#;
        let mut file = NamedTempFile::new().unwrap();
        write!(file, "{}", yaml).unwrap();

        let config = CommunityRulesConfig::load_from_file(file.path()).unwrap();
        assert_eq!(config.rules.len(), 2);
        assert_eq!(config.rules[0].name, "Custom Token");
        assert_eq!(config.rules[1].name, "Acme Corp Key");
    }
}
