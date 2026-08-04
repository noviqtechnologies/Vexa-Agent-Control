//! FR-303: Verified MCP Security Scoring Engine
//! Static and dynamic analysis engine for assigning Vexa Security Scores (0-100)
//! based on permission footprint, path access depth, network egress, and schema complexity.

use serde::{Deserialize, Serialize};

/// Detailed breakdown of an MCP Security Assessment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpSecurityScore {
    pub server_name: String,
    pub score: u8, // 0 to 100 (100 is safest)
    pub risk_level: String, // "LOW", "MEDIUM", "HIGH", "CRITICAL"
    pub path_access_depth: u8,
    pub network_egress_required: bool,
    pub schema_complexity_score: u8,
    pub vulnerability_flags: Vec<String>,
}

pub struct McpScorer;

impl McpScorer {
    /// Evaluates an MCP server configuration and outputs a Vexa Security Score.
    pub fn evaluate_server(
        server_name: &str,
        allowed_paths: &[String],
        allow_egress: bool,
        input_schema_complexity: u8,
    ) -> McpSecurityScore {
        let mut score: i16 = 100;
        let mut flags = Vec::new();

        // 1. Path depth evaluation
        let mut max_depth = 0;
        for path in allowed_paths {
            if path == "/" || path == "*" || path.contains("..") {
                score -= 30;
                flags.push("UNRESTRICTED_ROOT_OR_TRAVERSAL_PATH".to_string());
            } else {
                let depth = path.split('/').count() as u8;
                if depth > max_depth {
                    max_depth = depth;
                }
            }
        }

        if allowed_paths.is_empty() {
            score -= 10;
            flags.push("NO_EXPLICIT_PATH_ALLOWLIST".to_string());
        }

        // 2. Network egress evaluation
        if allow_egress {
            score -= 20;
            flags.push("EXTERNAL_NETWORK_EGRESS_ENABLED".to_string());
        }

        // 3. Schema complexity & injection surface
        if input_schema_complexity > 10 {
            score -= 15;
            flags.push("HIGH_SCHEMA_COMPLEXITY_PROMPT_INJECTION_SURFACE".to_string());
        }

        let final_score = score.clamp(0, 100) as u8;
        let risk_level = match final_score {
            80..=100 => "LOW",
            60..=79 => "MEDIUM",
            40..=59 => "HIGH",
            _ => "CRITICAL",
        }.to_string();

        McpSecurityScore {
            server_name: server_name.to_string(),
            score: final_score,
            risk_level,
            path_access_depth: max_depth,
            network_egress_required: allow_egress,
            schema_complexity_score: input_schema_complexity,
            vulnerability_flags: flags,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mcp_scoring() {
        let res = McpScorer::evaluate_server(
            "filesystem_mcp",
            &vec!["/home/user/project".to_string()],
            false,
            3,
        );
        assert_eq!(res.score, 100);
        assert_eq!(res.risk_level, "LOW");

        let dangerous = McpScorer::evaluate_server(
            "untrusted_mcp",
            &vec!["/".to_string()],
            true,
            15,
        );
        assert!(dangerous.score < 50);
        assert!(dangerous.vulnerability_flags.contains(&"UNRESTRICTED_ROOT_OR_TRAVERSAL_PATH".to_string()));
    }
}
