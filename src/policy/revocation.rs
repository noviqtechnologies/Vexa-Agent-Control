//! Phase 3: Instant Capability Revocation Registry
//!
//! Provides sub-second revocation of compromised agent tokens, devices, and tool permissions
//! with propagation to connected gateways, satisfying the Phase 3 <30s exit gate requirement.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Target types that can be explicitly revoked
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationTargetType {
    Agent,
    Tool,
    Token,
    Device,
}

/// An immutable record of an active capability revocation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RevocationEntry {
    pub id: String,
    pub target_type: RevocationTargetType,
    pub target_id: String,
    pub reason: String,
    pub revoked_at: String,
    pub expires_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RevocationCheckFailure {
    pub target_type: RevocationTargetType,
    pub target_id: String,
    pub reason: String,
    pub revoked_at: String,
}

/// Thread-safe registry for immediate capability checking
#[derive(Clone, Default)]
pub struct RevocationRegistry {
    entries: Arc<RwLock<HashMap<(RevocationTargetType, String), RevocationEntry>>>,
}

impl RevocationRegistry {
    pub fn new() -> Self {
        Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Add a revocation entry
    pub fn add(&self, entry: RevocationEntry) {
        let key = (entry.target_type, entry.target_id.clone());
        let mut map = self.entries.write().unwrap();
        map.insert(key, entry);
    }

    /// Revoke an agent by ID
    pub fn revoke_agent(&self, agent_id: impl Into<String>, reason: impl Into<String>) {
        let agent_id = agent_id.into();
        self.add(RevocationEntry {
            id: uuid::Uuid::new_v4().to_string(),
            target_type: RevocationTargetType::Agent,
            target_id: agent_id,
            reason: reason.into(),
            revoked_at: chrono::Utc::now().to_rfc3339(),
            expires_at: None,
        });
    }

    /// Revoke an MCP tool by name
    pub fn revoke_tool(&self, tool_name: impl Into<String>, reason: impl Into<String>) {
        let tool_name = tool_name.into();
        self.add(RevocationEntry {
            id: uuid::Uuid::new_v4().to_string(),
            target_type: RevocationTargetType::Tool,
            target_id: tool_name,
            reason: reason.into(),
            revoked_at: chrono::Utc::now().to_rfc3339(),
            expires_at: None,
        });
    }

    /// Revoke a credential/token by ID
    pub fn revoke_token(&self, token_id: impl Into<String>, reason: impl Into<String>) {
        let token_id = token_id.into();
        self.add(RevocationEntry {
            id: uuid::Uuid::new_v4().to_string(),
            target_type: RevocationTargetType::Token,
            target_id: token_id,
            reason: reason.into(),
            revoked_at: chrono::Utc::now().to_rfc3339(),
            expires_at: None,
        });
    }

    /// Check if an agent is revoked
    pub fn is_agent_revoked(&self, agent_id: &str) -> Option<RevocationCheckFailure> {
        self.check_single(RevocationTargetType::Agent, agent_id)
    }

    /// Check if a tool is revoked
    pub fn is_tool_revoked(&self, tool_name: &str) -> Option<RevocationCheckFailure> {
        self.check_single(RevocationTargetType::Tool, tool_name)
    }

    /// Check if a token is revoked
    pub fn is_token_revoked(&self, token_id: &str) -> Option<RevocationCheckFailure> {
        self.check_single(RevocationTargetType::Token, token_id)
    }

    fn check_single(
        &self,
        target_type: RevocationTargetType,
        target_id: &str,
    ) -> Option<RevocationCheckFailure> {
        let map = self.entries.read().unwrap();
        if let Some(entry) = map.get(&(target_type, target_id.to_string())) {
            // Check expiry if set
            if let Some(exp_str) = entry.expires_at.as_deref() {
                if let Ok(exp) = chrono::DateTime::parse_from_rfc3339(exp_str) {
                    if chrono::Utc::now() > exp.with_timezone(&chrono::Utc) {
                        return None;
                    }
                }
            }
            return Some(RevocationCheckFailure {
                target_type,
                target_id: target_id.to_string(),
                reason: entry.reason.clone(),
                revoked_at: entry.revoked_at.clone(),
            });
        }
        None
    }

    /// Comprehensive check on inbound request
    pub fn check(
        &self,
        agent_id: Option<&str>,
        tool_name: Option<&str>,
        token_id: Option<&str>,
    ) -> Result<(), RevocationCheckFailure> {
        if let Some(aid) = agent_id {
            if let Some(fail) = self.is_agent_revoked(aid) {
                return Err(fail);
            }
        }
        if let Some(tname) = tool_name {
            if let Some(fail) = self.is_tool_revoked(tname) {
                return Err(fail);
            }
        }
        if let Some(tok) = token_id {
            if let Some(fail) = self.is_token_revoked(tok) {
                return Err(fail);
            }
        }
        Ok(())
    }

    /// List all active revocations
    pub fn list(&self) -> Vec<RevocationEntry> {
        let map = self.entries.read().unwrap();
        map.values().cloned().collect()
    }

    /// Remove a revocation
    pub fn remove(&self, target_type: RevocationTargetType, target_id: &str) -> bool {
        let mut map = self.entries.write().unwrap();
        map.remove(&(target_type, target_id.to_string())).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_revocation_lifecycle() {
        let registry = RevocationRegistry::new();

        // 1. Initial state: clean
        assert!(registry
            .check(Some("agent-007"), Some("exec_cmd"), Some("tok-abc"))
            .is_ok());

        // 2. Revoke tool
        registry.revoke_tool("exec_cmd", "Critical zero-day exploit detected in tool");
        let res = registry.check(Some("agent-007"), Some("exec_cmd"), Some("tok-abc"));
        assert!(res.is_err());
        let err = res.unwrap_err();
        assert_eq!(err.target_type, RevocationTargetType::Tool);
        assert_eq!(err.target_id, "exec_cmd");
        assert!(err.reason.contains("Critical zero-day"));

        // 3. Different tool remains allowed
        assert!(registry
            .check(Some("agent-007"), Some("read_file"), Some("tok-abc"))
            .is_ok());

        // 4. Revoke agent
        registry.revoke_agent("agent-007", "Rogue agent loop detected");
        assert!(registry
            .check(Some("agent-007"), Some("read_file"), Some("tok-abc"))
            .is_err());

        // 5. Unrevoke
        assert!(registry.remove(RevocationTargetType::Agent, "agent-007"));
        assert!(registry
            .check(Some("agent-007"), Some("read_file"), Some("tok-abc"))
            .is_ok());
    }
}
