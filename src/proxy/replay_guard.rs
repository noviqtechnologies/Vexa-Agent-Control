//! Safe Operation Replay Classification (Phase 4)
//!
//! Unlike generic AI proxies that blindly retry failed upstream requests, Vexa
//! enforces conservative replay rules to protect against duplicate side effects
//! (e.g. duplicate financial transactions, ticket creation, file mutations).

use super::pipeline::OperationKind;

#[derive(Clone, Debug, PartialEq)]
pub enum ReplayClassification {
    /// Safe to retry across alternative deployments or with exponential backoff.
    CanRetry { max_attempts: u32 },
    /// Dangerous to retry: Side effects may have already executed upstream.
    CannotRetry { reason: &'static str },
}

pub struct ReplayGuard;

impl ReplayGuard {
    /// Evaluate whether a failed operation can be safely retried.
    pub fn classify(kind: &OperationKind, stream_started: bool, http_status: Option<u16>) -> ReplayClassification {
        // If SSE streaming has already delivered data chunks to the client,
        // we cannot seamlessly rewind or retry the request.
        if stream_started {
            return ReplayClassification::CannotRetry {
                reason: "Stream already committed to client",
            };
        }

        // Non-retryable HTTP status codes (client errors / bad requests / auth errors)
        if let Some(status) = http_status {
            if status == 400 || status == 401 || status == 403 || status == 422 {
                return ReplayClassification::CannotRetry {
                    reason: "Non-retryable client error (4xx)",
                };
            }
        }

        match kind {
            OperationKind::LlmCompletion { .. } => ReplayClassification::CanRetry { max_attempts: 3 },
            OperationKind::Embedding { .. } => ReplayClassification::CanRetry { max_attempts: 3 },
            OperationKind::McpToolCall { is_idempotent, .. } => {
                if *is_idempotent {
                    ReplayClassification::CanRetry { max_attempts: 2 }
                } else {
                    ReplayClassification::CannotRetry {
                        reason: "Side-effecting MCP tool call is non-idempotent",
                    }
                }
            }
        }
    }
}
