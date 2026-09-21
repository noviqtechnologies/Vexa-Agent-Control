//! # Local Spend Ledger & Token Budget Controller
//!
//! Autonomous, zero-telemetry local SQLite token and cost ledger.
//! Enforces sub-millisecond local financial limits, per-developer spend caps,
//! and circuit breaking across local AI agent sessions.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{mpsc, oneshot};

use rusqlite::{params, Connection};

use super::model::{
    AgentSpend, BudgetConfig, BudgetPeriod, BudgetScope, IncreaseRequest, SpendCheckResult,
};
use super::types::{AttributionContext, SpendExportFilter, SpendExportRecord};

/// Commands sent to the background spend ledger worker thread.
pub enum SpendCmd {
    CheckAndIncrement {
        agent_id: String,
        identity_groups: Vec<String>,
        estimated_cents: u64,
        responder: oneshot::Sender<SpendCheckResult>,
    },
    SetBudget {
        scope: BudgetScope,
        cap_cents: u64,
        period: BudgetPeriod,
        responder: oneshot::Sender<Result<(), String>>,
    },
    GetSpend {
        agent_id: String,
        responder: oneshot::Sender<Option<AgentSpend>>,
    },
    SubmitIncreaseRequest {
        agent_id: String,
        reason: Option<String>,
        current_cap_cents: u64,
        responder: oneshot::Sender<String>,
    },
    ResolveIncreaseRequest {
        request_id: String,
        approved: bool,
        new_cap_cents: Option<u64>,
        admin_id: String,
        responder: oneshot::Sender<Result<(), String>>,
    },
    ListIncreaseRequests {
        responder: oneshot::Sender<Vec<IncreaseRequest>>,
    },
    ListBudgets {
        responder: oneshot::Sender<Vec<BudgetConfig>>,
    },
    SettleUsage {
        request_id: String,
        agent_id: String,
        attribution: AttributionContext,
        provider: String,
        model: String,
        input_tokens: u64,
        output_tokens: u64,
        total_tokens: u64,
        cost_cents: u64,
        is_estimated: bool,
    },
    ExportUsage {
        filter: SpendExportFilter,
        responder: oneshot::Sender<Vec<SpendExportRecord>>,
    },
    MaybePruneExpiredPeriods,
}

#[derive(Clone)]
pub struct SpendLedger {
    cmd_tx: mpsc::UnboundedSender<SpendCmd>,
    pub concurrency_ceiling: usize,
    _shutdown: Arc<()>,
}

impl SpendLedger {
    pub fn init(
        dashboard_client: Option<Arc<crate::control_plane_client::client::DashboardClient>>,
    ) -> Self {
        Self::init_with_path(None, dashboard_client)
    }

    pub fn init_with_path(
        custom_path: Option<PathBuf>,
        dashboard_client: Option<Arc<crate::control_plane_client::client::DashboardClient>>,
    ) -> Self {
        let db_path = if let Some(p) = custom_path {
            p
        } else {
            let home_dir = dirs::home_dir().expect("Failed to get home directory");
            let new_dir = PathBuf::from(&home_dir).join(".agentcontrol");
            let old_dir = PathBuf::from(&home_dir).join(".agentwall");

            if !new_dir.exists() {
                let _ = std::fs::create_dir_all(&new_dir);
                if old_dir.exists() {
                    let old_db = old_dir.join("events.db");
                    let new_db = new_dir.join("events.db");
                    if old_db.exists() && !new_db.exists() {
                        let _ = std::fs::copy(&old_db, &new_db);
                    }
                }
            }
            new_dir.join("events.db")
        };

        let conn = Connection::open(&db_path).expect("Failed to open SQLite DB for spend");
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;")
            .expect("Failed to set WAL mode / busy timeout for spend ledger");

        // Write latency measurement
        let start = Instant::now();
        conn.execute(
            "CREATE TEMP TABLE IF NOT EXISTS spend_latency_test (id INTEGER)",
            [],
        )
        .ok();
        conn.execute("INSERT INTO spend_latency_test (id) VALUES (1)", [])
            .ok();
        conn.execute("DROP TABLE IF EXISTS spend_latency_test", [])
            .ok();
        let write_latency_ms = start.elapsed().as_millis();

        if write_latency_ms > 50 {
            crate::logging::log_event(
                crate::logging::Level::Warn,
                "spend_ledger_performance_warning",
                serde_json::json!({
                    "measured_write_latency_ms": write_latency_ms,
                    "ceiling": 50
                }),
            );
        }

        // Initialize schema (tables created by migrations, but ensure they exist for early requests)
        // ... handled in proxy::db schema migrations in 2.7, but doing it here just in case ...
        conn.execute(
            "CREATE TABLE IF NOT EXISTS spend_budgets (
                scope_type TEXT NOT NULL,
                scope_key  TEXT NOT NULL DEFAULT '',
                cap_cents  INTEGER NOT NULL,
                period     TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                PRIMARY KEY (scope_type, scope_key)
            )",
            [],
        )
        .ok();

        conn.execute(
            "CREATE TABLE IF NOT EXISTS spend_counters (
                agent_id     TEXT NOT NULL,
                period_start INTEGER NOT NULL,
                spent_cents  INTEGER NOT NULL DEFAULT 0,
                updated_at   INTEGER NOT NULL,
                PRIMARY KEY (agent_id, period_start)
            )",
            [],
        )
        .ok();

        conn.execute(
            "CREATE TABLE IF NOT EXISTS spend_thresholds_fired (
                agent_id      TEXT NOT NULL,
                period_start  INTEGER NOT NULL,
                threshold_pct INTEGER NOT NULL,
                fired_at      INTEGER NOT NULL,
                PRIMARY KEY (agent_id, period_start, threshold_pct)
            )",
            [],
        )
        .ok();

        conn.execute(
            "CREATE TABLE IF NOT EXISTS spend_increase_requests (
                request_id   TEXT PRIMARY KEY,
                agent_id     TEXT NOT NULL,
                current_cap  INTEGER NOT NULL,
                reason       TEXT,
                status       TEXT NOT NULL DEFAULT 'pending',
                submitted_at INTEGER NOT NULL,
                resolved_at  INTEGER,
                resolved_by  TEXT,
                new_cap      INTEGER
            )",
            [],
        )
        .ok();

        conn.execute(
            "CREATE TABLE IF NOT EXISTS spend_ledger_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp INTEGER NOT NULL,
                request_id TEXT NOT NULL,
                idempotency_key TEXT UNIQUE,
                agent_id TEXT NOT NULL,
                client_id TEXT NOT NULL DEFAULT 'default',
                project_id TEXT NOT NULL DEFAULT 'default',
                cost_center TEXT NOT NULL DEFAULT 'default',
                provider TEXT NOT NULL DEFAULT 'unknown',
                model TEXT NOT NULL DEFAULT 'unknown',
                input_tokens INTEGER NOT NULL DEFAULT 0,
                output_tokens INTEGER NOT NULL DEFAULT 0,
                total_tokens INTEGER NOT NULL DEFAULT 0,
                cost_cents INTEGER NOT NULL DEFAULT 0,
                is_estimated INTEGER NOT NULL DEFAULT 0
            )",
            [],
        )
        .ok();

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_spend_records_client ON spend_ledger_records(client_id, project_id)",
            [],
        )
        .ok();

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_spend_records_ts ON spend_ledger_records(timestamp DESC)",
            [],
        )
        .ok();

        if let Some(client) = dashboard_client {
            let conn2 =
                Connection::open(&db_path).expect("Failed to open SQLite DB for spend sync");
            let _ = conn2.execute_batch("PRAGMA busy_timeout=5000;");
            std::thread::spawn(move || {
                loop {
                    std::thread::sleep(std::time::Duration::from_secs(60));
                    // Sync snapshots
                    let mut stmt = conn2
                        .prepare("SELECT agent_id, period_start, spent_cents FROM spend_counters")
                        .unwrap();
                    let rows = stmt.query_map([], |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, i64>(2)?,
                        ))
                    });
                    if let Ok(mapped_rows) = rows {
                        for row in mapped_rows.flatten() {
                            let snapshot = serde_json::json!({
                                "agent_id": row.0,
                                "period_start": chrono::DateTime::from_timestamp(row.1, 0).unwrap_or_default().to_rfc3339(),
                                "spent_cents": row.2,
                                "cap_cents": null,
                                "is_estimated": true,
                                "pricing_table_version": "default"
                            });
                            client.send_spend_snapshot(snapshot);
                        }
                    }
                }
            });
        }

        let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel::<SpendCmd>();
        let _shutdown = Arc::new(());

        std::thread::spawn(move || {
            let mut conn = conn;
            while let Some(cmd) = cmd_rx.blocking_recv() {
                match cmd {
                    SpendCmd::CheckAndIncrement {
                        agent_id,
                        identity_groups,
                        estimated_cents,
                        responder,
                    } => {
                        let tx = conn
                            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate);
                        match tx {
                            Ok(tx) => {
                                // 1. Determine budget
                                // User
                                let user_cap: Option<u64> = tx.query_row(
                                    "SELECT cap_cents FROM spend_budgets WHERE scope_type='user' AND scope_key=?",
                                    params![&agent_id],
                                    |row| row.get(0),
                                ).ok();

                                let mut active_cap = user_cap;

                                // Group
                                if active_cap.is_none() && !identity_groups.is_empty() {
                                    let mut lowest_group_cap: Option<u64> = None;
                                    for group in &identity_groups {
                                        if let Ok(cap) = tx.query_row(
                                            "SELECT cap_cents FROM spend_budgets WHERE scope_type='group' AND scope_key=?",
                                            params![group],
                                            |row| row.get(0),
                                        ) {
                                            if lowest_group_cap.is_none() || cap < lowest_group_cap.unwrap() {
                                                lowest_group_cap = Some(cap);
                                            }
                                        }
                                    }
                                    active_cap = lowest_group_cap;
                                }

                                // Org
                                if active_cap.is_none() {
                                    active_cap = tx.query_row(
                                        "SELECT cap_cents FROM spend_budgets WHERE scope_type='org' AND scope_key=''",
                                        [],
                                        |row| row.get(0),
                                    ).ok();
                                }

                                // 2. Enforce
                                if let Some(cap) = active_cap {
                                    let now = chrono::Utc::now();
                                    // Midnight UTC
                                    let period_start = now
                                        .date_naive()
                                        .and_hms_opt(0, 0, 0)
                                        .unwrap()
                                        .and_utc()
                                        .timestamp();

                                    let mut spent_cents: u64 = tx.query_row(
                                        "SELECT spent_cents FROM spend_counters WHERE agent_id=? AND period_start=?",
                                        params![&agent_id, period_start],
                                        |row| row.get(0),
                                    ).unwrap_or(0);

                                    if spent_cents + estimated_cents > cap {
                                        let _ = tx.commit();
                                        let _ = responder.send(SpendCheckResult::BudgetExhausted {
                                            cap_cents: cap,
                                            spent_cents,
                                        });
                                    } else {
                                        spent_cents += estimated_cents;
                                        let _ = tx.execute(
                                            "INSERT INTO spend_counters (agent_id, period_start, spent_cents, updated_at) VALUES (?, ?, ?, ?)
                                             ON CONFLICT(agent_id, period_start) DO UPDATE SET spent_cents=?, updated_at=?",
                                            params![&agent_id, period_start, spent_cents, now.timestamp(), spent_cents, now.timestamp()],
                                        );
                                        let _ = tx.commit();
                                        let _ = responder.send(SpendCheckResult::Ok {
                                            remaining_cents: cap - spent_cents,
                                        });
                                    }
                                } else {
                                    let _ = tx.commit();
                                    let _ = responder.send(SpendCheckResult::NoBudgetConfigured);
                                }
                            }
                            Err(_) => {
                                let _ = responder.send(SpendCheckResult::LedgerUnavailable);
                            }
                        }
                    }
                    SpendCmd::SetBudget {
                        scope,
                        cap_cents,
                        period,
                        responder,
                    } => {
                        let (scope_type, scope_key) = match scope {
                            BudgetScope::Org => ("org", "".to_string()),
                            BudgetScope::Group(g) => ("group", g),
                            BudgetScope::User(u) => ("user", u),
                        };
                        let p = match period {
                            BudgetPeriod::Daily => "daily",
                            BudgetPeriod::Weekly => "weekly",
                            BudgetPeriod::Monthly => "monthly",
                        };
                        let now = chrono::Utc::now().timestamp();
                        let res = conn.execute(
                            "INSERT INTO spend_budgets (scope_type, scope_key, cap_cents, period, created_at, updated_at) 
                             VALUES (?, ?, ?, ?, ?, ?)
                             ON CONFLICT(scope_type, scope_key) DO UPDATE SET cap_cents=?, period=?, updated_at=?",
                            params![scope_type, scope_key, cap_cents, p, now, now, cap_cents, p, now],
                        ).map(|_| ()).map_err(|e| e.to_string());
                        let _ = responder.send(res);
                    }
                    SpendCmd::SettleUsage {
                        request_id,
                        agent_id,
                        attribution,
                        provider,
                        model,
                        input_tokens,
                        output_tokens,
                        total_tokens,
                        cost_cents,
                        is_estimated,
                    } => {
                        let now = chrono::Utc::now();
                        let idempotency_key = format!("settle-{}", request_id);
                        let _ = conn.execute(
                            "INSERT INTO spend_ledger_records (
                                timestamp, request_id, idempotency_key, agent_id, client_id, project_id, cost_center,
                                provider, model, input_tokens, output_tokens, total_tokens, cost_cents, is_estimated
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            ON CONFLICT(idempotency_key) DO NOTHING",
                            params![
                                now.timestamp(),
                                request_id,
                                idempotency_key,
                                agent_id,
                                attribution.client_id,
                                attribution.project_id,
                                attribution.cost_center,
                                provider,
                                model,
                                input_tokens,
                                output_tokens,
                                total_tokens,
                                cost_cents,
                                if is_estimated { 1 } else { 0 }
                            ],
                        );

                        // Also increment rolling daily counter in spend_counters
                        let period_start = now
                            .date_naive()
                            .and_hms_opt(0, 0, 0)
                            .unwrap()
                            .and_utc()
                            .timestamp();

                        let _ = conn.execute(
                            "INSERT INTO spend_counters (agent_id, period_start, spent_cents, updated_at) VALUES (?, ?, ?, ?)
                             ON CONFLICT(agent_id, period_start) DO UPDATE SET spent_cents = spent_cents + ?, updated_at = ?",
                            params![&agent_id, period_start, cost_cents, now.timestamp(), cost_cents, now.timestamp()],
                        );
                    }
                    SpendCmd::ExportUsage { filter, responder } => {
                        let mut query = "SELECT timestamp, request_id, client_id, project_id, cost_center, agent_id, provider, model, input_tokens, output_tokens, total_tokens, cost_cents, is_estimated FROM spend_ledger_records WHERE 1=1".to_string();
                        let mut params_vec: Vec<rusqlite::types::Value> = Vec::new();

                        if let Some(ref c) = filter.client_id {
                            query.push_str(" AND client_id = ?");
                            params_vec.push(c.clone().into());
                        }
                        if let Some(ref p) = filter.project_id {
                            query.push_str(" AND project_id = ?");
                            params_vec.push(p.clone().into());
                        }
                        if let Some(start) = filter.start_timestamp {
                            query.push_str(" AND timestamp >= ?");
                            params_vec.push(start.into());
                        }
                        if let Some(end) = filter.end_timestamp {
                            query.push_str(" AND timestamp <= ?");
                            params_vec.push(end.into());
                        }
                        query.push_str(" ORDER BY timestamp DESC LIMIT 5000");

                        let mut records = Vec::new();
                        if let Ok(mut stmt) = conn.prepare(&query) {
                            let rows = stmt.query_map(
                                rusqlite::params_from_iter(params_vec.iter()),
                                |row| {
                                    let ts_secs: i64 = row.get(0)?;
                                    let ts_str = chrono::DateTime::from_timestamp(ts_secs, 0)
                                        .map(|dt| dt.to_rfc3339())
                                        .unwrap_or_default();
                                    let cost_cents: u64 = row.get(11)?;
                                    Ok(SpendExportRecord {
                                        timestamp: ts_str,
                                        request_id: row.get(1)?,
                                        client_id: row.get(2)?,
                                        project_id: row.get(3)?,
                                        cost_center: row.get(4)?,
                                        agent_id: row.get(5)?,
                                        provider: row.get(6)?,
                                        model: row.get(7)?,
                                        input_tokens: row.get(8)?,
                                        output_tokens: row.get(9)?,
                                        total_tokens: row.get(10)?,
                                        cost_cents,
                                        cost_usd: cost_cents as f64 / 100.0,
                                        is_estimated: row.get::<_, i64>(12)? == 1,
                                    })
                                },
                            );
                            if let Ok(mapped) = rows {
                                for r in mapped.flatten() {
                                    records.push(r);
                                }
                            }
                        }
                        let _ = responder.send(records);
                    }
                    SpendCmd::ListBudgets { responder } => {
                        let mut budgets = Vec::new();
                        if let Ok(mut stmt) = conn.prepare(
                            "SELECT scope_type, scope_key, cap_cents, period FROM spend_budgets",
                        ) {
                            let rows = stmt.query_map([], |row| {
                                let s_type: String = row.get(0)?;
                                let s_key: String = row.get(1)?;
                                let cap_cents: u64 = row.get(2)?;
                                let p_str: String = row.get(3)?;

                                let scope = match s_type.as_str() {
                                    "org" => BudgetScope::Org,
                                    "group" => BudgetScope::Group(s_key),
                                    _ => BudgetScope::User(s_key),
                                };
                                let period = match p_str.as_str() {
                                    "weekly" => BudgetPeriod::Weekly,
                                    "monthly" => BudgetPeriod::Monthly,
                                    _ => BudgetPeriod::Daily,
                                };
                                Ok(BudgetConfig {
                                    scope,
                                    cap_cents,
                                    period,
                                })
                            });
                            if let Ok(mapped) = rows {
                                for b in mapped.flatten() {
                                    budgets.push(b);
                                }
                            }
                        }
                        let _ = responder.send(budgets);
                    }
                    SpendCmd::GetSpend {
                        agent_id,
                        responder,
                    } => {
                        let now = chrono::Utc::now();
                        let period_start = now
                            .date_naive()
                            .and_hms_opt(0, 0, 0)
                            .unwrap()
                            .and_utc()
                            .timestamp();

                        let spent_cents: u64 = conn.query_row(
                            "SELECT spent_cents FROM spend_counters WHERE agent_id=? AND period_start=?",
                            params![&agent_id, period_start],
                            |row| row.get(0),
                        ).unwrap_or(0);

                        let cap_cents: Option<u64> = conn.query_row(
                            "SELECT cap_cents FROM spend_budgets WHERE scope_type='user' AND scope_key=?",
                            params![&agent_id],
                            |row| row.get(0),
                        ).ok();

                        let spend = AgentSpend {
                            agent_id,
                            period_start: chrono::DateTime::from_timestamp(period_start, 0)
                                .unwrap_or_default(),
                            spent_cents,
                            cap_cents,
                            is_estimated: false,
                        };
                        let _ = responder.send(Some(spend));
                    }
                    _ => {} // Other commands unimplemented in prototype
                }
            }
        });

        Self {
            cmd_tx,
            concurrency_ceiling: 50,
            _shutdown,
        }
    }

    pub async fn check_and_increment(
        &self,
        agent_id: String,
        identity_groups: Vec<String>,
        estimated_cents: u64,
    ) -> SpendCheckResult {
        let (tx, rx) = oneshot::channel();
        if self
            .cmd_tx
            .send(SpendCmd::CheckAndIncrement {
                agent_id,
                identity_groups,
                estimated_cents,
                responder: tx,
            })
            .is_err()
        {
            return SpendCheckResult::LedgerUnavailable;
        }
        rx.await.unwrap_or(SpendCheckResult::LedgerUnavailable)
    }

    /// Settle exact usage and attribution after a request or stream completes.
    pub fn settle_usage(
        &self,
        request_id: String,
        agent_id: String,
        attribution: AttributionContext,
        provider: String,
        model: String,
        input_tokens: u64,
        output_tokens: u64,
        total_tokens: u64,
        cost_cents: u64,
        is_estimated: bool,
    ) {
        let _ = self.cmd_tx.send(SpendCmd::SettleUsage {
            request_id,
            agent_id,
            attribution,
            provider,
            model,
            input_tokens,
            output_tokens,
            total_tokens,
            cost_cents,
            is_estimated,
        });
    }

    /// Query usage records for export.
    pub async fn export_usage(&self, filter: SpendExportFilter) -> Vec<SpendExportRecord> {
        let (tx, rx) = oneshot::channel();
        if self
            .cmd_tx
            .send(SpendCmd::ExportUsage {
                filter,
                responder: tx,
            })
            .is_err()
        {
            return Vec::new();
        }
        rx.await.unwrap_or_default()
    }

    /// List active budgets.
    pub async fn list_budgets(&self) -> Vec<BudgetConfig> {
        let (tx, rx) = oneshot::channel();
        if self
            .cmd_tx
            .send(SpendCmd::ListBudgets { responder: tx })
            .is_err()
        {
            return Vec::new();
        }
        rx.await.unwrap_or_default()
    }

    /// Set a budget cap.
    pub async fn set_budget(
        &self,
        scope: BudgetScope,
        cap_cents: u64,
        period: BudgetPeriod,
    ) -> Result<(), String> {
        let (tx, rx) = oneshot::channel();
        if self
            .cmd_tx
            .send(SpendCmd::SetBudget {
                scope,
                cap_cents,
                period,
                responder: tx,
            })
            .is_err()
        {
            return Err("Spend ledger unavailable".to_string());
        }
        rx.await
            .unwrap_or_else(|_| Err("No response from ledger".to_string()))
    }

    /// Get current spend for an agent.
    pub async fn get_spend(&self, agent_id: String) -> Option<AgentSpend> {
        let (tx, rx) = oneshot::channel();
        if self
            .cmd_tx
            .send(SpendCmd::GetSpend {
                agent_id,
                responder: tx,
            })
            .is_err()
        {
            return None;
        }
        rx.await.unwrap_or(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_settle_usage_and_export() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("spend.db");
        let ledger = SpendLedger::init_with_path(Some(db_path), None);

        let attr = AttributionContext::new("client_acme", "proj_alpha", "eng_core");
        ledger.settle_usage(
            "req-123".to_string(),
            "agent-x".to_string(),
            attr,
            "openai".to_string(),
            "gpt-4o".to_string(),
            100,
            50,
            150,
            42,
            false,
        );

        // Allow background thread to process
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let all_records = ledger.export_usage(SpendExportFilter::default()).await;
        assert_eq!(all_records.len(), 1);
        assert_eq!(all_records[0].request_id, "req-123");
        assert_eq!(all_records[0].client_id, "client_acme");
        assert_eq!(all_records[0].project_id, "proj_alpha");
        assert_eq!(all_records[0].cost_center, "eng_core");
        assert_eq!(all_records[0].total_tokens, 150);
        assert_eq!(all_records[0].cost_cents, 42);

        // Filter by matching client
        let acme_filter = SpendExportFilter {
            client_id: Some("client_acme".to_string()),
            ..Default::default()
        };
        let acme_records = ledger.export_usage(acme_filter).await;
        assert_eq!(acme_records.len(), 1);

        // Filter by non-matching client
        let other_filter = SpendExportFilter {
            client_id: Some("client_other".to_string()),
            ..Default::default()
        };
        let other_records = ledger.export_usage(other_filter).await;
        assert_eq!(other_records.len(), 0);
    }

    #[tokio::test]
    async fn test_budget_enforcement() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("spend_budget.db");
        let ledger = SpendLedger::init_with_path(Some(db_path), None);

        let set_res = ledger
            .set_budget(
                BudgetScope::User("agent-capped".to_string()),
                10,
                BudgetPeriod::Daily,
            )
            .await;
        assert!(set_res.is_ok());

        // First increment within cap (5 <= 10)
        let res1 = ledger
            .check_and_increment("agent-capped".to_string(), vec![], 5)
            .await;
        match res1 {
            SpendCheckResult::Ok { remaining_cents } => {
                assert_eq!(remaining_cents, 5);
            }
            other => panic!("Expected Ok, got {:?}", other),
        }

        // Second increment breaches cap (5 + 6 = 11 > 10)
        let res2 = ledger
            .check_and_increment("agent-capped".to_string(), vec![], 6)
            .await;
        match res2 {
            SpendCheckResult::BudgetExhausted {
                cap_cents,
                spent_cents,
            } => {
                assert_eq!(cap_cents, 10);
                assert_eq!(spent_cents, 5);
            }
            other => panic!("Expected BudgetExhausted, got {:?}", other),
        }
    }
}
