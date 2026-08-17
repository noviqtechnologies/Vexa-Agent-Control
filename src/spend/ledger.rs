//! # LEGACY OBSERVATIONAL SPEND TELEMETRY PROTOTYPE
//!
//! **DEPRECATION NOTICE:**
//! This local SQLite token ledger is retained for legacy read-only local telemetry during transition.
//! Authoritative financial budgets and preflight reservation state live exclusively in the central
//! PostgreSQL ledger via `/api/v2/spend/*`. This local counter must NOT be treated as central
//! financial control truth or provider-invoice reconciled truth.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{mpsc, oneshot};

use rusqlite::{params, Connection};

use super::model::{
    AgentSpend, BudgetConfig, BudgetPeriod, BudgetScope, IncreaseRequest, SpendCheckResult,
};

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

        let db_path = new_dir.join("events.db");

        let start = Instant::now();
        let conn = Connection::open(&db_path).expect("Failed to open SQLite DB for spend");

        // Write latency measurement
        conn.execute(
            "CREATE TABLE IF NOT EXISTS spend_latency_test (id INTEGER)",
            [],
        )
        .ok();
        conn.execute("INSERT INTO spend_latency_test (id) VALUES (1)", [])
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

        if let Some(client) = dashboard_client {
            let conn2 =
                Connection::open(&db_path).expect("Failed to open SQLite DB for spend sync");
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
}
