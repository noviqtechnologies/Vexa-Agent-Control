// src/proxy/db.rs
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};

use rusqlite::{params, Connection, Transaction};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EgressEvent {
    pub timestamp_ns: i64,
    pub session_id: String,
    pub transport: String,
    pub method: Option<String>,
    pub target_host: String,
    pub target_port: Option<i64>,
    pub url_path: Option<String>,
    pub request_headers: Option<String>,
    pub request_body: Option<String>,
    pub request_body_hash: Option<String>,
    pub response_status: Option<i64>,
    pub response_body: Option<String>,
    pub response_body_hash: Option<String>,
    pub dlp_findings: Option<String>,
    pub injection_findings: Option<String>,
    pub latency_ms: Option<f64>,
    pub verdict: Option<String>,
    pub semantic_anomaly_score: Option<f64>,
    pub identity_context: Option<String>,
    pub source: Option<String>,
    pub policy_rule: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DbStats {
    pub total_events: i64,
    pub unique_tools: i64,
    pub risk_flag_count: i64,
}

// Commands sent to the DB manager thread
#[allow(clippy::large_enum_variant)]
pub enum DbCmd {
    Insert(EgressEvent),
    Fetch {
        limit: usize,
        responder: oneshot::Sender<Result<Vec<EgressEvent>, String>>,
    },
    /// Fetch all events in chronological order (oldest first) — used by generate-policy (FR-4)
    FetchAll {
        limit: usize,
        responder: oneshot::Sender<Result<Vec<EgressEvent>, String>>,
    },
    GetStats {
        responder: oneshot::Sender<Result<DbStats, String>>,
    },
    UpdateAnomalyScore {
        session_id: String,
        timestamp_ns: i64,
        score: f64,
    },
    Prune,
}

/// Handles SQLite interactions on a dedicated thread.
/// The manager is cheap to clone (Arc) and provides async helpers.
#[derive(Clone)]
pub struct DbManager {
    cmd_tx: mpsc::UnboundedSender<DbCmd>,
    // Keep a handle for potential graceful shutdown (not used currently)
    _shutdown: Arc<()>,
}

impl DbManager {
    /// Initialise the manager, opening/creating the DB file under $HOME/.agentcontrol/events.db.
    /// Spawns a background thread that processes commands.
    pub fn init() -> Self {
        // Resolve path with fallback
        let home_dir = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        let new_dir = PathBuf::from(&home_dir).join(".agentcontrol");
        let old_dir = PathBuf::from(&home_dir).join(".agentwall");

        if !new_dir.exists() {
            let _ = fs::create_dir_all(&new_dir);
            // Auto-migrate legacy database and credentials if they exist
            if old_dir.exists() {
                let old_db = old_dir.join("events.db");
                let new_db = new_dir.join("events.db");
                if old_db.exists() && !new_db.exists() {
                    let _ = fs::copy(&old_db, &new_db);
                }
            }
        }

        let db_path = new_dir.join("events.db");
        // Open connection with in-memory fallback on filesystem failure
        let conn = Connection::open(&db_path).unwrap_or_else(|e| {
            eprintln!("[db] warning: failed to open persistent SQLite at {:?}: {}. Falling back to in-memory DB.", db_path, e);
            Connection::open_in_memory().expect("failed to open fallback in-memory SQLite DB")
        });

        // Enable WAL mode so concurrent stdio-proxy processes can write without SQLITE_BUSY errors.
        if let Err(e) = conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;") {
            eprintln!("[db] warning: failed to set WAL mode: {}", e);
        }

        // Ensure schema exists
        if let Err(e) = conn.execute(
            "CREATE TABLE IF NOT EXISTS egress_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp_ns INTEGER NOT NULL,
                session_id TEXT NOT NULL,
                transport TEXT NOT NULL,
                method TEXT,
                target_host TEXT NOT NULL,
                target_port INTEGER,
                url_path TEXT,
                request_headers TEXT,
                request_body TEXT,
                request_body_hash TEXT,
                response_status INTEGER,
                response_body TEXT,
                response_body_hash TEXT,
                dlp_findings TEXT,
                injection_findings TEXT,
                latency_ms REAL,
                verdict TEXT,
                semantic_anomaly_score REAL,
                identity_context TEXT,
                source TEXT,
                policy_rule TEXT
            )",
            [],
        ) {
            eprintln!("[db] warning: failed to initialize egress_events table: {}", e);
        }

        // Schema v2.0 migrations
        let _ = conn.execute(
            "ALTER TABLE egress_events ADD COLUMN semantic_anomaly_score REAL",
            [],
        );
        let _ = conn.execute(
            "ALTER TABLE egress_events ADD COLUMN identity_context TEXT",
            [],
        );
        let _ = conn.execute(
            "ALTER TABLE egress_events ADD COLUMN source TEXT",
            [],
        );
        let _ = conn.execute(
            "ALTER TABLE egress_events ADD COLUMN policy_rule TEXT",
            [],
        );

        // Channel for commands
        let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel::<DbCmd>();
        // Use Arc to keep connection alive across thread boundaries safely
        let _shutdown = Arc::new(());
        // Spawn background thread
        std::thread::spawn(move || {
            // The thread owns the connection and a possible transaction.
            let conn = conn;
            let mut tx: Option<Transaction> = None;
            while let Some(cmd) = cmd_rx.blocking_recv() {
                match cmd {
                    DbCmd::Insert(event) => {
                        let sql = "INSERT INTO egress_events (
                                timestamp_ns, session_id, transport, method, target_host, target_port, url_path,
                                request_headers, request_body, request_body_hash, response_status, response_body, response_body_hash,
                                dlp_findings, injection_findings, latency_ms, verdict, semantic_anomaly_score, identity_context,
                                source, policy_rule
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
                        let params_arr = params![
                            event.timestamp_ns,
                            event.session_id,
                            event.transport,
                            event.method,
                            event.target_host,
                            event.target_port,
                            event.url_path,
                            event.request_headers,
                            event.request_body,
                            event.request_body_hash,
                            event.response_status,
                            event.response_body,
                            event.response_body_hash,
                            event.dlp_findings,
                            event.injection_findings,
                            event.latency_ms,
                            event.verdict,
                            event.semantic_anomaly_score,
                            event.identity_context,
                            event.source,
                            event.policy_rule
                        ];
                        let res = if let Some(ref mut tx) = tx {
                            tx.execute(sql, params_arr)
                        } else {
                            conn.execute(sql, params_arr)
                        };
                        if let Err(e) = res {
                            eprintln!("[db] failed to insert egress event: {}", e);
                        }
                    }
                    DbCmd::Fetch { limit, responder } => {
                        let stmt_res = conn.prepare(
                            "SELECT timestamp_ns, session_id, transport, method, target_host, target_port, url_path, request_headers, request_body, request_body_hash, response_status, response_body, response_body_hash, dlp_findings, injection_findings, latency_ms, verdict, semantic_anomaly_score, identity_context, source, policy_rule FROM egress_events ORDER BY id DESC LIMIT ?",
                        );
                        match stmt_res {
                            Ok(mut stmt) => {
                                match stmt.query_map(params![limit as i64], |row| {
                                    Ok(EgressEvent {
                                        timestamp_ns: row.get(0)?,
                                        session_id: row.get(1)?,
                                        transport: row.get(2)?,
                                        method: row.get(3)?,
                                        target_host: row.get(4)?,
                                        target_port: row.get(5)?,
                                        url_path: row.get(6)?,
                                        request_headers: row.get(7)?,
                                        request_body: row.get(8)?,
                                        request_body_hash: row.get(9)?,
                                        response_status: row.get(10)?,
                                        response_body: row.get(11)?,
                                        response_body_hash: row.get(12)?,
                                        dlp_findings: row.get(13)?,
                                        injection_findings: row.get(14)?,
                                        latency_ms: row.get(15)?,
                                        verdict: row.get(16)?,
                                        semantic_anomaly_score: row.get(17).unwrap_or(None),
                                        identity_context: row.get(18).unwrap_or(None),
                                        source: row.get(19).unwrap_or(None),
                                        policy_rule: row.get(20).unwrap_or(None),
                                    })
                                }) {
                                    Ok(rows) => {
                                        let mut events = Vec::new();
                                        for e in rows.flatten() {
                                            events.push(e);
                                        }
                                        let _ = responder.send(Ok(events));
                                    }
                                    Err(e) => {
                                        let _ = responder.send(Err(format!("Query execution failed: {}", e)));
                                    }
                                }
                            }
                            Err(e) => {
                                let _ = responder.send(Err(format!("Statement preparation failed: {}", e)));
                            }
                        }
                    }
                    DbCmd::FetchAll { limit, responder } => {
                        let stmt_res = conn.prepare(
                            "SELECT timestamp_ns, session_id, transport, method, target_host, target_port, url_path, request_headers, request_body, request_body_hash, response_status, response_body, response_body_hash, dlp_findings, injection_findings, latency_ms, verdict, semantic_anomaly_score, identity_context, source, policy_rule FROM egress_events ORDER BY id ASC LIMIT ?",
                        );
                        match stmt_res {
                            Ok(mut stmt) => {
                                match stmt.query_map(params![limit as i64], |row| {
                                    Ok(EgressEvent {
                                        timestamp_ns: row.get(0)?,
                                        session_id: row.get(1)?,
                                        transport: row.get(2)?,
                                        method: row.get(3)?,
                                        target_host: row.get(4)?,
                                        target_port: row.get(5)?,
                                        url_path: row.get(6)?,
                                        request_headers: row.get(7)?,
                                        request_body: row.get(8)?,
                                        request_body_hash: row.get(9)?,
                                        response_status: row.get(10)?,
                                        response_body: row.get(11)?,
                                        response_body_hash: row.get(12)?,
                                        dlp_findings: row.get(13)?,
                                        injection_findings: row.get(14)?,
                                        latency_ms: row.get(15)?,
                                        verdict: row.get(16)?,
                                        semantic_anomaly_score: row.get(17).unwrap_or(None),
                                        identity_context: row.get(18).unwrap_or(None),
                                        source: row.get(19).unwrap_or(None),
                                        policy_rule: row.get(20).unwrap_or(None),
                                    })
                                }) {
                                    Ok(rows) => {
                                        let mut events = Vec::new();
                                        for e in rows.flatten() {
                                            events.push(e);
                                        }
                                        let _ = responder.send(Ok(events));
                                    }
                                    Err(e) => {
                                        let _ = responder.send(Err(format!("Query execution failed: {}", e)));
                                    }
                                }
                            }
                            Err(e) => {
                                let _ = responder.send(Err(format!("Statement preparation failed: {}", e)));
                            }
                        }
                    }
                    DbCmd::GetStats { responder } => {
                        let total_events: i64 = conn
                            .query_row("SELECT COUNT(*) FROM egress_events", [], |row| row.get(0))
                            .unwrap_or(0);

                        let unique_tools: i64 = conn.query_row(
                                "SELECT COUNT(DISTINCT url_path) FROM egress_events WHERE transport='mcp'",
                                [],
                                |row| row.get(0),
                            ).unwrap_or(0);

                        let _ = responder.send(Ok(DbStats {
                            total_events,
                            unique_tools,
                            risk_flag_count: 0, // Inferred on client
                        }));
                    }
                    DbCmd::UpdateAnomalyScore {
                        session_id,
                        timestamp_ns,
                        score,
                    } => {
                        let sql = "UPDATE egress_events SET semantic_anomaly_score = ? WHERE session_id = ? AND timestamp_ns = ?";
                        let params_arr = params![score, session_id, timestamp_ns];
                        if let Some(ref mut tx) = tx {
                            tx.execute(sql, params_arr).ok();
                        } else {
                            conn.execute(sql, params_arr).ok();
                        }
                    }
                    DbCmd::Prune => {
                        // Prune if file size > 500 MiB
                        if let Ok(metadata) = fs::metadata(&db_path) {
                            if metadata.len() > 500 * 1024 * 1024 {
                                // Delete oldest 1000 rows
                                conn.execute(
                                        "DELETE FROM egress_events WHERE id IN (SELECT id FROM egress_events ORDER BY id ASC LIMIT 1000)",
                                        [],
                                    )
                                    .ok();
                            }
                        }
                    }
                }
            }
        });

        Self { cmd_tx, _shutdown }
    }

    /// Async insert of an event.
    pub async fn insert(&self, event: EgressEvent) -> Result<(), String> {
        self.cmd_tx
            .send(DbCmd::Insert(event))
            .map_err(|e| format!("Failed to send insert cmd: {}", e))
    }

    /// Async fetch of recent events in reverse-chronological order (newest first), limited to `limit`.
    pub async fn get_events(&self, limit: usize) -> Result<Vec<EgressEvent>, String> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(DbCmd::Fetch {
                limit,
                responder: tx,
            })
            .map_err(|e| format!("Failed to send fetch cmd: {}", e))?;
        rx.await
            .map_err(|e| format!("Fetch response error: {}", e))?
    }

    /// Async fetch of all events in chronological order (oldest first) for policy generation (FR-4).
    /// `limit` is capped at 500 by the `generate-policy` command.
    pub async fn get_all_events(&self, limit: usize) -> Result<Vec<EgressEvent>, String> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(DbCmd::FetchAll {
                limit,
                responder: tx,
            })
            .map_err(|e| format!("Failed to send fetch-all cmd: {}", e))?;
        rx.await
            .map_err(|e| format!("FetchAll response error: {}", e))?
    }

    /// Async fetch of aggregate stats.
    pub async fn get_stats(&self) -> Result<DbStats, String> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(DbCmd::GetStats { responder: tx })
            .map_err(|e| format!("Failed to send stats cmd: {}", e))?;
        rx.await
            .map_err(|e| format!("Stats response error: {}", e))?
    }

    /// Async update of anomaly score.
    pub fn update_anomaly_score(&self, session_id: String, timestamp_ns: i64, score: f64) {
        let _ = self.cmd_tx.send(DbCmd::UpdateAnomalyScore {
            session_id,
            timestamp_ns,
            score,
        });
    }

    /// Trigger pruning (optional public helper).
    pub fn prune(&self) {
        let _ = self.cmd_tx.send(DbCmd::Prune);
    }
}

// Helper to create a ready‑to‑use manager – mirrors the previous `new` function name.
pub fn init_db_manager() -> DbManager {
    DbManager::init()
}

// The module is deliberately lightweight; higher‑level code should call `insert` and `get_events`.
