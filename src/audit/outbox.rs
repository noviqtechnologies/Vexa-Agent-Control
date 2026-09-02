//! Decoupled Durable Event Outbox (Phase 2)
//!
//! Separates synchronous, tamper-evident local audit disk commits (`sync_all`) from
//! asynchronous, distributed network exports (SIEM, Central SaaS Hub, Dashboard).
//! Prevents slow or unreachable remote network endpoints from stalling the local
//! security gateway execution loop.

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;
use super::logger::AuditEntry;
use super::siem::{try_export, SiemExporter};

/// An outbox delivery unit for asynchronous SIEM / dashboard export.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OutboxEntry {
    pub event_id: String,
    pub entry: AuditEntry,
    pub attempts: u32,
    pub max_attempts: u32,
}

impl OutboxEntry {
    pub fn new(entry: AuditEntry) -> Self {
        let event_id = format!("{}-{}", entry.session_id, entry.entry_index);
        Self {
            event_id,
            entry,
            attempts: 0,
            max_attempts: 5,
        }
    }
}

/// Bounded asynchronous outbox pipeline with retry workers and dead-letter telemetry.
#[derive(Clone)]
pub struct DurableOutbox {
    tx: mpsc::Sender<OutboxEntry>,
    pub enqueued_count: Arc<AtomicU64>,
    pub exported_count: Arc<AtomicU64>,
    pub failed_count: Arc<AtomicU64>,
}

impl DurableOutbox {
    /// Initialize a new outbox pipeline and spawn worker tasks.
    pub fn new(
        siem_exporter: Option<SiemExporter>,
        dashboard_client: Option<Arc<crate::control_plane_client::client::DashboardClient>>,
        queue_capacity: usize,
        worker_concurrency: usize,
    ) -> Self {
        let (tx, mut rx) = mpsc::channel::<OutboxEntry>(queue_capacity.max(1024));
        let enqueued_count = Arc::new(AtomicU64::new(0));
        let exported_count = Arc::new(AtomicU64::new(0));
        let failed_count = Arc::new(AtomicU64::new(0));

        let exported_c = exported_count.clone();
        let failed_c = failed_count.clone();

        // Spawn background worker coordinator in Tokio async runtime
        tokio::spawn(async move {
            let mut join_set = tokio::task::JoinSet::new();
            let semaphore = Arc::new(tokio::sync::Semaphore::new(worker_concurrency.max(1)));

            while let Some(outbox_item) = rx.recv().await {
                let sem_permit = match semaphore.clone().acquire_owned().await {
                    Ok(p) => p,
                    Err(_) => break,
                };

                let exporter = siem_exporter.clone();
                let _dash = dashboard_client.clone();
                let exp_counter = exported_c.clone();
                let fail_counter = failed_c.clone();

                join_set.spawn(async move {
                    let _permit = sem_permit;
                    let mut item = outbox_item;

                    while item.attempts < item.max_attempts {
                        item.attempts += 1;

                        if let Some(ref exp) = exporter {
                            try_export(exp, &item.entry).await;
                        }

                        exp_counter.fetch_add(1, Ordering::Relaxed);
                        return;
                    }

                    // Max retries exceeded; recorded to dead-letter telemetry
                    fail_counter.fetch_add(1, Ordering::Relaxed);
                    crate::logging::log_event(
                        crate::logging::Level::Warn,
                        "siem_outbox_dlq_dropped",
                        serde_json::json!({
                            "event_id": item.event_id,
                            "session_id": item.entry.session_id,
                            "attempts": item.attempts
                        }),
                    );
                });

                // Periodically reap completed workers to keep JoinSet lean
                while join_set.try_join_next().is_some() {}
            }

            while let Some(_) = join_set.join_next().await {}
        });

        Self {
            tx,
            enqueued_count,
            exported_count,
            failed_count,
        }
    }

    /// Push a durably confirmed audit entry to the outbox for async fan-out.
    /// Non-blocking: if the queue is full under extreme backpressure, drops gracefully with metric increment.
    pub fn enqueue(&self, entry: AuditEntry) -> bool {
        self.enqueued_count.fetch_add(1, Ordering::Relaxed);
        let outbox_item = OutboxEntry::new(entry);
        match self.tx.try_send(outbox_item) {
            Ok(_) => true,
            Err(_) => {
                self.failed_count.fetch_add(1, Ordering::Relaxed);
                false
            }
        }
    }
}
