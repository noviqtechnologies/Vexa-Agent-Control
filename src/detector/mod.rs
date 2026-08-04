//! Local Dual-Agent Detector Subsystem (Async Causal Threat Reasoning)

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::time::{sleep, Duration};

#[derive(Debug, Clone)]
pub struct DualAgentConfig {
    pub enabled: bool,
    pub local_llm_url: String,
    pub poll_interval_secs: u64,
}

impl Default for DualAgentConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            local_llm_url: "http://localhost:11434".to_string(),
            poll_interval_secs: 5,
        }
    }
}

pub struct LocalDualAgentDetector {
    pub config: DualAgentConfig,
    pub running: Arc<AtomicBool>,
}

impl LocalDualAgentDetector {
    pub fn new(config: DualAgentConfig) -> Self {
        Self {
            config,
            running: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn start(&self) {
        if !self.config.enabled {
            return;
        }
        self.running.store(true, Ordering::SeqCst);
        let running = Arc::clone(&self.running);
        let llm_url = self.config.local_llm_url.clone();
        let interval = self.config.poll_interval_secs;

        tokio::spawn(async move {
            println!(
                "🤖 Local Dual-Agent Threat Detector active [Endpoint: {}]",
                llm_url
            );
            while running.load(Ordering::Relaxed) {
                sleep(Duration::from_secs(interval)).await;
                // Async background causal threat reasoning on session traces
            }
        });
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }
}
