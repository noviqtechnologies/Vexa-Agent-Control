use crate::wrap::ide_config::enforce_ide_target;
use colored::*;
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::PathBuf;
use std::sync::mpsc::channel;
use std::time::Duration;

pub struct SentryWatcher {
    watched_paths: Vec<(String, PathBuf)>, // (ide_name, path)
    proxy_url: String,
}

impl SentryWatcher {
    pub fn new(proxy_url: String) -> Self {
        Self {
            watched_paths: Vec::new(),
            proxy_url,
        }
    }

    pub fn register_target(&mut self, ide_name: &str, path: PathBuf) {
        self.watched_paths.push((ide_name.to_string(), path));
    }

    /// Enforces proxy settings initially and starts the background notify loop
    pub fn run_event_loop(&self) -> Result<(), String> {
        // 1. Initial enforcement sweep across all registered targets
        for (name, _) in &self.watched_paths {
            if let Err(e) = enforce_ide_target(name, &self.proxy_url) {
                eprintln!("{} [sentry] Initial enforcement for {} warning: {}", "⚠".yellow(), name, e);
            } else {
                eprintln!("{} [sentry] Verified and locked proxy configuration for {}", "✔".green(), name);
            }
        }

        let (tx, rx) = channel();

        let mut watcher = RecommendedWatcher::new(
            move |res: Result<Event, notify::Error>| {
                if let Ok(event) = res {
                    let _ = tx.send(event);
                }
            },
            Config::default().with_poll_interval(Duration::from_millis(500)),
        )
        .map_err(|e| format!("Failed to create filesystem watcher: {}", e))?;

        // 2. Watch parent directories of target configs
        for (name, path) in &self.watched_paths {
            if let Some(parent) = path.parent() {
                if parent.exists() {
                    let _ = watcher.watch(parent, RecursiveMode::NonRecursive);
                    eprintln!("{} [sentry] Watching directory for {}: {}", "ℹ".blue(), name, parent.display());
                }
            }
        }

        // 3. Process events and auto-heal on modification
        while let Ok(event) = rx.recv() {
            match event.kind {
                EventKind::Modify(_) | EventKind::Create(_) => {
                    for (name, path) in &self.watched_paths {
                        for modified in &event.paths {
                            if modified == path {
                                eprintln!("{} [sentry] Detected modification in {} config. Executing self-healing...", "⚡".cyan(), name);
                                match enforce_ide_target(name, &self.proxy_url) {
                                    Ok(_) => {
                                        eprintln!("{} [sentry] {} auto-healed successfully (proxy={})", "✔".green(), name, self.proxy_url);
                                    }
                                    Err(e) => {
                                        eprintln!("{} [sentry] Failed to auto-heal {}: {}", "✖".red(), name, e);
                                    }
                                }
                                crate::wrap::status::gather_and_send_mcp_servers_snapshot();
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        Ok(())
    }
}
