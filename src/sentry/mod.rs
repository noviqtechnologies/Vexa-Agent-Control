pub mod telemetry;
pub mod watcher;

use crate::wrap::ide_config::{
    cursor_settings_path, vscode_settings_path, windsurf_settings_path, zed_settings_path,
};

pub use telemetry::TelemetryClient;
pub use watcher::SentryWatcher;

/// Builds a standard Sentry Watcher pre-populated with all discovered IDE paths for the host OS
pub fn build_default_sentry_watcher(proxy_url: &str) -> SentryWatcher {
    let mut sentry = SentryWatcher::new(proxy_url.to_string());

    if let Some(p) = cursor_settings_path() {
        sentry.register_target("cursor", p);
    }
    if let Some(p) = vscode_settings_path() {
        sentry.register_target("vscode", p);
    }
    if let Some(p) = zed_settings_path() {
        sentry.register_target("zed", p);
    }
    if let Some(p) = windsurf_settings_path() {
        sentry.register_target("windsurf", p);
    }

    sentry
}
