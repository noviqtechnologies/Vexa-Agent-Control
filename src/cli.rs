//! CLI definitions — clap derive (§5.3)
//!
//! ## v6.1 Deprecation Changes
//!
//! - `--kill-mode process` / `--kill-mode both` removed from `start` and `wrap`.
//! - `agentcontrol init` is deprecated. Use a GitOps workflow instead.
//! - `agentcontrol test` now accepts `--gateway` and `--oidc-token` for CI/CD integration.

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "agentcontrol",
    bin_name = "agentcontrol",
    version,
    about = "VEXA Agent Control — centralized security gateway and governance proxy for AI agent tool calls over MCP",
    long_about = "VEXA Agent Control is a deterministic enterprise security gateway for Model Context Protocol (MCP)\n\
                  and AI agent tool executions. It enforces parameter DLP, prompt injection defense, token accounting,\n\
                  and HMAC-chained cryptographic audit trails across supported developer IDEs and autonomous agents."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Box<Commands>,
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)]
pub enum Commands {
    /// Browser PKCE OAuth authentication and zero-touch device onboarding
    Login {
        /// Control Hub API URL
        #[arg(
            long,
            alias = "hub",
            env = "AGENTCONTROL_HUB_URL",
            default_value = "https://app.vexasec.io"
        )]
        hub_url: String,

        /// Disable automatic opening of system browser
        #[arg(long, default_value_t = false)]
        no_browser: bool,
    },

    /// Configure a verified IDE client (codex, claude, vscode-continue) with ownership manifest
    Connect {
        /// Target client to connect
        target: crate::wrap::ConnectTarget,

        /// Connection mode (local or cloud-direct)
        #[arg(long, value_enum)]
        mode: Option<crate::wrap::ConnectMode>,

        /// Virtual key or authentication token (e.g. sk-vex-...)
        #[arg(long, short = 'k', env = "AGENTCONTROL_VIRTUAL_KEY")]
        key: Option<String>,

        /// Force connection even if client version is outside pinned range
        #[arg(long, default_value_t = false)]
        force: bool,
    },

    /// Non-destructively disconnect a client using ownership manifest, preserving all user customizations
    Disconnect {
        /// Target client to disconnect
        target: crate::wrap::ConnectTarget,
    },

    /// Read-only diagnostic health check returning standardized exit codes (0 healthy, 1 critical, 2 degraded)
    Doctor {
        /// Output results as JSON
        #[arg(long, default_value_t = false)]
        json: bool,
    },

    /// Generate a sanitized diagnostic support bundle (< 10MB) using structural allowlisting
    #[command(name = "support-bundle")]
    SupportBundle {
        /// Optional directory to save the support bundle
        #[arg(long)]
        output_dir: Option<std::path::PathBuf>,

        /// Automatically proceed without interactive confirmation prompt
        #[arg(long, short = 'y', default_value_t = false)]
        yes: bool,
    },

    /// Re-validate active configurations against manifests and repair background agent service
    Repair,

    /// Flush local workstation credentials and invalidate session
    Logout,

    /// Create a consistent online backup of local databases and audit logs (ADR 0.6)
    Backup {
        /// Optional destination directory (defaults to ~/.agentcontrol/backups)
        #[arg(long)]
        output_dir: Option<std::path::PathBuf>,
    },

    /// Verify the cryptographic HMAC chain of audit.jsonl and SQLite integrity of events.db (ADR 0.6)
    #[command(name = "verify-db")]
    VerifyDb {
        /// Optional custom path to audit.jsonl (defaults to ~/.agentcontrol/audit.jsonl)
        #[arg(long)]
        audit_path: Option<std::path::PathBuf>,
        /// Optional custom path to events.db (defaults to ~/.agentcontrol/events.db)
        #[arg(long)]
        db_path: Option<std::path::PathBuf>,
    },

    /// Purge local telemetry events and cache while preserving baseline config backups
    #[command(name = "reset-local-state")]
    ResetLocalState {
        /// Force reset without interactive confirmation prompt
        #[arg(long, default_value_t = false)]
        force: bool,
    },

    /// Rotate persistent local proxy bearer token and update connected client configurations
    #[command(name = "rotate-local-token")]
    RotateLocalToken,

    /// Perform PKI Device Enrollment with Control Hub
    #[command(hide = true)]
    Enroll {
        /// One-Time Enrollment Token (OTET)
        #[arg(long, env = "AGENTCONTROL_ENROLLMENT_TOKEN")]
        token: String,

        /// Control Hub API URL
        #[arg(
            long,
            env = "AGENTCONTROL_HUB_URL",
            default_value = "https://console.vexasec.io"
        )]
        hub_url: String,
    },

    /// Join organization / team workspace (SMB Feature)
    #[cfg(feature = "team")]
    #[command(hide = true)]
    Join {
        /// Organization or workspace join token
        #[arg(long)]
        token: String,

        /// Control Hub URL
        #[arg(long, default_value = "https://app.vexasec.io")]
        hub_url: String,
    },

    /// Manage Agent Control persistent OS Sentry Service Daemon
    Service {
        #[command(subcommand)]
        action: ServiceCliAction,
    },

    /// Start local shadow proxy (observation only, no enforcement) [DEPRECATED: Use 'start --shadow-mode']
    #[command(hide = true)]
    Dev {
        /// Listen address for HTTP mode (default: 127.0.0.1:18080)
        #[arg(long, default_value = "127.0.0.1:18080")]
        listen: String,

        /// Upstream HTTP MCP server URL (default: http://127.0.0.1:3000)
        #[arg(long, default_value = "http://127.0.0.1:3000")]
        mcp_url: String,

        /// Stdio proxy mode (wrap downstream command)
        #[arg(long, default_value_t = false)]
        stdio: bool,

        /// Disable automatic browser opening for the dashboard
        #[arg(long, default_value_t = false)]
        no_browser: bool,

        /// Enable active enforcement (prompt injection blocking, DLP blocking).
        /// By default dev runs in observation-only (shadow) mode.
        /// Pass --enforce to test blocking behaviour without a full `start` deployment.
        #[arg(long, default_value_t = false)]
        enforce: bool,

        /// Enable local policy learning mode (synthesizes agentcontrol-policy.yaml from local dev traffic)
        #[arg(long, default_value_t = false)]
        learn: bool,

        /// [EXPERIMENTAL] Enable opt-in local dual-agent threat detector worker (asynchronous advisory preview, disabled by default)
        #[arg(long, default_value_t = false)]
        dual_agent: bool,

        /// Only output LLM spend and cost interception logs on the terminal
        #[arg(long, default_value_t = false)]
        spend_only: bool,

        /// Minimum estimated prompt token threshold to display on terminal (useful to hide 15-token pings)
        #[arg(long, default_value_t = 0)]
        min_tokens: u64,

        /// Opt-in to recording raw prompt and response payloads in SQLite egress events (hashes stored by default)
        #[arg(long, env = "AGENTCONTROL_RECORD_PAYLOADS", default_value_t = false)]
        record_payloads: bool,

        /// [EXPERIMENTAL] Local LLM API endpoint for dual-agent advisory threat reasoning
        #[arg(long, default_value = "http://localhost:11434")]
        local_llm_url: String,

        /// Downstream command and arguments (for stdio mode)
        #[arg(last = true)]
        args: Vec<String>,
    },

    /// Start the local gateway proxy daemon (listening on 127.0.0.1:18080 by default)
    Start(Box<StartArgs>),

    /// Automatically wrap an existing agent command with AgentControl [LEGACY: Use 'connect']
    #[command(hide = true)]
    Wrap(Box<WrapArgs>),

    /// Validate a policy against a gateway instance using fixture test calls
    ///
    /// ## v6.1 Behavior
    ///
    /// File-only validation (without --gateway) is DEPRECATED. Policies must be validated
    /// against a deployed gateway instance in CI/CD pipelines to accurately simulate
    /// runtime DLP, cycle detection, and OIDC validation behavior.
    ///
    /// Use --gateway to point to a test gateway and --oidc-token for authentication.
    Test {
        /// YAML policy file path
        #[arg(long)]
        policy: String,

        /// Show DENY verdicts but exit 0 (for review without blocking CI)
        #[arg(long, default_value_t = false)]
        dry_run: bool,

        /// JSON fixture file
        fixture: String,

        /// Gateway endpoint URL for v6.1 gateway-mode validation (recommended)
        ///
        /// Example: --gateway https://agentcontrol.internal.corp/
        #[arg(long, env = "VEXA_GATEWAY_URL")]
        gateway: Option<String>,

        /// OIDC Bearer token for authenticating with the gateway
        #[arg(long, env = "AGENTCONTROL_OIDC_TOKEN")]
        oidc_token: Option<String>,
    },

    /// Run Vexa security scanner against local MCP server configurations
    Scan {
        /// Target policy or MCP configuration YAML file path
        #[arg(long, default_value = "agentcontrol-policy.yaml")]
        path: String,

        /// Output format (text|json)
        #[arg(long, default_value = "text")]
        format: String,
    },

    /// Agent Identity & Credential Governance
    Identity {
        #[command(subcommand)]
        command: IdentityCommands,
    },

    /// Generate compliance reports (SOC 2, ISO 27001, NIST AI RMF)
    Compliance {
        #[command(subcommand)]
        command: ComplianceCommands,
    },

    /// Spend budget enforcement and token accounting
    Spend {
        #[command(subcommand)]
        command: SpendCommands,
    },

    /// Restore AgentControl wrappers [LEGACY: Use 'disconnect']
    #[command(hide = true)]
    Unwrap {
        /// Target to unwrap (e.g. claude)
        #[command(subcommand)]
        target: UnwrapTarget,
    },

    /// Automatically discover IDEs, atomically wrap MCP configs, start gateway, and open dashboard [LEGACY: Use 'connect' and 'start']
    #[command(hide = true)]
    Protect {
        /// Preview changes without writing to disk or starting gateway
        #[arg(long, default_value_t = false)]
        dry_run: bool,

        /// Disable automatic opening of local dashboard in browser
        #[arg(long, default_value_t = false)]
        no_browser: bool,

        /// Listen address for gateway proxy (default: 127.0.0.1:18080)
        #[arg(long, default_value = "127.0.0.1:18080")]
        listen: String,

        /// Upstream HTTP MCP server URL (default: http://127.0.0.1:3000)
        #[arg(long, default_value = "http://127.0.0.1:3000")]
        mcp_url: String,

        /// Enable active enforcement mode (default: true for protect)
        #[arg(long, default_value_t = true)]
        enforce: bool,

        /// Enable observation-only shadow mode without active blocking
        #[arg(long, default_value_t = false)]
        shadow: bool,

        /// Only output LLM spend and cost interception logs on the terminal
        #[arg(long, default_value_t = false)]
        spend_only: bool,

        /// Minimum estimated prompt token threshold to display on terminal (useful to hide 15-token pings)
        #[arg(long, default_value_t = 0)]
        min_tokens: u64,

        /// Opt-in to recording raw prompt and response payloads in SQLite egress events (hashes stored by default)
        #[arg(long, env = "AGENTCONTROL_RECORD_PAYLOADS", default_value_t = false)]
        record_payloads: bool,

        /// YAML policy file path
        #[arg(long, default_value = "agentcontrol-policy.yaml")]
        policy: String,
    },

    /// One-command reversion — restore all IDE configurations from backups and verify integrity [LEGACY: Use 'disconnect']
    #[command(hide = true)]
    Unprotect {
        /// Preview unprotect operations without modifying disk
        #[arg(long, default_value_t = false)]
        dry_run: bool,

        /// Force restoration even if backup integrity warning is issued
        #[arg(long, default_value_t = false)]
        force: bool,
    },

    /// Internal command used by Claude Desktop to proxy tool calls
    #[command(name = "stdio-proxy", hide = true)]
    StdioProxy {
        /// Trailing arguments: -- <command> <args...>
        #[arg(last = true)]
        args: Vec<String>,

        /// Enable response scanning for secret detection
        #[arg(long, default_value_t = false)]
        scan_responses: bool,

        /// Block entire response on secret detection instead of redacting
        #[arg(long, default_value_t = false)]
        block_on_secrets: bool,

        /// Maximum response size to scan in bytes
        #[arg(long, default_value_t = 1048576)]
        max_scan_bytes: usize,
    },

    /// Validate a tool call payload against a policy file locally [LEGACY: Use 'test']
    #[command(hide = true)]
    Validate {
        /// YAML policy file path
        #[arg(long)]
        policy: String,

        /// Name of the tool to evaluate
        #[arg(long)]
        tool: String,

        /// Path to JSON file containing the parameters payload
        #[arg(long)]
        payload: String,
    },

    /// Lint a policy YAML file for schema and security warnings [LEGACY: Handled by Central Hub]
    #[command(hide = true)]
    Lint {
        /// YAML policy file path
        policy: String,
    },

    /// Show target configurations, capability vectors, and traffic freshness
    Status {
        /// Output results as structured JSON conforming to PRD schema
        #[arg(long, default_value_t = false)]
        json: bool,
    },

    /// Watch IDE configs and auto-wrap new MCP servers (daemon, event-driven) [LEGACY: Background daemon handles auto-detection]
    #[command(hide = true)]
    Watch {
        /// Watch all verified targets (currently Claude Desktop only — other
        /// paths are unverified and excluded from --all)
        #[arg(long, default_value_t = false)]
        all: bool,

        /// Target to watch (e.g. claude, cursor, vscode)
        #[command(subcommand)]
        target: Option<WatchTarget>,
    },

    /// Run live security verification probe against gateway (3-point smoke test)
    Verify {
        /// Gateway URL to test (default: http://127.0.0.1:18080)
        #[arg(long, default_value = "http://127.0.0.1:18080")]
        gateway: String,

        /// Output results as JSON
        #[arg(long, default_value_t = false)]
        json: bool,

        /// Optional Control Hub URL for authenticated effective-routing verification (REQ-VER-004)
        #[arg(long)]
        hub: Option<String>,

        /// Optional User ID to correlate verification against (defaults to OIDC claim or local OS user)
        #[arg(long)]
        user_id: Option<String>,

        /// Optional Assignment ID to verify
        #[arg(long)]
        assignment_id: Option<String>,

        /// Optional Gateway Auth Token / Secret (defaults to GATEWAY_SECRET or AGENTCONTROL_ADMIN_TOKEN env vars)
        #[arg(long)]
        token: Option<String>,
    },

    /// Manage gateway semantic vector cache and prompt economics
    Cache {
        #[command(subcommand)]
        command: CacheCommands,
    },
}

#[derive(Subcommand, Debug, Clone)]
pub enum CacheCommands {
    /// Show semantic cache hit ratio, tokens saved, and dollar cost advantage
    Status {
        /// Gateway URL to query (default: http://127.0.0.1:18080)
        #[arg(long, default_value = "http://127.0.0.1:18080")]
        gateway: String,

        /// Output results as raw JSON
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Clear all in-memory and Qdrant cache entries
    Clear {
        /// Gateway URL to query (default: http://127.0.0.1:18080)
        #[arg(long, default_value = "http://127.0.0.1:18080")]
        gateway: String,
    },
}

#[derive(Subcommand, Debug, Clone)]
pub enum WrapTarget {
    /// Wrap Claude Desktop MCP servers with AgentControl
    Claude {
        /// Preview what would change without writing (safe)
        #[arg(long, default_value_t = false)]
        dry_run: bool,

        /// Enable response scanning for secret detection
        #[arg(long, default_value_t = false)]
        scan_responses: bool,

        /// Block entire response on secret detection instead of redacting
        #[arg(long, default_value_t = false)]
        block_on_secrets: bool,
    },
    /// Wrap Cursor IDE with AgentControl
    Cursor {
        #[arg(long, default_value_t = false)]
        dry_run: bool,
    },
    /// Wrap VS Code with AgentControl
    Vscode {
        #[arg(long, default_value_t = false)]
        dry_run: bool,
    },
    /// Wrap JetBrains IDEs with AgentControl
    Jetbrains {
        #[arg(long, default_value_t = false)]
        dry_run: bool,
    },
    /// Wrap Zed Editor with AgentControl
    Zed {
        #[arg(long, default_value_t = false)]
        dry_run: bool,
    },
    /// Wrap Cline Extension with AgentControl
    Cline {
        #[arg(long, default_value_t = false)]
        dry_run: bool,
    },
    /// Wrap OpenCode with AgentControl
    Opencode {
        #[arg(long, default_value_t = false)]
        dry_run: bool,
    },
    /// Wrap Antigravity IDE with AgentControl
    Antigravity {
        #[arg(long, default_value_t = false)]
        dry_run: bool,
    },
    /// Wrap ChatGPT Codex with AgentControl
    Codex {
        #[arg(long, default_value_t = false)]
        dry_run: bool,
    },
}

#[derive(Subcommand)]
pub enum UnwrapTarget {
    /// Restore Claude Desktop config from the most recent AgentControl backup
    Claude {
        /// Restore even if backup is missing — prints manual cleanup instructions
        #[arg(long, default_value_t = false)]
        force: bool,
    },
    /// Restore Cursor config
    Cursor {
        #[arg(long, default_value_t = false)]
        force: bool,
    },
    /// Restore VS Code config
    Vscode {
        #[arg(long, default_value_t = false)]
        force: bool,
    },
    /// Restore JetBrains config
    Jetbrains {
        #[arg(long, default_value_t = false)]
        force: bool,
    },
    /// Restore Zed config
    Zed {
        #[arg(long, default_value_t = false)]
        force: bool,
    },
    /// Restore Cline config
    Cline {
        #[arg(long, default_value_t = false)]
        force: bool,
    },
    /// Restore OpenCode config
    Opencode {
        #[arg(long, default_value_t = false)]
        force: bool,
    },
    /// Restore Antigravity config
    Antigravity {
        #[arg(long, default_value_t = false)]
        force: bool,
    },
    /// Restore Codex config
    Codex {
        #[arg(long, default_value_t = false)]
        force: bool,
    },
}

#[derive(Subcommand, Clone, Debug)]
pub enum WatchTarget {
    /// Watch Claude Desktop MCP config (verified path — safe to use with --all)
    Claude {
        /// Enable response scanning for secret detection on each daemon-triggered re-wrap
        #[arg(long, default_value_t = false)]
        scan_responses: bool,

        /// Block entire response on secret detection instead of redacting
        #[arg(long, default_value_t = false)]
        block_on_secrets: bool,
    },
    /// Watch Cursor IDE config
    Cursor,
    /// Watch VS Code config
    Vscode,
    /// Watch JetBrains config
    Jetbrains,
    /// Watch Zed Editor config
    Zed,
    /// Watch Cline extension config
    Cline,
    /// Watch OpenCode config
    Opencode,
    /// Watch Antigravity IDE config
    Antigravity,
    /// Watch Codex config
    Codex,
}

#[derive(Subcommand)]
pub enum IdentityCommands {
    /// Provision a scoped, short-lived credential for an agent
    Create {
        /// Agent identifier
        #[arg(long)]
        agent: String,

        /// Scope string (e.g., "read-only")
        #[arg(long)]
        scope: String,

        /// Time-to-live (e.g., "1h", "30m")
        #[arg(long, default_value = "1h")]
        ttl: String,

        /// Optional rotation policy (e.g., "daily")
        #[arg(long)]
        rotation_policy: Option<String>,
    },

    /// Rotate an agent's active credential with zero downtime
    Rotate {
        /// Agent identifier
        #[arg(long)]
        agent: String,

        /// Drain period in seconds (old credential remains valid for this long)
        #[arg(long, default_value_t = 30)]
        drain_secs: u64,
    },

    /// Display the HMAC-chained identity audit history
    Audit {
        /// Agent identifier
        #[arg(long)]
        agent: String,

        /// Verify the HMAC chain integrity before displaying
        #[arg(long, default_value_t = false)]
        verify: bool,
    },

    /// Set per-tool-call credential scoping rules
    Scope {
        /// Agent identifier
        #[arg(long)]
        agent: String,

        /// Tool name to scope
        #[arg(long)]
        tool: String,

        /// Explicitly allow this tool (default)
        #[arg(long, group = "action")]
        allow: bool,

        /// Explicitly deny this tool
        #[arg(long, group = "action")]
        deny: bool,

        /// Policy file to update (optional)
        #[arg(long, default_value = "agentcontrol-policy.yaml")]
        policy: String,
    },

    /// Inspect a specific credential binding
    Inspect {
        /// Credential binding ID (UUID)
        #[arg(long)]
        credential: String,
    },

    /// Export JWKS keys from an OIDC provider for air-gapped deployment
    ExportJwks {
        /// OIDC discovery issuer URL
        #[arg(long)]
        issuer: String,

        /// Output path for local jwks.json file
        #[arg(long, default_value = "jwks.json")]
        output: String,
    },
}

#[derive(Subcommand)]
pub enum ComplianceCommands {
    /// Generate SOC 2 / ISO 27001 / NIST AI RMF compliance evidence report
    Report {
        /// Audit log file path
        #[arg(long, default_value = "audit.log")]
        log_path: String,

        /// Output format ("markdown" or "json")
        #[arg(long, default_value = "markdown")]
        format: String,

        /// Output file path (defaults to stdout if omitted)
        #[arg(long)]
        output: Option<String>,
    },
}

#[derive(Subcommand, Debug, Clone)]
pub enum SpendCommands {
    /// Show current spend and budget status
    Status {
        /// Agent ID (defaults to anonymous / current user)
        #[arg(long)]
        agent_id: Option<String>,
    },
    /// Export invoice-ready usage records (CSV or JSON)
    Export {
        /// Output format ("csv" or "json")
        #[arg(long, default_value = "csv")]
        format: String,

        /// Filter by client_id
        #[arg(long)]
        client: Option<String>,

        /// Filter by project_id
        #[arg(long)]
        project: Option<String>,

        /// Output file path (defaults to stdout if omitted)
        #[arg(long)]
        output: Option<String>,
    },
    /// Set a budget cap
    SetCap {
        /// Target agent or user ID
        #[arg(long)]
        agent_id: String,

        /// Budget cap in cents
        #[arg(long)]
        cap_cents: u64,

        /// Budget period ("daily", "weekly", "monthly")
        #[arg(long, default_value = "daily")]
        period: String,
    },
}

#[derive(Subcommand)]
pub enum ServiceCliAction {
    /// Install and register AgentControl as a persistent OS background service
    Install {
        /// Control Hub API URL
        #[arg(
            long,
            env = "AGENTCONTROL_HUB_URL",
            default_value = "https://console.vexasec.io"
        )]
        hub_url: String,

        /// Gateway shared secret — must match GATEWAY_SECRET configured on the Control Plane API.
        /// Can also be set via the GATEWAY_SECRET environment variable.
        #[arg(long, env = "GATEWAY_SECRET")]
        gateway_secret: Option<String>,

        /// Policy read secret — must match POLICY_READ_SECRET configured on the Control Plane API.
        /// Can also be set via the POLICY_READ_SECRET environment variable.
        #[arg(long, env = "POLICY_READ_SECRET")]
        policy_read_secret: Option<String>,

        /// Agent identifier for this machine in the Control Plane dashboard.
        /// Defaults to agent-<username>-<hostname> at runtime if not specified.
        /// Can also be set via the AGENT_ID environment variable.
        #[arg(long, env = "AGENT_ID")]
        agent_id: Option<String>,

        /// Install as an elevated system-wide enterprise daemon (Windows SCM, macOS LaunchDaemon, Linux systemd)
        #[arg(long, default_value_t = false)]
        enterprise: bool,

        /// Path to custom daemon configuration file
        #[arg(long)]
        config: Option<String>,

        /// Force re-pointing the daemon to a different hub URL even when already enrolled.
        /// Without this flag, changing the hub URL on an enrolled device prints a warning
        /// but proceeds. Providing --force suppresses the warning.
        #[arg(long, default_value_t = false)]
        force: bool,
    },
    /// Remove the persistent OS background service
    Uninstall,
    /// Display current OS background service status
    Status,
}

#[derive(clap::Args, Debug, Clone)]
pub struct StartArgs {
    /// Path to JSON daemon configuration file (defaults to ~/.agentcontrol/daemon.json or /etc/agentcontrol/daemon.json)
    #[arg(long, env = "AGENTCONTROL_CONFIG_PATH")]
    pub config: Option<String>,

    /// YAML policy file path
    #[arg(long, env = "AGENTCONTROL_POLICY_PATH")]
    pub policy: Option<String>,

    /// Gateway listen address
    #[arg(long, env = "AGENTCONTROL_LISTEN", default_value = "127.0.0.1:18080")]
    pub listen: String,

    /// Audit log output path
    #[arg(
        long,
        env = "AGENTCONTROL_LOG_PATH",
        default_value = "~/.agentcontrol/audit.jsonl"
    )]
    pub log_path: String,

    /// Upstream MCP server URL
    #[arg(
        long,
        env = "AGENTCONTROL_MCP_URL",
        default_value = "http://127.0.0.1:3000"
    )]
    pub mcp_url: String,

    /// Agent PID (ignored in v6.1 — process kill is removed)
    #[arg(long, env = "AGENTCONTROL_AGENT_PID", hide = true)]
    pub agent_pid: Option<u32>,

    /// Read agent PID from file (ignored in v6.1 — process kill is removed)
    #[arg(long, env = "AGENTCONTROL_AGENT_PID_FILE", hide = true)]
    pub agent_pid_file: Option<String>,

    /// Kill mode [DEPRECATED in v6.1 — only 'connection' is supported]
    #[arg(long, default_value = "connection")]
    pub kill_mode: String,

    /// Maximum log size in bytes before rotation (default 100MB)
    #[arg(long, default_value_t = 104857600)]
    pub log_max_bytes: u64,

    /// Dry-run mode: log violations but allow calls
    #[arg(long, env = "AGENTCONTROL_DRY_RUN", default_value_t = false)]
    pub dry_run: bool,

    /// Max tool calls per second (overrides policy)
    #[arg(long)]
    pub rate_limit: Option<u32>,

    /// OIDC issuer URL for identity binding. Required for enterprise deployments.
    #[arg(long, env = "AGENTCONTROL_OIDC_ISSUER")]
    pub oidc_issuer: Option<String>,

    /// Write session report on shutdown
    #[arg(long, env = "AGENTCONTROL_REPORT_PATH")]
    pub report_path: Option<String>,

    /// Enable balanced security profile
    #[arg(long, default_value_t = false)]
    pub balanced: bool,

    /// Enable strict security profile
    #[arg(long, default_value_t = false)]
    pub strict: bool,

    /// Enable response scanning for secret detection
    #[arg(long, default_value_t = false)]
    pub scan_responses: bool,

    /// Block entire response on secret detection instead of redacting
    #[arg(long, default_value_t = false)]
    pub block_on_secrets: bool,

    /// Maximum response size to scan in bytes (default: 1MB)
    #[arg(long, default_value_t = 1048576)]
    pub max_scan_bytes: usize,

    /// SIEM backend to export audit events to
    #[arg(long, env = "AGENTCONTROL_SIEM_BACKEND", default_value = "local")]
    pub siem_backend: String,

    /// SIEM ingestion endpoint URL
    #[arg(long, env = "AGENTCONTROL_SIEM_ENDPOINT", default_value = "")]
    pub siem_endpoint: String,

    /// SIEM authentication token
    #[arg(long, env = "AGENTCONTROL_SIEM_TOKEN", default_value = "")]
    pub siem_token: String,

    /// SIEM export per-request timeout in seconds (default: 2)
    #[arg(long, env = "AGENTCONTROL_SIEM_TIMEOUT", default_value_t = 2)]
    pub siem_timeout_secs: u64,

    /// Include raw tool call parameters in the audit log
    #[arg(long, env = "AGENTCONTROL_INCLUDE_PARAMS", default_value_t = false)]
    pub include_params: bool,

    /// Enable shadow mode: observe all traffic without enforcement
    #[arg(long, env = "AGENTCONTROL_SHADOW_MODE", default_value_t = false)]
    pub shadow_mode: bool,

    /// Upgrade credential scope mismatches from WARN to DENY
    #[arg(
        long,
        env = "AGENTCONTROL_STRICT_CREDENTIAL_SCOPE",
        default_value_t = false
    )]
    pub strict_credential_scope: bool,

    /// Opt-in to recording raw prompt and response payloads in SQLite egress events (hashes stored by default)
    #[arg(long, env = "AGENTCONTROL_RECORD_PAYLOADS", default_value_t = false)]
    pub record_payloads: bool,

    /// TLS certificate chain PEM file for HTTPS listener
    #[arg(long, env = "AGENTCONTROL_TLS_CERT")]
    pub tls_cert: Option<String>,

    /// TLS private key PEM file for HTTPS listener
    #[arg(long, env = "AGENTCONTROL_TLS_KEY")]
    pub tls_key: Option<String>,

    /// Run in centralized mode: binds to 0.0.0.0 by default, enables Hub credential management.
    #[arg(long, env = "AGENTCONTROL_CENTRALIZED", default_value_t = false)]
    pub centralized: bool,

    /// Deployment profile (local-shadow, local-enforce, team-enforce, dedicated-enforce)
    #[arg(long, env = "AGENTCONTROL_PROFILE")]
    pub profile: Option<String>,

    /// Private management/admin listener interface (default: 127.0.0.1:8082)
    #[arg(long, env = "AGENTCONTROL_ADMIN_LISTEN")]
    pub admin_listen: Option<String>,

    /// Shared secret token required for admin management endpoints if exposed over network
    #[arg(long, env = "AGENTCONTROL_ADMIN_TOKEN")]
    pub admin_token: Option<String>,

    /// Maximum incoming JSON-RPC frame size for stdio codec (default: 16MB)
    #[arg(long, default_value_t = 16777216)]
    pub max_frame_size: usize,

    /// Maximum concurrent connections accepted by the proxy listener
    #[arg(long, default_value_t = 1024)]
    pub max_concurrency: usize,

    /// Connection idle timeout in seconds
    #[arg(long, default_value_t = 30)]
    pub connection_timeout_secs: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum, serde::Serialize, serde::Deserialize)]
pub enum DeploymentProfile {
    #[value(name = "local-gateway", alias = "local-enforce", alias = "gateway")]
    LocalGateway,
    #[value(name = "local-firewall", alias = "firewall", alias = "air-gapped")]
    LocalFirewall,
    #[value(name = "team-gateway", alias = "team-enforce", alias = "team", alias = "dedicated-enforce", alias = "enterprise")]
    TeamGateway,
    #[value(name = "container-sidecar", alias = "sidecar", alias = "container")]
    ContainerSidecar,
    #[value(name = "local-shadow", alias = "shadow")]
    LocalShadow,
}

impl DeploymentProfile {
    pub fn try_parse(s: &str) -> Result<Self, String> {
        match s.to_ascii_lowercase().as_str() {
            "local-gateway" | "local_gateway" | "local-enforce" | "local_enforce" | "enforce" | "gateway" => {
                Ok(Self::LocalGateway)
            }
            "local-firewall" | "local_firewall" | "firewall" | "air-gapped" | "air_gapped" => {
                Ok(Self::LocalFirewall)
            }
            "team-gateway" | "team_gateway" | "team-enforce" | "team_enforce" | "team" | "dedicated-enforce" | "dedicated_enforce" | "dedicated" | "enterprise" => {
                Ok(Self::TeamGateway)
            }
            "container-sidecar" | "container_sidecar" | "sidecar" | "container" => {
                Ok(Self::ContainerSidecar)
            }
            "local-shadow" | "local_shadow" | "shadow" => {
                Ok(Self::LocalShadow)
            }
            unknown => Err(format!(
                "Unknown deployment profile '{}'. Valid profiles: local-gateway, local-firewall, team-gateway, container-sidecar",
                unknown
            )),
        }
    }

    /// Legacy parse function mapping unknown strings cleanly to an error or safe default with warning
    pub fn parse(s: &str) -> Self {
        Self::try_parse(s).unwrap_or_else(|e| {
            eprintln!("⚠ {}", e);
            Self::LocalGateway
        })
    }

    pub fn is_enforce(&self) -> bool {
        !matches!(self, Self::LocalShadow)
    }

    #[allow(non_upper_case_globals)]
    pub const TeamEnforce: DeploymentProfile = DeploymentProfile::TeamGateway;
    #[allow(non_upper_case_globals)]
    pub const DedicatedEnforce: DeploymentProfile = DeploymentProfile::TeamGateway;
    #[allow(non_upper_case_globals)]
    pub const LocalEnforce: DeploymentProfile = DeploymentProfile::LocalGateway;

    pub fn is_team(&self) -> bool {
        matches!(self, Self::TeamGateway)
    }

    pub fn is_air_gapped(&self) -> bool {
        matches!(self, Self::LocalFirewall)
    }

    pub fn default_scan_responses(&self) -> bool {
        matches!(self, Self::TeamGateway)
    }

    pub fn default_fail_closed(&self) -> bool {
        matches!(self, Self::TeamGateway)
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::LocalGateway => "local-gateway",
            Self::LocalFirewall => "local-firewall",
            Self::TeamGateway => "team-gateway",
            Self::ContainerSidecar => "container-sidecar",
            Self::LocalShadow => "local-shadow",
        }
    }
}

/// Durable operational profile record saved at ~/.agentcontrol/profile.json
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PersistedProfileRecord {
    pub profile: DeploymentProfile,
    pub updated_at: String,
    pub version: String,
}

impl PersistedProfileRecord {
    pub fn profile_path() -> Option<std::path::PathBuf> {
        dirs::home_dir().map(|h| h.join(".agentcontrol").join("profile.json"))
    }

    pub fn load() -> Option<DeploymentProfile> {
        let path = Self::profile_path()?;
        if path.exists() {
            if let Ok(content) = std::fs::read_to_string(&path) {
                if let Ok(rec) = serde_json::from_str::<PersistedProfileRecord>(&content) {
                    return Some(rec.profile);
                }
            }
        }
        None
    }

    pub fn save(profile: DeploymentProfile) -> std::io::Result<()> {
        if let Some(path) = Self::profile_path() {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let rec = PersistedProfileRecord {
                profile,
                updated_at: chrono::Utc::now().to_rfc3339(),
                version: env!("CARGO_PKG_VERSION").to_string(),
            };
            let json = serde_json::to_string_pretty(&rec)?;
            std::fs::write(&path, json)?;
        }
        Ok(())
    }
}

pub fn save_persisted_profile(profile: DeploymentProfile) -> std::io::Result<()> {
    PersistedProfileRecord::save(profile)
}

pub fn load_persisted_profile() -> Option<DeploymentProfile> {
    PersistedProfileRecord::load()
}


impl StartArgs {
    pub fn centralized_default() -> Self {
        Self {
            policy: None,
            listen: "127.0.0.1:18080".to_string(),
            log_path: "~/.agentcontrol/audit.jsonl".to_string(),
            mcp_url: "http://127.0.0.1:3000".to_string(),
            agent_pid: None,
            agent_pid_file: None,
            kill_mode: "connection".to_string(),
            log_max_bytes: 104857600,
            dry_run: false,
            rate_limit: None,
            oidc_issuer: None,
            report_path: None,
            balanced: false,
            strict: false,
            scan_responses: false,
            block_on_secrets: false,
            max_scan_bytes: 1048576,
            config: None,
            siem_backend: "local".to_string(),
            siem_endpoint: String::new(),
            siem_token: String::new(),
            siem_timeout_secs: 2,
            include_params: false,
            shadow_mode: false,
            strict_credential_scope: false,
            record_payloads: false,
            tls_cert: None,
            tls_key: None,
            centralized: true,
            profile: Some("team-enforce".to_string()),
            admin_listen: None,
            admin_token: None,
            max_frame_size: 16777216,
            max_concurrency: 1024,
            connection_timeout_secs: 30,
        }
    }
}

#[derive(clap::Args, Debug, Clone)]
pub struct WrapArgs {
    /// The command to wrap (e.g. "npx @modelcontextprotocol/server-memory")
    #[arg(long)]
    pub command: Option<String>,

    /// Automatically detect and wrap known agents
    #[arg(long, default_value_t = false)]
    pub auto_detect: bool,

    /// Wrap all installed IDE configurations at once
    #[arg(long, default_value_t = false)]
    pub all: bool,

    /// YAML policy file path
    #[arg(long)]
    pub policy: Option<String>,

    /// Dry-run mode: log violations but allow calls
    #[arg(long, env = "AGENTCONTROL_DRY_RUN", default_value_t = false)]
    pub dry_run: bool,

    /// Kill mode [DEPRECATED in v6.1 — only 'connection' is supported]
    #[arg(long, default_value = "connection")]
    pub kill_mode: String,

    /// Audit log output path
    #[arg(
        long,
        env = "AGENTCONTROL_LOG_PATH",
        default_value = "~/.agentcontrol/audit.jsonl"
    )]
    pub log_path: String,

    /// Enable balanced security profile
    #[arg(long, default_value_t = false)]
    pub balanced: bool,

    /// Enable strict security profile
    #[arg(long, default_value_t = false)]
    pub strict: bool,

    /// Enable response scanning for secret detection
    #[arg(long, default_value_t = false)]
    pub scan_responses: bool,

    /// Block entire response on secret detection instead of redacting
    #[arg(long, default_value_t = false)]
    pub block_on_secrets: bool,

    /// Maximum response size to scan in bytes (default: 1MB)
    #[arg(long, default_value_t = 1048576)]
    pub max_scan_bytes: usize,

    /// Target to wrap (e.g. claude)
    #[command(subcommand)]
    pub target: Option<WrapTarget>,
}
