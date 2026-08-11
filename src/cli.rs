//! CLI definitions — clap derive (§5.3)
//!
//! ## v6.1 Deprecation Changes
//!
//! - `--kill-mode process` / `--kill-mode both` removed from `start` and `wrap`.
//! - `agentwall init` is deprecated. Use a GitOps workflow instead.
//! - `agentwall test` now accepts `--gateway` and `--oidc-token` for CI/CD integration.

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "agentwall",
    version,
    about = "VEXA AgentWall — centralized enterprise security gateway for AI agent tool calls over MCP"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Box<Commands>,
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)]
pub enum Commands {
    /// Perform PKI Device Enrollment with Control Hub
    Enroll {
        /// One-Time Enrollment Token (OTET)
        #[arg(long, env = "AGENTWALL_ENROLLMENT_TOKEN")]
        token: String,

        /// Control Hub API URL
        #[arg(
            long,
            env = "DASHBOARD_API_URL",
            default_value = "http://localhost:8400"
        )]
        hub_url: String,
    },

    /// Manage AgentWall persistent OS Sentry Service Daemon
    Service {
        #[command(subcommand)]
        action: ServiceCliAction,
    },

    /// Start local shadow proxy (observation only, no enforcement)
    Dev {
        /// Listen address for HTTP mode (default: 127.0.0.1:8080)
        #[arg(long, default_value = "127.0.0.1:8080")]
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

        /// Enable local policy learning mode (synthesizes agentwall-policy.yaml from local dev traffic)
        #[arg(long, default_value_t = false)]
        learn: bool,

        /// Enable opt-in local dual-agent threat detector worker
        #[arg(long, default_value_t = false)]
        dual_agent: bool,

        /// Local LLM API endpoint for dual-agent threat reasoning
        #[arg(long, default_value = "http://localhost:11434")]
        local_llm_url: String,

        /// Downstream command and arguments (for stdio mode)
        #[arg(last = true)]
        args: Vec<String>,
    },

    /// Run ADR security benchmark suite (303 tasks, 17 attack classes, 133 MCP servers)
    Bench {
        /// Run all 303 benchmark scenarios across 17 attack classes
        #[arg(long, default_value_t = false)]
        full: bool,

        /// Benchmark comparative scoring against industry baselines (ALRPHFS, GuardAgent, LlamaFirewall)
        #[arg(long, default_value_t = false)]
        compare_baselines: bool,

        /// Render HTML/SVG figures and scorecards
        #[arg(long, default_value_t = false)]
        visualize: bool,

        /// Output path for benchmark HTML report
        #[arg(long, default_value = "./target/benchmark-report.html")]
        output: String,
    },

    /// Run the gateway server
    Start(Box<StartArgs>),

    /// Automatically wrap an existing agent command with AgentWall
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
        /// Example: --gateway https://agentwall.internal.corp/
        #[arg(long, env = "VEXA_GATEWAY_URL")]
        gateway: Option<String>,

        /// OIDC Bearer token for authenticating with the gateway
        #[arg(long, env = "AGENTWALL_OIDC_TOKEN")]
        oidc_token: Option<String>,
    },

    /// Validate and sign a policy for production
    Promote {
        /// YAML policy file to promote
        #[arg(long)]
        policy: String,

        /// Path to the Ed25519 private key (PEM or raw bytes)
        /// If not provided, a temporary key will be generated for demo purposes.
        #[arg(long)]
        key: Option<String>,
    },

    /// Verify HMAC chain integrity of an audit log
    VerifyLog {
        /// Audit log file path
        log_path: String,

        /// Optional path to HMAC signing key file for full payload verification
        #[arg(long, env = "AGENTWALL_KEY_FILE")]
        key_file: Option<String>,
    },

    /// Generate a session report from a completed audit log
    Report {
        /// Audit log file path
        log_path: String,

        /// Output file
        #[arg(long)]
        output: Option<String>,

        /// Report format (json|text)
        #[arg(long, default_value = "json")]
        format: String,

        /// Include raw params in report (WARNING: may leak PII/secrets)
        #[arg(long, default_value_t = false)]
        report_include_params: bool,

        /// Generate a Risk Delta summary report of hypothetical blocks/redactions from shadow mode
        #[arg(long, default_value_t = false)]
        risk: bool,
    },

    /// Run Vexa security scanner against local MCP server configurations
    Scan {
        /// Target policy or MCP configuration YAML file path
        #[arg(long, default_value = "agentwall-policy.yaml")]
        path: String,

        /// Output format (text|json)
        #[arg(long, default_value = "text")]
        format: String,
    },

    /// Generate a YAML security policy draft from observed shadow-mode traffic
    ///
    /// Reads all tool-call events recorded by `agentwall dev` (shadow mode) from the
    /// local SQLite database and produces a lint-passing `agentwall-policy.yaml` draft.
    ///
    /// ## Workflow
    ///
    /// 1. Run `agentwall dev` and route your agent's MCP traffic through it.
    /// 2. Run `agentwall generate-policy` to draft the policy.
    /// 3. Review and tighten the generated YAML.
    /// 4. Run `agentwall lint agentwall-policy.yaml` to validate.
    /// 5. Submit to your security/platform team for deployment to the centralized gateway.
    #[command(name = "generate-policy")]
    GeneratePolicy {
        /// Output file path for the generated policy (default: ./agentwall-policy.yaml)
        #[arg(long, default_value = "agentwall-policy.yaml")]
        output: String,

        /// Decay window in days for self-healing behavioral learning
        #[arg(long, default_value_t = 30)]
        decay_window: u32,
    },

    Init {
        #[command(subcommand)]
        target: Option<InitTarget>,
    },

    /// Agent Identity & Credential Governance
    Identity {
        #[command(subcommand)]
        command: IdentityCommands,
    },

    /// Enterprise License Management & Key Generation
    License {
        #[command(subcommand)]
        command: LicenseCommands,
    },

    /// Generate compliance reports (SOC 2, ISO 27001, NIST AI RMF)
    Compliance {
        #[command(subcommand)]
        command: ComplianceCommands,
    },

    /// Restore AgentWall wrappers
    Unwrap {
        /// Target to unwrap (e.g. claude)
        #[command(subcommand)]
        target: UnwrapTarget,
    },

    /// Automatically discover IDEs, atomically wrap MCP configs, start gateway, and open dashboard
    Protect {
        /// Preview changes without writing to disk or starting gateway
        #[arg(long, default_value_t = false)]
        dry_run: bool,

        /// Disable automatic opening of local dashboard in browser
        #[arg(long, default_value_t = false)]
        no_browser: bool,

        /// Listen address for gateway proxy (default: 127.0.0.1:8080)
        #[arg(long, default_value = "127.0.0.1:8080")]
        listen: String,

        /// Upstream HTTP MCP server URL (default: http://127.0.0.1:3000)
        #[arg(long, default_value = "http://127.0.0.1:3000")]
        mcp_url: String,

        /// Enable active enforcement mode (default: false / shadow mode)
        #[arg(long, default_value_t = false)]
        enforce: bool,

        /// YAML policy file path
        #[arg(long, default_value = "agentwall-policy.yaml")]
        policy: String,
    },

    /// One-command reversion — restore all IDE configurations from backups and verify integrity
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

    /// Validate a tool call payload against a policy file locally
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

    /// Lint a policy YAML file for schema and security warnings
    Lint {
        /// YAML policy file path
        policy: String,
    },

    /// Show config path, existence, and wrap status for all 8 IDE targets
    ///
    /// Displays a table with: target name, resolved config path, whether the
    /// file exists, and whether all MCP servers are wrapped. Paths that are
    /// known-wrong or unverified are flagged explicitly.
    Status,

    /// Watch IDE configs and auto-wrap new MCP servers (daemon, event-driven)
    ///
    /// Monitors the config file of each selected IDE target via OS-native
    /// filesystem events (inotify / FSEvents / ReadDirectoryChangesW).
    /// When an unwrapped `mcpServers` entry is detected, the daemon calls
    /// the same wrap logic as `agentwall wrap <target>` — closing the gap
    /// before the IDE's next restart.
    ///
    /// NOTE: IDEs load `mcpServers` at process startup. This daemon does NOT
    /// make IDEs hot-reload. Correct framing: "closes the gap before the
    /// IDE's next restart." You must restart the IDE for changes to take
    /// effect after each wrap.
    Watch {
        /// Watch all verified targets (currently Claude Desktop only — other
        /// paths are unverified and excluded from --all)
        #[arg(long, default_value_t = false)]
        all: bool,

        /// Target to watch (e.g. claude, cursor, vscode)
        #[command(subcommand)]
        target: Option<WatchTarget>,
    },
}

#[derive(Subcommand, Debug, Clone)]
pub enum WrapTarget {
    /// Wrap Claude Desktop MCP servers with AgentWall
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
    /// Wrap Cursor IDE with AgentWall
    Cursor {
        #[arg(long, default_value_t = false)]
        dry_run: bool,
    },
    /// Wrap VS Code with AgentWall
    Vscode {
        #[arg(long, default_value_t = false)]
        dry_run: bool,
    },
    /// Wrap JetBrains IDEs with AgentWall
    Jetbrains {
        #[arg(long, default_value_t = false)]
        dry_run: bool,
    },
    /// Wrap Zed Editor with AgentWall
    Zed {
        #[arg(long, default_value_t = false)]
        dry_run: bool,
    },
    /// Wrap Cline Extension with AgentWall
    Cline {
        #[arg(long, default_value_t = false)]
        dry_run: bool,
    },
    /// Wrap OpenCode with AgentWall
    Opencode {
        #[arg(long, default_value_t = false)]
        dry_run: bool,
    },
    /// Wrap Antigravity IDE with AgentWall
    Antigravity {
        #[arg(long, default_value_t = false)]
        dry_run: bool,
    },
    /// Wrap ChatGPT Codex with AgentWall
    Codex {
        #[arg(long, default_value_t = false)]
        dry_run: bool,
    },
}

#[derive(Subcommand)]
pub enum UnwrapTarget {
    /// Restore Claude Desktop config from the most recent AgentWall backup
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
pub enum InitTarget {
    /// Generate a Kubernetes sidecar manifest for AgentWall proxy
    Sidecar {
        /// Upstream MCP server URL
        #[arg(long, default_value = "http://mcp-server:3000")]
        mcp_upstream: String,
    },
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
        #[arg(long, default_value = "agentwall-policy.yaml")]
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
pub enum LicenseCommands {
    /// Generate an Ed25519 signing keypair for license issuance
    Keygen {
        /// Output directory to write vexa_license.key and vexa_license.pub
        #[arg(long, default_value = "./keys")]
        output: String,
    },

    /// Issue an Ed25519-signed JWT license token
    Generate {
        /// Organization identifier (e.g. "acme-corp")
        #[arg(long)]
        org: String,

        /// License tier ("community", "team", "enterprise")
        #[arg(long, default_value = "team")]
        tier: String,

        /// Maximum allowed seats / devices
        #[arg(long, default_value_t = 25)]
        seats: usize,

        /// License validity period in days
        #[arg(long, default_value_t = 365)]
        days: i64,

        /// Path to the Ed25519 private signing key file
        #[arg(long, default_value = "./keys/vexa_license.key")]
        signing_key: String,

        /// Optional custom feature flags (comma-separated)
        #[arg(long, value_delimiter = ',')]
        features: Option<Vec<String>>,
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

#[derive(Subcommand)]
pub enum ServiceCliAction {
    /// Install and register AgentWall as a persistent OS background service
    Install {
        /// Control Hub API URL
        #[arg(
            long,
            env = "DASHBOARD_API_URL",
            default_value = "http://localhost:8400"
        )]
        hub_url: String,

        /// Gateway shared secret — must match GATEWAY_SECRET configured on the Control Plane API.
        /// Can also be set via the GATEWAY_SECRET environment variable.
        #[arg(long, env = "GATEWAY_SECRET")]
        gateway_secret: String,

        /// Policy read secret — must match POLICY_READ_SECRET configured on the Control Plane API.
        /// Can also be set via the POLICY_READ_SECRET environment variable.
        #[arg(long, env = "POLICY_READ_SECRET")]
        policy_read_secret: String,

        /// Agent identifier for this machine in the Control Plane dashboard.
        /// Defaults to agent-<username>-<hostname> at runtime if not specified.
        /// Can also be set via the AGENT_ID environment variable.
        #[arg(long, env = "AGENT_ID")]
        agent_id: Option<String>,
    },
    /// Remove the persistent OS background service
    Uninstall,
    /// Display current OS background service status
    Status,
}

#[derive(clap::Args, Debug, Clone)]
pub struct StartArgs {
    /// YAML policy file path
    #[arg(long, env = "AGENTWALL_POLICY_PATH")]
    pub policy: Option<String>,

    /// Gateway listen address
    #[arg(long, env = "AGENTWALL_LISTEN", default_value = "127.0.0.1:8080")]
    pub listen: String,

    /// Audit log output path
    #[arg(long, env = "AGENTWALL_LOG_PATH", default_value = "audit.log")]
    pub log_path: String,

    /// Upstream MCP server URL
    #[arg(
        long,
        env = "AGENTWALL_MCP_URL",
        default_value = "http://127.0.0.1:3000"
    )]
    pub mcp_url: String,

    /// Agent PID (ignored in v6.1 — process kill is removed)
    #[arg(long, env = "AGENTWALL_AGENT_PID", hide = true)]
    pub agent_pid: Option<u32>,

    /// Read agent PID from file (ignored in v6.1 — process kill is removed)
    #[arg(long, env = "AGENTWALL_AGENT_PID_FILE", hide = true)]
    pub agent_pid_file: Option<String>,

    /// Kill mode [DEPRECATED in v6.1 — only 'connection' is supported]
    #[arg(long, default_value = "connection")]
    pub kill_mode: String,

    /// Maximum log size in bytes before rotation (default 100MB)
    #[arg(long, default_value_t = 104857600)]
    pub log_max_bytes: u64,

    /// Dry-run mode: log violations but allow calls
    #[arg(long, env = "AGENTWALL_DRY_RUN", default_value_t = false)]
    pub dry_run: bool,

    /// Max tool calls per second (overrides policy)
    #[arg(long)]
    pub rate_limit: Option<u32>,

    /// OIDC issuer URL for identity binding. Required for enterprise deployments.
    #[arg(long, env = "AGENTWALL_OIDC_ISSUER")]
    pub oidc_issuer: Option<String>,

    /// Write session report on shutdown
    #[arg(long, env = "AGENTWALL_REPORT_PATH")]
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
    #[arg(long, env = "AGENTWALL_SIEM_BACKEND", default_value = "local")]
    pub siem_backend: String,

    /// SIEM ingestion endpoint URL
    #[arg(long, env = "AGENTWALL_SIEM_ENDPOINT", default_value = "")]
    pub siem_endpoint: String,

    /// SIEM authentication token
    #[arg(long, env = "AGENTWALL_SIEM_TOKEN", default_value = "")]
    pub siem_token: String,

    /// SIEM export per-request timeout in seconds (default: 2)
    #[arg(long, env = "AGENTWALL_SIEM_TIMEOUT", default_value_t = 2)]
    pub siem_timeout_secs: u64,

    /// Include raw tool call parameters in the audit log
    #[arg(long, env = "AGENTWALL_INCLUDE_PARAMS", default_value_t = false)]
    pub include_params: bool,

    /// Enable shadow mode: observe all traffic without enforcement
    #[arg(long, env = "AGENTWALL_SHADOW_MODE", default_value_t = false)]
    pub shadow_mode: bool,

    /// Upgrade credential scope mismatches from WARN to DENY
    #[arg(
        long,
        env = "AGENTWALL_STRICT_CREDENTIAL_SCOPE",
        default_value_t = false
    )]
    pub strict_credential_scope: bool,

    /// TLS certificate chain PEM file for HTTPS listener
    #[arg(long, env = "AGENTWALL_TLS_CERT")]
    pub tls_cert: Option<String>,

    /// TLS private key PEM file for HTTPS listener
    #[arg(long, env = "AGENTWALL_TLS_KEY")]
    pub tls_key: Option<String>,

    /// Run in centralized mode: binds to 0.0.0.0 by default, enables Hub credential management.
    #[arg(long, env = "AGENTWALL_CENTRALIZED", default_value_t = false)]
    pub centralized: bool,
}

impl StartArgs {
    pub fn centralized_default() -> Self {
        Self {
            policy: None,
            listen: "127.0.0.1:8080".to_string(),
            log_path: "audit.log".to_string(),
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
            siem_backend: "local".to_string(),
            siem_endpoint: String::new(),
            siem_token: String::new(),
            siem_timeout_secs: 2,
            include_params: false,
            shadow_mode: false,
            strict_credential_scope: false,
            tls_cert: None,
            tls_key: None,
            centralized: true,
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
    #[arg(long, env = "AGENTWALL_DRY_RUN", default_value_t = false)]
    pub dry_run: bool,

    /// Kill mode [DEPRECATED in v6.1 — only 'connection' is supported]
    #[arg(long, default_value = "connection")]
    pub kill_mode: String,

    /// Audit log output path
    #[arg(long, env = "AGENTWALL_LOG_PATH", default_value = "audit.log")]
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
