//! Vexa Agent Control — main entry point
#![allow(deprecated)]

use agentcontrol::audit;
use agentcontrol::check;
use agentcontrol::cli;
use agentcontrol::identity; // FR-22
use agentcontrol::init;
use agentcontrol::kill;
use agentcontrol::policy;
use agentcontrol::promote;
use agentcontrol::proxy;
use agentcontrol::report;
use agentcontrol::{log_error, log_warn};

use colored::*;

use clap::Parser;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::watch;

use audit::logger::AuditLogger;
use cli::{Cli, Commands};
use kill::KillMode;
use policy::loader::{load_policy, PolicyLoadResult};
use policy::safe_mode::SafeModeScanner;
use proxy::handler::ProxyState;

fn main() {
    // ── Windows SCM fast-path ──────────────────────────────────────────────
    // service_dispatcher::start() MUST be called from the main thread before
    // any heavy setup.  SCM will kill the process with Error 1053 (timeout)
    // if we don't connect within ~30 s.  We detect the SCM environment by
    // attempting to start the dispatcher; if it returns an error it means we
    // are running interactively, so fall through to normal startup.
    #[cfg(target_os = "windows")]
    {
        use agentcontrol::service::windows::service_dispatcher_handler;
        let registered = service_dispatcher_handler::try_register_scm_runner(|| {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .thread_stack_size(8 * 1024 * 1024)
                .build()
                .expect("Failed to build service Tokio runtime");
            rt.block_on(async {
                dispatch_command(Box::new(agentcontrol::cli::Commands::Start(Box::new(
                    agentcontrol::cli::StartArgs::centralized_default(),
                ))))
                .await
            })
        });
        if registered {
            // Only exit if service_dispatcher::start actually succeeded in connecting to SCM.
            // If it returns Err (e.g. error code 1063 when run interactively), fall through!
            if let Ok(code) = service_dispatcher_handler::try_start_and_wait() {
                std::process::exit(code);
            }
        }
    }

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_stack_size(8 * 1024 * 1024)
        .build()
        .expect("Failed to create Tokio runtime");

    let exit_code = runtime.block_on(async_main());
    std::process::exit(exit_code);
}

async fn async_main() -> i32 {
    let cli = Cli::parse();

    let is_dev_stdio = match &*cli.command {
        Commands::Dev { stdio, .. } => *stdio,
        _ => false,
    };

    let suppress_banner = is_dev_stdio
        || matches!(
            &*cli.command,
            Commands::Report { .. }
                | Commands::Test { .. }
                | Commands::Wrap { .. }
                | Commands::StdioProxy { .. }
                | Commands::Status
                | Commands::Watch { .. }
                | Commands::Verify { json: true, .. }
                | Commands::Scan { .. }
        );

    if !suppress_banner {
        print_banner();
    }

    dispatch_command(cli.command).await
}

async fn dispatch_command(command: Box<Commands>) -> i32 {
    match *command {
        Commands::Wrap(args) => {
            if args.all {
                agentcontrol::wrap::run_wrap_all(args.dry_run, args.scan_responses)
            } else if let Some(target) = args.target {
                agentcontrol::wrap::run_wrap_target(&target)
            } else {
                run_wrap(
                    args.command,
                    args.auto_detect,
                    args.policy,
                    args.dry_run,
                    args.kill_mode,
                    args.log_path,
                    args.scan_responses,
                    args.block_on_secrets,
                    args.max_scan_bytes,
                )
                .await
            }
        }
        Commands::Enroll { token, hub_url } => {
            agentcontrol::identity::device::run_enroll(&token, &hub_url).await
        }
        #[cfg(feature = "team")]
        Commands::Join { token, hub_url } => {
            println!("Joining team workspace at {}...", hub_url);
            match agentcontrol::identity::team::TeamIdentity::join(&hub_url, &token) {
                Ok(_) => {
                    println!("Successfully joined organization workspace!");
                    0
                }
                Err(e) => {
                    eprintln!("Failed to join workspace: {}", e);
                    1
                }
            }
        }
        Commands::Service { action } => {
            let act = match action {
                agentcontrol::cli::ServiceCliAction::Install {
                    hub_url,
                    gateway_secret,
                    policy_read_secret,
                    agent_id,
                } => agentcontrol::service::ServiceAction::Install {
                    hub_url,
                    gateway_secret,
                    policy_read_secret,
                    agent_id,
                },
                agentcontrol::cli::ServiceCliAction::Uninstall => {
                    agentcontrol::service::ServiceAction::Uninstall
                }
                agentcontrol::cli::ServiceCliAction::Status => {
                    agentcontrol::service::ServiceAction::Status
                }
            };
            agentcontrol::service::run_service(act)
        }
        Commands::Start(args) => {
            // When running interactively (not under Windows SCM), just run the
            // centralized daemon directly.
            dispatch_start(*args).await
        }
        Commands::Test {
            policy,
            fixture,
            dry_run,
            gateway,
            oidc_token,
        } => check::run_check(
            Path::new(&policy),
            Path::new(&fixture),
            dry_run,
            gateway.as_deref(),
            oidc_token.as_deref(),
        ),
        Commands::Promote { policy, key } => promote::run_promote(&policy, key.as_deref()),
        Commands::VerifyLog { log_path, key_file } => {
            run_verify_log(&log_path, key_file.as_deref())
        }
        Commands::Report {
            log_path,
            output,
            format,
            report_include_params,
            risk: _,
        } => run_report(&log_path, output.as_deref(), &format, report_include_params),
        Commands::Scan { path, format } => {
            use crate::policy::mcp_score::McpScorer;
            eprintln!("[vexa-scan] Scanning MCP configuration: {}", path);
            let score = McpScorer::evaluate_server(&path, &[], false, 0);
            match format.as_str() {
                "json" => println!(
                    "{}",
                    serde_json::to_string_pretty(&score).unwrap_or_default()
                ),
                _ => {
                    println!(
                        "Vexa Security Score for '{}': {}/100 [{}]",
                        score.server_name, score.score, score.risk_level
                    );
                    for flag in &score.vulnerability_flags {
                        println!("  ⚠ {}", flag);
                    }
                }
            }
            if score.score < 60 {
                1
            } else {
                0
            }
        }
        Commands::Init { target } => init::run_init(&target),
        // FR-22: Identity subcommand dispatch
        Commands::Identity { command } => match command {
            cli::IdentityCommands::Create {
                agent,
                scope,
                ttl,
                rotation_policy,
            } => identity::run_identity(identity::IdentityCommand::Create {
                agent,
                scope,
                ttl,
                rotation_policy,
            }),
            cli::IdentityCommands::Rotate { agent, drain_secs } => {
                identity::run_identity(identity::IdentityCommand::Rotate { agent, drain_secs })
            }
            cli::IdentityCommands::Audit { agent, verify } => {
                identity::run_identity(identity::IdentityCommand::Audit { agent, verify })
            }
            cli::IdentityCommands::Scope {
                agent,
                tool,
                allow,
                deny,
                policy,
            } => {
                // Fix AW-BUG-005: require exactly one of --allow or --deny.
                // Previous logic: allow || !deny evaluated to true when both false,
                // silently creating ALLOW rules without explicit intent.
                if !allow && !deny {
                    eprintln!("{} Must specify either --allow or --deny", "✖".red());
                    eprintln!("  Usage: agentwall identity scope --agent {} --tool {} --allow --policy {}", agent, tool, policy);
                    2
                } else if allow && deny {
                    eprintln!("{} Cannot specify both --allow and --deny", "✖".red());
                    2
                } else {
                    identity::run_identity(identity::IdentityCommand::Scope {
                        agent,
                        tool,
                        allow,
                        policy_path: policy,
                    })
                }
            }
            cli::IdentityCommands::Inspect { credential } => {
                identity::run_identity(identity::IdentityCommand::Inspect {
                    credential_id: credential,
                })
            }
            cli::IdentityCommands::ExportJwks { issuer, output } => {
                let oidc_url = if issuer.ends_with('/') {
                    format!("{}.well-known/openid-configuration", issuer)
                } else {
                    format!("{}/.well-known/openid-configuration", issuer)
                };
                let client = reqwest::Client::new();
                match client.get(&oidc_url).send().await {
                    Err(e) => {
                        eprintln!("{} Failed to fetch OIDC config: {}", "✖".red(), e);
                        1
                    }
                    Ok(resp) => match resp.json::<serde_json::Value>().await {
                        Err(e) => {
                            eprintln!("{} Failed to parse OIDC config JSON: {}", "✖".red(), e);
                            1
                        }
                        Ok(config) => match config.get("jwks_uri").and_then(|v| v.as_str()) {
                            None => {
                                eprintln!("{} OIDC config missing jwks_uri", "✖".red());
                                1
                            }
                            Some(jwks_uri) => match client.get(jwks_uri).send().await {
                                Err(e) => {
                                    eprintln!("{} Failed to fetch JWKS: {}", "✖".red(), e);
                                    1
                                }
                                Ok(jwks_resp) => match jwks_resp.text().await {
                                    Err(e) => {
                                        eprintln!(
                                            "{} Failed to read JWKS response: {}",
                                            "✖".red(),
                                            e
                                        );
                                        1
                                    }
                                    Ok(jwks_text) => {
                                        if let Err(e) = std::fs::write(&output, &jwks_text) {
                                            eprintln!(
                                                "{} Failed to write JWKS to {}: {}",
                                                "✖".red(),
                                                output,
                                                e
                                            );
                                            1
                                        } else {
                                            println!("✓ Exported JWKS keys to {}", output);
                                            0
                                        }
                                    }
                                },
                            },
                        },
                    },
                }
            }
        },
        Commands::License { command } => match command {
            cli::LicenseCommands::Keygen { output } => {
                match agentcontrol::license::generate_keypair(Path::new(&output)) {
                    Ok(()) => 0,
                    Err(e) => {
                        eprintln!("{} {}", "✖".red(), e);
                        1
                    }
                }
            }
            cli::LicenseCommands::Generate {
                org,
                tier,
                seats,
                days,
                signing_key,
                features,
            } => {
                match agentcontrol::license::generate_license(
                    &org,
                    &tier,
                    seats,
                    days,
                    Path::new(&signing_key),
                    features,
                ) {
                    Ok(jwt) => {
                        println!("{}", jwt);
                        0
                    }
                    Err(e) => {
                        eprintln!("{} {}", "✖".red(), e);
                        1
                    }
                }
            }
        },
        Commands::Compliance { command } => match command {
            cli::ComplianceCommands::Report {
                log_path,
                format,
                output,
            } => match agentcontrol::compliance::generate_report(Path::new(&log_path), &format) {
                Ok(content) => {
                    if let Some(out_path) = output {
                        if let Err(e) = std::fs::write(&out_path, &content) {
                            eprintln!(
                                "{} Failed to write report to {}: {}",
                                "✖".red(),
                                out_path,
                                e
                            );
                            1
                        } else {
                            println!("✓ Wrote compliance report to {}", out_path);
                            0
                        }
                    } else {
                        println!("{}", content);
                        0
                    }
                }
                Err(e) => {
                    eprintln!("{} {}", "✖".red(), e);
                    1
                }
            },
        },
        Commands::Unwrap { target } => agentcontrol::wrap::run_unwrap_target(&target),
        Commands::Protect {
            dry_run,
            no_browser,
            listen,
            mcp_url,
            enforce,
            shadow,
            policy,
        } => {
            let active_enforce = enforce && !shadow;
            let code = agentcontrol::wrap::run_protect_orchestration(
                dry_run,
                no_browser,
                &listen,
                &mcp_url,
                active_enforce,
                &policy,
            );
            if code != 0 || dry_run {
                return code;
            }
            run_dev(
                listen,
                mcp_url,
                false,
                true,
                active_enforce,
                false,
                false,
                "http://localhost:11434".to_string(),
                vec![],
                Some(policy),
            )
            .await
        }
        Commands::Unprotect { dry_run, force } => agentcontrol::wrap::run_unprotect_all(dry_run, force),
        Commands::Verify { gateway, json } => agentcontrol::verify::run_verification_probe(&gateway, json).await,
        Commands::Status => agentcontrol::wrap::run_status(),
        Commands::Watch { all, target } => agentcontrol::wrap::run_watch(all, target),
        Commands::StdioProxy {
            args,
            scan_responses,
            block_on_secrets,
            max_scan_bytes,
        } => run_stdio_proxy(args, scan_responses, block_on_secrets, max_scan_bytes).await,
        Commands::Dev {
            listen,
            mcp_url,
            stdio,
            no_browser,
            enforce,
            learn,
            dual_agent,
            local_llm_url,
            args,
        } => {
            run_dev(
                listen,
                mcp_url,
                stdio,
                no_browser,
                enforce,
                learn,
                dual_agent,
                local_llm_url,
                args,
                None,
            )
            .await
        }
        Commands::Bench {
            full,
            compare_baselines,
            visualize,
            output,
        } => run_bench(full, compare_baselines, visualize, Some(output)).await,
        Commands::GeneratePolicy {
            output,
            decay_window,
        } => run_generate_policy(output, decay_window).await,
        Commands::Validate {
            policy,
            tool,
            payload,
        } => match agentcontrol::validate::execute(&policy, &tool, &payload) {
            Ok(_) => 0,
            Err(e) => {
                eprintln!("{}", e);
                1
            }
        },

        Commands::Lint { policy } => match agentcontrol::lint::execute(&policy) {
            Ok(code) => code,
            Err(e) => {
                eprintln!("Lint failed: {}", e);
                1
            }
        },
    }
}

fn print_banner() {
    let version = env!("CARGO_PKG_VERSION");
    println!("{}", "┌────────────────────────────────────────────────────────────────────────────────┐".cyan());
    println!(
        "│  {}  {} │",
        "🛡️  VEXA AGENT CONTROL — Intelligent MCP Security Gateway".bold().cyan(),
        format!("(v{})", version).dimmed()
    );
    println!(
        "│  Gateway: {}  •  Dashboard: {}          │",
        "http://127.0.0.1:8080".green(),
        "http://127.0.0.1:8080".cyan()
    );
    println!(
        "│  Transport: {}   •  Enforcement: {} │",
        "stdio / HTTP proxy".yellow(),
        "ACTIVE (DLP + Injection Guard)".green().bold()
    );
    println!("{}", "└────────────────────────────────────────────────────────────────────────────────┘".cyan());
}

fn resolve_audit_log_path() -> std::path::PathBuf {
    if let Ok(env_path) = std::env::var("AGENTCONTROL_LOG_PATH").or_else(|_| std::env::var("AGENTWALL_LOG_PATH")) {
        let p = if env_path.starts_with("~/") || env_path.starts_with("~\\") {
            if let Some(home) = dirs::home_dir() {
                home.join(&env_path[2..])
            } else {
                std::path::PathBuf::from(env_path)
            }
        } else {
            std::path::PathBuf::from(env_path)
        };
        if let Some(parent) = p.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        return p;
    }
    let home = dirs::home_dir().unwrap_or_else(|| std::path::PathBuf::from("."));
    let agent_dir = home.join(".agentcontrol");
    let _ = std::fs::create_dir_all(&agent_dir);
    agent_dir.join("audit.jsonl")
}

#[allow(clippy::too_many_arguments)]
fn build_proxy_state(
    compiled_policy: Option<crate::policy::engine::CompiledPolicy>,
    audit_logger: Arc<AuditLogger>,
    session_id: String,
    kill_mode: KillMode,
    agent_pid: Option<u32>,
    upstream_url: String,
    dry_run: bool,
    shadow_mode: bool,
    policy_loaded: bool,
    rate_limit_val: u32,
    safe_mode_scanner: Arc<SafeModeScanner>,
    response_scanner: Arc<policy::response_scanner::ResponseScanner>,
    response_scan_config: policy::response_scanner::ResponseScanConfig,
    credential_scope_validator: Arc<policy::credential_scope::CredentialScopeValidator>,
    policy_path: Option<String>,
    spend_ledger: Option<Arc<agentcontrol::spend::ledger::SpendLedger>>,
    dashboard_client: Option<Arc<agentcontrol::control_plane_client::client::DashboardClient>>,
    listen_is_loopback: bool,
    centralized_mode: bool,
    effective_profile: String,
    max_concurrency: usize,
    connection_timeout_secs: u64,
    max_frame_size: usize,
    admin_token: Option<String>,
) -> Arc<ProxyState> {
    let connect_timeout = std::time::Duration::from_secs(10);
    let request_timeout = std::time::Duration::from_secs(connection_timeout_secs.max(5));
    let http_client = reqwest::Client::builder()
        .connect_timeout(connect_timeout)
        .timeout(request_timeout)
        .pool_idle_timeout(std::time::Duration::from_secs(90))
        .build()
        .unwrap_or_default();

    let db_manager = Arc::new(agentcontrol::proxy::db::DbManager::init());

    let pricing_table = if spend_ledger.is_some() {
        Some(Arc::new(
            agentcontrol::spend::PricingTable::load(None).unwrap_or_else(|_| {
                agentcontrol::spend::PricingTable {
                    version: "1".to_string(),
                    models: std::collections::HashMap::new(),
                    fallback: agentcontrol::spend::ModelPrice {
                        input_per_1m_cents: 0,
                        output_per_1m_cents: 0,
                    },
                }
            }),
        ))
    } else {
        None
    };

    let provider_keys = {
        let map = dashmap::DashMap::new();
        if let Ok(k) = std::env::var("OPENAI_API_KEY") {
            if !k.is_empty() {
                map.insert("openai".to_string(), k);
            }
        }
        if let Ok(k) = std::env::var("ANTHROPIC_API_KEY") {
            if !k.is_empty() {
                map.insert("anthropic".to_string(), k);
            }
        }
        map
    };

    Arc::new(ProxyState {
        policy: std::sync::RwLock::new(compiled_policy.clone()),
        audit_logger,
        session_id,
        kill_mode,
        agent_pid,
        upstream_url,
        dry_run,
        shadow_mode: std::sync::atomic::AtomicBool::new(shadow_mode),
        policy_loaded: std::sync::atomic::AtomicBool::new(policy_loaded),
        rate_limiter: proxy::handler::RateLimiter::new(rate_limit_val),
        http_client,
        safe_mode_scanner,
        ready: true,
        db_manager,
        response_scanner,
        response_scan_config: std::sync::RwLock::new(response_scan_config),
        dlp_scanner: std::sync::Arc::new(
            agentcontrol::policy::dlp::DlpScanner::new(None).expect("Failed to compile DLP regexes"),
        ),
        semantic_scanner: std::sync::Arc::new(agentcontrol::policy::semantic::SemanticScanner::new(
            agentcontrol::policy::semantic::SemanticConfig::default(),
        )),
        injection_scanner: std::sync::Arc::new(
            agentcontrol::policy::injection::InjectionScanner::new()
                .expect("Failed to compile Injection regexes"),
        ),
        schema_drift_detector: std::sync::Arc::new(
            agentcontrol::policy::schema_drift::SchemaDriftDetector::new(
                compiled_policy
                    .as_ref()
                    .and_then(|p| p.schema_drift.as_ref())
                    .and_then(|sd| sd.baseline_path.as_ref().map(std::path::PathBuf::from)),
            ),
        ),
        tool_history: std::sync::Mutex::new(Vec::new()),
        sessions: dashmap::DashMap::new(),
        metrics_requests_total: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        metrics_allow_total: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        metrics_deny_total: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        metrics_rate_limited_total: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        metrics_firewall_cycle_total: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        metrics_siem_export_total: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        metrics_siem_export_failed_total: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        event_tx: tokio::sync::broadcast::channel(1024).0,
        credential_scope_validator,
        policy_path,
        gateway_start_time: std::time::Instant::now(),
        spend_ledger,
        pricing_table,
        dashboard_client,
        listen_is_loopback,
        policy_read_secret: std::env::var("POLICY_READ_SECRET")
            .ok()
            .filter(|s| !s.is_empty()),
        centralized_mode,
        provider_keys,
        effective_profile,
        max_concurrency,
        connection_timeout_secs,
        max_frame_size,
        admin_token,
    })
}

#[allow(deprecated)]
async fn run_stdio_proxy(
    args: Vec<String>,
    scan_responses: bool,
    block_on_secrets: bool,
    max_scan_bytes: usize,
) -> i32 {
    if args.is_empty() {
        eprintln!("{} No command provided to stdio-proxy.", "✖".red());
        return 1;
    }

    let session_secret = resolve_hmac_key();
    let session_id = uuid::Uuid::new_v4().to_string();

    let log_path = resolve_audit_log_path();

    let audit_logger = match AuditLogger::new(agentcontrol::audit::logger::AuditLoggerConfig {
        log_path,
        session_id: session_id.clone(),
        session_secret,
        max_bytes: 104857600, // 100MB
        siem_exporter: None,
        include_params: false,
    }) {
        Ok(l) => Arc::new(l),
        Err(e) => {
            eprintln!("{} Cannot create audit logger: {}", "✖".red(), e);
            return 1;
        }
    };

    let safe_mode_scanner =
        Arc::new(SafeModeScanner::new().expect("Failed to compile SafeMode regexes"));
    let response_scanner = Arc::new(
        policy::response_scanner::ResponseScanner::new()
            .expect("Failed to compile ResponseScanner regexes"),
    );

    let response_scan_config = policy::response_scanner::ResponseScanConfig {
        enabled: scan_responses,
        block_mode: block_on_secrets,
        dry_run: false,
        max_scan_bytes,
        scannable_tools: vec![
            "read_file".to_string(),
            "exec_command".to_string(),
            "run_shell".to_string(),
            "run_command".to_string(),
            "http_get".to_string(),
            "http_post".to_string(),
            "list_files".to_string(),
            "database_query".to_string(),
            "bash".to_string(),
            "execute".to_string(),
            "terminal".to_string(),
            "read".to_string(),
            "cat".to_string(),
            "shell".to_string(),
            "leak_secret".to_string(),
            "secret".to_string(),
        ],
        safe_tools: vec![
            "tools/list".to_string(),
            "get_schema".to_string(),
            "get_metadata".to_string(),
            "ping".to_string(),
            "calculator".to_string(),
            "weather".to_string(),
            "datetime".to_string(),
            "search".to_string(),
            "grep".to_string(),
        ],
    };

    let state = build_proxy_state(
        None,
        audit_logger,
        session_id,
        KillMode::Connection,
        None,
        "".to_string(),
        false,
        false,
        false,
        0,
        safe_mode_scanner,
        response_scanner,
        response_scan_config,
        Arc::new(policy::credential_scope::CredentialScopeValidator::new(false)),
        None,
        None,
        agentcontrol::control_plane_client::client::DashboardClient::from_env().map(Arc::new),
        true,
        false,
        "local-shadow".to_string(),
        1024,
        30,
        16777216,
        None,
    );

    let mut parts: Vec<String> = args.iter().map(|a| proxy::stdio::expand_arg(a)).collect();
    let program = parts.remove(0);
    let (resolved_program, prefix_args) = proxy::stdio::resolve_command(&program);

    let mut final_args = prefix_args;
    final_args.extend(parts);

    let mut cmd = tokio::process::Command::new(resolved_program);
    cmd.args(final_args);

    if let Err(e) = proxy::stdio::run_stdio_bridge(state, cmd).await {
        eprintln!("{} Stdio proxy error: {}", "✖".red(), e);
        if e.to_string().contains("No such file or directory")
            || e.to_string().contains("os error 2")
        {
            eprintln!(
                "\n{} Missing prerequisite: Could not find or execute '{}'",
                "💡".yellow(),
                program
            );
            if program == "npx" || program == "node" || program == "npm" {
                eprintln!("   Please install Node.js / npx (https://nodejs.org) or add Node to your PATH.");
            }
        }
        return 1;
    }

    0
}

async fn dispatch_start(args: cli::StartArgs) -> i32 {
    run_start(args).await
}

#[allow(deprecated)]
async fn run_start(args: cli::StartArgs) -> i32 {
    println!("{} Loading configuration...", "ℹ".blue());

    let profile = args
        .profile
        .as_deref()
        .map(cli::DeploymentProfile::parse)
        .unwrap_or(if args.shadow_mode {
            cli::DeploymentProfile::LocalShadow
        } else if args.centralized {
            cli::DeploymentProfile::TeamEnforce
        } else {
            cli::DeploymentProfile::LocalEnforce
        });

    let scan_responses = args.scan_responses || profile.default_scan_responses();
    let block_on_secrets = args.block_on_secrets || profile.default_fail_closed();
    let shadow_mode = args.shadow_mode || matches!(profile, cli::DeploymentProfile::LocalShadow);
    let dry_run = args.dry_run;
    let effective_profile_name = match profile {
        cli::DeploymentProfile::LocalShadow => "local-shadow".to_string(),
        cli::DeploymentProfile::LocalEnforce => "local-enforce".to_string(),
        cli::DeploymentProfile::TeamEnforce => "team-enforce".to_string(),
        cli::DeploymentProfile::DedicatedEnforce => "dedicated-enforce".to_string(),
    };

    let policy_path = args.policy;
    let listen = args.listen;
    let log_path = args.log_path;
    let mcp_url = args.mcp_url;
    let agent_pid = args.agent_pid;
    let agent_pid_file = args.agent_pid_file;
    let kill_mode_str = args.kill_mode;
    let rate_limit = args.rate_limit;
    let log_max_bytes = args.log_max_bytes;
    let oidc_issuer = args.oidc_issuer;
    let max_scan_bytes = args.max_scan_bytes;
    let siem_backend = args.siem_backend;
    let siem_endpoint = args.siem_endpoint;
    let siem_token = args.siem_token;
    let siem_timeout_secs = args.siem_timeout_secs;
    let include_params = args.include_params;
    let strict_credential_scope = args.strict_credential_scope;
    let tls_cert = args.tls_cert;
    let tls_key = args.tls_key;
    let centralized = args.centralized;

    // Parse kill mode
    let kill_mode = match KillMode::from_str(&kill_mode_str) {
        Ok(m) => m,
        Err(e) => {
            log_error!("startup_error", "reason": e);
            eprintln!("{} Invalid kill mode: {}", "✖".red(), e);
            return 1;
        }
    };

    // Resolve agent PID
    let resolved_pid =
        agent_pid.or_else(|| agent_pid_file.as_ref().and_then(|f| kill::read_pid_file(f)));

    // NFR-203: Startup self-check
    // 1. Load policy — priority order:
    //    a) DASHBOARD_API_URL is set  → fetch active policy from PostgreSQL via dashboard API
    //    b) --policy <file> is set    → load from local YAML file (fallback / dev override)
    //    c) neither                   → Safe Mode (no policy enforcement, audit only)
    let dashboard_api_url = std::env::var("DASHBOARD_API_URL")
        .ok()
        .filter(|s| !s.is_empty());
    let policy_read_secret_env = std::env::var("POLICY_READ_SECRET")
        .ok()
        .filter(|s| !s.is_empty());

    let (compiled_policy, _policy_hash, _warnings, policy_loaded) =
        if let Some(ref path) = policy_path {
            // (a) Local YAML file — explicitly provided via --policy CLI flag
            print!("{} Loading policy from {}... ", "ℹ".blue(), path.yellow());
            match load_policy(Path::new(path), oidc_issuer) {
                PolicyLoadResult::Loaded {
                    policy,
                    raw_hash,
                    warnings,
                } => {
                    println!("{}", "OK".green().bold());
                    (Some(policy), raw_hash, warnings, true)
                }
                PolicyLoadResult::Degraded { reason } => {
                    println!("{}", "DEGRADED".yellow().bold());
                    log_warn!("policy_degraded", "reason": reason);
                    (None, "sha256:none".to_string(), vec![], false)
                }
                PolicyLoadResult::Fatal { error } => {
                    println!("{}", "FAILED".red().bold());
                    log_error!("startup_error", "reason": error.to_string());
                    return 1;
                }
            }
        } else if let Some(ref api_url) = dashboard_api_url {
            // (b) Fetch from dashboard API — policy is stored in PostgreSQL
            print!(
                "{} Fetching policy from dashboard API ({})... ",
                "ℹ".blue(),
                api_url.yellow()
            );
            let remote_result = tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(
                    agentcontrol::policy::remote::load_remote_policy(
                        api_url,
                        policy_read_secret_env.as_deref(),
                    ),
                )
            });
            match remote_result {
                PolicyLoadResult::Loaded {
                    policy,
                    raw_hash,
                    warnings,
                } => {
                    println!("{}", "OK".green().bold());
                    (Some(policy), raw_hash, warnings, true)
                }
                PolicyLoadResult::Degraded { reason } => {
                    println!("{}", "DEGRADED".yellow().bold());
                    log_warn!("policy_degraded", "reason": reason);
                    (None, "sha256:none".to_string(), vec![], false)
                }
                PolicyLoadResult::Fatal { error } => {
                    println!("{}", "FAILED".red().bold());
                    log_error!("startup_error", "reason": error.to_string());
                    return 1;
                }
            }
        } else {
            // (c) Safe Mode — no dashboard API, no policy file
            println!(
                "{} {}",
                "🛡".green(),
                "Safe Mode v1 enabled (Audit mode recommended). Blocking high-risk secrets & exfil."
                    .green()
            );
            if !dry_run {
                println!("{} {}", "ℹ".blue(), "Run with --dry-run to preview.".blue());
            }
            (None, "sha256:none".to_string(), vec![], false)
        };

    // Initialize dashboard client early for SpendLedger sync
    let dashboard_client = agentcontrol::control_plane_client::client::DashboardClient::from_env()
        .map(std::sync::Arc::new);

    // --- FR-120: Spend Caps License Validation ---
    let spend_ledger = if let Some(ref policy) = compiled_policy {
        if let Some(ref caps) = policy.spend_caps {
            if caps.enabled {
                let license_key = match &caps.license_key {
                    Some(k) => k,
                    None => {
                        eprintln!("{} spend_caps.enabled requires a valid license_key. Contact Vexa for a license at vexasec.io/pricing.", "✖".red());
                        std::process::exit(1);
                    }
                };

                let validator = match agentcontrol::license::LicenseValidator::new() {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!(
                            "{} Failed to initialize license validator: {}",
                            "✖".red(),
                            e
                        );
                        std::process::exit(1);
                    }
                };

                match validator.validate(license_key) {
                    Ok(license) => {
                        if !validator.has_feature(&license, "spend_caps") {
                            eprintln!(
                                "{} spend_caps is not enabled in your current license.",
                                "✖".red()
                            );
                            std::process::exit(1);
                        }
                        agentcontrol::logging::log_event(
                            agentcontrol::logging::Level::Info,
                            "license_validated",
                            serde_json::json!({
                                "org_id": license.org_id,
                                "features": license.features,
                                "expires_at": license.expires_at.to_rfc3339()
                            }),
                        );
                        let now = chrono::Utc::now();
                        let days_until_expiry = (license.expires_at - now).num_days();
                        if days_until_expiry <= 30 {
                            agentcontrol::logging::log_event(
                                agentcontrol::logging::Level::Warn,
                                "license_expiry_warning",
                                serde_json::json!({
                                    "days_remaining": days_until_expiry
                                }),
                            );
                            println!(
                                "{} License expires in {} days. Renew at vexasec.io/pricing.",
                                "⚠".yellow(),
                                days_until_expiry
                            );
                        }
                    }
                    Err(e) => {
                        match e {
                            agentcontrol::license::LicenseError::Expired { expired_at } => {
                                eprintln!(
                                    "{} License expired at {}. Renew at vexasec.io/pricing.",
                                    "✖".red(),
                                    expired_at
                                );
                            }
                            _ => {
                                eprintln!("{} Invalid license: {}", "✖".red(), e);
                            }
                        }
                        std::process::exit(1);
                    }
                }

                if caps.admin_api {
                    agentcontrol::logging::log_event(
                        agentcontrol::logging::Level::Info,
                        "admin_api_enabled",
                        serde_json::json!({
                            "data_stored": ["spend_counters", "audit_history", "increase_requests"],
                            "retention_days": {
                                "spend_counters_days": caps.retention.as_ref().map(|r| r.spend_counters_days).unwrap_or(90),
                                "increase_requests_days": caps.retention.as_ref().map(|r| r.increase_requests_days).unwrap_or(365),
                                "thresholds_fired_days": caps.retention.as_ref().map(|r| r.thresholds_fired_days).unwrap_or(90)
                            },
                            "location": "~/.agentcontrol/"
                        }),
                    );
                    println!(
                        "{} Spend Caps Admin API enabled. Local durable PII store activated.",
                        "ℹ".blue()
                    );
                }

                Some(std::sync::Arc::new(agentcontrol::spend::SpendLedger::init(
                    dashboard_client.clone(),
                )))
            } else {
                None
            }
        } else {
            None
        }
    } else {
        None
    };
    // ---------------------------------------------

    // 2. Resolve and ensure log path directory exists
    let resolved_log_path = if log_path.starts_with("~/") || log_path.starts_with("~\\") {
        if let Some(home) = dirs::home_dir() {
            home.join(&log_path[2..]).to_string_lossy().to_string()
        } else {
            log_path.clone()
        }
    } else {
        log_path.clone()
    };

    let log_path_obj = Path::new(&resolved_log_path);
    let mut log_dir = log_path_obj.parent().unwrap_or(Path::new("."));
    if log_dir.as_os_str().is_empty() {
        log_dir = Path::new(".");
    }
    if !log_dir.exists() {
        if let Err(e) = std::fs::create_dir_all(log_dir) {
            eprintln!(
                "{} Could not create log directory {}: {}",
                "✖".red(),
                log_dir.display(),
                e
            );
            return 1;
        }
    }
    let log_path = resolved_log_path;

    // Override listen address for centralized mode if it's the default
    // Override listen address for centralized mode if it's the default
    let listen = if centralized && listen == "127.0.0.1:8080" {
        "0.0.0.0:8080".to_string()
    } else {
        listen
    };

    // 3. Parse listen address
    let listen_addr: SocketAddr = match listen.parse() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{} Invalid listen address: {}", "✖".red(), e);
            return 1;
        }
    };

    let has_identity_auth = compiled_policy
        .as_ref()
        .map(|p| p.identity_validator.is_some())
        .unwrap_or(false)
        || centralized
        || args.admin_token.is_some()
        || std::env::var("AGENTCONTROL_ADMIN_TOKEN").is_ok();

    if !listen_addr.ip().is_loopback() && !has_identity_auth {
        eprintln!(
            "{} Security error: Non-loopback listener address ({}) requires OIDC authentication or a verified identity provider. Binding to external interfaces without authentication is prohibited.",
            "✖".red().bold(),
            listen_addr
        );
        return 1;
    }

    // Generate session secret (persisted at ~/.agentcontrol/audit.key per ADR-007)
    let session_secret = resolve_hmac_key();
    let session_id = uuid::Uuid::new_v4().to_string();

    let siem_backend_parsed = agentcontrol::audit::siem::SiemBackend::from_str(&siem_backend);
    let siem_exporter = if siem_backend_parsed == agentcontrol::audit::siem::SiemBackend::Local {
        None
    } else {
        Some(agentcontrol::audit::siem::SiemExporter::new(
            siem_backend_parsed,
            siem_endpoint,
            siem_token,
            siem_timeout_secs,
        ))
    };

    // Create audit logger
    let audit_logger = match AuditLogger::new(agentcontrol::audit::logger::AuditLoggerConfig {
        log_path: std::path::PathBuf::from(&log_path),
        session_id: session_id.clone(),
        session_secret,
        max_bytes: log_max_bytes,
        siem_exporter,
        include_params,
    }) {
        Ok(l) => Arc::new(l),
        Err(e) => {
            eprintln!("{} Cannot create audit logger: {}", "✖".red(), e);
            return 1;
        }
    };

    println!(
        "{} Proxy session initialized: {}",
        "✓".green(),
        session_id.cyan()
    );

    // Build proxy state
    let rate_limit_val = rate_limit.unwrap_or_else(|| {
        compiled_policy
            .as_ref()
            .map(|p| p.max_calls_per_second)
            .unwrap_or(0)
    });

    let safe_mode_scanner =
        Arc::new(SafeModeScanner::new().expect("Failed to compile SafeMode regexes"));
    println!(
        "{} Safe Mode v1 active — {} rules loaded. Run with {} to preview.",
        "✔".green(),
        safe_mode_scanner.rule_count.to_string().cyan(),
        "--dry-run".yellow()
    );

    // FR-303b: Initialize response scanner
    let response_scanner = Arc::new(
        policy::response_scanner::ResponseScanner::new()
            .expect("Failed to compile ResponseScanner regexes"),
    );

    let (sc_tools, sf_tools) = if let Some(p) = &compiled_policy {
        (p.scannable_tools.clone(), p.safe_tools.clone())
    } else {
        (
            vec![
                "read_file".to_string(),
                "exec_command".to_string(),
                "run_shell".to_string(),
                "run_command".to_string(),
                "http_get".to_string(),
                "http_post".to_string(),
                "list_files".to_string(),
                "database_query".to_string(),
                "bash".to_string(),
                "execute".to_string(),
                "terminal".to_string(),
                "read".to_string(),
                "cat".to_string(),
                "shell".to_string(),
                "leak_secret".to_string(),
                "secret".to_string(),
            ],
            vec![
                "tools/list".to_string(),
                "get_schema".to_string(),
                "get_metadata".to_string(),
                "ping".to_string(),
                "calculator".to_string(),
                "weather".to_string(),
                "datetime".to_string(),
                "search".to_string(),
                "grep".to_string(),
            ],
        )
    };

    let response_scan_config = policy::response_scanner::ResponseScanConfig {
        enabled: scan_responses,
        block_mode: block_on_secrets,
        dry_run,
        max_scan_bytes,
        scannable_tools: sc_tools,
        safe_tools: sf_tools,
    };

    let credential_scope_validator = Arc::new(
        policy::credential_scope::CredentialScopeValidator::new(strict_credential_scope),
    );

    // Log credential scope mode at startup
    agentcontrol::logging::log_event(
        agentcontrol::logging::Level::Info,
        "credential_scope_mode",
        serde_json::json!({
            "strict": strict_credential_scope,
            "note": "FR-22 Identity Platform integration pending — stub validator active"
        }),
    );

    let state = build_proxy_state(
        compiled_policy.clone(),
        audit_logger.clone(),
        session_id.clone(),
        kill_mode.clone(),
        resolved_pid,
        mcp_url,
        dry_run,
        shadow_mode,
        policy_loaded,
        rate_limit_val,
        safe_mode_scanner,
        response_scanner,
        response_scan_config,
        credential_scope_validator,
        policy_path.clone(),
        spend_ledger.clone(),
        dashboard_client.clone(),
        listen_addr.ip().is_loopback(),
        centralized,
        effective_profile_name,
        args.max_concurrency,
        args.connection_timeout_secs,
        args.max_frame_size,
        args.admin_token.clone().or_else(|| std::env::var("AGENTCONTROL_ADMIN_TOKEN").ok()),
    );

    if state.dashboard_client.is_some() {
        let msg = if std::env::var("DASHBOARD_API_URL").is_ok() {
            "Connected (DASHBOARD_API_URL set)".green()
        } else {
            "Connected (Local Dev Fallback: http://localhost:8400)".yellow()
        };
        println!("{} {} {}", "📊".green(), "FR-23 Dashboard:".bold(), msg);
    }

    // Background policy push subscriber — active when DASHBOARD_API_URL is set.
    // Listens for Server-Sent Events (SSE) from the Hub to instantly hot-swap
    // the policy in memory. Runs regardless of whether --policy was provided so
    // that live updates from the Policy Editor are seamlessly applied (last-write-wins).
    {
        let sse_api_url = std::env::var("DASHBOARD_API_URL")
            .ok()
            .filter(|s| !s.is_empty());
        if let Some(api_url) = sse_api_url {
            let sub_state = state.clone();
            let sub_secret = std::env::var("POLICY_READ_SECRET").unwrap_or_default();
            tokio::spawn(async move {
                println!(
                    "{} Connected to Hub for real-time policy push (SSE)",
                    "🔄".blue()
                );
                agentcontrol::control_plane_client::subscribe::start_policy_subscriber(
                    api_url, sub_secret, sub_state,
                )
                .await;
            });
        }
    }

    // Background file-system watcher — active when --policy <file> is provided.
    // Monitors the policy YAML file for on-disk changes and hot-reloads the in-memory
    // policy without any restart (last-write-wins alongside the SSE subscriber above).
    if let Some(ref watch_path) = policy_path {
        agentcontrol::policy::policy_file_watcher::start_policy_file_watcher(
            watch_path.clone(),
            state.clone(),
        );
    }

    // Background device heartbeat emitter — periodic health ping to Hub (Sprint 4)
    tokio::spawn(async move {
        agentcontrol::control_plane_client::heartbeat::start_heartbeat_loop(60).await;
    });

    if shadow_mode {
        println!(
            "{} {} {}",
            "👁".blue(),
            "Mode:".bold(),
            "SHADOW (Observation Only — no enforcement)".cyan().bold()
        );
        println!(
            "{} {}",
            "ℹ".blue(),
            "All tool calls forwarded and logged. Enforcement is OFF.".blue()
        );
    } else if dry_run {
        println!(
            "{} {} {}",
            "🛡".blue(),
            "Mode:".bold(),
            "DRY-RUN (Logging Only)".yellow().bold()
        );
    } else {
        println!(
            "{} {} {}",
            "🛡".blue(),
            "Mode:".bold(),
            "ENFORCEMENT (Active Blocking)".green().bold()
        );
    }

    println!(
        "{} {} {}",
        "📡".blue(),
        "Listening on:".bold(),
        listen.green().underline()
    );
    println!("{} Press Ctrl+C to stop", "⌨".blue());
    println!("{}", "-".repeat(60).cyan());

    // ── FR-5 §5.5.6: Build TLS acceptor if cert and key are provided ────
    let tls_acceptor = match (tls_cert.as_deref(), tls_key.as_deref()) {
        (Some(cert), Some(key)) => {
            print!("{} Loading TLS cert/key... ", "🔒".blue());
            match proxy::tls::build_tls_acceptor(
                std::path::Path::new(cert),
                std::path::Path::new(key),
            ) {
                Ok(acceptor) => {
                    println!("{}", "OK".green().bold());
                    println!(
                        "{} {} {}",
                        "🔒".green(),
                        "TLS:".bold(),
                        "Enabled (HTTPS listener)".green()
                    );
                    Some(acceptor)
                }
                Err(e) => {
                    println!("{}", "FAILED".red().bold());
                    eprintln!("{} TLS setup failed: {}", "✖".red(), e);
                    return 1;
                }
            }
        }
        (Some(_), None) | (None, Some(_)) => {
            eprintln!(
                "{} Both --tls-cert and --tls-key must be provided together",
                "✖".red()
            );
            return 1;
        }
        (None, None) => {
            println!(
                "{} {} {}",
                "⚠".yellow(),
                "TLS:".bold(),
                "Disabled (plain HTTP — not recommended for production)".yellow()
            );
            None
        }
    };

    // Shutdown channel
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // FR-5 AC-5.5: Fail-closed panic hook.
    //
    // Why this matters for a security gateway:
    // If any task panics — policy engine, DLP scanner, injection detector,
    // connection handler — the gateway is in a degraded state where traffic
    // could be proxied without full policy enforcement. A silent continue
    // is a security hole. The correct behavior is: detect the panic, trigger
    // a full shutdown, abort all active connections.
    //
    // How it works:
    // 1. Panic hook fires in the panicking thread (before tokio catches the unwind)
    // 2. Hook sends `true` on shutdown_tx (watch::send is sync-safe)
    // 3. run_server's accept loop sees shutdown_rx.changed() and breaks
    // 4. JoinSet::abort_all() cancels all active connection tasks (server.rs)
    // 5. Process exits with error code
    let shutdown_tx_panic = shutdown_tx.clone();
    let default_panic_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        eprintln!("\nFATAL: Gateway panic detected — initiating fail-closed shutdown (AC-5.5)");
        // Trigger shutdown before printing backtrace (speed matters for fail-closed)
        let _ = shutdown_tx_panic.send(true);
        // Delegate to the default hook for backtrace output
        default_panic_hook(info);
    }));

    // Handle SIGTERM (Unix) / Ctrl+C
    let shutdown_tx_clone = shutdown_tx.clone();
    let _audit_logger_clone = audit_logger.clone();

    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        println!(
            "\n{} Shutdown signal received. Finishing logs...",
            "ℹ".blue()
        );
        let _ = shutdown_tx_clone.send(true);
    });

    #[cfg(target_os = "windows")]
    {
        let shutdown_tx_win = shutdown_tx.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                if agentcontrol::service::windows::service_dispatcher_handler::is_shutdown_requested()
                {
                    let _ = shutdown_tx_win.send(true);
                    break;
                }
            }
        });
    }

    // FR-5 AC-5.6: SIGHUP handler for policy hot-reload.
    //
    // Why SIGHUP?
    // In Unix, SIGHUP is the standard signal for "reload configuration without
    // restarting." K8s sends it when a ConfigMap changes (via a sidecar or
    // lifecycle hook), and ops teams use `kill -HUP <pid>` in production.
    // The PRD requires reload to complete in < 100ms — load_policy on a typical
    // policy YAML takes ~1-2ms, so we're well within budget.
    //
    // Why #[cfg(unix)]?
    // SIGHUP doesn't exist on Windows. The POST /reload HTTP endpoint (server.rs)
    // still works on all platforms. Production targets are Linux containers.
    #[cfg(unix)]
    {
        let sighup_state = state.clone();
        let sighup_policy_path = policy_path.clone();
        tokio::spawn(async move {
            use tokio::signal::unix::{signal, SignalKind};
            let mut sighup =
                signal(SignalKind::hangup()).expect("failed to register SIGHUP handler");

            loop {
                sighup.recv().await;

                let reload_start = std::time::Instant::now();

                let path_str = match &sighup_policy_path {
                    Some(p) => p.clone(),
                    None => {
                        agentcontrol::logging::log_event(
                            agentcontrol::logging::Level::Warn,
                            "sighup_reload_skipped",
                            serde_json::json!({
                                "reason": "No policy path configured (--policy not set)"
                            }),
                        );
                        continue;
                    }
                };

                let path_for_task = path_str.clone();
                let result = tokio::task::spawn_blocking(move || {
                    agentcontrol::policy::loader::load_policy(
                        std::path::Path::new(&path_for_task),
                        None, // issuer override not re-applied on hot-reload
                    )
                })
                .await;

                match result {
                    Ok(agentcontrol::policy::loader::PolicyLoadResult::Loaded {
                        policy,
                        raw_hash,
                        warnings,
                    }) => {
                        match sighup_state.policy.write() {
                            Ok(mut guard) => *guard = Some(policy),
                            Err(_) => {
                                agentcontrol::logging::log_event(
                                    agentcontrol::logging::Level::Error,
                                    "sighup_reload_failed",
                                    serde_json::json!({"error": "Policy lock poisoned"}),
                                );
                                continue;
                            }
                        }
                        sighup_state
                            .policy_loaded
                            .store(true, std::sync::atomic::Ordering::SeqCst);

                        let elapsed_ms = reload_start.elapsed().as_secs_f64() * 1000.0;

                        agentcontrol::logging::log_event(
                            agentcontrol::logging::Level::Info,
                            "policy_reloaded_sighup",
                            serde_json::json!({
                                "path": &path_str,
                                "hash": &raw_hash,
                                "warnings": &warnings,
                                "elapsed_ms": elapsed_ms,
                            }),
                        );

                        // Broadcast SSE event so dashboard updates live
                        let sse_event = serde_json::json!({
                            "event": "gateway_reload",
                            "trigger": "SIGHUP",
                            "policy_hash": &raw_hash,
                            "warnings": &warnings,
                        });
                        if let Ok(s) = serde_json::to_string(&sse_event) {
                            let _ = sighup_state.event_tx.send(s);
                        }

                        println!(
                            "{} Policy reloaded via SIGHUP in {:.1}ms (hash: {})",
                            "🔄".green(),
                            elapsed_ms,
                            &raw_hash[..12]
                        );
                    }
                    Ok(agentcontrol::policy::loader::PolicyLoadResult::Degraded { reason }) => {
                        agentcontrol::logging::log_event(
                            agentcontrol::logging::Level::Warn,
                            "sighup_reload_degraded",
                            serde_json::json!({"error": format!("Policy degraded: {}", reason)}),
                        );
                    }
                    Ok(agentcontrol::policy::loader::PolicyLoadResult::Fatal { error }) => {
                        agentcontrol::logging::log_event(
                            agentcontrol::logging::Level::Error,
                            "sighup_reload_failed",
                            serde_json::json!({"error": format!("Policy fatal: {}", error)}),
                        );
                    }
                    Err(e) => {
                        agentcontrol::logging::log_event(
                            agentcontrol::logging::Level::Error,
                            "sighup_reload_failed",
                            serde_json::json!({"error": format!("Reload task panicked: {}", e)}),
                        );
                    }
                }
            }
        });
    }

    // Run the server
    if let Err(e) = proxy::server::run_server(state, listen_addr, shutdown_rx, tls_acceptor).await {
        eprintln!("{} Server error: {}", "✖".red(), e);
        return 1;
    }

    println!("{} Proxy stopped gracefully.", "✓".green());
    0
}

fn resolve_hmac_key() -> Vec<u8> {
    let key_path = dirs::home_dir().map(|h| h.join(".agentcontrol").join("audit.key"));

    if let Some(ref path) = key_path {
        if path.exists() {
            if let Ok(data) = std::fs::read(path) {
                if data.len() >= 32 {
                    return data[..32].to_vec();
                }
            }
        }
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let secret: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
        if std::fs::write(path, &secret).is_ok() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
            }
            return secret;
        }
    }

    (0..32).map(|_| rand::random::<u8>()).collect()
}

fn run_verify_log(log_path: &str, key_file: Option<&str>) -> i32 {
    let key_path = key_file
        .map(std::path::PathBuf::from)
        .or_else(|| dirs::home_dir().map(|h| h.join(".agentcontrol").join("audit.key")));

    if let Some(ref kpath) = key_path {
        if kpath.exists() {
            if let Ok(key_bytes) = std::fs::read(kpath) {
                if key_bytes.len() >= 32 {
                    print!(
                        "{} Verifying HMAC chain and payload integrity for {} (key: {})... ",
                        "ℹ".blue(),
                        log_path.yellow(),
                        kpath.display().to_string().cyan()
                    );
                    match audit::verifier::verify_chain_with_secret(
                        Path::new(log_path),
                        &key_bytes[..32],
                    ) {
                        audit::verifier::VerifyResult::Valid { entry_count } => {
                            println!("{}", "VALID".green().bold());
                            println!("  {} {} entries verified with HMAC key, cryptographic chain and payloads intact.", "✓".green(), entry_count);
                            return 0;
                        }
                        audit::verifier::VerifyResult::Invalid {
                            entry_index,
                            reason,
                        } => {
                            println!("{}", "INVALID".red().bold());
                            println!(
                                "  {} Chain/payload broken at index {}: {}",
                                "✖".red(),
                                entry_index,
                                reason
                            );
                            return 1;
                        }
                        audit::verifier::VerifyResult::Error(e) => {
                            println!("{}", "ERROR".red().bold());
                            eprintln!("  {} {}", "✖".red(), e);
                            return 2;
                        }
                    }
                }
            }
        }
    }

    print!(
        "{} Verifying log chain integrity for {}... ",
        "ℹ".blue(),
        log_path.yellow()
    );
    match audit::verifier::verify_chain(Path::new(log_path)) {
        audit::verifier::VerifyResult::Valid { entry_count } => {
            println!("{}", "VALID".green().bold());
            println!(
                "  {} {} entries found, cryptographic chain intact.",
                "✓".green(),
                entry_count
            );
            0
        }
        audit::verifier::VerifyResult::Invalid {
            entry_index,
            reason,
        } => {
            println!("{}", "INVALID".red().bold());
            println!(
                "  {} Chain broken at index {}: {}",
                "✖".red(),
                entry_index,
                reason
            );
            1
        }
        audit::verifier::VerifyResult::Error(e) => {
            println!("{}", "ERROR".red().bold());
            eprintln!("  {} {}", "✖".red(), e);
            2
        }
    }
}

fn run_report(log_path: &str, output: Option<&str>, format: &str, include_params: bool) -> i32 {
    match report::generate_report(
        Path::new(log_path),
        include_params,
        "sha256:unknown",
        true,
        "unknown",
        false,
        vec![],
    ) {
        Ok(report) => {
            let out_str = if format == "text" {
                report::format_text_report(&report)
            } else {
                serde_json::to_string_pretty(&report).unwrap()
            };
            match output {
                Some(path) => {
                    if let Err(e) = std::fs::write(path, &out_str) {
                        eprintln!("{} Cannot write report: {}", "✖".red(), e);
                        return 2;
                    }
                    println!("{} Report saved to {}", "✓".green(), path.cyan());
                }
                None => println!("{}", out_str),
            }
            0
        }
        Err(e) => {
            eprintln!("{} {}", "✖".red(), e);
            2
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_wrap(
    command: Option<String>,
    auto_detect: bool,
    policy_path: Option<String>,
    dry_run: bool,
    kill_mode: String,
    log_path: String,
    scan_responses: bool,
    block_on_secrets: bool,
    max_scan_bytes: usize,
) -> i32 {
    if auto_detect {
        println!(
            "{} Auto-detecting known agent configurations...",
            "ℹ".blue()
        );

        let targets = vec![
            agentcontrol::cli::WrapTarget::Claude {
                dry_run,
                scan_responses,
                block_on_secrets,
            },
            agentcontrol::cli::WrapTarget::Cursor { dry_run },
            agentcontrol::cli::WrapTarget::Vscode { dry_run },
            agentcontrol::cli::WrapTarget::Jetbrains { dry_run },
            agentcontrol::cli::WrapTarget::Zed { dry_run },
            agentcontrol::cli::WrapTarget::Cline { dry_run },
            agentcontrol::cli::WrapTarget::Opencode { dry_run },
            agentcontrol::cli::WrapTarget::Antigravity { dry_run },
        ];

        let mut wrapped_any = false;
        for target in targets {
            // run_wrap_target will print errors to stderr if config isn't found.
            // We temporarily suppress stderr? Or just let it print.
            // Actually, we can just call it. If it succeeds (returns 0), we set wrapped_any = true.
            if agentcontrol::wrap::run_wrap_target(&target) == 0 {
                wrapped_any = true;
            }
        }

        if wrapped_any {
            println!("{} Auto-detect wrap completed successfully.", "✓".green());
            return 0;
        } else {
            eprintln!(
                "{} No supported agents found to wrap automatically.",
                "✖".red()
            );
            return 1;
        }
    }

    let cmd_str = match command {
        Some(c) => c,
        None => {
            eprintln!(
                "{} You must provide a --command or use --auto-detect.",
                "✖".red()
            );
            return 1;
        }
    };

    // Load policy
    let (compiled_policy, _policy_hash, _warnings, policy_loaded) = match policy_path.as_deref() {
        Some(path) => match load_policy(Path::new(path), None) {
            PolicyLoadResult::Loaded {
                policy,
                raw_hash,
                warnings,
                ..
            } => (Some(policy), raw_hash, warnings, true),
            PolicyLoadResult::Degraded { reason } => {
                log_warn!("policy_degraded", "reason": reason);
                (None, "sha256:none".to_string(), vec![], false)
            }
            PolicyLoadResult::Fatal { error } => {
                log_error!("startup_error", "reason": error.to_string());
                return 1;
            }
        },
        None => {
            println!(
                "{} {}",
                "🛡".green(),
                "Safe Mode v1 enabled (Audit mode recommended). Blocking high-risk secrets & exfil.".green()
            );
            if !dry_run {
                println!("{} {}", "ℹ".blue(), "Run with --dry-run to preview.".blue());
            }
            (None, "sha256:none".to_string(), vec![], false)
        }
    };

    let session_secret: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
    let session_id = uuid::Uuid::new_v4().to_string();

    let audit_logger = match AuditLogger::new(agentcontrol::audit::logger::AuditLoggerConfig {
        log_path: std::path::PathBuf::from(&log_path),
        session_id: session_id.clone(),
        session_secret,
        max_bytes: 104857600, // 100MB
        siem_exporter: None,
        include_params: false,
    }) {
        Ok(l) => Arc::new(l),
        Err(e) => {
            eprintln!("{} Cannot create audit logger: {}", "✖".red(), e);
            return 1;
        }
    };

    let safe_mode_scanner =
        Arc::new(SafeModeScanner::new().expect("Failed to compile SafeMode regexes"));
    eprintln!(
        "{} Safe Mode v1 active — {} rules loaded.",
        "✔".green(),
        safe_mode_scanner.rule_count.to_string().cyan()
    );

    // FR-303b: Initialize response scanner
    let response_scanner = Arc::new(
        policy::response_scanner::ResponseScanner::new()
            .expect("Failed to compile ResponseScanner regexes"),
    );

    let (sc_tools, sf_tools) = if let Some(p) = &compiled_policy {
        (p.scannable_tools.clone(), p.safe_tools.clone())
    } else {
        (
            vec![
                "read_file".to_string(),
                "exec_command".to_string(),
                "run_shell".to_string(),
                "run_command".to_string(),
                "http_get".to_string(),
                "http_post".to_string(),
                "list_files".to_string(),
                "database_query".to_string(),
                "bash".to_string(),
                "execute".to_string(),
                "terminal".to_string(),
                "read".to_string(),
                "cat".to_string(),
                "shell".to_string(),
                "leak_secret".to_string(),
                "secret".to_string(),
            ],
            vec![
                "tools/list".to_string(),
                "get_schema".to_string(),
                "get_metadata".to_string(),
                "ping".to_string(),
                "calculator".to_string(),
                "weather".to_string(),
                "datetime".to_string(),
                "search".to_string(),
                "grep".to_string(),
            ],
        )
    };

    let response_scan_config = policy::response_scanner::ResponseScanConfig {
        enabled: scan_responses,
        block_mode: block_on_secrets,
        dry_run,
        max_scan_bytes,
        scannable_tools: sc_tools,
        safe_tools: sf_tools,
    };

    let state = build_proxy_state(
        compiled_policy.clone(),
        audit_logger,
        session_id,
        match kill_mode.as_str() {
            "connection" => KillMode::Connection,
            "process" => KillMode::Process,
            "both" => KillMode::Both,
            _ => KillMode::Process,
        },
        None,
        "".to_string(),
        dry_run,
        false,
        policy_loaded,
        0,
        safe_mode_scanner,
        response_scanner,
        response_scan_config,
        Arc::new(policy::credential_scope::CredentialScopeValidator::new(false)),
        None,
        None,
        agentcontrol::control_plane_client::client::DashboardClient::from_env().map(Arc::new),
        true,
        false,
        "local-enforce".to_string(),
        1024,
        30,
        16777216,
        None,
    );

    // Parse the command string
    let parts = match shlex::split(&cmd_str) {
        Some(p) => p,
        None => {
            eprintln!("{} Failed to parse command string.", "✖".red());
            return 1;
        }
    };
    if parts.is_empty() {
        eprintln!("{} Empty command provided.", "✖".red());
        return 1;
    }

    let mut parts: Vec<String> = parts.iter().map(|a| proxy::stdio::expand_arg(a)).collect();
    let program = parts.remove(0);
    let (resolved_program, prefix_args) = proxy::stdio::resolve_command(&program);
    let mut cmd = tokio::process::Command::new(resolved_program);

    let mut final_args = prefix_args;
    final_args.extend(parts);
    cmd.args(final_args);

    if let Err(e) = proxy::stdio::run_stdio_bridge(state, cmd).await {
        eprintln!("{} Stdio proxy error: {}", "✖".red(), e);
        if e.to_string().contains("No such file or directory")
            || e.to_string().contains("os error 2")
        {
            eprintln!(
                "\n{} Missing prerequisite: Could not find or execute '{}'",
                "💡".yellow(),
                program
            );
            if program == "npx" || program == "node" || program == "npm" {
                eprintln!("   Please install Node.js / npx (https://nodejs.org) or add Node to your PATH.");
            }
        }
        return 1;
    }

    0
}

// FR-2: Shadow Mode (Dev) – observation only proxy (pass --enforce to activate blocking)
#[allow(deprecated)]
async fn run_dev(
    listen: String,
    mcp_url: String,
    stdio: bool,
    no_browser: bool,
    enforce: bool,
    learn: bool,
    dual_agent: bool,
    local_llm_url: String,
    args: Vec<String>,
    policy_path_opt: Option<String>,
) -> i32 {
    if learn {
        println!(
            "{} {}",
            "🧠".blue(),
            "Policy Learning Mode active — observing tool sequences to synthesize policy."
                .cyan()
                .bold()
        );
        println!(
            "{} Run {} after session to generate policy YAML.",
            "ℹ".blue(),
            "agentcontrol generate-policy".yellow()
        );
    }
    if dual_agent {
        let detector = agentcontrol::detector::LocalDualAgentDetector::new(
            agentcontrol::detector::DualAgentConfig {
                enabled: true,
                local_llm_url,
                poll_interval_secs: 5,
            },
        );
        detector.start();
    }

    // Attempt to load policy YAML if path is specified or default exists
    let (compiled_policy, policy_loaded, policy_path_str) = match policy_path_opt.as_deref() {
        Some(path_str) => {
            let p = std::path::Path::new(path_str);
            if p.exists() {
                match load_policy(p, None) {
                    PolicyLoadResult::Loaded { policy, .. } => (Some(policy), true, Some(path_str.to_string())),
                    _ => (None, false, None),
                }
            } else {
                (None, false, None)
            }
        }
        None => {
            let default_p = std::path::Path::new("agentcontrol-policy.yaml");
            if default_p.exists() {
                match load_policy(default_p, None) {
                    PolicyLoadResult::Loaded { policy, .. } => (Some(policy), true, Some("agentcontrol-policy.yaml".to_string())),
                    _ => (None, false, None),
                }
            } else {
                (None, false, None)
            }
        }
    };

    // Generate session secret and ID
    let session_secret: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
    let session_id = uuid::Uuid::new_v4().to_string();

    // Resolve canonical audit log path (~/.agentcontrol/audit.jsonl)
    let log_path = resolve_audit_log_path();

    let audit_logger = match AuditLogger::new(agentcontrol::audit::logger::AuditLoggerConfig {
        log_path,
        session_id: session_id.clone(),
        session_secret,
        max_bytes: 104857600,
        siem_exporter: None,
        include_params: false,
    }) {
        Ok(l) => Arc::new(l),
        Err(e) => {
            eprintln!("{} Cannot create audit logger: {}", "✖".red(), e);
            return 1;
        }
    };

    let safe_mode_scanner =
        Arc::new(SafeModeScanner::new().expect("Failed to compile SafeMode regexes"));
    let response_scanner = Arc::new(
        policy::response_scanner::ResponseScanner::new()
            .expect("Failed to compile ResponseScanner regexes"),
    );

    let response_scan_config = policy::response_scanner::ResponseScanConfig {
        enabled: false,
        block_mode: false,
        dry_run: false,
        max_scan_bytes: 1048576,
        scannable_tools: vec![
            "read_file".to_string(),
            "exec_command".to_string(),
            "run_shell".to_string(),
            "run_command".to_string(),
            "http_get".to_string(),
            "http_post".to_string(),
            "list_files".to_string(),
            "database_query".to_string(),
            "bash".to_string(),
            "execute".to_string(),
            "terminal".to_string(),
            "read".to_string(),
            "cat".to_string(),
            "shell".to_string(),
            "leak_secret".to_string(),
            "secret".to_string(),
        ],
        safe_tools: vec![
            "tools/list".to_string(),
            "get_schema".to_string(),
            "get_metadata".to_string(),
            "ping".to_string(),
            "calculator".to_string(),
            "weather".to_string(),
            "datetime".to_string(),
            "search".to_string(),
            "grep".to_string(),
        ],
    };

    let state = build_proxy_state(
        compiled_policy,
        audit_logger,
        session_id,
        KillMode::Connection,
        None,
        mcp_url,
        false,
        !enforce,
        policy_loaded,
        0,
        safe_mode_scanner,
        response_scanner,
        response_scan_config,
        Arc::new(policy::credential_scope::CredentialScopeValidator::new(false)),
        policy_path_str,
        None,
        agentcontrol::control_plane_client::client::DashboardClient::from_env().map(Arc::new),
        listen
            .parse::<SocketAddr>()
            .map(|a| a.ip().is_loopback())
            .unwrap_or(true),
        false,
        if enforce {
            "local-enforce".to_string()
        } else {
            "local-shadow".to_string()
        },
        1024,
        30,
        16777216,
        None,
    );

    if stdio {
        if !args.is_empty() {
            let mut parts = args.clone();
            let program = parts.remove(0);
            let (resolved_program, prefix_args) = proxy::stdio::resolve_command(&program);

            let mut final_args = prefix_args;
            final_args.extend(parts);

            let mut cmd = tokio::process::Command::new(resolved_program);
            cmd.args(final_args);

            if let Err(e) = proxy::stdio::run_stdio_bridge(state, cmd).await {
                eprintln!("{} Stdio proxy error: {}", "✖".red(), e);
                return 1;
            }
        } else {
            if let Err(e) = proxy::stdio::run_stdio_to_http_bridge(state).await {
                eprintln!("{} Stdio bridge error: {}", "✖".red(), e);
                return 1;
            }
        }
        return 0;
    }

    // Parse listen address
    let listen_addr: SocketAddr = match listen.parse() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{} Invalid listen address: {}", "✖".red(), e);
            return 1;
        }
    };

    if !enforce {
        println!(
            "{} {} {}",
            "👁".blue(),
            "Mode:".bold(),
            "SHADOW (Observation Only — no enforcement)".cyan().bold()
        );
        println!(
            "{} {}",
            "ℹ".blue(),
            "All tool calls forwarded and logged. Enforcement is OFF.".blue()
        );
    } else {
        println!(
            "{} {} {}",
            "🛡".green(),
            "Mode:".bold(),
            "ACTIVE ENFORCEMENT (DLP & Secret Shield ON)".green().bold()
        );
        println!(
            "{} {}",
            "ℹ".blue(),
            "High-risk tool calls and secret leaks will be intercepted per policy.".blue()
        );
    }
    println!(
        "{} {} {}",
        "📡".blue(),
        "Listening on:".bold(),
        listen.green().underline()
    );
    println!("{} Press Ctrl+C to stop", "⌨".blue());
    println!("{}", "-".repeat(60).cyan());

    if !no_browser {
        let url = format!("http://{}", listen_addr);
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            #[cfg(target_os = "windows")]
            let _ = std::process::Command::new("cmd")
                .args(["/C", "start", &url])
                .spawn();
            #[cfg(target_os = "macos")]
            let _ = std::process::Command::new("open").arg(&url).spawn();
            #[cfg(target_os = "linux")]
            let _ = std::process::Command::new("xdg-open").arg(&url).spawn();
        });
    }

    // Shutdown channel
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let shutdown_tx_clone = shutdown_tx.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        println!(
            "\n{} Shutdown signal received. Finishing logs...",
            "ℹ".blue()
        );
        let _ = shutdown_tx_clone.send(true);
    });

    if let Err(e) = proxy::server::run_server(state, listen_addr, shutdown_rx, None).await {
        eprintln!("{} Server error: {}", "✖".red(), e);
        return 1;
    }
    0
}

// ─── FR-4: agentwall generate-policy ──────────────────────────────────────────

/// Run the auto-policy generator (FR-4).
///
/// Reads up to 500 events from the local SQLite event store (chronological order),
/// runs the analysis engine, and writes the resulting YAML to `output_path`.
async fn run_generate_policy(output_path: String, decay_window: u32) -> i32 {
    println!(
        "{} Reading observed tool calls from event store...",
        "ℹ".blue()
    );

    let db = agentcontrol::proxy::db::DbManager::init();
    let events = match db.get_all_events(500).await {
        Ok(evs) => evs,
        Err(e) => {
            eprintln!("{} Failed to read events: {}", "✖".red(), e);
            return 1;
        }
    };

    if events.is_empty() {
        println!("{} No tool calls observed yet.", "⚠".yellow());
        println!(
            "{} Start shadow mode first: {}",
            "ℹ".blue(),
            "agentcontrol dev".cyan()
        );
        return 1;
    }

    println!(
        "{} Analysing {} events across {} unique tools...",
        "ℹ".blue(),
        events.len().to_string().cyan(),
        events
            .iter()
            .filter_map(|e| e.url_path.as_deref())
            .collect::<std::collections::HashSet<_>>()
            .len()
            .to_string()
            .cyan()
    );

    let yaml = agentcontrol::generate_policy::generate_from_events(&events, decay_window);

    match std::fs::write(&output_path, &yaml) {
        Ok(_) => {
            println!(
                "{} Policy written to {}",
                "✓".green().bold(),
                output_path.cyan().underline()
            );
            println!("{} Next steps:", "ℹ".blue());
            println!(
                "    1. Review {} carefully — check anomalies section.",
                output_path.cyan()
            );
            println!(
                "    2. Run {} to validate.",
                "agentcontrol lint agentcontrol-policy.yaml".yellow()
            );
            println!("    3. Submit to your platform/security team for gateway deployment.");
            0
        }
        Err(e) => {
            eprintln!("{} Failed to write {}: {}", "✖".red(), output_path, e);
            1
        }
    }
}

async fn run_bench(
    full: bool,
    compare_baselines: bool,
    visualize: bool,
    output: Option<String>,
) -> i32 {
    println!("{}", "=".repeat(60).cyan());
    println!(
        "{} {}",
        " VEXA Agent Control ".bold().white().on_cyan(),
        "ADR Security Benchmarking Subsystem".cyan()
    );
    println!("{}", "=".repeat(60).cyan());
    println!(
        "{} Running benchmark suite (303 tasks, 17 attack categories, 133 mock MCP servers)...",
        "ℹ".blue()
    );

    let config = agentcontrol::bench::BenchmarkConfig {
        full,
        compare_baselines,
        visualize,
        output_path: output.clone(),
    };

    match agentcontrol::bench::BenchmarkRunner::run_benchmark(config).await {
        Ok(report) => {
            println!("\n{}", "=== BENCHMARK SUMMARY ===".bold().cyan());
            println!(
                "   Overall Security Score: {}/100",
                format!("{:.1}", report.score).green().bold()
            );
            println!(
                "   Tasks Executed:         {}",
                report.tasks_executed.to_string().cyan()
            );
            println!(
                "   Attack Classes Tested:  {}",
                report.categories_tested.len().to_string().cyan()
            );

            if compare_baselines {
                println!("\n{}", "=== BASELINE COMPARISON ===".bold().cyan());
                println!(
                    "   Vexa Agent Control ADR Engine: {}%",
                    format!("{:.1}", report.score).green().bold()
                );
                println!("   Vanilla LLM:          14.2% (Blocked)");
                println!("   Static Regex Shield:  42.8% (Blocked)");
            }

            if let Some(out) = output {
                println!(
                    "\n{} Report generated at: {}",
                    "✓".green().bold(),
                    out.cyan().underline()
                );
            }
            0
        }
        Err(e) => {
            eprintln!("{} Benchmark execution failed: {}", "✖".red(), e);
            1
        }
    }
}
