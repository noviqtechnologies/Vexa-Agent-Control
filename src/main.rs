//! Vexa Agent Control — main entry point
#![allow(deprecated)]
#![allow(
    clippy::too_many_arguments,
    clippy::type_complexity,
    clippy::upper_case_acronyms,
    clippy::large_enum_variant,
    clippy::single_match,
    clippy::collapsible_match,
    clippy::collapsible_if,
    clippy::needless_borrows_for_generic_args,
    clippy::derivable_impls,
    clippy::unnecessary_unwrap,
    clippy::manual_strip,
    clippy::lines_filter_map_ok,
    clippy::redundant_pattern_matching,
    clippy::let_unit_value,
    clippy::needless_return,
    clippy::new_without_default,
    clippy::never_loop,
    clippy::manual_range_contains,
    clippy::manual_unwrap_or,
    clippy::manual_ok_err
)]

use agentcontrol::audit;
use agentcontrol::check;
use agentcontrol::cli;
use agentcontrol::identity; // FR-22
use agentcontrol::kill;
use agentcontrol::policy;
use agentcontrol::proxy;
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
    // ── Panic Hook with Secret Scrubbing (Task 3.6 / PRD §FR-9) ───────────────
    std::panic::set_hook(Box::new(|info| {
        let msg = match info.payload().downcast_ref::<&'static str>() {
            Some(s) => *s,
            None => match info.payload().downcast_ref::<String>() {
                Some(s) => &s[..],
                None => "Box<dyn Any>",
            },
        };
        let location = info
            .location()
            .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
            .unwrap_or_else(|| "unknown".to_string());
        let (scrubbed, _) = agentcontrol::mcp::policy::scan_and_redact_text(msg);
        eprintln!(
            "thread '{}' panicked at {}: {}",
            std::thread::current().name().unwrap_or("<unnamed>"),
            location,
            scrubbed
        );
    }));

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

    let exit_code = runtime.block_on(async { tokio::spawn(async_main()).await.unwrap_or(1) });
    std::process::exit(exit_code);
}

async fn async_main() -> i32 {
    let cli = Cli::parse();
    dispatch_command(cli.command).await
}

async fn dispatch_command(command: Box<Commands>) -> i32 {
    match *command {
        Commands::Login {
            hub_url,
            no_browser,
        } => agentcontrol::identity::oauth::run_login(&hub_url, no_browser).await,
        Commands::Connect {
            target,
            mode,
            key,
            force,
        } => agentcontrol::wrap::run_connect(target, mode, key, force).await,
        Commands::Disconnect { target } => agentcontrol::wrap::run_disconnect(target),
        Commands::Doctor { json } => agentcontrol::doctor::run_doctor(json).await,
        Commands::SupportBundle { output_dir, yes } => {
            agentcontrol::support::run_support_bundle(output_dir, yes).await
        }
        Commands::Repair => agentcontrol::support::run_repair().await,
        Commands::Logout => agentcontrol::support::run_logout(),
        Commands::Backup { output_dir } => agentcontrol::audit::maintenance::run_backup(output_dir),
        Commands::VerifyDb {
            audit_path,
            db_path,
        } => agentcontrol::audit::maintenance::run_verify_db(audit_path, db_path),
        Commands::ResetLocalState { force } => agentcontrol::support::run_reset_local_state(force),
        Commands::RotateLocalToken => agentcontrol::support::run_rotate_local_token().await,
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
            // Guide users to the primary onboarding path. The PKI OTET enroll command
            // is reserved for headless/CI/MDM provisioning where the Control Hub admin
            // has issued a one-time enrollment token. For interactive developer setup,
            // 'agentcontrol login' is the zero-touch path (PKCE + enroll + service install).
            if token.is_empty() {
                eprintln!(
                    "{} For standard workstation setup, use:",
                    "⚠".yellow().bold()
                );
                eprintln!(
                    "    {}",
                    "agentcontrol login --hub <control-hub-url>".cyan()
                );
                eprintln!("  This opens browser PKCE authentication and automatically registers");
                eprintln!("  the device and background service in one step.");
                eprintln!();
                eprintln!(
                    "  'agentcontrol enroll --token' requires an admin-issued one-time token"
                );
                eprintln!("  and is reserved for headless / MDM / CI provisioning workflows.");
                return 1;
            }
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
                    enterprise,
                    config,
                    force,
                } => agentcontrol::service::ServiceAction::Install {
                    hub_url,
                    gateway_secret,
                    policy_read_secret,
                    agent_id,
                    enterprise,
                    config,
                    force,
                },
                agentcontrol::cli::ServiceCliAction::Uninstall => {
                    agentcontrol::service::ServiceAction::Uninstall
                }
                agentcontrol::cli::ServiceCliAction::Status => {
                    agentcontrol::service::ServiceAction::Status
                }
            };
            // called_from_login: false — this is an explicit CLI invocation, not
            // the internal post-login auto-install. The enrollment pre-check applies.
            // quiet: false — show full verbose output for explicit 'service install' command.
            agentcontrol::service::run_service(act, false, false).await
        }
        Commands::Start(args) => {
            if args.record_payloads {
                std::env::set_var("AGENTCONTROL_RECORD_PAYLOADS", "true");
            }
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
        Commands::Spend { command } => match command {
            cli::SpendCommands::Status { agent_id } => {
                let ledger = agentcontrol::spend::ledger::SpendLedger::init(None);
                let target_agent = agent_id.unwrap_or_else(|| "default".to_string());
                if let Some(spend) = ledger.get_spend(target_agent.clone()).await {
                    println!("Agent ID: {}", spend.agent_id);
                    println!("Period Start: {}", spend.period_start);
                    println!(
                        "Spent: {} cents (${:.2})",
                        spend.spent_cents,
                        spend.spent_cents as f64 / 100.0
                    );
                    if let Some(cap) = spend.cap_cents {
                        println!("Budget Cap: {} cents (${:.2})", cap, cap as f64 / 100.0);
                    } else {
                        println!("Budget Cap: Unlimited");
                    }
                } else {
                    println!("No spend recorded yet for agent: {}", target_agent);
                }
                0
            }
            cli::SpendCommands::Export {
                format,
                client,
                project,
                output,
            } => {
                let ledger = agentcontrol::spend::ledger::SpendLedger::init(None);
                let filter = agentcontrol::spend::types::SpendExportFilter {
                    client_id: client,
                    project_id: project,
                    start_timestamp: None,
                    end_timestamp: None,
                };
                let records = ledger.export_usage(filter).await;
                let content = if format.to_lowercase() == "json" {
                    serde_json::to_string_pretty(&records).unwrap_or_else(|_| "[]".to_string())
                } else {
                    let mut csv = String::from("timestamp,request_id,client_id,project_id,cost_center,agent_id,provider,model,input_tokens,output_tokens,total_tokens,cost_cents,cost_usd,is_estimated\n");
                    for r in records {
                        csv.push_str(&format!(
                            "{},{},{},{},{},{},{},{},{},{},{},{},{:.4},{}\n",
                            r.timestamp,
                            r.request_id,
                            r.client_id,
                            r.project_id,
                            r.cost_center,
                            r.agent_id,
                            r.provider,
                            r.model,
                            r.input_tokens,
                            r.output_tokens,
                            r.total_tokens,
                            r.cost_cents,
                            r.cost_usd,
                            r.is_estimated
                        ));
                    }
                    csv
                };
                if let Some(out_path) = output {
                    if let Err(e) = std::fs::write(&out_path, &content) {
                        eprintln!("Failed to write export to {}: {}", out_path, e);
                        1
                    } else {
                        println!("✓ Exported spend usage records to {}", out_path);
                        0
                    }
                } else {
                    print!("{}", content);
                    0
                }
            }
            cli::SpendCommands::SetCap {
                agent_id,
                cap_cents,
                period,
            } => {
                let ledger = agentcontrol::spend::ledger::SpendLedger::init(None);
                let p = match period.to_lowercase().as_str() {
                    "weekly" => agentcontrol::spend::model::BudgetPeriod::Weekly,
                    "monthly" => agentcontrol::spend::model::BudgetPeriod::Monthly,
                    _ => agentcontrol::spend::model::BudgetPeriod::Daily,
                };
                match ledger
                    .set_budget(
                        agentcontrol::spend::model::BudgetScope::User(agent_id.clone()),
                        cap_cents,
                        p,
                    )
                    .await
                {
                    Ok(()) => {
                        println!(
                            "✓ Successfully set budget cap of {} cents (${:.2}) ({:?}) for agent {}",
                            cap_cents,
                            cap_cents as f64 / 100.0,
                            p,
                            agent_id
                        );
                        0
                    }
                    Err(e) => {
                        eprintln!("✖ Failed to set budget cap: {}", e);
                        1
                    }
                }
            }
        },
        Commands::Unwrap { target } => agentcontrol::wrap::run_unwrap_target(&target),
        Commands::Protect {
            dry_run,
            no_browser,
            listen,
            mcp_url,
            enforce,
            shadow,
            spend_only,
            min_tokens,
            record_payloads,
            policy,
        } => {
            if spend_only {
                agentcontrol::logging::set_spend_only(true);
            }
            if record_payloads {
                std::env::set_var("AGENTCONTROL_RECORD_PAYLOADS", "true");
            }
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
                spend_only,
                min_tokens,
            )
            .await
        }
        Commands::Unprotect { dry_run, force } => {
            agentcontrol::wrap::run_unprotect_all(dry_run, force)
        }
        Commands::Verify {
            gateway,
            json,
            hub,
            user_id,
            assignment_id,
            token,
        } => {
            agentcontrol::verify::run_verification_probe(
                &gateway,
                json,
                hub.as_deref(),
                user_id.as_deref(),
                assignment_id.as_deref(),
                token.as_deref(),
            )
            .await
        }
        Commands::Cache { command } => match command {
            cli::CacheCommands::Status { gateway, json } => {
                let url = format!("{}/api/v1/cache/stats", gateway.trim_end_matches('/'));
                let client = reqwest::Client::new();
                match client.get(&url).send().await {
                    Ok(resp) => {
                        if resp.status().is_success() {
                            let stats: serde_json::Value = resp.json().await.unwrap_or_default();
                            if json {
                                println!(
                                    "{}",
                                    serde_json::to_string_pretty(&stats).unwrap_or_default()
                                );
                            } else {
                                let gw = stats.get("gateway_cache");
                                let prov = stats.get("provider_cache");
                                let comp = stats.get("comparative_summary");

                                println!(
                                    "\n{}",
                                    "=== Vexa Gateway Semantic Cache Observatory ==="
                                        .bright_green()
                                        .bold()
                                );
                                println!(
                                    "  Exact Hits:          {}",
                                    gw.and_then(|g| g.get("exact_hits"))
                                        .unwrap_or(&serde_json::json!(0))
                                );
                                println!(
                                    "  Semantic Vector Hits:{}",
                                    gw.and_then(|g| g.get("semantic_hits"))
                                        .unwrap_or(&serde_json::json!(0))
                                );
                                println!(
                                    "  Cache Misses:        {}",
                                    gw.and_then(|g| g.get("misses"))
                                        .unwrap_or(&serde_json::json!(0))
                                );
                                println!(
                                    "  Hit Ratio:           {}%",
                                    gw.and_then(|g| g.get("hit_ratio_pct"))
                                        .unwrap_or(&serde_json::json!(0.0))
                                );
                                println!(
                                    "  Tokens 100% Avoided: {}",
                                    gw.and_then(|g| g.get("tokens_saved"))
                                        .and_then(|t| t.get("total"))
                                        .unwrap_or(&serde_json::json!(0))
                                );
                                println!(
                                    "  Vexa Cost Saved:     ${}",
                                    gw.and_then(|g| g.get("cost_saved_usd"))
                                        .unwrap_or(&serde_json::json!(0.0))
                                );
                                println!(
                                    "  Avg Serving Latency: {} ms (vs ~1180ms upstream)",
                                    gw.and_then(|g| g.get("avg_serving_latency_ms"))
                                        .unwrap_or(&serde_json::json!(2.4))
                                );

                                println!(
                                    "\n{}",
                                    "--- Upstream Provider Prompt Cache ---".cyan().bold()
                                );
                                println!(
                                    "  Prefix Cache Hits:   {}",
                                    prov.and_then(|p| p.get("prefix_cache_hits"))
                                        .unwrap_or(&serde_json::json!(0))
                                );
                                println!(
                                    "  Cached Tokens:       {}",
                                    prov.and_then(|p| p.get("cached_tokens"))
                                        .unwrap_or(&serde_json::json!(0))
                                );
                                println!(
                                    "  Provider Discount:   ${}",
                                    prov.and_then(|p| p.get("discount_usd"))
                                        .unwrap_or(&serde_json::json!(0.0))
                                );

                                println!(
                                    "\n{}",
                                    "--- Enterprise ROI & Attribution ---".purple().bold()
                                );
                                println!(
                                    "  Total Cost Avoided:  ${}",
                                    comp.and_then(|c| c.get("total_savings_usd"))
                                        .unwrap_or(&serde_json::json!(0.0))
                                );
                                println!(
                                    "  Vexa Contribution:   {}%",
                                    comp.and_then(|c| c.get("vexa_contribution_pct"))
                                        .unwrap_or(&serde_json::json!(0.0))
                                );
                                println!(
                                    "  Vexa ROI Multiplier: {}x over provider cache\n",
                                    comp.and_then(|c| c.get("roi_multiplier"))
                                        .unwrap_or(&serde_json::json!(1.0))
                                );
                            }
                            0
                        } else {
                            eprintln!(
                                "{} Failed to fetch cache stats: HTTP {}",
                                "✖".red(),
                                resp.status()
                            );
                            1
                        }
                    }
                    Err(e) => {
                        eprintln!(
                            "{} Failed to connect to gateway at {}: {}",
                            "✖".red(),
                            gateway,
                            e
                        );
                        1
                    }
                }
            }
            cli::CacheCommands::Clear { gateway } => {
                let url = format!("{}/api/v1/cache/clear", gateway.trim_end_matches('/'));
                let client = reqwest::Client::new();
                match client.post(&url).send().await {
                    Ok(resp) => {
                        if resp.status().is_success() {
                            println!("{} Semantic vector cache and exact hash cache cleared successfully.", "✔".green());
                            0
                        } else {
                            eprintln!(
                                "{} Failed to clear cache: HTTP {}",
                                "✖".red(),
                                resp.status()
                            );
                            1
                        }
                    }
                    Err(e) => {
                        eprintln!(
                            "{} Failed to connect to gateway at {}: {}",
                            "✖".red(),
                            gateway,
                            e
                        );
                        1
                    }
                }
            }
        },
        Commands::Status { json } => agentcontrol::wrap::run_status(json),
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
            spend_only,
            min_tokens,
            record_payloads,
            local_llm_url,
            args,
        } => {
            if spend_only {
                agentcontrol::logging::set_spend_only(true);
            }
            if record_payloads {
                std::env::set_var("AGENTCONTROL_RECORD_PAYLOADS", "true");
            }
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
                spend_only,
                min_tokens,
            )
            .await
        }
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

fn print_gateway_startup_banner(
    listen: &str,
    mcp_url: &str,
    profile: &cli::DeploymentProfile,
    shadow_mode: bool,
    is_enrolled: bool,
) {
    use std::io::IsTerminal;
    if !std::io::stdout().is_terminal() {
        return;
    }

    let version = env!("CARGO_PKG_VERSION");
    let mode_str = if shadow_mode {
        "SHADOW (Observation Only; Non-Enforcing)".yellow().bold()
    } else {
        match profile {
            cli::DeploymentProfile::LocalShadow => {
                "SHADOW (Observation Only; Non-Enforcing)".yellow().bold()
            }
            cli::DeploymentProfile::LocalGateway => {
                "LOCAL GATEWAY (Developer LLM Proxy Active)".green().bold()
            }
            cli::DeploymentProfile::LocalFirewall => {
                "LOCAL FIREWALL (Air-Gapped Local-Only Enforcement)"
                    .cyan()
                    .bold()
            }
            cli::DeploymentProfile::TeamGateway => {
                "TEAM GATEWAY (Fleet Governed + Control Hub)".green().bold()
            }
            cli::DeploymentProfile::ContainerSidecar => {
                "CONTAINER SIDECAR (Hardened Sidecar Enforcement)"
                    .blue()
                    .bold()
            }
        }
    };

    let storage_desc = if cfg!(windows) {
        "OS_KEYRING (Windows Credential Manager)"
    } else if cfg!(target_os = "macos") {
        "OS_KEYRING (macOS Keychain)"
    } else if std::env::var("DISPLAY").is_ok() || std::env::var("WAYLAND_DISPLAY").is_ok() {
        "OS_KEYRING (FreeDesktop Secret Service)"
    } else {
        "STRICT_PERM_FILE (Headless Linux 0600 Mode)"
    };

    let enroll_status = if is_enrolled && matches!(profile, cli::DeploymentProfile::TeamGateway) {
        "Enrolled (Control Hub)".green()
    } else if is_enrolled {
        "Local Standalone (Hub enrollment dormant)".dimmed()
    } else {
        "Local Standalone".dimmed()
    };

    println!();
    println!(
        "{}",
        "┌─────────────────────────────────────────────────────────────────────────────┐".cyan()
    );
    println!(
        "│  {} {:<21} │",
        "VEXA AGENT CONTROL — MCP Security Gateway & Proxy"
            .bold()
            .white(),
        format!("(v{})", version).cyan()
    );
    println!(
        "{}",
        "├─────────────────────────────────────────────────────────────────────────────┤".cyan()
    );
    println!(
        "│  Proxy Listener:    {:<55} │",
        format!("http://{}", listen).green().bold()
    );
    println!("│  Upstream MCP:      {:<55} │", mcp_url.yellow());
    println!("│  Governance Mode:   {:<55} │", mode_str);
    println!("│  Device Identity:   {:<55} │", enroll_status);
    println!("│  Credential Vault:  {:<55} │", storage_desc.dimmed());
    println!(
        "{}",
        "├─────────────────────────────────────────────────────────────────────────────┤".cyan()
    );
    println!(
        "│  {} Native shell commands (bash/git) run out-of-band & bypass proxy! │",
        "⚠  Notice:".yellow().bold()
    );
    println!(
        "{}",
        "└─────────────────────────────────────────────────────────────────────────────┘".cyan()
    );
    println!();
}

fn resolve_audit_log_path() -> std::path::PathBuf {
    if let Ok(env_path) =
        std::env::var("AGENTCONTROL_LOG_PATH").or_else(|_| std::env::var("AGENTWALL_LOG_PATH"))
    {
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
    spend_only: bool,
    min_tokens: u64,
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
        if let Some(k) = agentcontrol::proxy::llm_proxy::get_env_or_dotenv("OPENAI_API_KEY") {
            map.insert("openai".to_string(), k);
        }
        if let Some(k) = agentcontrol::proxy::llm_proxy::get_env_or_dotenv("ANTHROPIC_API_KEY") {
            map.insert("anthropic".to_string(), k);
        }
        if let Some(k) = agentcontrol::proxy::llm_proxy::get_env_or_dotenv("GEMINI_API_KEY")
            .or_else(|| agentcontrol::proxy::llm_proxy::get_env_or_dotenv("GOOGLE_API_KEY"))
        {
            map.insert("google".to_string(), k.clone());
            map.insert("gemini".to_string(), k);
        }
        if let Some(k) = agentcontrol::proxy::llm_proxy::get_env_or_dotenv("DEEPSEEK_API_KEY") {
            map.insert("deepseek".to_string(), k);
        }
        if let Some(k) = agentcontrol::proxy::llm_proxy::get_env_or_dotenv("GROQ_API_KEY") {
            map.insert("groq".to_string(), k);
        }
        map
    };

    let (
        initial_cursor_mode,
        initial_allowed_models,
        initial_default_model,
        initial_model_enforcement,
    ) = {
        let llm = compiled_policy.as_ref().and_then(|p| p.llm.as_ref());
        let mode = llm
            .and_then(|l| l.cursor_mode.clone())
            .or_else(|| std::env::var("AGENTCONTROL_CURSOR_MODE").ok())
            .unwrap_or_else(|| "passthrough".to_string());
        let allowed = llm.and_then(|l| l.allowed_models.clone());
        let default_m = llm.and_then(|l| l.default_model.clone());
        let enf = llm
            .and_then(|l| l.model_enforcement.clone())
            .unwrap_or_else(|| "restrict".to_string());
        (mode, allowed, default_m, enf)
    };

    let semantic_cache = {
        let sc_opt = compiled_policy
            .as_ref()
            .and_then(|p| p.llm.as_ref())
            .and_then(|l| l.semantic_cache.as_ref());
        if let Some(sc) = sc_opt {
            let threshold = sc.similarity_threshold.unwrap_or(0.88);
            let max_entries = sc.max_entries.unwrap_or(10_000);
            let ttl = std::time::Duration::from_secs(sc.ttl_seconds.unwrap_or(86400));
            let embedder_engine = match sc.resolved_embedding_provider().as_deref() {
                Some("openai") => {
                    agentcontrol::proxy::semantic_cache::embedder::EmbedderEngine::OpenAi {
                        api_key: sc
                            .resolved_embedding_api_key()
                            .unwrap_or_else(|| std::env::var("OPENAI_API_KEY").unwrap_or_default()),
                        endpoint: sc.resolved_embedding_endpoint().unwrap_or_default(),
                        model: sc
                            .resolved_embedding_model()
                            .unwrap_or_else(|| "text-embedding-3-small".to_string()),
                    }
                }
                Some("ollama") => {
                    agentcontrol::proxy::semantic_cache::embedder::EmbedderEngine::Ollama {
                        endpoint: sc
                            .resolved_embedding_endpoint()
                            .unwrap_or_else(|| "http://localhost:11434".to_string()),
                        model: sc
                            .resolved_embedding_model()
                            .unwrap_or_else(|| "nomic-embed-text".to_string()),
                    }
                }
                _ => agentcontrol::proxy::semantic_cache::embedder::EmbedderEngine::Local,
            };

            if sc.backend.as_deref() == Some("qdrant") {
                let url = sc
                    .resolved_qdrant_url()
                    .unwrap_or_else(|| "http://localhost:6333".to_string());
                Arc::new(
                    agentcontrol::proxy::semantic_cache::SemanticCache::new_qdrant(
                        sc.enabled,
                        threshold,
                        max_entries,
                        ttl,
                        url,
                        sc.resolved_qdrant_api_key(),
                        sc.resolved_qdrant_collection(),
                        embedder_engine,
                    ),
                )
            } else {
                Arc::new(
                    agentcontrol::proxy::semantic_cache::SemanticCache::new_in_memory(
                        sc.enabled,
                        threshold,
                        max_entries,
                        ttl,
                        embedder_engine,
                    ),
                )
            }
        } else {
            Arc::new(agentcontrol::proxy::semantic_cache::SemanticCache::default())
        }
    };

    let dlp_scanner_arc = std::sync::Arc::new(
        agentcontrol::policy::dlp::DlpScanner::new(None).expect("Failed to compile DLP regexes"),
    );
    let hook_registry = Arc::new(
        agentcontrol::proxy::hooks::HookRegistry::with_default_scanners(dlp_scanner_arc.clone()),
    );

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
        dlp_scanner: dlp_scanner_arc,
        semantic_scanner: std::sync::Arc::new(
            agentcontrol::policy::semantic::SemanticScanner::new(
                agentcontrol::policy::semantic::SemanticConfig::default(),
            ),
        ),
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
        ca_manager: agentcontrol::ca::CaManager::init_or_load(None)
            .ok()
            .map(Arc::new),
        cursor_mode: std::sync::RwLock::new(initial_cursor_mode),
        allowed_models: std::sync::RwLock::new(initial_allowed_models),
        default_model: std::sync::RwLock::new(initial_default_model),
        model_enforcement: std::sync::RwLock::new(initial_model_enforcement),
        min_tokens,
        spend_only,
        prompt_cache: Arc::new(agentcontrol::proxy::prompt_cache::PromptCache::default()),
        semantic_cache,
        local_key_cache: Arc::new(agentcontrol::proxy::local_key_cache::LocalKeyCache::default()),
        request_coalescer: Arc::new(
            agentcontrol::proxy::request_coalescer::RequestCoalescer::default(),
        ),
        adaptive_timeout: Arc::new(
            agentcontrol::proxy::adaptive_timeout::AdaptiveTimeoutManager::default(),
        ),
        embedding_batcher: Arc::new(
            agentcontrol::proxy::embedding_batcher::EmbeddingBatcher::default(),
        ),
        provider_router: Arc::new(agentcontrol::proxy::provider_router::ProviderRouter::default()),
        hook_registry,
        hitl_manager: Arc::new(agentcontrol::policy::hitl::HitlManager::new(hex::encode(
            resolve_hmac_key(),
        ))),
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

    // Automatically discover and resolve active GitOps policy (.agentcontrol.yaml)
    let (compiled_policy, policy_path_buf) =
        agentcontrol::policy::loader::resolve_active_policy(None, None);
    let policy_path_str = policy_path_buf.map(|p| p.to_string_lossy().to_string());
    let policy_loaded = compiled_policy.is_some();

    let spend_ledger = Some(Arc::new(agentcontrol::spend::ledger::SpendLedger::init(
        None,
    )));

    let state = build_proxy_state(
        compiled_policy,
        audit_logger,
        session_id,
        KillMode::Connection,
        None,
        "".to_string(),
        false,
        false,
        policy_loaded,
        0,
        safe_mode_scanner,
        response_scanner,
        response_scan_config,
        Arc::new(policy::credential_scope::CredentialScopeValidator::new(
            false,
        )),
        policy_path_str,
        spend_ledger,
        agentcontrol::control_plane_client::client::DashboardClient::from_env().map(Arc::new),
        true,
        false,
        if policy_loaded {
            "local-enforce".to_string()
        } else {
            "local-shadow".to_string()
        },
        1024,
        30,
        16777216,
        None,
        false,
        0,
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

    // Load self-contained daemon.json if present (user or enterprise scope)
    let daemon_cfg = agentcontrol::service::load_daemon_config(args.config.as_deref(), false)
        .ok()
        .flatten()
        .or_else(|| {
            agentcontrol::service::load_daemon_config(None, true)
                .ok()
                .flatten()
        });

    if let Some(ref cfg) = daemon_cfg {
        if !cfg.hub_url.is_empty() {
            let _ = agentcontrol::identity::device::save_hub_url(&cfg.hub_url);
        }
        if let Some(ref s) = cfg.gateway_secret {
            std::env::set_var("GATEWAY_SECRET", s);
        }
        if let Some(ref s) = cfg.policy_read_secret {
            std::env::set_var("POLICY_READ_SECRET", s);
        }
        if let Some(ref s) = cfg.agent_id {
            std::env::set_var("AGENT_ID", s);
        }
    }

    let is_enrolled = agentcontrol::identity::device::is_device_enrolled();

    let profile = if let Some(p_str) = args.profile.as_deref() {
        match cli::DeploymentProfile::try_parse(p_str) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("{} {}", "✖".red(), e);
                return 1;
            }
        }
    } else if args.shadow_mode {
        cli::DeploymentProfile::LocalShadow
    } else if let Some(persisted) = cli::PersistedProfileRecord::load() {
        persisted
    } else if args.centralized || is_enrolled {
        cli::DeploymentProfile::TeamGateway
    } else {
        cli::DeploymentProfile::LocalGateway
    };

    let _ = cli::PersistedProfileRecord::save(profile);

    let scan_responses = args.scan_responses || profile.default_scan_responses();
    let block_on_secrets = args.block_on_secrets || profile.default_fail_closed();
    let shadow_mode = args.shadow_mode || matches!(profile, cli::DeploymentProfile::LocalShadow);
    let dry_run = args.dry_run;
    let effective_profile_name = profile.name().to_string();

    let policy_path = args.policy;
    let listen = if args.listen != "127.0.0.1:18080" {
        args.listen
    } else if let Some(ref cfg) = daemon_cfg {
        cfg.listen.clone()
    } else {
        args.listen
    };
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

    // Check and recover from any stale or interrupted protect transaction
    let _ = agentcontrol::wrap::journal::ProtectJournal::recover_if_stale();

    print_gateway_startup_banner(&listen, &mcp_url, &profile, shadow_mode, is_enrolled);

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
    //    a) If profile is TeamGateway and load_hub_url() is set → fetch active policy from PostgreSQL via dashboard API
    //    b) --policy <file> is set    → load from local YAML file (fallback / dev override)
    //    c) neither                   → Safe Mode (no policy enforcement, audit only)
    let dashboard_api_url = if matches!(profile, cli::DeploymentProfile::TeamGateway) {
        agentcontrol::identity::device::load_hub_url()
    } else {
        None
    };
    let policy_read_secret_env = std::env::var("POLICY_READ_SECRET")
        .ok()
        .filter(|s| !s.is_empty());

    if is_enrolled && matches!(profile, cli::DeploymentProfile::TeamGateway) {
        if let Some(ref hub) = dashboard_api_url {
            println!(
                "{} Device enrolled — active enterprise governance via {} (central-enforce)",
                "●".green().bold(),
                hub.cyan()
            );
        }
    }

    let break_glass = std::env::var("AGENTCONTROL_BREAK_GLASS")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    let (compiled_policy, _policy_hash, _warnings, policy_loaded) =
        if matches!(profile, cli::DeploymentProfile::TeamGateway)
            && is_enrolled
            && dashboard_api_url.is_some()
            && !break_glass
        {
            // (a) Team mode + enrolled -> Central Hub policy ALWAYS takes precedence!
            let api_url = dashboard_api_url.as_ref().unwrap();
            print!(
                "{} Fetching central policy from dashboard API ({})... ",
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
        } else if let Some(ref path) = policy_path {
            // (b) Local YAML file — provided via --policy (local standalone or break-glass override)
            if matches!(profile, cli::DeploymentProfile::TeamGateway) && is_enrolled {
                println!(
                    "{} [BREAK-GLASS] Local policy override active for enrolled Team profile.",
                    "⚠".yellow().bold()
                );
            }
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
            // (c) Fetch from dashboard API fallback
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

    // Initialize dashboard client early for SpendLedger sync (active only in Team mode with enrollment)
    let dashboard_client = if profile.is_team() && is_enrolled {
        agentcontrol::control_plane_client::client::DashboardClient::from_env()
            .map(std::sync::Arc::new)
    } else {
        None
    };

    // --- FR-120: Spend Caps License Validation ---
    let spend_ledger = if let Some(ref policy) = compiled_policy {
        if let Some(ref caps) = policy.spend_caps {
            if caps.enabled {
                if let Some(license_key) = &caps.license_key {
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
                                    "{} License expires in {} days. Renew at https://vexasec.io.",
                                    "⚠".yellow(),
                                    days_until_expiry
                                );
                            }
                        }
                        Err(e) => {
                            match e {
                                agentcontrol::license::LicenseError::Expired { expired_at } => {
                                    eprintln!(
                                        "{} License expired at {}. Renew at https://vexasec.io.",
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
                } else {
                    println!(
                        "{} spend_caps running in Early Access Mode (unlicensed evaluation). For fleet SLA & production support, visit https://vexasec.io.",
                        "ℹ".cyan()
                    );
                    agentcontrol::logging::log_event(
                        agentcontrol::logging::Level::Info,
                        "license_early_access_evaluation",
                        serde_json::json!({
                            "mode": "early_access",
                            "feature": "spend_caps"
                        }),
                    );
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
        args.admin_token
            .clone()
            .or_else(|| std::env::var("AGENTCONTROL_ADMIN_TOKEN").ok()),
        false,
        0,
    );

    if state.dashboard_client.is_some() {
        let msg = if agentcontrol::identity::device::load_hub_url().is_some() {
            "Connected (Hub URL resolved)".green()
        } else {
            "Connected (Local Dev Fallback: http://localhost:8400)".yellow()
        };
        println!("{} {} {}", "📊".green(), "FR-23 Dashboard:".bold(), msg);
    }

    // Background policy push subscriber — active when in Team mode and enrolled.
    // In local-gateway and local-firewall modes, this is completely dormant (ADR 0.3).
    if profile.is_team() && is_enrolled {
        let sse_api_url = agentcontrol::identity::device::load_hub_url();
        if let Some(api_url) = sse_api_url {
            let sub_state = state.clone();
            let sub_secret = std::env::var("POLICY_READ_SECRET").unwrap_or_default();
            let sub_secret_clone = sub_secret.clone();
            let sub_state_clone = state.clone();
            let api_url_clone = api_url.clone();
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

            // Periodic pull reconciliation loop (60s) to guarantee convergence if SSE disconnects
            tokio::spawn(async move {
                agentcontrol::policy::remote::start_policy_poll(
                    sub_state_clone,
                    api_url_clone,
                    if sub_secret_clone.is_empty() {
                        None
                    } else {
                        Some(sub_secret_clone)
                    },
                    60,
                )
                .await;
            });
        }
    }

    // Background file-system watcher — active when --policy <file> is provided.
    // In Team mode, central remote policy strictly dominates and local file watching is suppressed
    // unless break-glass override is explicitly declared via AGENTCONTROL_BREAK_GLASS=true (Gate 5).
    if let Some(ref watch_path) = policy_path {
        let is_break_glass = std::env::var("AGENTCONTROL_BREAK_GLASS")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        if !profile.is_team() || is_break_glass {
            agentcontrol::policy::policy_file_watcher::start_policy_file_watcher(
                watch_path.clone(),
                state.clone(),
            );
        } else {
            agentcontrol::logging::log_event(
                agentcontrol::logging::Level::Warn,
                "local_policy_watcher_suppressed",
                serde_json::json!({
                    "reason": "Team mode enforces central remote policy governance; local file watching suppressed without AGENTCONTROL_BREAK_GLASS=true",
                    "path": watch_path,
                }),
            );
        }
    }

    // Background device heartbeat emitter — periodic health ping to Hub (Sprint 4)
    // Active strictly in team-gateway mode when enrolled; completely dormant in local modes (ADR 0.3).
    if profile.is_team() && is_enrolled {
        tokio::spawn(async move {
            agentcontrol::control_plane_client::heartbeat::start_heartbeat_loop(60).await;
        });
    }

    // Background provider keys and routing reconciler (REQ-DSM-004 / REQ-DSM-005)
    // 60-second pull convergence loop active strictly in team-gateway mode when enrolled.
    if profile.is_team() && is_enrolled {
        let poll_hub_url = agentcontrol::identity::device::load_hub_url();
        if let Some(hub_url) = poll_hub_url {
            let poll_state = state.clone();
            let (_wake_tx, wake_rx) = tokio::sync::mpsc::channel(16);
            tokio::spawn(async move {
                agentcontrol::policy::remote_keys::start_provider_keys_poll(
                    poll_state, hub_url, 60, wake_rx,
                )
                .await;
            });
        }
    }

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
    agentcontrol::wrap::connect::print_upstream_provider_status();
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
                if agentcontrol::service::windows::service_dispatcher_handler::is_shutdown_requested(
                ) {
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
        Arc::new(policy::credential_scope::CredentialScopeValidator::new(
            false,
        )),
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
        false,
        0,
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
    spend_only: bool,
    min_tokens: u64,
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
        println!(
            "{} {}",
            "⚠️ [EXPERIMENTAL PREVIEW]".yellow().bold(),
            "Opt-in Dual-Agent Threat Detector active (Advisory only — cannot override policy)"
                .dimmed()
        );
        let detector = agentcontrol::detector::LocalDualAgentDetector::new(
            agentcontrol::detector::DualAgentConfig {
                enabled: true,
                local_llm_url,
                poll_interval_secs: 5,
                max_trace_events: 20,
                max_payload_bytes: 16 * 1024,
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
                    PolicyLoadResult::Loaded { policy, .. } => {
                        (Some(policy), true, Some(path_str.to_string()))
                    }
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
                    PolicyLoadResult::Loaded { policy, .. } => (
                        Some(policy),
                        true,
                        Some("agentcontrol-policy.yaml".to_string()),
                    ),
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

    // Parse and validate listen address
    let listen_addr: SocketAddr = match listen.parse() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{} Invalid listen address: {}", "✖".red(), e);
            return 1;
        }
    };

    let is_bridge_mode = std::env::var("AGENTCONTROL_CONTAINER_BRIDGE_MODE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    if !listen_addr.ip().is_loopback() && !is_bridge_mode {
        eprintln!(
            "{} Security error: Non-loopback listener address ({}) is prohibited in standalone developer mode without container bridge mode (AGENTCONTROL_CONTAINER_BRIDGE_MODE=true) or enterprise authentication.",
            "✖".red().bold(),
            listen_addr
        );
        return 1;
    }

    // Absolute dormancy in standalone developer mode: zero Hub telemetry client
    let dashboard_client = None;

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
        Arc::new(policy::credential_scope::CredentialScopeValidator::new(
            false,
        )),
        policy_path_str,
        None,
        dashboard_client,
        listen_addr.ip().is_loopback(),
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
        spend_only,
        min_tokens,
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
    agentcontrol::wrap::connect::print_upstream_provider_status();
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
