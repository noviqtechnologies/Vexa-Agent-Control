//! Stdio bridge proxy for local MCP servers (FR-302, FR-303b)

use futures_util::{SinkExt, StreamExt};
use std::process::Stdio;
use std::sync::Arc;
use tokio::process::Command;
use tokio_util::codec::{FramedRead, FramedWrite};

use crate::kill::KillMode;
use crate::logging;
use crate::policy::response_scanner::ScanResult;
use crate::proxy::codec::JsonRpcCodec;
use crate::proxy::handler::{evaluate_jsonrpc, ProxyAction, ProxyState};

/// Expands leading `~` to $HOME if present.
pub fn expand_arg(arg: &str) -> String {
    if arg.starts_with("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return format!("{}{}", home, &arg[1..]);
        }
    }
    arg.to_string()
}

/// Resolves a command name to an absolute path, handling Windows extensions and cmd /C wrapping if necessary.
pub fn resolve_command(program: &str) -> (String, Vec<String>) {
    let program = &expand_arg(program);
    #[cfg(not(windows))]
    {
        use std::env;
        use std::path::Path;

        let path = Path::new(program);
        if path.is_absolute() && path.exists() {
            return (program.to_string(), vec![]);
        }

        if let Ok(path_var) = env::var("PATH") {
            for p in env::split_paths(&path_var) {
                let full_path = p.join(program);
                if full_path.is_file() {
                    return (full_path.to_string_lossy().to_string(), vec![]);
                }
            }
        }

        // Search common Node.js / nvm / Homebrew / macports binary locations if not found in PATH
        if program == "npx" || program == "node" || program == "npm" {
            let extra_paths = vec![
                "/usr/local/bin",
                "/opt/homebrew/bin",
                "/opt/homebrew/share/npm/bin",
                "~/.nvm/current/bin",
                "~/.fnm/current/bin",
                "~/.n/bin",
                "~/.volta/bin",
            ];

            if let Ok(home) = env::var("HOME") {
                if let Ok(entries) = std::fs::read_dir(format!("{}/.nvm/versions/node", home)) {
                    for entry in entries.flatten() {
                        let bin_dir = entry.path().join("bin");
                        if bin_dir.exists() {
                            let candidate = bin_dir.join(program);
                            if candidate.is_file() {
                                return (candidate.to_string_lossy().to_string(), vec![]);
                            }
                        }
                    }
                }
            }

            for extra in extra_paths {
                let expanded = expand_arg(extra);
                let candidate = Path::new(&expanded).join(program);
                if candidate.is_file() {
                    return (candidate.to_string_lossy().to_string(), vec![]);
                }
            }
        }

        (program.to_string(), vec![])
    }

    #[cfg(windows)]
    {
        use std::path::PathBuf;

        let mut final_program = program.to_string();
        let mut found = false;

        let path = PathBuf::from(program);
        if path.is_absolute() && path.exists() {
            final_program = program.to_string();
            found = true;
        } else {
            // Try with common extensions FIRST on Windows
            for ext in &["exe", "cmd", "bat", "ps1"] {
                let with_ext = if program.to_lowercase().ends_with(&format!(".{}", ext)) {
                    program.to_string()
                } else {
                    format!("{}.{}", program, ext)
                };

                if let Ok(p) = which_windows(&with_ext) {
                    final_program = p;
                    found = true;
                    break;
                }
            }

            // Fallback to as-is if no extension found
            if !found {
                if let Ok(p) = which_windows(program) {
                    final_program = p;
                    found = true;
                }
            }
        }

        if !found {
            return (program.to_string(), vec![]);
        }

        // If it's a script, we MUST use cmd /C on Windows
        let lower = final_program.to_lowercase();
        if lower.ends_with(".cmd") || lower.ends_with(".bat") || !lower.ends_with(".exe") {
            // On Windows, if it's not an .exe, it's likely a script that needs cmd /C or is a shell script
            return ("cmd".to_string(), vec!["/C".to_string(), final_program]);
        }

        if lower.ends_with(".ps1") {
            return (
                "powershell".to_string(),
                vec![
                    "-ExecutionPolicy".to_string(),
                    "Bypass".to_string(),
                    "-File".to_string(),
                    final_program,
                ],
            );
        }

        (final_program, vec![])
    }
}

#[cfg(windows)]
fn which_windows(program: &str) -> Result<String, ()> {
    use std::env;
    use std::path::Path;

    // Check current directory first
    if Path::new(program).exists() {
        return Ok(program.to_string());
    }

    // Check PATH
    if let Ok(path_var) = env::var("PATH") {
        for p in env::split_paths(&path_var) {
            let full_path = p.join(program);
            if full_path.exists() {
                return Ok(full_path.to_string_lossy().to_string());
            }
        }
    }
    Err(())
}

/// Extracts canonical decision evidence from a JSON-RPC error response,
/// preserving DLP and injection classifications, exact rule IDs, and findings.
fn extract_decision_evidence(
    resp: &serde_json::Value,
) -> (
    Option<i64>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    String,
) {
    let err = resp.get("error");
    let verdict_detail = err
        .and_then(|e| e.get("message"))
        .and_then(|m| m.as_str())
        .unwrap_or("policy_violation")
        .to_string();

    let rule_from_data = err
        .and_then(|e| e.get("data"))
        .and_then(|d| d.get("rule"))
        .and_then(|r| r.as_str())
        .map(|s| s.to_string());

    let detail_lower = verdict_detail.to_lowercase();
    let is_dlp = detail_lower.contains("dlp")
        || detail_lower.contains("secret")
        || detail_lower.contains("access key");
    let is_injection = detail_lower.contains("injection")
        || detail_lower.contains("jailbreak")
        || detail_lower.contains("override");

    let (policy_rule, dlp_findings, injection_findings) = if let Some(rule) = rule_from_data {
        let dlp = if is_dlp {
            Some(serde_json::json!({"blocked": verdict_detail}).to_string())
        } else {
            None
        };
        let inj = if is_injection {
            Some(serde_json::json!({"blocked": verdict_detail}).to_string())
        } else {
            None
        };
        (rule, dlp, inj)
    } else if is_dlp {
        (
            "DLP-01-HIGH-ENTROPY".to_string(),
            Some(serde_json::json!({"blocked": verdict_detail}).to_string()),
            None,
        )
    } else if is_injection {
        (
            "INJ-04-OVERRIDE".to_string(),
            None,
            Some(serde_json::json!({"blocked": verdict_detail}).to_string()),
        )
    } else {
        ("tool_deny".to_string(), None, None)
    };

    let response_status = Some(400);
    let response_body = Some(verdict_detail);
    let verdict = "deny".to_string();

    (
        response_status,
        response_body,
        dlp_findings,
        injection_findings,
        Some(policy_rule),
        verdict,
    )
}

/// Helper to resolve the most specific agent identifier available:
/// 1. Explicit JWT / SSO subject (identity_sub)
/// 2. Explicit AGENT_ID environment variable
/// 3. Sentry Device Enrollment token / ID (if present)
/// 4. Auto-detected IDE / agent + user + host (e.g. "cursor@workstation-01", "claude-desktop@macbook")
/// 5. Fallback: "agent-<user>@<host>" or "workstation-agent"
fn resolve_workstation_agent_id(session: &crate::proxy::session::SessionContext) -> String {
    if let Some(sub) = session.identity_sub.as_deref() {
        if !sub.trim().is_empty() {
            return sub.to_string();
        }
    }

    if let Ok(env_id) = std::env::var("AGENT_ID") {
        if !env_id.trim().is_empty() {
            return env_id;
        }
    }

    if let Some(dev_token) = crate::identity::device::load_device_token() {
        if !dev_token.trim().is_empty() {
            return dev_token;
        }
    }

    // Auto-detect IDE or Agent environment
    let ide_tag = if std::env::var("CURSOR_TRACE_ID").is_ok()
        || std::env::var("CURSOR_VERSION").is_ok()
        || std::env::var("CURSOR_SHARED_DATA_DIR").is_ok()
    {
        Some("cursor")
    } else if std::env::var("CLAUDE_DESKTOP").is_ok() || std::env::var("CLAUDE_CODE").is_ok() {
        Some("claude-desktop")
    } else if std::env::var("VSCODE_PID").is_ok()
        || std::env::var("VSCODE_INJECTION").is_ok()
        || std::env::var("VSCODE_GIT_IPC_HANDLE").is_ok()
    {
        Some("vscode")
    } else if std::env::var("WINDSURF_VERSION").is_ok() {
        Some("windsurf")
    } else if std::env::var("ANTIGRAVITY_IDE").is_ok() {
        Some("antigravity")
    } else if std::env::var("ROO_CODE_VERSION").is_ok() || std::env::var("ROO_VERSION").is_ok() {
        Some("roo-code")
    } else if std::env::var("CLINE_VERSION").is_ok() {
        Some("cline")
    } else {
        None
    };

    let user_opt = std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .ok();
    let host_opt = std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .ok();

    match (ide_tag, user_opt, host_opt) {
        (Some(ide), Some(user), Some(host)) => format!("{}@{}-{}", ide, user, host),
        (Some(ide), _, Some(host)) => format!("{}@{}", ide, host),
        (Some(ide), Some(user), _) => format!("{}-{}", ide, user),
        (Some(ide), None, None) => format!("{}-agent", ide),
        (None, Some(user), Some(host)) => format!("agent-{}@{}", user, host),
        (None, Some(user), None) => format!("agent-{}", user),
        (None, None, Some(host)) => format!("workstation-{}", host),
        (None, None, None) => "workstation-agent".to_string(),
    }
}

/// Helper to asynchronously transmit redacted telemetry to Central Control Hub if configured
fn send_dashboard_event(
    state: &ProxyState,
    session: &crate::proxy::session::SessionContext,
    tool_name: &str,
    decision: control_plane_proto::redact::RawDecision,
) {
    if let Some(ref dc) = state.dashboard_client {
        let agent_id_str = resolve_workstation_agent_id(session);

        let tool_on_allowlist = {
            let guard = state.policy.read().unwrap_or_else(|e| e.into_inner());
            guard
                .as_ref()
                .map(|p| p.tools.iter().any(|t| t.name == tool_name))
                .unwrap_or(false)
        };

        let raw = control_plane_proto::redact::RawEventForRedaction {
            session_id: &session.session_id,
            agent_id: &agent_id_str,
            tool_name,
            tool_name_is_allowlisted: tool_on_allowlist,
            decision,
            timestamp_ms: chrono::Utc::now().timestamp_millis(),
            dlp_findings: &[],
            injection_findings: &[],
            semantic_findings: &[],
        };

        let redacted = control_plane_proto::redact::redact_event(&raw);
        dc.send_event(redacted);
    }
}

/// Enforces process memory quota (< 64MB RSS) across Windows, Linux, and macOS (PRD §FR-7, Task 3.4).
pub fn enforce_child_memory_quota(_pid: u32, max_bytes: usize) -> Result<(), String> {
    #[cfg(windows)]
    #[allow(non_camel_case_types, non_upper_case_globals)]
    {
        use std::os::raw::c_void;

        type HANDLE = *mut c_void;
        type BOOL = i32;
        type DWORD = u32;
        type SIZE_T = usize;

        #[repr(C)]
        struct IO_COUNTERS {
            read_operation_count: u64,
            write_operation_count: u64,
            other_operation_count: u64,
            read_transfer_count: u64,
            write_transfer_count: u64,
            other_transfer_count: u64,
        }

        #[repr(C)]
        struct JOBOBJECT_BASIC_LIMIT_INFORMATION {
            per_process_user_time_limit: i64,
            per_job_user_time_limit: i64,
            limit_flags: DWORD,
            minimum_working_set_size: SIZE_T,
            maximum_working_set_size: SIZE_T,
            active_process_limit: DWORD,
            affinity: usize,
            priority_class: DWORD,
            scheduling_class: DWORD,
        }

        #[repr(C)]
        struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
            basic_limit_information: JOBOBJECT_BASIC_LIMIT_INFORMATION,
            io_info: IO_COUNTERS,
            process_memory_limit: SIZE_T,
            job_memory_limit: SIZE_T,
            peak_process_memory_limit: SIZE_T,
            peak_job_memory_limit: SIZE_T,
        }

        const JOB_OBJECT_LIMIT_PROCESS_MEMORY: DWORD = 0x00000100;
        const JOB_OBJECT_LIMIT_JOB_MEMORY: DWORD = 0x00000200;
        const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: DWORD = 0x00002000;
        const JobObjectExtendedLimitInformation: i32 = 9;
        const PROCESS_SET_QUOTA: DWORD = 0x0100;
        const PROCESS_TERMINATE: DWORD = 0x0001;

        extern "system" {
            fn OpenProcess(dwDesiredAccess: DWORD, bInheritHandle: BOOL, dwProcessId: DWORD) -> HANDLE;
            fn CreateJobObjectW(lpJobAttributes: *mut c_void, lpName: *const u16) -> HANDLE;
            fn SetInformationJobObject(
                hJob: HANDLE,
                JobObjectInformationClass: i32,
                lpJobObjectInformation: *const c_void,
                cbJobObjectInformationLength: DWORD,
            ) -> BOOL;
            fn AssignProcessToJobObject(hJob: HANDLE, hProcess: HANDLE) -> BOOL;
            fn CloseHandle(hObject: HANDLE) -> BOOL;
        }

        unsafe {
            let proc_handle = OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, 0, _pid);
            if proc_handle.is_null() {
                return Err("OpenProcess failed for child PID".to_string());
            }

            let job = CreateJobObjectW(std::ptr::null_mut(), std::ptr::null());
            if job.is_null() {
                CloseHandle(proc_handle);
                return Err("CreateJobObjectW failed".to_string());
            }

            let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
            info.basic_limit_information.limit_flags =
                JOB_OBJECT_LIMIT_PROCESS_MEMORY | JOB_OBJECT_LIMIT_JOB_MEMORY | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            info.process_memory_limit = max_bytes;
            info.job_memory_limit = max_bytes;

            let ret = SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                &info as *const _ as *const c_void,
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as DWORD,
            );
            if ret == 0 {
                CloseHandle(proc_handle);
                CloseHandle(job);
                return Err("SetInformationJobObject failed".to_string());
            }

            let assign_ret = AssignProcessToJobObject(job, proc_handle);
            CloseHandle(proc_handle);
            if assign_ret == 0 {
                CloseHandle(job);
                return Err("AssignProcessToJobObject failed".to_string());
            }
            Ok(())
        }
    }

    #[cfg(unix)]
    {
        unsafe {
            let rlim = libc::rlimit {
                rlim_cur: max_bytes as libc::rlim_t,
                rlim_max: max_bytes as libc::rlim_t,
            };
            #[cfg(target_os = "linux")]
            let res = libc::setrlimit(libc::RLIMIT_AS, &rlim);
            #[cfg(target_os = "macos")]
            let res = libc::setrlimit(libc::RLIMIT_DATA, &rlim);
            #[cfg(not(any(target_os = "linux", target_os = "macos")))]
            let res = -1;

            if res != 0 {
                return Err("setrlimit memory limit unavailable in current environment".to_string());
            }
            Ok(())
        }
    }

    #[cfg(not(any(windows, unix)))]
    {
        Err("Unsupported operating system for memory quota".to_string())
    }
}

pub async fn run_stdio_bridge(
    state: Arc<ProxyState>,
    mut command: Command,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Configure stdio for the child process with stream separation (stderr strictly isolated)
    command.stdin(Stdio::piped());
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());

    let mut child = command.spawn()?;

    // Enforce 64MB memory limit across Windows/macOS/Linux
    if let Some(pid) = child.id() {
        if let Err(e) = enforce_child_memory_quota(pid, crate::mcp::policy::MAX_MEMORY_RSS_BYTES) {
            crate::logging::log_event(
                crate::logging::Level::Warn,
                "RESOURCE_LIMIT_UNAVAILABLE",
                serde_json::json!({
                    "reason": e,
                    "pid": pid,
                    "target_limit_bytes": crate::mcp::policy::MAX_MEMORY_RSS_BYTES
                }),
            );
        }
    }

    // Stream Separation: Forward child stderr to terminal with prefix [mcp-stderr]
    if let Some(child_stderr) = child.stderr.take() {
        tokio::spawn(async move {
            use tokio::io::AsyncBufReadExt;
            let mut lines = tokio::io::BufReader::new(child_stderr).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                eprintln!("[mcp-stderr] {}", line);
            }
        });
    }

    let child_stdin = child.stdin.take().expect("Failed to open stdin");
    let child_stdout = child.stdout.take().expect("Failed to open stdout");

    // We use FramedRead/Write to parse JSON objects from the streams
    let mut upstream_reader = FramedRead::new(child_stdout, JsonRpcCodec::new());
    let mut upstream_writer = FramedWrite::new(child_stdin, JsonRpcCodec::new());

    // Also wrap our own stdin/stdout to communicate with the local agent
    let agent_stdin = tokio::io::stdin();
    let agent_stdout = tokio::io::stdout();

    let mut agent_reader = FramedRead::new(agent_stdin, JsonRpcCodec::new());
    let mut agent_writer = FramedWrite::new(agent_stdout, JsonRpcCodec::new());

    // Create a local isolated SessionContext representing the active session (FR-101)
    let local_policy = match state.policy.read() {
        Ok(guard) => guard.clone(),
        Err(_) => None,
    };
    let local_session = Arc::new(crate::proxy::session::SessionContext::new(
        None,
        None,
        vec![],
        local_policy,
        None,
        std::env::var("AGENTCONTROL_CREDENTIAL_ID").ok(),
    ));

    // FR-303b: Track forwarded tools by their JSON-RPC ID for response correlation.
    let mut forwarded_requests: std::collections::HashMap<serde_json::Value, String> =
        std::collections::HashMap::new();

    loop {
        tokio::select! {
            // Read from Agent (client)
            msg = agent_reader.next() => {
                match msg {
                    Some(Ok(mut json)) => {
                        // Protocol Check: Verify JSON nesting depth <= 32 levels
                        let depth = crate::mcp::policy::calculate_json_depth(&json);
                        if depth > crate::mcp::policy::MAX_JSON_DEPTH {
                            let err_resp = serde_json::json!({
                                "jsonrpc": "2.0",
                                "id": json.get("id"),
                                "error": {
                                    "code": -32600,
                                    "message": "JSON-RPC nesting depth exceeded maximum of 32 levels"
                                }
                            });
                            let _ = agent_writer.send(err_resp).await;
                            continue;
                        }

                        // Parameter DLP: Scan and redact sensitive tool call arguments in-place
                        if let Some(params) = json.get_mut("params") {
                            if let Some(args) = params.get_mut("arguments") {
                                let findings = crate::mcp::policy::scan_and_redact_json(args);
                                if !findings.is_empty() {
                                    crate::logging::log_event(
                                        crate::logging::Level::Info,
                                        "mcp_parameter_dlp_redacted",
                                        serde_json::json!({
                                            "findings_count": findings.len(),
                                            "pattern": findings[0].pattern_type
                                        }),
                                    );
                                }
                            }
                        }

                        // FR-303b: Extract tool name before forwarding
                        let method = json.get("method").and_then(|m| m.as_str()).unwrap_or("");
                        let tool_name = if method == "tools/list" {
                            "tools/list".to_string()
                        } else {
                            json.get("params")
                                .and_then(|p| p.get("name"))
                                .and_then(|n| n.as_str())
                                .unwrap_or("")
                                .to_string()
                        };

                        let req_body_preview = serde_json::to_string(&json).ok()
                            .map(|s| s.chars().take(512).collect::<String>());
                        let timestamp_ns = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0);
                        let action = evaluate_jsonrpc(&state, &local_session, &json).await;
                        match action {
                            ProxyAction::Forward => {
                                // Track the tool name for response scanning using its ID
                                if let Some(id) = json.get("id") {
                                    forwarded_requests.insert(id.clone(), tool_name.clone());
                                }
                                // P0 fix: persist tool_allow event to events.db so the dashboard
                                // can observe real stdio traffic from wrapped clients.
                                let event = crate::proxy::db::EgressEvent {
                                    timestamp_ns,
                                    session_id: local_session.session_id.clone(),
                                    transport: "stdio".to_string(),
                                    method: Some(tool_name.clone()),
                                    target_host: "localhost".to_string(),
                                    target_port: None,
                                    url_path: Some(format!("/{}", tool_name)),
                                    request_headers: None,
                                    request_body: req_body_preview,
                                    request_body_hash: None,
                                    response_status: Some(200),
                                    response_body: None,
                                    response_body_hash: None,
                                    dlp_findings: None,
                                    injection_findings: None,
                                    latency_ms: Some(0.0),
                                    verdict: Some("allow".to_string()),
                                    semantic_anomaly_score: None,
                                    identity_context: None,
                                    source: Some("production".to_string()),
                                    policy_rule: Some("tool_allow".to_string()),
                                };
                                if let Ok(json_str) = serde_json::to_string(&event) {
                                    let _ = state.event_tx.send(json_str);
                                }
                                let db = state.db_manager.clone();
                                tokio::spawn(async move { let _ = db.insert(event).await; });

                                send_dashboard_event(
                                    &state,
                                    &local_session,
                                    &tool_name,
                                    control_plane_proto::redact::RawDecision::Allowed,
                                );

                                if let Err(e) = upstream_writer.send(json).await {
                                    eprintln!("Error sending to upstream: {}", e);
                                    break;
                                }
                            }
                            ProxyAction::Respond(resp) | ProxyAction::RespondWithStatus(_, resp) => {
                                // P0 fix: persist canonical tool_deny event with full threat fidelity
                                let (response_status, response_body, dlp_findings, injection_findings, policy_rule, verdict) =
                                    extract_decision_evidence(&resp);

                                let event = crate::proxy::db::EgressEvent {
                                    timestamp_ns,
                                    session_id: local_session.session_id.clone(),
                                    transport: "stdio".to_string(),
                                    method: Some(tool_name.clone()),
                                    target_host: "localhost".to_string(),
                                    target_port: None,
                                    url_path: Some(format!("/{}", tool_name)),
                                    request_headers: None,
                                    request_body: req_body_preview,
                                    request_body_hash: None,
                                    response_status,
                                    response_body,
                                    response_body_hash: None,
                                    dlp_findings,
                                    injection_findings,
                                    latency_ms: Some(0.0),
                                    verdict: Some(verdict),
                                    semantic_anomaly_score: None,
                                    identity_context: None,
                                    source: Some("production".to_string()),
                                    policy_rule,
                                };
                                if let Ok(json_str) = serde_json::to_string(&event) {
                                    let _ = state.event_tx.send(json_str);
                                }
                                let db = state.db_manager.clone();
                                tokio::spawn(async move { let _ = db.insert(event).await; });

                                send_dashboard_event(
                                    &state,
                                    &local_session,
                                    &tool_name,
                                    control_plane_proto::redact::RawDecision::Denied,
                                );

                                if let Err(e) = agent_writer.send(resp).await {
                                    eprintln!("Error sending to agent: {}", e);
                                    break;
                                }
                            }
                            ProxyAction::KillAndRespond(resp) | ProxyAction::KillAndRespondWithStatus(_, resp) => {
                                // P0 fix: persist canonical denial event with complete threat findings
                                // before terminating child process.
                                let (response_status, response_body, dlp_findings, injection_findings, policy_rule, verdict) =
                                    extract_decision_evidence(&resp);

                                let event = crate::proxy::db::EgressEvent {
                                    timestamp_ns,
                                    session_id: local_session.session_id.clone(),
                                    transport: "stdio".to_string(),
                                    method: Some(tool_name.clone()),
                                    target_host: "localhost".to_string(),
                                    target_port: None,
                                    url_path: Some(format!("/{}", tool_name)),
                                    request_headers: None,
                                    request_body: req_body_preview,
                                    request_body_hash: None,
                                    response_status,
                                    response_body,
                                    response_body_hash: None,
                                    dlp_findings,
                                    injection_findings,
                                    latency_ms: Some(0.0),
                                    verdict: Some(verdict),
                                    semantic_anomaly_score: None,
                                    identity_context: None,
                                    source: Some("production".to_string()),
                                    policy_rule,
                                };
                                if let Ok(json_str) = serde_json::to_string(&event) {
                                    let _ = state.event_tx.send(json_str);
                                }
                                let db = state.db_manager.clone();
                                tokio::spawn(async move { let _ = db.insert(event).await; });

                                send_dashboard_event(
                                    &state,
                                    &local_session,
                                    &tool_name,
                                    control_plane_proto::redact::RawDecision::Denied,
                                );

                                let _ = agent_writer.send(resp).await;
                                #[allow(deprecated)]
                                if state.kill_mode == KillMode::Process || state.kill_mode == KillMode::Both {
                                    eprintln!("Violation: Killing process and exiting.");
                                    let _ = child.kill().await;
                                    break;
                                }
                            }
                        }
                    }
                    Some(Err(e)) => {
                        // P2-b fix: distinguish genuine framing errors from normal EOF-adjacent
                        // framing artifacts (e.g. "bytes remaining on stream" after a clean JSON
                        // message). Real MCP clients close stdin cleanly after the last message;
                        // this must not print noise to the terminal.
                        let msg = e.to_string();
                        if e.kind() == std::io::ErrorKind::UnexpectedEof
                            || msg.contains("bytes remaining")
                            || msg.contains("unexpected end of file")
                        {
                            // Normal stream close after valid JSON — silent exit.
                        } else {
                            eprintln!("Error reading from agent: {}", e);
                        }
                        break;
                    }
                    None => {
                        // P2-b fix: clean EOF — client closed stdin normally, no need to log.
                        break;
                    }
                }
            }

            // Read from Upstream (MCP Server)
            msg = upstream_reader.next() => {
                match msg {
                    Some(Ok(json)) => {
                        // FR-303b: Scan response for secrets before forwarding to agent
                        // Correlate with the original tool name using the response ID
                        let id = json.get("id").cloned().unwrap_or(serde_json::Value::Null);
                        let tool_name = forwarded_requests.remove(&id).unwrap_or_default();

                        let processed = stdio_scan_response(&state, &local_session.session_id, &json, &tool_name).await;
                        if let Err(e) = agent_writer.send(processed).await {
                            eprintln!("Error sending to agent: {}", e);
                            break;
                        }
                    }
                    Some(Err(e)) => {
                        let msg = e.to_string();
                        if e.kind() == std::io::ErrorKind::UnexpectedEof
                            || msg.contains("bytes remaining")
                            || msg.contains("unexpected end of file")
                        {
                            // Normal upstream EOF — silent.
                        } else {
                            eprintln!("Error reading from upstream: {}", e);
                        }
                        break;
                    }
                    None => {
                        // Upstream closed — break silently, child.wait() arm will log exit status.
                        break;
                    }
                }
            }

            // Subprocess exited
            status = child.wait() => {
                match status {
                    Ok(s) if s.success() => {
                        // Clean exit — no noise needed
                    }
                    Ok(s) => eprintln!("Child process exited with status: {}", s),
                    Err(e) => eprintln!("Error waiting for child: {}", e),
                }
                break;
            }
        }
    }

    // Ensure child is dead
    let _ = child.kill().await;

    Ok(())
}

/// FR-303b: Scan a stdio response for secrets — mirrors the HTTP scan_and_process_response logic.
/// Fail-open: any scanner error passes the response through with audit log.
async fn stdio_scan_response(
    state: &ProxyState,
    session_id: &str,
    response: &serde_json::Value,
    tool_name: &str,
) -> serde_json::Value {
    // 1. Injection & Poisoning Scan (FR-13)
    let enforce_mode = !state.shadow_mode.load(std::sync::atomic::Ordering::Relaxed);
    let inj_scan_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        state
            .injection_scanner
            .scan_response(response, tool_name, session_id, enforce_mode)
    }));

    match inj_scan_result {
        Ok(crate::policy::injection::ScanResult::Block { findings }) => {
            let f = &findings[0];
            let _ = state
                .audit_logger
                .write_entry(
                    session_id,
                    "injection_blocked",
                    tool_name,
                    None,
                    Some(format!("pattern={} preview={}", f.pattern_name, f.preview)),
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                )
                .await;
            logging::log_event(
                logging::Level::Warn,
                "injection_blocked",
                serde_json::json!({"tool": tool_name, "session": session_id, "pattern": &f.pattern_name}),
            );

            // Notify UI
            let event = crate::proxy::db::EgressEvent {
                timestamp_ns: chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0),
                session_id: session_id.to_string(),
                transport: "stdio".to_string(),
                method: Some(tool_name.to_string()),
                target_host: "localhost".to_string(),
                target_port: None,
                url_path: None,
                request_headers: None,
                request_body: None,
                request_body_hash: None,
                response_status: Some(403),
                response_body: None,
                response_body_hash: None,
                dlp_findings: None,
                injection_findings: Some(serde_json::json!({"findings": findings.iter().map(|f| format!("{}: {}", f.category.as_str(), f.preview)).collect::<Vec<_>>()}).to_string()),
                latency_ms: Some(0.0),
                verdict: Some("deny".to_string()),
                semantic_anomaly_score: None,
                identity_context: None,
                source: Some("production".to_string()),
                policy_rule: Some("INJ-04-AUDIT".to_string()),
            };
            if let Ok(json_str) = serde_json::to_string(&event) {
                let _ = state.event_tx.send(json_str);
            }

            let id = response
                .get("id")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            return serde_json::json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {
                    "code": -32002,
                    "message": format!("Response blocked: prompt injection detected ({}).", f.pattern_name),
                    "data": { "session_id": session_id, "pattern": &f.pattern_name }
                }
            });
        }
        Ok(crate::policy::injection::ScanResult::Timeout) => {
            if enforce_mode {
                let _ = state
                    .audit_logger
                    .write_entry(
                        session_id,
                        "injection_blocked_timeout",
                        tool_name,
                        None,
                        Some("Scanner timed out (potential ReDoS) — Blocked".to_string()),
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                    )
                    .await;
                logging::log_event(
                    logging::Level::Warn,
                    "injection_blocked_timeout",
                    serde_json::json!({"tool": tool_name, "session": session_id}),
                );

                // Notify UI
                let event = crate::proxy::db::EgressEvent {
                    timestamp_ns: chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0),
                    session_id: session_id.to_string(),
                    transport: "stdio".to_string(),
                    method: Some(tool_name.to_string()),
                    target_host: "localhost".to_string(),
                    target_port: None,
                    url_path: None,
                    request_headers: None,
                    request_body: None,
                    request_body_hash: None,
                    response_status: Some(403),
                    response_body: None,
                    response_body_hash: None,
                    dlp_findings: None,
                    injection_findings: Some(
                        serde_json::json!({"findings": ["timeout: potential ReDoS"]}).to_string(),
                    ),
                    latency_ms: Some(0.0),
                    verdict: Some("deny".to_string()),
                    semantic_anomaly_score: None,
                    identity_context: None,
                    source: Some("production".to_string()),
                    policy_rule: Some("INJ-SCAN-TIMEOUT".to_string()),
                };
                if let Ok(json_str) = serde_json::to_string(&event) {
                    let _ = state.event_tx.send(json_str);
                }

                let id = response
                    .get("id")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null);
                return serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": {
                        "code": -32002,
                        "message": "Response blocked: injection scan timeout (potential ReDoS).",
                        "data": { "session_id": session_id }
                    }
                });
            } else {
                let _ = state
                    .audit_logger
                    .write_entry(
                        session_id,
                        "injection_warning_timeout",
                        tool_name,
                        None,
                        Some(
                            "Scanner timed out (potential ReDoS) — Warn (Shadow Mode)".to_string(),
                        ),
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                    )
                    .await;
                logging::log_event(
                    logging::Level::Warn,
                    "injection_warning_timeout",
                    serde_json::json!({"tool": tool_name, "session": session_id}),
                );
            }
        }
        Ok(crate::policy::injection::ScanResult::Warn { findings }) => {
            let f = &findings[0];
            let _ = state
                .audit_logger
                .write_entry(
                    session_id,
                    "injection_warning",
                    tool_name,
                    None,
                    Some(format!("pattern={} preview={}", f.pattern_name, f.preview)),
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                )
                .await;
            logging::log_event(
                logging::Level::Warn,
                "injection_warning",
                serde_json::json!({"tool": tool_name, "session": session_id, "pattern": &f.pattern_name, "count": findings.len()}),
            );

            // Notify UI
            let event = crate::proxy::db::EgressEvent {
                timestamp_ns: chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0),
                session_id: session_id.to_string(),
                transport: "stdio".to_string(),
                method: Some(tool_name.to_string()),
                target_host: "localhost".to_string(),
                target_port: None,
                url_path: None,
                request_headers: None,
                request_body: None,
                request_body_hash: None,
                response_status: Some(200),
                response_body: None,
                response_body_hash: None,
                dlp_findings: None,
                injection_findings: Some(serde_json::json!({"findings": findings.iter().map(|f| format!("{}: {}", f.category.as_str(), f.preview)).collect::<Vec<_>>()}).to_string()),
                latency_ms: Some(0.0),
                verdict: Some("allow".to_string()),
                semantic_anomaly_score: None,
                identity_context: None,
                source: Some("production".to_string()),
                policy_rule: Some("INJ-04-AUDIT-WARN".to_string()),
            };
            if let Ok(json_str) = serde_json::to_string(&event) {
                let _ = state.event_tx.send(json_str);
            }
        }
        Ok(crate::policy::injection::ScanResult::ScannerError { error }) => {
            let _ = state
                .audit_logger
                .write_entry(
                    session_id,
                    "INJECTION_SCANNER_FAILURE",
                    tool_name,
                    None,
                    Some(format!("Scanner error: {} — fail-open applied", error)),
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                )
                .await;
            logging::log_event(
                logging::Level::Error,
                "INJECTION_SCANNER_FAILURE",
                serde_json::json!({"tool": tool_name, "session": session_id, "error": &error}),
            );
        }
        Err(_) => {
            let _ = state
                .audit_logger
                .write_entry(
                    session_id,
                    "INJECTION_SCANNER_FAILURE",
                    tool_name,
                    None,
                    Some("Injection scanner panicked — fail-open applied".to_string()),
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                )
                .await;
            logging::log_event(
                logging::Level::Error,
                "INJECTION_SCANNER_FAILURE",
                serde_json::json!({"tool": tool_name, "session": session_id, "reason": "scanner_panic"}),
            );
        }
        Ok(crate::policy::injection::ScanResult::Clean) => {}
    }

    // FR-601: MCP Schema-Drift Evaluation on discovery responses
    if tool_name == "tools/list" {
        let drift_cfg = state
            .policy
            .read()
            .ok()
            .and_then(|p| p.as_ref().and_then(|pol| pol.schema_drift.clone()));
        let drift_result =
            state
                .schema_drift_detector
                .evaluate_catalog("stdio", response, drift_cfg.as_ref());
        match drift_result {
            crate::policy::schema_drift::DriftResult::Drift {
                server_name,
                action,
                added_tools,
                removed_tools,
                modified_tools,
                ..
            } => {
                let _ = state
                    .audit_logger
                    .write_entry(
                        session_id,
                        "schema_drift_detected",
                        tool_name,
                        None,
                        Some(format!(
                            "server={} action={:?} added={:?} removed={:?} modified={:?}",
                            server_name, action, added_tools, removed_tools, modified_tools
                        )),
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                    )
                    .await;
                logging::log_event(
                    logging::Level::Warn,
                    "schema_drift_detected",
                    serde_json::json!({
                        "server": server_name,
                        "action": format!("{:?}", action),
                        "added": added_tools,
                        "removed": removed_tools,
                        "modified": modified_tools,
                    }),
                );
                if action == crate::policy::schema_drift::DriftAction::Block
                    && !state.shadow_mode.load(std::sync::atomic::Ordering::Relaxed)
                {
                    let id = response
                        .get("id")
                        .cloned()
                        .unwrap_or(serde_json::Value::Null);
                    return serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": {
                            "code": -32002,
                            "message": "MCP schema drift violation: tool catalog modified from baseline",
                            "data": {
                                "server": server_name,
                                "added": added_tools,
                                "removed": removed_tools,
                                "modified": modified_tools
                            }
                        }
                    });
                }
            }
            _ => {}
        }
    }

    // 2. Secret Response Scanner (FR-303b)
    let scan_config = match state.response_scan_config.read() {
        Ok(guard) => guard.clone(),
        Err(_) => crate::policy::response_scanner::ResponseScanConfig::default(),
    };
    let scan_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        state
            .response_scanner
            .scan_response(response, tool_name, &scan_config)
    }));

    let scan_result = match scan_result {
        Ok(result) => result,
        Err(_) => {
            let _ = state
                .audit_logger
                .write_entry(
                    session_id,
                    "SCANNER_FAILURE",
                    tool_name,
                    None,
                    Some("Response scanner panicked — fail-open applied".to_string()),
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                )
                .await;
            logging::log_event(
                logging::Level::Error,
                "SCANNER_FAILURE",
                serde_json::json!({"tool": tool_name, "session": session_id, "reason": "scanner_panic"}),
            );
            return response.clone();
        }
    };

    match scan_result {
        ScanResult::Pass | ScanResult::Clean => response.clone(),

        ScanResult::Skipped { reason } => {
            let _ = state
                .audit_logger
                .write_entry(
                    session_id,
                    "response_scan_skipped",
                    tool_name,
                    None,
                    Some(reason.clone()),
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                )
                .await;
            logging::log_event(
                logging::Level::Warn,
                "response_scan_skipped",
                serde_json::json!({"tool": tool_name, "session": session_id, "reason": &reason}),
            );
            response.clone()
        }

        ScanResult::Redact { findings } => {
            if scan_config.dry_run {
                for f in &findings {
                    let _ = state
                        .audit_logger
                        .write_entry(
                            session_id,
                            "response_scan_dry_run",
                            tool_name,
                            None,
                            Some(format!(
                                "Would redact {} at {}:{} preview={}",
                                f.pattern_name, f.field_path, f.position, f.preview
                            )),
                            None,
                            None,
                            None,
                            None,
                            None,
                            None,
                        )
                        .await;
                }
                logging::log_event(
                    logging::Level::Warn,
                    "response_scan_dry_run",
                    serde_json::json!({"tool": tool_name, "session": session_id, "action": "redact", "count": findings.len()}),
                );
                return response.clone();
            }
            for f in &findings {
                let _ = state
                    .audit_logger
                    .write_entry(
                        session_id,
                        "response_secret_redacted",
                        tool_name,
                        None,
                        Some(format!(
                            "pattern={} field={} pos={} len={} preview={}",
                            f.pattern_name, f.field_path, f.position, f.length, f.preview
                        )),
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                    )
                    .await;
            }
            logging::log_event(
                logging::Level::Warn,
                "response_secret_redacted",
                serde_json::json!({"tool": tool_name, "session": session_id, "count": findings.len()}),
            );
            state
                .response_scanner
                .redact_response(response, &scan_config)
        }

        ScanResult::Block { findings } => {
            if scan_config.dry_run {
                for f in &findings {
                    let _ = state
                        .audit_logger
                        .write_entry(
                            session_id,
                            "response_scan_dry_run",
                            tool_name,
                            None,
                            Some(format!(
                                "Would block: {} preview={}",
                                f.pattern_name, f.preview
                            )),
                            None,
                            None,
                            None,
                            None,
                            None,
                            None,
                        )
                        .await;
                }
                logging::log_event(
                    logging::Level::Warn,
                    "response_scan_dry_run",
                    serde_json::json!({"tool": tool_name, "session": session_id, "action": "block", "count": findings.len()}),
                );
                return response.clone();
            }
            let f = &findings[0];
            let _ = state
                .audit_logger
                .write_entry(
                    session_id,
                    "response_secret_blocked",
                    tool_name,
                    None,
                    Some(format!(
                        "pattern={} field={} preview={}",
                        f.pattern_name, f.field_path, f.preview
                    )),
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                )
                .await;
            logging::log_event(
                logging::Level::Warn,
                "response_secret_blocked",
                serde_json::json!({"tool": tool_name, "session": session_id, "pattern": &f.pattern_name}),
            );

            let id = response
                .get("id")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {
                    "code": -32002,
                    "message": format!("Response blocked: secret detected ({}). Use --dry-run to preview, or adjust policy.", f.pattern_name),
                    "data": { "session_id": session_id, "pattern": &f.pattern_name }
                }
            })
        }

        ScanResult::ScannerError { error } => {
            let _ = state
                .audit_logger
                .write_entry(
                    session_id,
                    "SCANNER_FAILURE",
                    tool_name,
                    None,
                    Some(format!("Scanner error: {} — fail-open applied", error)),
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                )
                .await;
            logging::log_event(
                logging::Level::Error,
                "SCANNER_FAILURE",
                serde_json::json!({"tool": tool_name, "session": session_id, "error": &error}),
            );
            response.clone()
        }
    }
}

pub async fn run_stdio_to_http_bridge(
    state: Arc<ProxyState>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use futures_util::{SinkExt, StreamExt};
    use tokio_util::codec::{FramedRead, FramedWrite};

    let agent_stdin = tokio::io::stdin();
    let agent_stdout = tokio::io::stdout();

    let mut agent_reader = FramedRead::new(agent_stdin, JsonRpcCodec::new());
    let mut agent_writer = FramedWrite::new(agent_stdout, JsonRpcCodec::new());

    let local_policy = match state.policy.read() {
        Ok(guard) => guard.clone(),
        Err(_) => None,
    };
    let local_session = Arc::new(crate::proxy::session::SessionContext::new(
        None,
        None,
        vec![],
        local_policy,
        None,
        std::env::var("AGENTCONTROL_CREDENTIAL_ID").ok(),
    ));

    while let Some(msg) = agent_reader.next().await {
        match msg {
            Ok(json) => {
                let method = json.get("method").and_then(|m| m.as_str()).unwrap_or("");
                let tool_name = if method == "tools/list" {
                    "tools/list".to_string()
                } else {
                    json.get("params")
                        .and_then(|p| p.get("name"))
                        .and_then(|n| n.as_str())
                        .unwrap_or("")
                        .to_string()
                };

                let action = evaluate_jsonrpc(&state, &local_session, &json).await;
                match action {
                    ProxyAction::Forward => {
                        send_dashboard_event(
                            &state,
                            &local_session,
                            &tool_name,
                            control_plane_proto::redact::RawDecision::Allowed,
                        );

                        let response = crate::proxy::forward::forward_request(
                            &state.http_client,
                            &state.upstream_url,
                            &json,
                        )
                        .await;

                        match response {
                            Ok(resp) => {
                                let processed = stdio_scan_response(
                                    &state,
                                    &local_session.session_id,
                                    &resp,
                                    &tool_name,
                                )
                                .await;
                                if let Err(e) = agent_writer.send(processed).await {
                                    eprintln!("Error sending to agent: {}", e);
                                    break;
                                }
                            }
                            Err(e) => {
                                let id = json.get("id").cloned().unwrap_or(serde_json::Value::Null);
                                let err_resp = serde_json::json!({
                                    "jsonrpc": "2.0",
                                    "id": id,
                                    "error": {
                                        "code": -32001,
                                        "message": format!("Forwarding error: {}", e)
                                    }
                                });
                                if let Err(e) = agent_writer.send(err_resp).await {
                                    eprintln!("Error sending to agent: {}", e);
                                    break;
                                }
                            }
                        }
                    }
                    ProxyAction::Respond(resp) | ProxyAction::RespondWithStatus(_, resp) => {
                        send_dashboard_event(
                            &state,
                            &local_session,
                            &tool_name,
                            control_plane_proto::redact::RawDecision::Denied,
                        );
                        if let Err(e) = agent_writer.send(resp).await {
                            eprintln!("Error sending to agent: {}", e);
                            break;
                        }
                    }
                    ProxyAction::KillAndRespond(resp)
                    | ProxyAction::KillAndRespondWithStatus(_, resp) => {
                        send_dashboard_event(
                            &state,
                            &local_session,
                            &tool_name,
                            control_plane_proto::redact::RawDecision::Denied,
                        );
                        let _ = agent_writer.send(resp).await;
                        break;
                    }
                }
            }
            Err(e) => {
                eprintln!("Error reading from agent: {}", e);
                break;
            }
        }
    }

    Ok(())
}
