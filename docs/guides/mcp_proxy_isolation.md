# Model Context Protocol (MCP) Stdio Proxy Isolation & Sandboxing Guide

**Document Target:** Engineering & Platform Security Teams  
**Applies To:** Windows 11/10, macOS 13+ (Apple Silicon & Intel), Ubuntu/Debian/Fedora Linux

---

## 1. Process Isolation Architecture

Local MCP servers (filesystem access, PostgreSQL connectors, GitHub tools, terminal runners) execute arbitrary code on developer workstations. If an MCP server leaks memory, hangs, or encounters an uncaught exception, a monolithic proxy crashes alongside it.

AgentControl decouples every configured MCP server into an isolated **Child Stdio Proxy process**:

```text
┌─────────────────────────────────────────────────────────────┐
│                    Developer Workstation                    │
│                                                             │
│   ┌─────────────────────────────────────────────────────┐   │
│   │        agentcontrol daemon (Background Service)     │   │
│   │             (127.0.0.1:18080 / Named Pipe)          │   │
│   └──────────────────────────┬──────────────────────────┘   │
│                              │ Spawns isolated child per MCP│
│                              ▼                              │
│   ┌─────────────────────────────────────────────────────┐   │
│   │             agentcontrol stdio-proxy                │   │
│   │  - JSON-RPC 2.0 Framing (< 16MB)                    │   │
│   │  - Nesting Depth Limit (< 32 levels)                │   │
│   │  - Parameter DLP: Redacts API keys, credentials     │   │
│   │  - 60-second Tool Execution Timeout                 │   │
│   │  - Strict < 64MB Memory RSS Enforcement             │   │
│   │  - Stderr stream separation ([mcp-stderr:<server>]) │   │
│   │  - Crash Isolation (Daemon survives MCP failure)    │   │
│   └──────────────────────────┬──────────────────────────┘   │
│                              │ Stdio pipes                  │
│                              ▼                              │
│   ┌─────────────────────────────────────────────────────┐   │
│   │             Target Local MCP Server Process         │   │
│   │         (npx @modelcontextprotocol/server-postgres) │   │
│   └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

---

## 2. Multi-OS Memory Limit Enforcement (< 64MB RSS)

Every child process spawned by `agentcontrol stdio-proxy` has a hard 64MB memory limit enforced using OS-native kernel primitives:

| Operating System | Enforcement Mechanism | Failure Action |
| :--- | :--- | :--- |
| **Windows 11 / 10** | **Windows Job Object** (`JOB_OBJECT_LIMIT_PROCESS_MEMORY`) | Windows kernel terminates child immediately; exit code `STATUS_QUOTA_EXCEEDED`. |
| **Linux (Ubuntu/Debian)** | **POSIX Resource Limit** (`libc::setrlimit(RLIMIT_AS, 64MB)`) | Kernel aborts heap allocation (`SIGSEGV` or `ENOMEM`). |
| **macOS 13+** | **POSIX Resource Limit** (`libc::setrlimit(RLIMIT_DATA, 64MB)`) | Allocation fails gracefully; observed RSS monitor ensures process isolation. |
| **Containers / Fallback** | **Observed RSS Limit** (`RESOURCE_LIMIT_UNAVAILABLE` warning) | Process monitored; 60s execution timeout enforces termination. |

---

## 3. Protocol Safety & Parameter DLP

Before any tool call argument reaches the MCP server, `stdio-proxy` performs inline inspection:

1. **Max Frame Size:** Strict 16MB ceiling. Frames exceeding 16MB are rejected with JSON-RPC error `-32600`.
2. **Nesting Depth:** Structures deeper than 32 levels are rejected with `-32600` to prevent JSON recursive parsing stack overflows.
3. **Parameter DLP (Data Loss Prevention):**
   - API keys (`sk-...`, GitHub tokens, AWS access keys)
   - Database connection strings (`postgres://...`, `mysql://...`)
   - Private keys (`-----BEGIN ... PRIVATE KEY-----`)
   - Sensitive values are redacted with `[REDACTED:<TYPE>]` before execution.
4. **Execution Timeout:** 60-second default ceiling. If a tool hangs, SIGTERM is dispatched followed by SIGKILL, returning error `-32000`.

---

## 4. Complete Stderr Stream Separation

Child process stderr output is strictly isolated from the JSON-RPC communication channel:
- Output is prefixed with `[mcp-stderr]` and piped directly to the user's terminal.
- Terminal output from MCP servers never corrupts the JSON-RPC protocol framing.
