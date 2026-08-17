# ADR Security Benchmark Guide

> **What is ADR?**
> **ADR** stands for **AI Detection & Response** — an AI governance framework that stress-tests your agent security gateway against real-world attack techniques. It encompasses stateful multi-step sequence rules, security benchmarking, and self-healing policy synthesis.

Agent Control ships with a built-in **303-task ADR benchmark suite** that measures how effectively your current gateway configuration detects and blocks 17 categories of AI attack patterns. The benchmark runs entirely offline against a local gateway instance, so it produces reproducible results without any external dependencies.

---

## Why Run the Benchmark?

Without objective testing, it is difficult to know whether your policy covers the attacks your AI agents are actually vulnerable to. The ADR benchmark:

- Gives you a concrete **A/B/C security grade** across 17 attack dimensions.
- Shows **per-category pass rates** so you know exactly which attack classes slip through.
- Provides **comparative baselines** against GuardAgent, LlamaFirewall, and ALRPHFS — helping you understand how Agent Control's coverage compares.
- Surfaces **actionable policy recommendations** so you can incrementally improve your score.

---

## Running the Benchmark

### Prerequisites
- Agent Control binary installed, **or** the project built from source (`cargo build --release`).
- No active Agent Control gateway process required — the benchmark spawns its own internal gateway instance.

### Command

* **macOS / Linux (Bash / Zsh):**
  ```bash
  agentcontrol bench --full
  ```

* **Windows (PowerShell):**
  ```powershell
  agentcontrol.exe bench --full
  ```

* **Windows (Command Prompt - CMD):**
  ```cmd
  agentcontrol.exe bench --full
  ```

*(When building from source: `cargo run -- bench --full`)*

The benchmark typically completes in under 60 seconds on a standard developer workstation.

### Output

After completion, Agent Control writes the report to:

```
target/benchmark-report.html
```

Open it with:

```bash
# macOS
open target/benchmark-report.html

# Linux
xdg-open target/benchmark-report.html

# Windows (PowerShell)
Start-Process target/benchmark-report.html

# Windows (Command Prompt - CMD)
start target\benchmark-report.html
```

The **ADR Benchmark tab** in the local dashboard (`http://127.0.0.1:8080`) also renders the report interactively after you run `agentcontrol dev`.

---

## Understanding the Report

### Overall Security Grade

The report opens with a dashboard hero section showing your **overall security grade**:

| Grade | Score Range | Meaning |
|-------|-------------|---------|
| **A** | ≥ 90% | Excellent — your gateway blocks nearly all tested attack patterns. |
| **B** | 75%–89% | Good — some attack classes need attention. |
| **C** | < 75% | Needs improvement — significant attack surface remains unblocked. |

The score is a weighted average of all 17 category pass rates.

### Per-Category Breakdown

The body of the report shows a card for each of the 17 attack categories, including:
- A plain-English description of what the category tests.
- The number of tasks that **passed** (Agent Control correctly blocked the attack) vs. **failed** (the attack was not caught).
- A **pass rate percentage** and a color-coded severity badge.

### Comparative Baselines

A bar chart compares Agent Control's overall score against published results for comparable tools:

| Tool | Approximate Overall Score |
|------|--------------------------|
| **Agent Control** | Your score |
| GuardAgent | ~72% |
| LlamaFirewall | ~68% |
| ALRPHFS | ~65% |

> **Note:** Baseline scores are derived from published research benchmarks and represent typical configurations. Agent Control's score depends on your specific policy configuration.

---

## The 17 Attack Categories

| # | Category | What It Tests |
|---|----------|---------------|
| 1 | **Prompt Injection** | Attempts to hijack the agent's reasoning via injected instructions in tool arguments or responses |
| 2 | **Tool Abuse** | Misuse of trusted tools (e.g., using `read_file` to read SSH keys, `exec` to spawn shells) |
| 3 | **Data Exfiltration** | Patterns that attempt to send sensitive data to external HTTP endpoints |
| 4 | **SSRF** | Requests targeting internal network addresses and cloud metadata endpoints (`169.254.169.254`) |
| 5 | **Privilege Escalation** | Attempts to invoke tools or read resources beyond the agent's configured credential scope |
| 6 | **Path Traversal** | Directory traversal attacks (`../../etc/passwd`, `..\windows\system32`) |
| 7 | **Secret Leakage** | Requests that trigger disclosure of API keys, tokens, or environment variables |
| 8 | **Loop / Recursion** | Infinite agent self-invocation or repeated tool call loops |
| 9 | **Multi-Step Chains** | Coordinated multi-turn sequences designed to bypass single-call detection rules |
| 10 | **Denial of Service** | High-frequency or computationally expensive requests designed to exhaust gateway resources |
| 11 | **Encoding Evasion** | Obfuscation via Base64, URL-encoding, leetspeak, and Cyrillic homoglyph substitution |
| 12 | **Supply Chain** | Attacks via compromised or malicious MCP tool definitions and external resources |
| 13 | **Lateral Movement** | Sequential calls probing adjacent systems after initial tool access is established |
| 14 | **Credential Theft** | Attempts to access credential stores, token files, or key material |
| 15 | **Policy Bypass** | Direct attempts to manipulate, disable, or hot-reload the policy engine |
| 16 | **Identity Spoofing** | Forged JWT tokens or fraudulent agent identity claims |
| 17 | **Indirect Injection** | Injection via tool response payloads (e.g., poisoned file content, malicious MCP responses) |

---

## Improving Your Score

The report includes per-category recommendations. Common improvements:

### Enable Sequence Rules for Multi-Step Attacks

Categories 9 (Multi-Step Chains) and 13 (Lateral Movement) are best addressed by adding `sequence_rules` to your policy:

```yaml
sequence_rules:
  - id: "no-read-then-exec"
    description: "Block shell execution following a file read"
    window: 5
    pattern:
      - tool: read_file
      - tool: execute_command
    action: deny
    message: "Exfiltration chain: read_file → execute_command"
```

### Restrict Path Parameters for Path Traversal (Category 6)

```yaml
tools:
  - name: read_file
    action: allow
    parameters:
      - name: path
        type: string
        validators:
          - path_traversal
        regex: "^/allowed/safe/path/.*"
        deny_patterns: ["\\.ssh", "\\.env", "\\.aws", "etc/shadow"]
```

### Add DLP Patterns for Secret Leakage (Category 7)

```yaml
dlp:
  patterns:
    - name: "aws_access_key"
      regex: "AKIA[0-9A-Z]{16}"
      action: block
    - name: "github_token"
      regex: "ghp_[A-Za-z0-9]{36}"
      action: block
    - name: "generic_api_key"
      regex: "(?i)(api[_-]?key|token|secret)[\"'\\s]*[:=][\"'\\s]*[A-Za-z0-9+/]{20,}"
      action: redact
```

### Block SSRF Targets (Category 4)

Safe Mode already blocks `169.254.169.254`. To extend coverage, add URL deny patterns:

```yaml
tools:
  - name: http_get
    action: allow
    parameters:
      - name: url
        type: string
        deny_patterns:
          - "169\\.254\\.169\\.254"
          - "metadata\\.google\\.internal"
          - "10\\.\\d+\\.\\d+\\.\\d+"
          - "192\\.168\\.\\d+\\.\\d+"
```

---

## Benchmark in the Local Dashboard

When `agentcontrol dev` is running, the **ADR Benchmark tab** in the sidebar at `http://127.0.0.1:8080` shows the results of the last `agentcontrol bench --full` run as an interactive embedded report. This allows you to:

- See your **ADR Security Score Ring** (SVG gauge) at a glance.
- Browse per-category results without leaving the dashboard.
- Cross-reference live sequence rule violations with benchmark categories.

---

## Related Documentation

- [Configuration & Policy Reference](configuration.md) — Sequence rules, DLP patterns, and tool allowlisting.
- [Comprehensive Functional Walkthrough](comprehensive_guide.md) — Step-by-step CLI scenarios for all 10 core capabilities.
- [Documentation Hub](index.md) — Full documentation index.
