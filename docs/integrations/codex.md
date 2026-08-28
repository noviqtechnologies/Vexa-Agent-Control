# ChatGPT Codex Integration Guide

This guide details configuring Vexa Agent Control to intercept and secure tool calls from OpenAI ChatGPT Codex agents.

---

## Configuration Location

Codex stores agent tool configurations in:
- **macOS / Linux:** `~/.codex/config.toml`
- **Windows:** `%USERPROFILE%\.codex\config.toml`

---

## Setup Instructions

1. **Verify Configuration Exists:**
   ```bash
   agentcontrol status
   ```

2. **Wrap Codex MCP Servers:**
   ```bash
   agentcontrol wrap codex
   ```

3. **Start Security Gateway:**
   ```bash
   agentcontrol protect
   ```

4. **Verify Enforcement:**
   ```bash
   agentcontrol verify
   ```

---

## Unwrapping Codex

To restore the original Codex configuration from its timestamped backup:
```bash
agentcontrol unwrap codex
```
