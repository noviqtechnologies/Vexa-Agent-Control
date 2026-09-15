# VS Code Continue Integration Guide

This guide details how to govern the **Continue** open-source AI code assistant in Visual Studio Code with **Vexa Agent Control**.

---

## Overview

Continue connects to customizable model providers via standard OpenAI or Anthropic API formats.
When connected, Vexa Agent Control redirects Continue's model completions through the local loopback proxy (`127.0.0.1:18080`), applying inline DLP, prompt-injection defense, and spend ledger tracking.

---

## Configuration File Location

- **All Platforms:** `~/.continue/config.json` (or `%USERPROFILE%\.continue\config.json` on Windows).

---

## Connecting Continue

Run:

```bash
agentcontrol connect vscode-continue
```

### What Happens During Connect:

1. **Safety Backup:**
   A backup is saved to `~/.agentcontrol/backups/continue.config.<timestamp>.bak`.
   An immutable baseline `.agentcontrol.baseline.bak` is initialized if not present.

2. **Model Provider Routing:**
   `~/.continue/config.json` is updated to route models through Agent Control:
   ```json
   {
     "models": [
       {
         "title": "Vexa Governed (Auto-Route)",
         "provider": "openai",
         "model": "gpt-4o",
         "apiBase": "http://127.0.0.1:18080/v1",
         "apiKey": "local-proxy-session-token"
       }
     ]
   }
   ```

3. **Ownership Manifest:**
   An ownership manifest is written to `~/.agentcontrol/manifests/vscode-continue.manifest.json`.

---

## Disconnecting Continue

To cleanly disconnect Continue:

```bash
agentcontrol disconnect vscode-continue
```

- Agent Control removes the injected `apiBase` and resets the managed model configuration.
- Any custom slash commands, contexts (`@code`, `@docs`), and custom keybindings configured in `config.json` remain untouched.

---

## Verification

```bash
agentcontrol doctor
agentcontrol status
```
Continue will be reported as `CONFIGURED` with freshness tier `ACTIVE_FRESH`.
