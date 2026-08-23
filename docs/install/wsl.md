# Windows Subsystem for Linux (WSL2) Guide

This guide explains how Vexa Agent Control functions inside WSL2 and defines the protection boundary between the Linux guest and Windows host.

---

## The WSL Protection Boundary

> [!IMPORTANT]
> **Understanding the Boundary:**
> - When `agentcontrol` is installed **inside WSL2**, it protects CLI agents, Python/Node scripts, and MCP servers running **inside the WSL Linux environment**.
> - It does **not** automatically modify Windows-host IDE configuration files (such as Claude Desktop running on Windows) unless you also install and run `agentcontrol` on the Windows host.
> - If your AI agents execute inside WSL (e.g. VS Code Remote-WSL), install `agentcontrol` inside WSL.
> - If your AI desktop apps run natively on Windows, install `agentcontrol` in Windows PowerShell.

---

## Installation inside WSL

1. Open your WSL2 distribution terminal (Ubuntu / Debian).
2. Execute the Linux installer script:
   ```bash
   curl -fsSL https://raw.githubusercontent.com/noviqtechnologies/Vexa-Agent-Control/main/install/install.sh | bash
   export PATH="$HOME/.local/bin:$PATH"
   agentcontrol --version
   ```

---

## Running in WSL

Launch the local security gateway:

```bash
agentcontrol protect
```

### Browser Opening in WSL
Vexa Agent Control detects WSL environments automatically:
1. It attempts to launch `wslview` to open the Local Dashboard in your default Windows browser.
2. If `wslview` is not available, it calls `/mnt/c/Windows/System32/cmd.exe /c start <url>`.
3. If run in headless mode or if browser launch fails, simply open your browser on Windows and navigate to:
   ```text
   http://localhost:8080
   ```
   *(WSL2 mirrors localhost ports to the Windows host automatically).*

---

## Protecting Python / Custom Agents in WSL

For agents running inside WSL (e.g., LangChain, CrewAI, AutoGen):

```bash
export AGENTCONTROL_PROXY_URL="http://127.0.0.1:8080"
export HTTP_PROXY="http://127.0.0.1:8080"
export HTTPS_PROXY="http://127.0.0.1:8080"

python my_agent.py
```

---

## Verification & Removal

Run the 3-point live smoke test from within WSL:

```bash
agentcontrol verify
```

To clean up:
```bash
curl -fsSL https://raw.githubusercontent.com/noviqtechnologies/Vexa-Agent-Control/main/uninstall.sh | bash
```
