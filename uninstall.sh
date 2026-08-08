#!/usr/bin/env bash
set -e

echo "============================================="
echo "        AgentWall Clean Uninstaller         "
echo "============================================="

LOCALBIN="$HOME/.local/bin"
AGENTWALL_BIN=""

if command -v agentwall &>/dev/null; then
  AGENTWALL_BIN="$(command -v agentwall)"
elif [ -f "${LOCALBIN}/agentwall" ]; then
  AGENTWALL_BIN="${LOCALBIN}/agentwall"
fi

# Step 1: Unwrap all IDE targets (restore original MCP configurations)
if [ -n "$AGENTWALL_BIN" ] && [ -x "$AGENTWALL_BIN" ]; then
  echo "[*] Step 1/4: Unwrapping MCP servers across all IDEs..."
  "$AGENTWALL_BIN" unwrap --all 2>/dev/null || echo "[!] Notice: IDE unwrap skipped or completed with warnings."
else
  echo "[!] Notice: agentwall binary not found; skipping IDE unwrap step."
fi

# Step 2: Stop and uninstall persistent OS daemon service
echo "[*] Step 2/4: Uninstalling AgentWall service daemon..."
if [ -n "$AGENTWALL_BIN" ] && [ -x "$AGENTWALL_BIN" ]; then
  "$AGENTWALL_BIN" service uninstall 2>/dev/null || true
fi

# Fallback service cleanup for Linux systemd / macOS launchd
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
if [[ "$OS" == *"darwin"* || "$OS" == *"mac"* ]]; then
  LAUNCHD_PLIST="$HOME/Library/LaunchAgents/com.agentwall.sentry.plist"
  if [ -f "$LAUNCHD_PLIST" ]; then
    launchctl unload "$LAUNCHD_PLIST" 2>/dev/null || true
    rm -f "$LAUNCHD_PLIST"
    echo "[✓] Removed macOS LaunchAgent plist."
  fi
elif [[ "$OS" == *"linux"* ]]; then
  SYSTEMD_SERVICE="$HOME/.config/systemd/user/agentwall-sentry.service"
  if [ -f "$SYSTEMD_SERVICE" ]; then
    systemctl --user stop agentwall-sentry.service 2>/dev/null || true
    systemctl --user disable agentwall-sentry.service 2>/dev/null || true
    rm -f "$SYSTEMD_SERVICE"
    systemctl --user daemon-reload 2>/dev/null || true
    echo "[✓] Removed Linux systemd user service."
  fi
fi

# Step 3: Remove binary executables
echo "[*] Step 3/4: Removing binary executables..."
rm -f "${LOCALBIN}/agentwall"
rm -f "${LOCALBIN}/quickstart_agent.py"
echo "[✓] Removed binaries from ${LOCALBIN}."

# Step 4: Purge local configuration and PKI credentials
echo "[*] Step 4/4: Purging configuration and credentials..."
CONFIG_DIR="$HOME/.agentwall"
if [ -d "$CONFIG_DIR" ]; then
  rm -rf "$CONFIG_DIR"
  echo "[✓] Purged ${CONFIG_DIR}."
fi

echo ""
echo "[✓] AgentWall has been cleanly uninstalled from your machine."
