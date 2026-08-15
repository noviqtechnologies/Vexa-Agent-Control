#!/usr/bin/env bash
set -e

echo "============================================="
echo "    Vexa Agent Control Clean Uninstaller     "
echo "============================================="

LOCALBIN="$HOME/.local/bin"
AGENTCONTROL_BIN=""

if command -v agentcontrol &>/dev/null; then
  AGENTCONTROL_BIN="$(command -v agentcontrol)"
elif [ -f "${LOCALBIN}/agentcontrol" ]; then
  AGENTCONTROL_BIN="${LOCALBIN}/agentcontrol"
elif command -v agentwall &>/dev/null; then
  AGENTCONTROL_BIN="$(command -v agentwall)"
elif [ -f "${LOCALBIN}/agentwall" ]; then
  AGENTCONTROL_BIN="${LOCALBIN}/agentwall"
fi

# Step 1: Unwrap all IDE targets (restore original MCP configurations)
if [ -n "$AGENTCONTROL_BIN" ] && [ -x "$AGENTCONTROL_BIN" ]; then
  echo "[*] Step 1/4: Unwrapping MCP servers across all IDEs..."
  "$AGENTCONTROL_BIN" unwrap --all 2>/dev/null || echo "[!] Notice: IDE unwrap skipped or completed with warnings."
else
  echo "[!] Notice: binary not found; skipping IDE unwrap step."
fi

# Step 2: Stop and uninstall persistent OS daemon service
echo "[*] Step 2/4: Uninstalling Agent Control service daemon..."
if [ -n "$AGENTCONTROL_BIN" ] && [ -x "$AGENTCONTROL_BIN" ]; then
  "$AGENTCONTROL_BIN" service uninstall 2>/dev/null || true
fi

# Fallback service cleanup for Linux systemd / macOS launchd
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
if [[ "$OS" == *"darwin"* || "$OS" == *"mac"* ]]; then
  for plist in "$HOME/Library/LaunchAgents/io.vexasec.agentcontrol.plist" "$HOME/Library/LaunchAgents/io.vexasec.agentwall.plist" "$HOME/Library/LaunchAgents/com.agentwall.sentry.plist"; do
    if [ -f "$plist" ]; then
      launchctl unload "$plist" 2>/dev/null || true
      rm -f "$plist"
    fi
  done
  echo "[✓] Removed macOS LaunchAgent plists."
elif [[ "$OS" == *"linux"* ]]; then
  for svc in "agent-control.service" "agentwall.service" "agentwall-sentry.service"; do
    systemctl --user stop "$svc" 2>/dev/null || true
    systemctl --user disable "$svc" 2>/dev/null || true
    rm -f "$HOME/.config/systemd/user/$svc"
  done
  systemctl --user daemon-reload 2>/dev/null || true
  echo "[✓] Removed Linux systemd user services."
fi

# Step 3: Remove binary executables
echo "[*] Step 3/4: Removing binary executables..."
rm -f "${LOCALBIN}/agentcontrol"
rm -f "${LOCALBIN}/agentwall"
rm -f "${LOCALBIN}/quickstart_agent.py"
echo "[✓] Removed binaries from ${LOCALBIN}."

# Step 4: Purge local configuration and PKI credentials
echo "[*] Step 4/4: Purging configuration and credentials..."
for cdir in "$HOME/.agent-control" "$HOME/.agentwall"; do
  if [ -d "$cdir" ]; then
    rm -rf "$cdir"
    echo "[✓] Purged ${cdir}."
  fi
done

echo ""
echo "[✓] Vexa Agent Control has been cleanly uninstalled from your machine."
