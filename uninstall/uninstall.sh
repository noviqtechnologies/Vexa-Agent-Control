#!/usr/bin/env bash
set -e

echo "============================================="
echo "    Vexa Agent Control Clean Uninstaller     "
echo "============================================="

KEEP_CONFIG=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    --keep-config|-k)
      KEEP_CONFIG=true
      shift
      ;;
    -h|--help)
      echo "Usage: uninstall.sh [--keep-config]"
      echo "  --keep-config, -k  Retain local configuration, logs, and PKI credentials"
      exit 0
      ;;
    *)
      shift
      ;;
  esac
done

LOCALBIN="$HOME/.local/bin"
AGENTCONTROL_BIN=""

if [ -x "${LOCALBIN}/agentcontrol" ]; then
  AGENTCONTROL_BIN="${LOCALBIN}/agentcontrol"
elif command -v agentcontrol &>/dev/null; then
  AGENTCONTROL_BIN="$(command -v agentcontrol)"
elif [ -x "${LOCALBIN}/agentwall" ]; then
  AGENTCONTROL_BIN="${LOCALBIN}/agentwall"
elif command -v agentwall &>/dev/null; then
  AGENTCONTROL_BIN="$(command -v agentwall)"
fi

# Step 1: Unprotect all IDE targets (restore original MCP configurations from backups)
if [ -n "$AGENTCONTROL_BIN" ] && [ -x "$AGENTCONTROL_BIN" ]; then
  echo "[*] Step 1/5: Restoring original MCP configurations across all IDEs..."
  "$AGENTCONTROL_BIN" unprotect --force 2>/dev/null || echo "[!] Notice: IDE unprotect skipped or completed with warnings."
else
  echo "[!] Notice: Binary not found; skipping IDE unprotect step."
fi

# Step 2: Stop and uninstall persistent OS daemon service
echo "[*] Step 2/5: Uninstalling Agent Control service daemon..."
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
  echo "[✓] Checked macOS LaunchAgent service registrations."
elif [[ "$OS" == *"linux"* ]]; then
  for svc in "agent-control.service" "agentcontrol.service" "agentwall.service" "agentwall-sentry.service"; do
    systemctl --user stop "$svc" 2>/dev/null || true
    systemctl --user disable "$svc" 2>/dev/null || true
    rm -f "$HOME/.config/systemd/user/$svc"
  done
  systemctl --user daemon-reload 2>/dev/null || true
  echo "[✓] Checked Linux systemd user service registrations."
fi

# Step 3: Remove Root CA certificate from OS trust store
echo "[*] Step 3/5: Cleaning Root CA certificates from trust store..."
if [[ "$OS" == *"darwin"* || "$OS" == *"mac"* ]]; then
  for ca_name in "Vexa Agent Control CA" "Agent Control Local CA" "AgentWall Root CA"; do
    for keychain in "$HOME/Library/Keychains/login.keychain-db" "$HOME/Library/Keychains/login.keychain"; do
      if [ -f "$keychain" ]; then
        security delete-certificate -c "$ca_name" "$keychain" 2>/dev/null || true
      fi
    done
  done
  echo "[✓] Cleaned CA certificates from macOS Keychain."
fi

# Step 4: Remove binary executables
echo "[*] Step 4/5: Removing binary executables..."
rm -f "${LOCALBIN}/agentcontrol"
rm -f "${LOCALBIN}/.agentcontrol.new"
rm -f "${LOCALBIN}/agentwall"
rm -f "${LOCALBIN}/quickstart_agent.py"
rm -f "${LOCALBIN}/.quickstart_agent.py.new"
echo "[✓] Removed binaries from ${LOCALBIN}."

# Step 5: Purge local configuration, logs, and PKI credentials
if [ "$KEEP_CONFIG" = false ]; then
  echo "[*] Step 5/5: Purging configuration, logs, and credentials..."
  for cdir in "$HOME/.agentcontrol" "$HOME/.agent-control" "$HOME/.agentwall"; do
    if [ -d "$cdir" ]; then
      rm -rf "$cdir"
      echo "[✓] Purged ${cdir}."
    fi
  done
else
  echo "[*] Step 5/5: Skipping configuration purge (--keep-config specified)."
fi

echo ""
echo "[✓] Vexa Agent Control has been cleanly uninstalled from your machine."
