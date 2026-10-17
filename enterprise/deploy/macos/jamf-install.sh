#!/bin/bash
# ==============================================================================
# Jamf Pro / Kandji / Fleet Deployment Script for Vexa Agent Control (macOS)
# ==============================================================================
# Installs Vexa Agent Control as a managed LaunchDaemon on macOS (Intel/Apple Silicon)
# Sets up mandatory system environment variables and manages daemon health.
# ==============================================================================

set -euo pipefail

VERSION="v1.0.95"
INSTALL_DIR="/usr/local/bin"
LOG_DIR="/var/log/agentcontrol"
PLIST_PATH="/Library/LaunchDaemons/io.vexasec.agentcontrol.plist"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] $*"
}

log_err() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] $*" >&2
}

if [[ $EUID -ne 0 ]]; then
   log_err "This deployment script must be run as root (via MDM or sudo)."
   exit 1
fi

log "=== Deploying Vexa Agent Control Sentry on macOS ==="

# 1. Detect Architecture
ARCH=$(uname -m)
case "$ARCH" in
    x86_64)  TARGET_ARCH="x86_64-apple-darwin" ;;
    arm64)   TARGET_ARCH="aarch64-apple-darwin" ;;
    *)       log_err "Unsupported macOS architecture: $ARCH"; exit 1 ;;
esac
log "Detected architecture: $ARCH ($TARGET_ARCH)"

# 2. Prepare Directories
mkdir -p "$INSTALL_DIR"
mkdir -p "$LOG_DIR"
chmod 755 "$LOG_DIR"

# 3. Unload existing LaunchDaemon if running
if launchctl list | grep -q "io.vexasec.agentcontrol"; then
    log "Unloading existing LaunchDaemon..."
    launchctl bootout system "$PLIST_PATH" 2>/dev/null || launchctl unload "$PLIST_PATH" 2>/dev/null || true
fi

# 4. Download and Install Binary if not bundled locally
BIN_PATH="$INSTALL_DIR/agentcontrol"
if [[ -f "./agentcontrol" ]]; then
    log "Installing bundled local binary..."
    cp "./agentcontrol" "$BIN_PATH"
else
    log "Downloading pinned release $VERSION for $TARGET_ARCH..."
    ARCHIVE_URL="https://github.com/noviqtechnologies/Vexa-Agent-Control/releases/download/${VERSION}/agentcontrol-${TARGET_ARCH}.tar.gz"
    TEMP_DIR=$(mktemp -d)
    curl -fL --proto '=https' --tlsv1.2 "$ARCHIVE_URL" -o "$TEMP_DIR/agentcontrol.tar.gz"
    tar -xzf "$TEMP_DIR/agentcontrol.tar.gz" -C "$TEMP_DIR"
    cp "$TEMP_DIR/agentcontrol" "$BIN_PATH"
    rm -rf "$TEMP_DIR"
fi

chmod 755 "$BIN_PATH"
chown root:wheel "$BIN_PATH"
log "Installed binary to $BIN_PATH"

# 5. Deploy LaunchDaemon Plist
cat << 'EOF' > "$PLIST_PATH"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>io.vexasec.agentcontrol</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/agentcontrol</string>
        <string>start</string>
        <string>--port</string>
        <string>18080</string>
        <string>--log-dir</string>
        <string>/var/log/agentcontrol</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
        <key>NetworkState</key>
        <true/>
    </dict>
    <key>StandardOutPath</key>
    <string>/var/log/agentcontrol/daemon.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/agentcontrol/daemon.err</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
        <key>AGENTCONTROL_GATEWAY_URL</key>
        <string>http://127.0.0.1:18080</string>
    </dict>
</dict>
</plist>
EOF

chmod 644 "$PLIST_PATH"
chown root:wheel "$PLIST_PATH"

# 6. Load and Start LaunchDaemon
log "Loading LaunchDaemon into system domain..."
launchctl bootstrap system "$PLIST_PATH" || launchctl load "$PLIST_PATH"

# 7. Configure System-wide Environment Variable for Terminal Sessions
ENV_FILE="/etc/paths.d/agentcontrol"
echo "/usr/local/bin" > "$ENV_FILE"
chmod 644 "$ENV_FILE"

log "Verification check:"
"$BIN_PATH" --version
log "Vexa Agent Control macOS deployment completed successfully."
exit 0
