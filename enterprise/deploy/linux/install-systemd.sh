#!/usr/bin/env bash
# ==============================================================================
# Linux Enterprise Systemd Deployment Script for Vexa Agent Control
# ==============================================================================
# Automates installation of agentcontrol as a secured, sandboxed systemd service
# across Ubuntu, Debian, RHEL, CentOS, Rocky Linux, and Fedora.
# ==============================================================================

set -euo pipefail

VERSION="v1.0.95"
INSTALL_BIN="/usr/local/bin/agentcontrol"
SYSTEMD_UNIT="/etc/systemd/system/agentcontrol.service"
LOG_DIR="/var/log/agentcontrol"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] $*"
}

log_err() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] $*" >&2
}

if [[ $EUID -ne 0 ]]; then
   log_err "This deployment script must be run as root (sudo)."
   exit 1
fi

log "=== Deploying Vexa Agent Control on Linux (systemd) ==="

# 1. Detect Architecture
ARCH=$(uname -m)
case "$ARCH" in
    x86_64)   TARGET_ARCH="x86_64-unknown-linux-gnu" ;;
    aarch64)  TARGET_ARCH="aarch64-unknown-linux-gnu" ;;
    arm64)    TARGET_ARCH="aarch64-unknown-linux-gnu" ;;
    *)        log_err "Unsupported Linux architecture: $ARCH"; exit 1 ;;
esac

# 2. Install Binary
if [[ -f "./agentcontrol" ]]; then
    log "Installing bundled local binary..."
    cp "./agentcontrol" "$INSTALL_BIN"
else
    log "Downloading release $VERSION ($TARGET_ARCH)..."
    ARCHIVE_URL="https://github.com/noviqtechnologies/Vexa-Agent-Control/releases/download/${VERSION}/agentcontrol-${TARGET_ARCH}.tar.gz"
    TEMP_DIR=$(mktemp -d)
    curl -fL --proto '=https' --tlsv1.2 "$ARCHIVE_URL" -o "$TEMP_DIR/agentcontrol.tar.gz"
    tar -xzf "$TEMP_DIR/agentcontrol.tar.gz" -C "$TEMP_DIR"
    cp "$TEMP_DIR/agentcontrol" "$INSTALL_BIN"
    rm -rf "$TEMP_DIR"
fi

chmod 755 "$INSTALL_BIN"
chown root:root "$INSTALL_BIN"
log "Installed binary to $INSTALL_BIN"

# 3. Create Log Directory
mkdir -p "$LOG_DIR"
chmod 755 "$LOG_DIR"

# 4. Install Systemd Unit
cat << 'EOF' > "$SYSTEMD_UNIT"
[Unit]
Description=Vexa Agent Control Sentry Daemon
Documentation=https://github.com/noviqtechnologies/Vexa-Agent-Control
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/agentcontrol start --port 18080 --log-dir /var/log/agentcontrol
Restart=always
RestartSec=5s

# Security and Sandboxing
DynamicUser=yes
StateDirectory=agentcontrol
LogsDirectory=agentcontrol
RuntimeDirectory=agentcontrol
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
ProtectSystem=strict
ProtectHome=read-only
NoNewPrivileges=yes
PrivateTmp=yes

Environment=AGENTCONTROL_GATEWAY_URL=http://127.0.0.1:18080

[Install]
WantedBy=multi-user.target
EOF

chmod 644 "$SYSTEMD_UNIT"

# 5. Reload and Enable Service
log "Reloading systemd daemon and enabling service..."
systemctl daemon-reload
systemctl enable --now agentcontrol.service

# 6. Set System-wide Profile Variable
echo "export AGENTCONTROL_GATEWAY_URL=http://127.0.0.1:18080" > /etc/profile.d/agentcontrol.sh
chmod 644 /etc/profile.d/agentcontrol.sh

log "Verification check:"
systemctl status agentcontrol.service --no-pager
"$INSTALL_BIN" --version
log "Linux enterprise deployment completed successfully."
exit 0
