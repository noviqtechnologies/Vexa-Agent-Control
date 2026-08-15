#!/usr/bin/env bash
set -e

echo "[*] AgentWall Team OTET Enterprise Provisioning Installer"

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

if [[ "$OS" == *"mingw"* || "$OS" == *"msys"* || "$OS" == *"cygwin"* ]]; then
  OS="windows"
fi

if [[ "$OS" == "darwin" ]]; then
  OS="macos"
fi

if [[ "$ARCH" == "amd64" ]]; then
  ARCH="x86_64"
elif [[ "$ARCH" == "arm64" ]]; then
  ARCH="aarch64"
fi

TOKEN="${AGENTWALL_TOKEN:-${AGENTWALL_ENROLLMENT_TOKEN:-}}"
HUB_URL="${AGENTWALL_HUB_URL:-${DASHBOARD_API_URL:-http://localhost:8400}}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    -t|--token)
      TOKEN="$2"
      shift 2
      ;;
    -u|--hub-url|-d|--dashboard-url)
      HUB_URL="$2"
      shift 2
      ;;
    -h|--help)
      echo "Usage: team_otet.sh -t <token> [-u <hub-url>]"
      echo "  -t, --token    Enrollment token for enterprise onboarding"
      echo "  -u, --hub-url  Control Hub / Dashboard URL (e.g. http://host:8400)"
      exit 0
      ;;
    *)
      if [[ -z "$TOKEN" ]]; then
        TOKEN="$1"
      fi
      shift
      ;;
  esac
done

if [[ -z "$TOKEN" ]]; then
  echo "[!] Error: Enterprise enrollment token required."
  echo "    Usage: ./install/team_otet.sh -t <TOKEN> [-u <HUB_URL>]"
  exit 1
fi

INSTALL_DIR="${HOME}/.local/bin"
REPO="noviqtechnologies/Vexa-Agent-Control"
echo "[*] Fetching latest release version..."
VERSION=$(curl -sSf "https://api.github.com/repos/${REPO}/releases?per_page=1" \
  | grep '"tag_name"' \
  | head -1 \
  | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')

if [[ -z "$VERSION" ]]; then
  echo "[!] Failed to determine latest release version."
  exit 1
fi

echo "[*] Version: $VERSION | OS: $OS | Hub: $HUB_URL"

LOCALBIN="$HOME/.local/bin"
ASSET_NAME="agentwall-${VERSION}-${OS}-${ARCH}.zip"
BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"
ASSET_URL="${BASE_URL}/${ASSET_NAME}"

TEMPDIR=$(mktemp -d)
trap 'rm -rf "$TEMPDIR"' EXIT

echo "[*] Downloading asset package..."
curl -sSL "$ASSET_URL" -o "${TEMPDIR}/asset.zip"

mkdir -p "$LOCALBIN"
unzip -q -o "${TEMPDIR}/asset.zip" -d "$TEMPDIR"
BINARY_PATH=$(find "$TEMPDIR" -type f \( -name "agentwall" -o -name "agentwall.exe" \) | head -1 || true)

mv "$BINARY_PATH" "${LOCALBIN}/agentwall"
chmod +x "${LOCALBIN}/agentwall"

echo "[*] Initializing Enterprise Device Governance..."
echo "[*] Step 1/3: PKI Device Enrollment..."
if ! "${LOCALBIN}/agentwall" enroll --token "$TOKEN" --hub-url "$HUB_URL"; then
  echo "[!] Enrollment failed. Aborting provisioning."
  exit 1
fi

echo "[*] Step 2/3: Installing Persistent OS Sentry Daemon..."
if [ "$(id -u)" -ne 0 ] && command -v sudo &>/dev/null; then
  sudo "${LOCALBIN}/agentwall" service install --hub-url "$HUB_URL" || echo "[!] Note: Could not install machine-level system service without root."
else
  "${LOCALBIN}/agentwall" service install --hub-url "$HUB_URL" || echo "[!] Note: Sentry service installation requires appropriate permissions."
fi

echo "[*] Step 3/3: Auto-wrapping active IDE targets..."
"${LOCALBIN}/agentwall" wrap --all || true

echo ""
echo "[+] Automated Enterprise Provisioning Completed!"
echo "Get started by running:"
echo "  agentwall protect"
echo ""
