#!/usr/bin/env bash
set -e

echo "[*] AgentWall Installer"

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

if [[ "$OS" == *"mingw"* || "$OS" == *"msys"* || "$OS" == *"cygwin"* ]]; then
  OS="windows"
fi

if [[ "$OS" == "darwin" ]]; then
  OS="macos"
fi

# We map architecture strings so they match our GitHub release artifacts
if [[ "$ARCH" == "amd64" ]]; then
  ARCH="x86_64"
elif [[ "$ARCH" == "arm64" ]]; then
  ARCH="aarch64"
fi

echo "[*] Detected OS: $OS"
echo "[*] Detected Arch: $ARCH"

# Parse optional flags for custom Token and Hub/Dashboard URL (including custom ports)
TOKEN="${AGENTWALL_TOKEN:-${AGENTWALL_ENROLLMENT_TOKEN:-}}"
HUB_URL="${AGENTWALL_HUB_URL:-${DASHBOARD_API_URL:-}}"

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
      echo "Usage: install.sh [-t <token>] [-u <hub-url>]"
      echo "  -t, --token           Enrollment token for enterprise onboarding"
      echo "  -u, --hub-url         Control Hub / Dashboard URL (e.g. http://host:8080)"
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

REPO="noviqtechnologies/agentwall"

# Fetch the latest release (including pre-releases) via /releases?per_page=1
# NOTE: /releases/latest only returns stable releases and would skip pre-releases.
echo "[*] Fetching latest release version..."
VERSION=$(curl -sSf "https://api.github.com/repos/${REPO}/releases?per_page=1" \
  | grep '"tag_name"' \
  | head -1 \
  | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')

if [[ -z "$VERSION" ]]; then
  echo "[!] Failed to determine the latest release version."
  exit 1
fi

echo "[*] Using version: $VERSION"

# Check currently installed version
LOCALBIN="$HOME/.local/bin"
INSTALLED_VERSION=""
if command -v agentwall &>/dev/null || [ -f "${LOCALBIN}/agentwall" ]; then
  INSTALLED_VERSION=$("${LOCALBIN}/agentwall" --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)
fi

if [[ -n "$INSTALLED_VERSION" && "v${INSTALLED_VERSION}" == "$VERSION" ]]; then
  echo ""
  echo "[✓] AgentWall $VERSION is already up to date. Nothing to do."
  exit 0
elif [[ -n "$INSTALLED_VERSION" ]]; then
  echo "[*] Upgrading $INSTALLED_VERSION → ${VERSION}..."
else
  echo "[*] Fresh install of AgentWall $VERSION..."
fi

ASSET_NAME="agentwall-${VERSION}-${OS}-${ARCH}.zip"
BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"
ASSET_URL="${BASE_URL}/${ASSET_NAME}"
CHECKSUMS_URL="${BASE_URL}/checksums.txt"

TEMPDIR=$(mktemp -d)
trap 'rm -rf "$TEMPDIR"' EXIT

echo "[*] Downloading $ASSET_URL..."
curl -sSL "$ASSET_URL" -o "${TEMPDIR}/asset.zip"

if [ ! -f "${TEMPDIR}/asset.zip" ]; then
  echo "[!] Download failed."
  exit 1
fi

echo "[*] Downloading checksums..."
if curl -sSL "$CHECKSUMS_URL" -o "${TEMPDIR}/checksums.txt" 2>/dev/null; then
  echo "[*] Verifying checksum..."
  EXPECTED_HASH=$(grep "$ASSET_NAME" "${TEMPDIR}/checksums.txt" | awk '{print $1}' || true)
  if [[ -n "$EXPECTED_HASH" ]]; then
    if command -v sha256sum &>/dev/null; then
      ACTUAL_HASH=$(sha256sum "${TEMPDIR}/asset.zip" | awk '{print $1}')
    elif command -v shasum &>/dev/null; then
      ACTUAL_HASH=$(shasum -a 256 "${TEMPDIR}/asset.zip" | awk '{print $1}')
    fi

    if [[ -n "$ACTUAL_HASH" && "$EXPECTED_HASH" != "$ACTUAL_HASH" ]]; then
      echo "[!] Checksum mismatch! Expected: $EXPECTED_HASH, Got: $ACTUAL_HASH"
      exit 1
    fi
    echo "[✓] Checksum verified."
  fi
fi

echo "[*] Extracting..."
unzip -q -o "${TEMPDIR}/asset.zip" -d "$TEMPDIR"

# Locate the binary inside the extracted archive dynamically
BINARY_PATH=$(find "$TEMPDIR" -type f \( -name "agentwall" -o -name "agentwall.exe" \) | head -1 || true)

if [[ -z "$BINARY_PATH" || ! -f "$BINARY_PATH" ]]; then
  echo "[!] Failed to locate agentwall binary inside the extracted archive."
  exit 1
fi

LOCALBIN="$HOME/.local/bin"
mkdir -p "$LOCALBIN"

echo "[*] Installing to $LOCALBIN..."
mv "$BINARY_PATH" "${LOCALBIN}/agentwall"
chmod +x "${LOCALBIN}/agentwall"

QUICKSTART_SRC=$(find "$TEMPDIR" -name "quickstart_agent.py" | head -1 || true)
if [[ -n "$QUICKSTART_SRC" && -f "$QUICKSTART_SRC" ]]; then
  cp "$QUICKSTART_SRC" "${LOCALBIN}/quickstart_agent.py"
  chmod +x "${LOCALBIN}/quickstart_agent.py"
  echo "[✓] Installed quickstart_agent.py to ${LOCALBIN}/quickstart_agent.py"
else
  curl -sSL "https://raw.githubusercontent.com/${REPO}/${VERSION}/quickstart_agent.py" -o "${LOCALBIN}/quickstart_agent.py" 2>/dev/null && chmod +x "${LOCALBIN}/quickstart_agent.py" || true
fi

echo ""
if [[ -n "$INSTALLED_VERSION" ]]; then
  echo "[✓] AgentWall upgraded from $INSTALLED_VERSION to ${VERSION} successfully!"
else
  echo "[✓] AgentWall $VERSION has been installed to ${LOCALBIN}/agentwall"
fi
echo ""

if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
  echo "[!] Warning: $HOME/.local/bin is not in your PATH."
  echo "    Please add it to your profile (e.g. ~/.bashrc, ~/.zshrc) like so:"
  echo '    export PATH="$HOME/.local/bin:$PATH"'
  echo ""
fi

# Automated Enterprise Enrollment & OS Service Registration
if [[ -z "$HUB_URL" ]]; then
  HUB_URL="http://localhost:8400"
fi

if [[ -n "$TOKEN" ]]; then
  echo "[*] Initializing Enterprise Device Governance..."
  echo "[*] Hub / Dashboard URL: ${HUB_URL}"
  echo "[*] Step 1/3: PKI Device Enrollment..."
  "${LOCALBIN}/agentwall" enroll --token "$TOKEN" --hub-url "$HUB_URL" || true

  echo "[*] Step 2/3: Installing Persistent OS Sentry Service Daemon..."
  if [ "$(id -u)" -ne 0 ] && command -v sudo &>/dev/null; then
    sudo "${LOCALBIN}/agentwall" service install --hub-url "$HUB_URL" || true
  else
    "${LOCALBIN}/agentwall" service install --hub-url "$HUB_URL" || true
  fi

  echo "[*] Step 3/3: Auto-wrapping active IDE targets..."
  "${LOCALBIN}/agentwall" wrap --all || true
  echo "[✓] Automated Enterprise Provisioning Completed!"
fi

echo "To secure all your AI IDE tools and start the gateway:"
echo "  agentwall protect"
echo ""
echo "To run the demo test script (requires Python 3.8+):"
echo "  python3 \$HOME/.local/bin/quickstart_agent.py"
echo ""
echo "Run 'agentwall --help' to get started."
