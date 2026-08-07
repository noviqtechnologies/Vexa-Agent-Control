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
ASSET_URL="https://github.com/noviqtechnologies/agentwall/releases/download/${VERSION}/${ASSET_NAME}"

TEMPDIR=$(mktemp -d)
trap 'rm -rf "$TEMPDIR"' EXIT

echo "[*] Downloading $ASSET_URL..."
curl -sSL "$ASSET_URL" -o "${TEMPDIR}/asset.zip"

if [ ! -f "${TEMPDIR}/asset.zip" ]; then
  echo "[!] Download failed."
  exit 1
fi

echo "[*] Extracting..."
unzip -q -o "${TEMPDIR}/asset.zip" -d "$TEMPDIR"

BINARY_PATH="${TEMPDIR}/bin/agentwall"
if [[ "$OS" == "windows" ]]; then
  BINARY_PATH="${TEMPDIR}/bin/agentwall.exe"
fi

if [ ! -f "$BINARY_PATH" ]; then
  echo "[!] Failed to locate the binary inside the extracted archive at $BINARY_PATH."
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
HUB_URL="${AGENTWALL_HUB_URL:-http://localhost:8400}"
TOKEN="${AGENTWALL_TOKEN:-$1}"

if [[ -n "$TOKEN" ]]; then
  echo "[*] Initializing Enterprise Device Governance..."
  echo "[*] Step 1/3: PKI Device Enrollment..."
  "${LOCALBIN}/agentwall" enroll --token "$TOKEN" --hub-url "$HUB_URL" || true

  echo "[*] Step 2/3: Installing Persistent OS Sentry Service Daemon..."
  "${LOCALBIN}/agentwall" service install --hub-url "$HUB_URL" || true

  echo "[*] Step 3/3: Auto-wrapping active IDE targets..."
  "${LOCALBIN}/agentwall" wrap --all || true
  echo "[✓] Automated Enterprise Provisioning Completed!"
fi

echo "To run the demo test script (requires Python 3.8+):"
echo "  python3 \$HOME/.local/bin/quickstart_agent.py"
echo ""
echo "Run 'agentwall --help' to get started."
