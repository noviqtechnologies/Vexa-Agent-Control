#!/usr/bin/env bash
set -euo pipefail

echo "[*] AgentWall Installer (Standalone Developer Edition)"

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

VERSION="${AGENTWALL_VERSION:-}"
MODE="${AGENTWALL_MODE:-solo}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    -v|--version)
      VERSION="$2"
      shift 2
      ;;
    -m|--mode|--edition)
      MODE="$2"
      shift 2
      ;;
    -h|--help)
      echo "Usage: install.sh [-v <version>] [-m <solo|team|enterprise>]"
      echo "  -v, --version         Version tag to install (default: latest)"
      echo "  -m, --mode, --edition Edition mode: solo (default), team, enterprise"
      exit 0
      ;;
    *)
      shift
      ;;
  esac
done

REPO="noviqtechnologies/agentwall"

if [[ -z "$VERSION" ]]; then
  echo "[*] Fetching latest release version from GitHub..."
  VERSION=$(curl -sSf "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep '"tag_name"' \
    | head -1 \
    | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')
  if [[ -z "$VERSION" ]]; then
    echo "[!] Error: Failed to determine the latest release version. Use -v to specify one."
    exit 1
  fi
  echo "[*] Latest version: $VERSION"
fi

# Ensure version tag has 'v' prefix
if [[ "$VERSION" != v* ]]; then
  VERSION="v${VERSION}"
fi

echo "[*] Target version: $VERSION"

LOCALBIN="$HOME/.local/bin"
mkdir -p "$LOCALBIN"
INSTALLED_VERSION=""
if command -v agentwall &>/dev/null || [ -f "${LOCALBIN}/agentwall" ]; then
  INSTALLED_VERSION=$("${LOCALBIN}/agentwall" --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)
fi

if [[ -n "$INSTALLED_VERSION" && "v${INSTALLED_VERSION}" == "$VERSION" ]]; then
  echo ""
  echo "[✓] AgentWall $VERSION is already installed and up to date."
  exit 0
elif [[ -n "$INSTALLED_VERSION" ]]; then
  echo "[*] Upgrading v$INSTALLED_VERSION → ${VERSION}..."
else
  echo "[*] Fresh install of AgentWall $VERSION..."
fi

ASSET_NAME="agentwall-${VERSION}-${OS}-${ARCH}.zip"
BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"
ASSET_URL="${BASE_URL}/${ASSET_NAME}"
CHECKSUMS_URL="${BASE_URL}/checksums.txt"

TEMPDIR=$(mktemp -d)
trap 'rm -rf "$TEMPDIR"' EXIT

echo "[*] Downloading release artifact: $ASSET_URL..."
if ! curl -sSL "$ASSET_URL" -o "${TEMPDIR}/asset.zip"; then
  echo "[!] Error: Failed to download release asset from $ASSET_URL"
  exit 1
fi

if [ ! -f "${TEMPDIR}/asset.zip" ]; then
  echo "[!] Error: Downloaded file missing."
  exit 1
fi

echo "[*] Downloading checksum manifest: $CHECKSUMS_URL..."
if ! curl -sSL "$CHECKSUMS_URL" -o "${TEMPDIR}/checksums.txt"; then
  echo "[!] Mandatory Security Check Failed: Unable to retrieve checksums.txt."
  exit 1
fi

echo "[*] Verifying cryptographic SHA-256 checksum..."
EXPECTED_HASH=$(grep "$ASSET_NAME" "${TEMPDIR}/checksums.txt" | awk '{print $1}' || true)
if [[ -z "$EXPECTED_HASH" ]]; then
  echo "[!] Security Violation: No matching checksum entry found for $ASSET_NAME in checksums.txt."
  exit 1
fi

ACTUAL_HASH=""
if command -v sha256sum &>/dev/null; then
  ACTUAL_HASH=$(sha256sum "${TEMPDIR}/asset.zip" | awk '{print $1}')
elif command -v shasum &>/dev/null; then
  ACTUAL_HASH=$(shasum -a 256 "${TEMPDIR}/asset.zip" | awk '{print $1}')
else
  echo "[!] Security Violation: Neither sha256sum nor shasum is available on host system."
  exit 1
fi

if [[ "$EXPECTED_HASH" != "$ACTUAL_HASH" ]]; then
  echo "[!] Cryptographic Checksum Mismatch!"
  echo "    Expected: $EXPECTED_HASH"
  echo "    Got:      $ACTUAL_HASH"
  exit 1
fi
echo "[✓] Checksum verified successfully."

echo "[*] Extracting package..."
unzip -q -o "${TEMPDIR}/asset.zip" -d "$TEMPDIR"

BINARY_PATH=$(find "$TEMPDIR" -type f \( -name "agentwall" -o -name "agentwall.exe" \) | head -1 || true)
if [[ -z "$BINARY_PATH" || ! -f "$BINARY_PATH" ]]; then
  echo "[!] Error: Failed to locate agentwall binary inside the extracted archive."
  exit 1
fi

echo "[*] Installing binary to ${LOCALBIN}/agentcontrol..."
cp "$BINARY_PATH" "${LOCALBIN}/agentcontrol"
chmod +x "${LOCALBIN}/agentcontrol"
ln -sf "${LOCALBIN}/agentcontrol" "${LOCALBIN}/agentwall" || cp "$BINARY_PATH" "${LOCALBIN}/agentwall"

QUICKSTART_SRC=$(find "$TEMPDIR" -name "quickstart_agent.py" | head -1 || true)
if [[ -n "$QUICKSTART_SRC" && -f "$QUICKSTART_SRC" ]]; then
  cp "$QUICKSTART_SRC" "${LOCALBIN}/quickstart_agent.py"
  chmod +x "${LOCALBIN}/quickstart_agent.py"
fi

echo ""
echo "[✓] Vexa Agent Control $VERSION successfully installed to ${LOCALBIN}/agentcontrol (and alias agentwall)"
echo ""

if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
  echo "[!] Note: Add $HOME/.local/bin to your PATH to run 'agentcontrol' directly:"
  echo '    export PATH="$HOME/.local/bin:$PATH"'
  echo ""
fi

if [[ "$MODE" == "team" ]]; then
  echo "Installing Vexa Agent Control: Team Edition..."
  echo "To join your team workspace, run:"
  echo "  agentcontrol join --token <YOUR_ORGANIZATION_TOKEN>"
else
  echo "Installing Vexa Agent Control: Standalone (Solo Edition)..."
  echo "To secure all installed AI IDEs and start local protection:"
  echo "  agentcontrol protect"
fi
echo ""


