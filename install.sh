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

echo "Run 'agentwall --help' to get started."
