#!/usr/bin/env bash
set -e

echo "[*] AgentWall CLI Workstation Installer"

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

echo "[*] Target OS: $OS | Arch: $ARCH"

REPO="noviqtechnologies/agentwall"

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

LOCALBIN="$HOME/.local/bin"
INSTALLED_VERSION=""
if command -v agentwall &>/dev/null || [ -f "${LOCALBIN}/agentwall" ]; then
  INSTALLED_VERSION=$("${LOCALBIN}/agentwall" --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)
fi

if [[ -n "$INSTALLED_VERSION" && "v${INSTALLED_VERSION}" == "$VERSION" ]]; then
  echo "[✓] AgentWall $VERSION is already up to date."
else
  if [[ -n "$INSTALLED_VERSION" ]]; then
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

  if curl -sSL "$CHECKSUMS_URL" -o "${TEMPDIR}/checksums.txt" 2>/dev/null; then
    EXPECTED_HASH=$(grep "$ASSET_NAME" "${TEMPDIR}/checksums.txt" | awk '{print $1}' || true)
    if [[ -n "$EXPECTED_HASH" ]]; then
      if command -v sha256sum &>/dev/null; then
        ACTUAL_HASH=$(sha256sum "${TEMPDIR}/asset.zip" | awk '{print $1}')
      elif command -v shasum &>/dev/null; then
        ACTUAL_HASH=$(shasum -a 256 "${TEMPDIR}/asset.zip" | awk '{print $1}')
      fi
      if [[ -n "$ACTUAL_HASH" && "$EXPECTED_HASH" != "$ACTUAL_HASH" ]]; then
        echo "[!] Checksum mismatch!"
        exit 1
      fi
      echo "[✓] Checksum verified."
    fi
  fi

  mkdir -p "$LOCALBIN"
  unzip -q -o "${TEMPDIR}/asset.zip" -d "$TEMPDIR"
  BINARY_PATH=$(find "$TEMPDIR" -type f \( -name "agentwall" -o -name "agentwall.exe" \) | head -1 || true)
  
  if [[ -z "$BINARY_PATH" || ! -f "$BINARY_PATH" ]]; then
    echo "[!] Failed to locate agentwall binary."
    exit 1
  fi

  mv "$BINARY_PATH" "${LOCALBIN}/agentwall"
  chmod +x "${LOCALBIN}/agentwall"

  QUICKSTART_SRC=$(find "$TEMPDIR" -name "quickstart_agent.py" | head -1 || true)
  if [[ -n "$QUICKSTART_SRC" && -f "$QUICKSTART_SRC" ]]; then
    cp "$QUICKSTART_SRC" "${LOCALBIN}/quickstart_agent.py"
    chmod +x "${LOCALBIN}/quickstart_agent.py"
  fi

  echo "[✓] AgentWall binary installed to ${LOCALBIN}/agentwall"
fi

if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
  echo "[!] Warning: $HOME/.local/bin is not in your PATH."
  echo '    Add to PATH: export PATH="$HOME/.local/bin:$PATH"'
fi

echo ""
echo "Get started by securing all your AI IDE tools:"
echo "  agentwall protect"
echo ""
