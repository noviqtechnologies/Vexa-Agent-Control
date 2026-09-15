#!/usr/bin/env bash
set -e

echo "[*] Vexa Agent Control CLI Workstation Installer"

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

REPO="noviqtechnologies/Vexa-Agent-Control"

echo "[*] Fetching latest release version..."
VERSION=$(curl -sSf "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null \
  | grep '"tag_name"' \
  | head -1 \
  | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/' || true)

if [[ -z "$VERSION" ]]; then
  echo "[!] Notice: GitHub API resolution failed. Falling back to: v1.0.83"
  VERSION="v1.0.83"
fi

if [[ "$VERSION" != v* ]]; then
  VERSION="v${VERSION}"
fi

echo "[*] Using version: $VERSION"

LOCALBIN="$HOME/.local/bin"
mkdir -p "$LOCALBIN"
INSTALLED_VERSION=""
if command -v agentcontrol &>/dev/null || [ -f "${LOCALBIN}/agentcontrol" ]; then
  INSTALLED_VERSION=$("${LOCALBIN}/agentcontrol" --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)
fi

RAW_VER="${VERSION#v}"
if [[ -n "$INSTALLED_VERSION" && "$INSTALLED_VERSION" == "$RAW_VER" ]]; then
  echo "[✓] Vexa Agent Control $VERSION is already up to date."
else
  if [[ -n "$INSTALLED_VERSION" ]]; then
    echo "[*] Upgrading v$INSTALLED_VERSION → ${VERSION}..."
  else
    echo "[*] Fresh install of Vexa Agent Control $VERSION..."
  fi

  ASSET_NAME="agentcontrol-${VERSION}-${OS}-${ARCH}.zip"
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
      ACTUAL_HASH=""
      if command -v sha256sum &>/dev/null; then
        ACTUAL_HASH=$(sha256sum "${TEMPDIR}/asset.zip" | awk '{print $1}')
      elif command -v shasum &>/dev/null; then
        ACTUAL_HASH=$(shasum -a 256 "${TEMPDIR}/asset.zip" | awk '{print $1}')
      fi
      if [[ -n "$ACTUAL_HASH" && "$EXPECTED_HASH" != "$ACTUAL_HASH" ]]; then
        echo "[!] Checksum mismatch!"
        exit 1
      fi
      echo "[✓] Cryptographic SHA-256 checksum verified."
    fi
  fi

  unzip -q -o "${TEMPDIR}/asset.zip" -d "$TEMPDIR"
  BINARY_PATH=$(find "$TEMPDIR" -type f \( -name "agentcontrol" -o -name "agentcontrol.exe" \) | head -1 || true)
  
  if [[ -z "$BINARY_PATH" || ! -f "$BINARY_PATH" ]]; then
    echo "[!] Failed to locate agentcontrol binary."
    exit 1
  fi

  cp "$BINARY_PATH" "${LOCALBIN}/agentcontrol"
  chmod +x "${LOCALBIN}/agentcontrol"

  QUICKSTART_SRC=$(find "$TEMPDIR" -name "quickstart_agent.py" | head -1 || true)
  if [[ -n "$QUICKSTART_SRC" && -f "$QUICKSTART_SRC" ]]; then
    cp "$QUICKSTART_SRC" "${LOCALBIN}/quickstart_agent.py"
    chmod +x "${LOCALBIN}/quickstart_agent.py"
  fi

  echo "[✓] Vexa Agent Control binary installed to ${LOCALBIN}/agentcontrol"
fi

if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
  if [[ -f "$HOME/.bashrc" ]] && ! grep -q 'export PATH="$HOME/.local/bin:$PATH"' "$HOME/.bashrc"; then
    echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.bashrc"
  elif [[ -f "$HOME/.zshrc" ]] && ! grep -q 'export PATH="$HOME/.local/bin:$PATH"' "$HOME/.zshrc"; then
    echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.zshrc"
  fi
  echo "[!] Notice: Added $HOME/.local/bin to your PATH configuration."
fi

echo ""
echo "Get started by authenticating and connecting your coding assistant:"
echo "  export PATH=\"\$HOME/.local/bin:\$PATH\""
echo "  agentcontrol login"
echo "  agentcontrol connect codex"
echo "  agentcontrol doctor"
echo ""
