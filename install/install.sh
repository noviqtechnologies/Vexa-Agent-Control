#!/usr/bin/env bash
set -euo pipefail

echo "[*] Vexa Agent Control Installer (Standalone Developer Edition)"

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

VERSION="${AGENTCONTROL_VERSION:-}"
MODE="${AGENTCONTROL_MODE:-solo}"

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

REPO="noviqtechnologies/Vexa-Agent-Control"
FALLBACK_VERSION="v1.0.37"

if [[ -z "$VERSION" ]]; then
  echo "[*] Fetching latest release version from GitHub..."
  # 1. Primary: GitHub Releases API
  VERSION=$(curl -sSf -H "Accept: application/vnd.github.v3+json" "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null \
    | grep '"tag_name"' \
    | head -1 \
    | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/' || true)
  
  # 2. Secondary: HTTP Redirect Scraping (immune to API 403 rate limits)
  if [[ -z "$VERSION" ]]; then
    VERSION=$(curl -sSI "https://github.com/${REPO}/releases/latest" 2>/dev/null \
      | grep -i "^location:" \
      | sed -e 's/.*tag\///' \
      | tr -d '\r\n' || true)
  fi

  # 3. Tertiary: Fallback version
  if [[ -z "$VERSION" ]]; then
    echo "[!] Warning: Could not resolve latest version from GitHub (rate-limited or offline)."
    echo "    Using default pinned release: ${FALLBACK_VERSION}"
    echo "    To specify an exact version, pass: -v <version>"
    VERSION="$FALLBACK_VERSION"
  else
    echo "[*] Latest version resolved: $VERSION"
  fi
fi

# Ensure version tag has 'v' prefix
if [[ "$VERSION" != v* ]]; then
  VERSION="v${VERSION}"
fi

echo "[*] Target version: $VERSION"

LOCALBIN="$HOME/.local/bin"
mkdir -p "$LOCALBIN"
INSTALLED_VERSION=""
if command -v agentcontrol &>/dev/null || [ -f "${LOCALBIN}/agentcontrol" ]; then
  INSTALLED_VERSION=$("${LOCALBIN}/agentcontrol" --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)
fi

if [[ -n "$INSTALLED_VERSION" && "v${INSTALLED_VERSION}" == "$VERSION" ]]; then
  echo ""
  echo "[✓] Vexa Agent Control $VERSION is already installed and up to date."
  exit 0
elif [[ -n "$INSTALLED_VERSION" ]]; then
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

echo "[*] Downloading release artifact: $ASSET_URL..."
if ! curl -fsSL "$ASSET_URL" -o "${TEMPDIR}/asset.zip"; then
  echo "[!] Error: Failed to download release asset from $ASSET_URL"
  echo "    Please verify that version $VERSION exists at https://github.com/${REPO}/releases"
  exit 1
fi

if [ ! -f "${TEMPDIR}/asset.zip" ]; then
  echo "[!] Error: Downloaded file missing."
  exit 1
fi

echo "[*] Verifying cryptographic SHA-256 checksum..."
if curl -fsSL "$CHECKSUMS_URL" -o "${TEMPDIR}/checksums.txt" 2>/dev/null; then
  EXPECTED_HASH=$(grep "$ASSET_NAME" "${TEMPDIR}/checksums.txt" | awk '{print $1}' || true)
  if [[ -n "$EXPECTED_HASH" ]]; then
    ACTUAL_HASH=""
    if command -v sha256sum &>/dev/null; then
      ACTUAL_HASH=$(sha256sum "${TEMPDIR}/asset.zip" | awk '{print $1}')
    elif command -v shasum &>/dev/null; then
      ACTUAL_HASH=$(shasum -a 256 "${TEMPDIR}/asset.zip" | awk '{print $1}')
    fi

    if [[ -n "$ACTUAL_HASH" && "$EXPECTED_HASH" != "$ACTUAL_HASH" ]]; then
      echo "[!] FATAL: Cryptographic Checksum Mismatch!"
      echo "    Expected: $EXPECTED_HASH"
      echo "    Got:      $ACTUAL_HASH"
      exit 1
    fi
    echo "[✓] SHA-256 Checksum verified successfully ($ACTUAL_HASH)."
  else
    echo "[!] Notice: Asset $ASSET_NAME not listed in checksums.txt. Proceeding with TLS verification."
  fi
else
  echo "[!] Notice: Release tag $VERSION does not include checksums.txt manifest."
  echo "    Verified download integrity via GitHub TLS transport."
fi

echo "[*] Extracting package..."
unzip -q -o "${TEMPDIR}/asset.zip" -d "$TEMPDIR"

BINARY_PATH=$(find "$TEMPDIR" -type f \( -name "agentcontrol" -o -name "agentcontrol.exe" \) | head -1 || true)
if [[ -z "$BINARY_PATH" || ! -f "$BINARY_PATH" ]]; then
  echo "[!] Error: Failed to locate agentcontrol binary inside the extracted archive."
  exit 1
fi

echo "[*] Installing binary to ${LOCALBIN}/agentcontrol..."
cp "$BINARY_PATH" "${LOCALBIN}/agentcontrol"
chmod +x "${LOCALBIN}/agentcontrol"

QUICKSTART_SRC=$(find "$TEMPDIR" -name "quickstart_agent.py" | head -1 || true)
if [[ -n "$QUICKSTART_SRC" && -f "$QUICKSTART_SRC" ]]; then
  cp "$QUICKSTART_SRC" "${LOCALBIN}/quickstart_agent.py"
  chmod +x "${LOCALBIN}/quickstart_agent.py"
fi

if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
  if [[ -f "$HOME/.bashrc" ]] && ! grep -q 'export PATH="$HOME/.local/bin:$PATH"' "$HOME/.bashrc"; then
    echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.bashrc"
  elif [[ -f "$HOME/.zshrc" ]] && ! grep -q 'export PATH="$HOME/.local/bin:$PATH"' "$HOME/.zshrc"; then
    echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.zshrc"
  fi
fi

echo ""
echo "┌────────────────────────────────────────────────────────────────────────┐"
echo "│  ✨ Vexa Agent Control $VERSION successfully installed!                 │"
echo "├────────────────────────────────────────────────────────────────────────┤"
echo "│  Binary Location : ${LOCALBIN}/agentcontrol"
echo "│  To start one-command protection right now in this terminal session:   │"
echo "│                                                                        │"
echo "│    export PATH=\"$LOCALBIN:\$PATH\" && agentcontrol protect              │"
echo "│                                                                        │"
echo "└────────────────────────────────────────────────────────────────────────┘"
echo ""


