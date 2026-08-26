#!/usr/bin/env bash
set -euo pipefail

echo "[*] Vexa Agent Control Team OTET Enterprise Provisioning Installer"

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

PROD_HUB_URL="https://console.vexasec.io"
STAGE_HUB_URL="https://console-stage.vexasec.io"

VERSION="${AGENTCONTROL_VERSION:-}"
TOKEN="${AGENTCONTROL_TOKEN:-${AGENTCONTROL_ENROLLMENT_TOKEN:-${AGENTWALL_TOKEN:-${AGENTWALL_ENROLLMENT_TOKEN:-}}}}"
TARGET_ENV="${AGENTCONTROL_ENV:-${AGENTCONTROL_ENVIRONMENT:-${AGENTWALL_ENV:-}}}"
HUB_URL="${AGENTCONTROL_HUB_URL:-${AGENTWALL_HUB_URL:-${DASHBOARD_API_URL:-}}}"
INSTALL_SERVICE=""

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
    -e|--env|--environment)
      TARGET_ENV="$2"
      shift 2
      ;;
    --staging|--stage)
      TARGET_ENV="staging"
      shift
      ;;
    --prod|--production)
      TARGET_ENV="production"
      shift
      ;;
    -v|--version)
      VERSION="$2"
      shift 2
      ;;
    --install-service)
      INSTALL_SERVICE="true"
      shift
      ;;
    --no-service)
      INSTALL_SERVICE="false"
      shift
      ;;
    -h|--help)
      echo "Usage: team_otet.sh -t <token> [-u <hub-url>] [-e <staging|production>] [--staging] [--prod] [-v <version>] [--install-service] [--no-service]"
      echo "  -t, --token            Enrollment token for enterprise onboarding"
      echo "  -u, --hub-url          Control Hub / Dashboard URL (or 'staging' / 'production')"
      echo "  -e, --env              Target environment: 'staging' (https://console-stage.vexasec.io) or 'production' (https://console.vexasec.io)"
      echo "      --staging          Shorthand to use staging Control Hub (https://console-stage.vexasec.io)"
      echo "      --prod             Shorthand to use production Control Hub (https://console.vexasec.io)"
      echo "  -v, --version          Pin specific release version (default: latest)"
      echo "      --install-service  Force install persistent system service daemon"
      echo "      --no-service       Skip system service daemon installation"
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

TARGET_ENV_LOWER=$(echo "${TARGET_ENV:-}" | tr '[:upper:]' '[:lower:]')
if [[ "$TARGET_ENV_LOWER" == "staging" || "$TARGET_ENV_LOWER" == "stage" ]]; then
  HUB_URL="$STAGE_HUB_URL"
elif [[ "$TARGET_ENV_LOWER" == "production" || "$TARGET_ENV_LOWER" == "prod" ]]; then
  HUB_URL="$PROD_HUB_URL"
fi

if [[ -n "$HUB_URL" ]]; then
  HUB_URL_LOWER=$(echo "$HUB_URL" | tr '[:upper:]' '[:lower:]')
  case "$HUB_URL_LOWER" in
    staging|stage|"https://console-stage.vexasec.io"|"https://console-stage.vexasec.io/")
      HUB_URL="$STAGE_HUB_URL"
      ;;
    production|prod|default|"https://console.vexasec.io"|"https://console.vexasec.io/")
      HUB_URL="$PROD_HUB_URL"
      ;;
  esac
fi

if [[ -z "$HUB_URL" || "$HUB_URL" == "http://localhost:8400" ]]; then
  HUB_URL="$PROD_HUB_URL"
fi

HUB_URL="${HUB_URL%/}"
export DASHBOARD_API_URL="$HUB_URL"
export AGENTCONTROL_HUB_URL="$HUB_URL"

if [[ -z "$TOKEN" ]]; then
  echo "[!] Error: Enterprise enrollment token required."
  echo "    Usage: ./install/team_otet.sh -t <TOKEN> [-u <HUB_URL>] [--staging | --prod]"
  echo "    Hub Endpoints: Production (--prod / https://console.vexasec.io) | Staging (--staging / https://console-stage.vexasec.io)"
  exit 1
fi

LOCALBIN="${HOME}/.local/bin"
REPO="noviqtechnologies/Vexa-Agent-Control"

if [[ -z "$VERSION" ]]; then
  echo "[*] Fetching latest release version..."
  VERSION=$(curl -sSf "https://api.github.com/repos/${REPO}/releases?per_page=1" 2>/dev/null \
    | grep '"tag_name"' \
    | head -1 \
    | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/' || true)

  if [[ -z "$VERSION" ]]; then
    VERSION="v1.0.67"
  fi
fi

# Ensure version tag has 'v' prefix
if [[ "$VERSION" != v* ]]; then
  VERSION="v${VERSION}"
fi

echo "[*] Version: $VERSION | OS: $OS | Arch: $ARCH | Hub: $HUB_URL"

ASSET_NAME="agentcontrol-${VERSION}-${OS}-${ARCH}.zip"
BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"
ASSET_URL="${BASE_URL}/${ASSET_NAME}"
CHECKSUMS_URL="${BASE_URL}/checksums.txt"

TEMPDIR=$(mktemp -d)
trap 'rm -rf "$TEMPDIR"' EXIT

echo "[*] Downloading asset package: $ASSET_URL..."
if ! curl -fsSL "$ASSET_URL" -o "${TEMPDIR}/asset.zip"; then
  echo "[!] Error: Failed to download release asset from $ASSET_URL"
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

    if [[ -z "$ACTUAL_HASH" ]]; then
      echo "[!] FATAL: Cannot verify checksum — no sha256sum or shasum found on PATH. Aborting."
      exit 1
    fi

    if [[ "$EXPECTED_HASH" != "$ACTUAL_HASH" ]]; then
      echo "[!] FATAL: Cryptographic Checksum Mismatch!"
      echo "    Expected: $EXPECTED_HASH"
      echo "    Got:      $ACTUAL_HASH"
      echo "    The release artifact may be corrupted or tampered with. Aborting installation."
      exit 1
    fi
    echo "[✓] SHA-256 Checksum verified successfully ($ACTUAL_HASH)."
  else
    echo "[!] FATAL: Asset $ASSET_NAME not found in checksums.txt. Cannot verify integrity. Aborting."
    exit 1
  fi
else
  echo "[!] FATAL: Could not download checksums.txt from $CHECKSUMS_URL. Aborting installation for security."
  exit 1
fi

mkdir -p "$LOCALBIN"
unzip -q -o "${TEMPDIR}/asset.zip" -d "$TEMPDIR"
BINARY_PATH=$(find "$TEMPDIR" -type f \( -name "agentcontrol" -o -name "agentcontrol.exe" \) | head -1 || true)

if [[ -z "$BINARY_PATH" || ! -f "$BINARY_PATH" ]]; then
  echo "[!] Error: Failed to locate agentcontrol binary inside the extracted archive."
  exit 1
fi

mv "$BINARY_PATH" "${LOCALBIN}/agentcontrol"
chmod +x "${LOCALBIN}/agentcontrol"

echo "[*] Initializing Enterprise Device Governance..."
echo "[*] Step 1/3: PKI Device Enrollment..."
if ! "${LOCALBIN}/agentcontrol" enroll --token "$TOKEN" --hub-url "$HUB_URL"; then
  echo "[!] Enrollment failed. Aborting provisioning."
  exit 1
fi

SHOULD_INSTALL_SERVICE="false"
if [[ "$INSTALL_SERVICE" == "true" ]] || [[ "$INSTALL_SERVICE" != "false" && "$(id -u)" -eq 0 ]]; then
  SHOULD_INSTALL_SERVICE="true"
fi

if [[ "$SHOULD_INSTALL_SERVICE" == "true" ]]; then
  echo "[*] Step 2/3: Installing Persistent OS Sentry Daemon..."
  if [ "$(id -u)" -ne 0 ] && command -v sudo &>/dev/null; then
    sudo "${LOCALBIN}/agentcontrol" service install --hub-url "$HUB_URL" || echo "[!] Note: Could not install machine-level system service without root."
  else
    "${LOCALBIN}/agentcontrol" service install --hub-url "$HUB_URL" || echo "[!] Note: Sentry service installation requires appropriate permissions."
  fi
else
  echo "[*] Step 2/3: Skipping system daemon installation (run as root or pass --install-service to enable)."
fi

echo "[*] Step 3/3: Auto-wrapping active IDE targets..."
"${LOCALBIN}/agentcontrol" wrap --all || true

echo ""
echo "[+] Automated Enterprise Provisioning Completed!"
echo "  • Version: $VERSION"
echo "  • SHA-256: $ACTUAL_HASH"
echo "Get started by running:"
echo "  agentcontrol protect"
echo ""
