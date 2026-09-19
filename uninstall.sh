#!/usr/bin/env bash
# Compatibility wrapper for uninstall/uninstall.sh
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "${SCRIPT_DIR}/uninstall/uninstall.sh" ]; then
  exec bash "${SCRIPT_DIR}/uninstall/uninstall.sh" "$@"
else
  # Fallback to fetching remote uninstaller
  curl -fsSL "https://raw.githubusercontent.com/noviqtechnologies/Vexa-Agent-Control/main/uninstall/uninstall.sh" | bash -s -- "$@"
fi
