#!/usr/bin/env bash
# ==============================================================================
# Vexa Agent Control — Runtime Enforcement Pilot Master Runner (POSIX / Bash)
# Unified entrypoint that dispatches to the dedicated OS-specific pilot script:
#   - Linux:   scripts/run-pilot-linux.sh
#   - macOS:   scripts/run-pilot-macos.sh
#   - Windows: scripts/run-pilot-windows.sh
# Results are saved into unique datetime folders under result/<os>/<yyyyMMdd_HHmmss>/
# with ZERO duplicate files.
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

UNAME_S="$(uname -s)"
case "${UNAME_S}" in
    Darwin*)
        DETECTED_OS="macos"
        ;;
    Linux*)
        DETECTED_OS="linux"
        ;;
    CYGWIN*|MINGW*|MSYS*)
        DETECTED_OS="windows"
        ;;
    *)
        DETECTED_OS="linux"
        ;;
esac

TARGET_OS="auto"
PASSTHROUGH_ARGS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --os|-o)
            TARGET_OS="$2"
            shift 2
            ;;
        *)
            PASSTHROUGH_ARGS+=("$1")
            shift
            ;;
    esac
done

if [ "${TARGET_OS}" = "auto" ]; then
    TARGET_OS_LIST=("${DETECTED_OS}")
elif [ "${TARGET_OS}" = "all" ]; then
    TARGET_OS_LIST=("windows" "linux" "macos")
else
    TARGET_OS_LIST=("${TARGET_OS}")
fi

for TARGET in "${TARGET_OS_LIST[@]}"; do
    case "${TARGET}" in
        windows)
            "${SCRIPT_DIR}/run-pilot-windows.sh" "${PASSTHROUGH_ARGS[@]}"
            ;;
        linux)
            "${SCRIPT_DIR}/run-pilot-linux.sh" "${PASSTHROUGH_ARGS[@]}"
            ;;
        macos)
            "${SCRIPT_DIR}/run-pilot-macos.sh" "${PASSTHROUGH_ARGS[@]}"
            ;;
        *)
            echo "Unknown target OS: ${TARGET}"
            exit 1
            ;;
    esac
done
