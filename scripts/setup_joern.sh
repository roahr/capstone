#!/bin/bash
# ============================================================================
# SEC-C Framework -- Joern Setup Script
#
# Downloads and installs the Joern static analysis framework for Code
# Property Graph (CPG) generation.
#
# Requirements:
#   - Java 11+ (OpenJDK 17 recommended)
#   - curl
#
# Usage:
#   chmod +x scripts/setup_joern.sh
#   ./scripts/setup_joern.sh
#
# Environment variables:
#   JOERN_HOME  -- Install directory (default: ~/.sec-c/joern)
# ============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

INSTALL_DIR="${JOERN_HOME:-$HOME/.sec-c/joern}"
JOERN_RELEASES="https://github.com/joernio/joern/releases"

COLOR_CYAN='\033[0;36m'
COLOR_GREEN='\033[0;32m'
COLOR_YELLOW='\033[0;33m'
COLOR_RED='\033[0;31m'
COLOR_RESET='\033[0m'

info()  { echo -e "  ${COLOR_CYAN}[INFO]${COLOR_RESET}  $*"; }
ok()    { echo -e "  ${COLOR_GREEN}[OK]${COLOR_RESET}    $*"; }
warn()  { echo -e "  ${COLOR_YELLOW}[WARN]${COLOR_RESET}  $*"; }
fail()  { echo -e "  ${COLOR_RED}[FAIL]${COLOR_RESET}  $*" >&2; }

# ---------------------------------------------------------------------------
# Check for existing installation
# ---------------------------------------------------------------------------

check_existing() {
    if command -v joern &>/dev/null; then
        ok "Joern already installed"
        joern --version 2>/dev/null || true
        echo ""
        info "To reinstall, remove the existing installation first."
        exit 0
    fi

    if [ -f "${INSTALL_DIR}/joern" ]; then
        ok "Joern found at ${INSTALL_DIR}/joern"
        "${INSTALL_DIR}/joern" --version 2>/dev/null || true
        echo ""
        info "To reinstall, remove ${INSTALL_DIR} first."
        exit 0
    fi
}

# ---------------------------------------------------------------------------
# Check Java 11+ requirement
# ---------------------------------------------------------------------------

check_java() {
    if ! command -v java &>/dev/null; then
        fail "Java 11+ is required but not found."
        echo ""
        echo "  Install Java:"
        echo "    Ubuntu/Debian:  sudo apt install openjdk-17-jdk"
        echo "    Fedora/RHEL:    sudo dnf install java-17-openjdk-devel"
        echo "    macOS:          brew install openjdk@17"
        echo "    Windows:        https://adoptium.net/"
        echo ""
        exit 1
    fi

    # Parse Java version -- handles both old (1.8.x) and new (17.x) schemes.
    local java_version_raw
    java_version_raw=$(java -version 2>&1 | head -1)

    local java_major
    java_major=$(echo "$java_version_raw" \
        | sed -E 's/.*"([0-9]+)(\.[0-9]+)*.*/\1/')

    # For old-style versions like "1.8.0", the major version is the second number.
    if [ "$java_major" = "1" ]; then
        java_major=$(echo "$java_version_raw" \
            | sed -E 's/.*"1\.([0-9]+)\..*/\1/')
    fi

    if [ -z "$java_major" ] || ! [[ "$java_major" =~ ^[0-9]+$ ]]; then
        warn "Could not parse Java version from: ${java_version_raw}"
        warn "Proceeding anyway -- Joern requires Java 11+."
    elif [ "$java_major" -lt 11 ]; then
        fail "Java 11+ required, but found Java ${java_major}"
        echo "  Detected: ${java_version_raw}"
        echo "  Please upgrade to Java 11 or later."
        exit 1
    else
        ok "Java ${java_major} detected (${java_version_raw})"
    fi
}

# ---------------------------------------------------------------------------
# Check platform
# ---------------------------------------------------------------------------

check_platform() {
    case "$(uname -s)" in
        MINGW*|MSYS*|CYGWIN*|Windows*)
            warn "Windows detected."
            echo ""
            echo "  Joern's install script does not natively support Windows."
            echo "  Options:"
            echo ""
            echo "    1. Use WSL2 (recommended):"
            echo "       wsl --install"
            echo "       # Then re-run this script inside WSL2"
            echo ""
            echo "    2. Manual install:"
            echo "       a. Download from: ${JOERN_RELEASES}"
            echo "       b. Extract the archive"
            echo "       c. Add the directory to your PATH"
            echo ""
            echo "    3. Docker:"
            echo "       docker pull ghcr.io/joernio/joern"
            echo "       docker run --rm -it -v \$(pwd):/code ghcr.io/joernio/joern"
            echo ""
            info "SEC-C works without Joern (using simplified graph analysis)."
            exit 0
            ;;
    esac
}

# ---------------------------------------------------------------------------
# Download and install Joern
# ---------------------------------------------------------------------------

install_joern() {
    local installer_url="${JOERN_RELEASES}/latest/download/joern-install.sh"
    local tmp_installer
    tmp_installer=$(mktemp /tmp/joern-install-XXXXXX.sh)

    info "Downloading Joern installer..."
    curl -sL -o "$tmp_installer" "$installer_url"

    if [ ! -s "$tmp_installer" ]; then
        fail "Failed to download Joern installer"
        rm -f "$tmp_installer"
        exit 1
    fi

    info "Running Joern installer (target: ${INSTALL_DIR})..."
    mkdir -p "$INSTALL_DIR"
    chmod +x "$tmp_installer"

    # The installer may prompt -- pass --install-dir to automate.
    bash "$tmp_installer" --install-dir="$INSTALL_DIR" || {
        warn "Installer exited with non-zero status."
        warn "Joern may have installed to a different location."
    }

    rm -f "$tmp_installer"
}

# ---------------------------------------------------------------------------
# Verify installation
# ---------------------------------------------------------------------------

verify_installation() {
    local joern_bin=""

    if [ -f "${INSTALL_DIR}/joern" ]; then
        joern_bin="${INSTALL_DIR}/joern"
    elif [ -f "${INSTALL_DIR}/joern-cli/joern" ]; then
        joern_bin="${INSTALL_DIR}/joern-cli/joern"
    elif command -v joern &>/dev/null; then
        joern_bin=$(command -v joern)
    fi

    if [ -n "$joern_bin" ]; then
        ok "Joern installed: ${joern_bin}"
        "$joern_bin" --version 2>/dev/null || true
    else
        warn "Could not locate the Joern binary after installation."
        echo "  Check these locations:"
        echo "    ${INSTALL_DIR}/"
        echo "    ${INSTALL_DIR}/joern-cli/"
        echo "    ~/bin/"
    fi
}

# ---------------------------------------------------------------------------
# Print PATH instructions
# ---------------------------------------------------------------------------

print_path_instructions() {
    echo ""
    echo "  ============================================================"
    ok "Joern setup complete!"
    echo "  ============================================================"
    echo ""
    echo -e "  ${COLOR_YELLOW}Add Joern to your PATH:${COLOR_RESET}"
    echo ""
    echo "    # Bash/Zsh:"
    echo "    echo 'export PATH=\"${INSTALL_DIR}:\$PATH\"' >> ~/.bashrc"
    echo "    source ~/.bashrc"
    echo ""
    echo "    # Fish:"
    echo "    fish_add_path ${INSTALL_DIR}"
    echo ""
    echo "  Verify with:  joern --version"
    echo ""
    info "Joern is optional. SEC-C works without it (using simplified graph analysis)."
    echo "  ============================================================"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
    echo ""
    echo -e "  ${COLOR_CYAN}SEC-C Framework -- Joern Setup${COLOR_RESET}"
    echo ""

    check_existing
    check_java
    check_platform
    install_joern
    verify_installation
    print_path_instructions
}

main "$@"
