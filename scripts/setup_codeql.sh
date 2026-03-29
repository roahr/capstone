#!/bin/bash
# ============================================================================
# SEC-C Framework -- CodeQL CLI Setup Script
#
# Downloads and installs the CodeQL CLI and standard security query packs.
#
# Usage:
#   chmod +x scripts/setup_codeql.sh
#   ./scripts/setup_codeql.sh
#
# Environment variables:
#   CODEQL_VERSION  -- Pin a specific release tag (default: latest)
#   CODEQL_HOME     -- Install directory (default: ~/.sec-c/codeql)
# ============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

CODEQL_VERSION="${CODEQL_VERSION:-latest}"
INSTALL_DIR="${CODEQL_HOME:-$HOME/.sec-c/codeql}"
GITHUB_API="https://api.github.com/repos/github/codeql-cli-binaries/releases"

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
# Pre-flight dependency check
# ---------------------------------------------------------------------------

check_dependencies() {
    local missing=()
    for cmd in curl unzip; do
        if ! command -v "$cmd" &>/dev/null; then
            missing+=("$cmd")
        fi
    done
    if [ ${#missing[@]} -gt 0 ]; then
        fail "Missing required tools: ${missing[*]}"
        echo "  Install them and re-run this script."
        exit 1
    fi
    ok "Required tools present (curl, unzip)"
}

# ---------------------------------------------------------------------------
# Check for existing installation
# ---------------------------------------------------------------------------

check_existing() {
    if command -v codeql &>/dev/null; then
        local current_version
        current_version=$(codeql --version 2>/dev/null | head -1)
        ok "CodeQL already installed: ${current_version}"
        echo ""
        info "Updating query packs..."
        codeql pack download codeql/python-queries 2>/dev/null || true
        codeql pack download codeql/javascript-queries 2>/dev/null || true
        codeql pack download codeql/java-queries 2>/dev/null || true
        codeql pack download codeql/cpp-queries 2>/dev/null || true
        codeql pack download codeql/go-queries 2>/dev/null || true
        ok "Query packs updated"
        exit 0
    fi
}

# ---------------------------------------------------------------------------
# Detect operating system and architecture
# ---------------------------------------------------------------------------

detect_platform() {
    OS="unknown"
    ARCH="64"

    case "$(uname -s)" in
        Linux*)                         OS="linux" ;;
        Darwin*)                        OS="osx" ;;
        MINGW*|MSYS*|CYGWIN*|Windows*) OS="win" ;;
    esac

    case "$(uname -m)" in
        arm64|aarch64) ARCH="arm64" ;;
        x86_64|amd64)  ARCH="64" ;;
    esac

    if [ "$OS" = "unknown" ]; then
        fail "Unsupported OS: $(uname -s)"
        echo "  Download manually: https://github.com/github/codeql-cli-binaries/releases"
        exit 1
    fi

    info "Detected platform: ${OS}-${ARCH}"
}

# ---------------------------------------------------------------------------
# Resolve latest release version
# ---------------------------------------------------------------------------

resolve_version() {
    info "Querying GitHub for CodeQL releases..."

    local release_url
    if [ "$CODEQL_VERSION" = "latest" ]; then
        release_url="${GITHUB_API}/latest"
    else
        release_url="${GITHUB_API}/tags/${CODEQL_VERSION}"
    fi

    RESOLVED_TAG=$(curl -sL "$release_url" \
        | grep '"tag_name"' \
        | head -1 \
        | cut -d'"' -f4)

    if [ -z "${RESOLVED_TAG:-}" ]; then
        fail "Could not resolve CodeQL version. Check your network connection."
        exit 1
    fi

    info "Resolved version: ${RESOLVED_TAG}"
}

# ---------------------------------------------------------------------------
# Build download URL for the detected platform
# ---------------------------------------------------------------------------

build_download_url() {
    local filename

    if [ "$OS" = "win" ]; then
        filename="codeql-win64.zip"
    elif [ "$OS" = "osx" ]; then
        filename="codeql-osx64.zip"
    elif [ "$OS" = "linux" ] && [ "$ARCH" = "arm64" ]; then
        filename="codeql-linux-arm64.zip"
    else
        filename="codeql-linux64.zip"
    fi

    DOWNLOAD_URL="https://github.com/github/codeql-cli-binaries/releases/download/${RESOLVED_TAG}/${filename}"
    info "Download URL: ${DOWNLOAD_URL}"
}

# ---------------------------------------------------------------------------
# Download and extract CodeQL CLI
# ---------------------------------------------------------------------------

download_and_extract() {
    local tmp_file
    tmp_file=$(mktemp)

    info "Downloading CodeQL CLI..."
    curl -L --progress-bar -o "$tmp_file" "$DOWNLOAD_URL"

    info "Extracting to ${INSTALL_DIR}..."
    mkdir -p "$(dirname "$INSTALL_DIR")"
    unzip -qo "$tmp_file" -d "$(dirname "$INSTALL_DIR")"
    rm -f "$tmp_file"

    # Verify the binary exists
    if [ -f "${INSTALL_DIR}/codeql" ] || [ -f "${INSTALL_DIR}/codeql.exe" ]; then
        chmod +x "${INSTALL_DIR}/codeql" 2>/dev/null || true
        ok "CodeQL CLI installed to ${INSTALL_DIR}"
    else
        fail "Binary not found after extraction"
        exit 1
    fi
}

# ---------------------------------------------------------------------------
# Download standard security query packs
# ---------------------------------------------------------------------------

download_query_packs() {
    info "Downloading CodeQL security query packs..."

    local codeql_bin="${INSTALL_DIR}/codeql"
    [ -f "${codeql_bin}.exe" ] && codeql_bin="${codeql_bin}.exe"

    local packs=(
        "codeql/python-queries"
        "codeql/javascript-queries"
        "codeql/java-queries"
        "codeql/cpp-queries"
        "codeql/go-queries"
    )

    for pack in "${packs[@]}"; do
        info "  Fetching ${pack}..."
        "$codeql_bin" pack download "$pack" 2>/dev/null || {
            warn "  Could not download ${pack} (may require authentication)"
        }
    done

    ok "Query packs installed"
}

# ---------------------------------------------------------------------------
# Verify the installation
# ---------------------------------------------------------------------------

verify_installation() {
    local codeql_bin="${INSTALL_DIR}/codeql"
    [ -f "${codeql_bin}.exe" ] && codeql_bin="${codeql_bin}.exe"

    local version_output
    version_output=$("$codeql_bin" version 2>&1) || {
        fail "CodeQL verification failed"
        exit 1
    }

    ok "Verified: ${version_output}"
}

# ---------------------------------------------------------------------------
# Print PATH configuration instructions
# ---------------------------------------------------------------------------

print_path_instructions() {
    echo ""
    echo "  ============================================================"
    ok "CodeQL CLI setup complete!"
    echo "  ============================================================"
    echo ""
    echo -e "  ${COLOR_YELLOW}Add CodeQL to your PATH:${COLOR_RESET}"
    echo ""
    echo "    # Bash/Zsh:"
    echo "    echo 'export PATH=\"${INSTALL_DIR}:\$PATH\"' >> ~/.bashrc"
    echo "    source ~/.bashrc"
    echo ""
    echo "    # Fish:"
    echo "    fish_add_path ${INSTALL_DIR}"
    echo ""
    echo "    # Windows PowerShell:"
    echo "    \$env:PATH += \";${INSTALL_DIR}\""
    echo ""
    echo "  Verify with:  codeql version"
    echo "  ============================================================"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
    echo ""
    echo -e "  ${COLOR_CYAN}SEC-C Framework -- CodeQL CLI Setup${COLOR_RESET}"
    echo ""

    check_dependencies
    check_existing
    detect_platform
    resolve_version
    build_download_url
    download_and_extract
    verify_installation
    download_query_packs
    print_path_instructions
}

main "$@"
