#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VERSION="0.1.0"
CLI_BIN="onvault"
DAEMON_BIN="onvaultd"

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

info()    { echo -e "${CYAN}${BOLD}==> $1${NC}"; }
success() { echo -e "${GREEN}${BOLD}==> $1${NC}"; }
error()   { echo -e "${RED}${BOLD}==> ERROR: $1${NC}" >&2; }
warn()    { echo -e "${YELLOW}${BOLD}==> $1${NC}"; }

# --- Usage ---
usage() {
    cat <<EOF
${BOLD}onvault v${VERSION} -- Project Management Script${NC}

${CYAN}USAGE:${NC}
    ./app.sh [FLAGS...]

${CYAN}FLAGS:${NC}
    --build,   -b       Build development binaries
    --dist              Build distribution binaries (static linking)
    --test,    -t       Run full test suite (25 tests)
    --run,     -r       Build and run daemon in foreground (with menu bar)
    --start             Build and start daemon in background
    --clean,   -c       Remove binaries, object files, test artifacts
    --deps,    -d       Install all build dependencies
    --check             Check system readiness (deps, macFUSE, ESF)
    --install           Install binaries to /usr/local/bin
    --uninstall         Remove binaries from /usr/local/bin
    --stop              Stop running daemon
    --status            Show daemon status and web UI URL
    --help,    -h       Show this help message

${CYAN}EXAMPLES:${NC}
    ./app.sh --deps --build --test   # Install deps, build, test
    ./app.sh --build --start         # Build and start daemon (background)
    ./app.sh --build --run           # Build and run daemon (foreground)
    ./app.sh --dist                  # Build for distribution
    ./app.sh --clean --build --test  # Clean rebuild + test
    ./app.sh --check                 # Verify system readiness
    ./app.sh --status                # Show daemon status + web UI URL
    ./app.sh --stop                  # Stop running daemon

${CYAN}END USER SETUP:${NC}
    1. brew install --cask macfuse   # One-time, requires reboot
    2. ./app.sh --deps --build       # Build onvault
    3. ./onvault init                # Set passphrase
    4. ./app.sh --start              # Start daemon
    5. Open menu bar → Unlock → Add Vault

${CYAN}NOTES:${NC}
    Flags can be combined. Execution order is always:
    deps -> clean -> check -> build -> test -> dist -> install -> run
EOF
}

# --- Flag parsing ---
DO_DEPS=false
DO_CLEAN=false
DO_CHECK=false
DO_BUILD=false
DO_TEST=false
DO_DIST=false
DO_INSTALL=false
DO_UNINSTALL=false
DO_RUN=false
DO_START=false
DO_STOP=false
DO_STATUS=false

if [[ $# -eq 0 ]]; then
    usage
    exit 0
fi

while [[ $# -gt 0 ]]; do
    case "$1" in
        --deps|-d|--install-deps|--dependencies|--requirements)
            DO_DEPS=true ;;
        --clean|-c)
            DO_CLEAN=true ;;
        --check)
            DO_CHECK=true ;;
        --build|-b)
            DO_BUILD=true ;;
        --test|-t)
            DO_TEST=true ;;
        --dist)
            DO_DIST=true ;;
        --install)
            DO_INSTALL=true ;;
        --uninstall)
            DO_UNINSTALL=true ;;
        --run|-r)
            DO_RUN=true ;;
        --start)
            DO_START=true ;;
        --stop)
            DO_STOP=true ;;
        --status)
            DO_STATUS=true ;;
        --help|-h)
            usage; exit 0 ;;
        *)
            error "Unknown flag: $1"
            usage; exit 1 ;;
    esac
    shift
done

# --- Dependencies ---
deps() {
    info "Installing build dependencies..."

    if ! command -v brew &>/dev/null; then
        error "Homebrew not found. Install from https://brew.sh"
        exit 1
    fi

    # OpenSSL
    if brew list openssl@3 &>/dev/null; then
        success "OpenSSL 3 already installed"
    else
        info "Installing OpenSSL 3..."
        brew install openssl@3
    fi

    # Argon2
    if brew list argon2 &>/dev/null; then
        success "libargon2 already installed"
    else
        info "Installing libargon2..."
        brew install argon2
    fi

    # macFUSE
    if brew list --cask macfuse &>/dev/null; then
        success "macFUSE already installed"
    else
        warn "macFUSE not installed. Installing..."
        warn "You will need to approve the system extension in System Settings > Privacy & Security"
        warn "A reboot may be required."
        brew install --cask macfuse
    fi

    # Xcode CLI Tools
    if xcode-select -p &>/dev/null; then
        success "Xcode Command Line Tools installed"
    else
        info "Installing Xcode Command Line Tools..."
        xcode-select --install
    fi

    echo ""
    success "All dependencies installed."
}

# --- Clean ---
clean() {
    info "Cleaning build artifacts..."
    make -C "$SCRIPT_DIR" clean 2>/dev/null || true
    rm -f "$SCRIPT_DIR/$CLI_BIN" "$SCRIPT_DIR/$DAEMON_BIN"
    success "Clean complete."
}

# --- System check ---
check() {
    info "Checking system readiness..."
    echo ""

    local all_ok=true

    # macOS version
    local macos_ver
    macos_ver=$(sw_vers -productVersion 2>/dev/null || echo "unknown")
    echo -e "  macOS version:    ${BOLD}${macos_ver}${NC}"

    # Architecture
    local arch
    arch=$(uname -m)
    echo -e "  Architecture:     ${BOLD}${arch}${NC}"

    # Homebrew
    if command -v brew &>/dev/null; then
        echo -e "  Homebrew:         ${GREEN}installed${NC}"
    else
        echo -e "  Homebrew:         ${RED}NOT installed${NC}"
        all_ok=false
    fi

    # OpenSSL
    if brew list openssl@3 &>/dev/null; then
        local ssl_ver
        ssl_ver=$(brew info openssl@3 --json | python3 -c "import sys,json; print(json.load(sys.stdin)[0]['versions']['stable'])" 2>/dev/null || echo "?")
        echo -e "  OpenSSL:          ${GREEN}${ssl_ver}${NC}"
    else
        echo -e "  OpenSSL:          ${RED}NOT installed${NC} (brew install openssl)"
        all_ok=false
    fi

    # Argon2
    if brew list argon2 &>/dev/null; then
        echo -e "  libargon2:        ${GREEN}installed${NC}"
    else
        echo -e "  libargon2:        ${RED}NOT installed${NC} (brew install argon2)"
        all_ok=false
    fi

    # macFUSE
    if brew list --cask macfuse &>/dev/null; then
        echo -e "  macFUSE:          ${GREEN}installed${NC}"
    else
        echo -e "  macFUSE:          ${RED}NOT installed${NC} (brew install --cask macfuse)"
        all_ok=false
    fi

    # FUSE library
    if pkg-config --exists fuse 2>/dev/null; then
        echo -e "  FUSE library:     ${GREEN}found${NC}"
    else
        echo -e "  FUSE library:     ${YELLOW}not found via pkg-config${NC} (reboot may be needed)"
    fi

    # ESF SDK
    local esf_found=false
    for sdk in /Library/Developer/CommandLineTools/SDKs/MacOSX26*.sdk /Library/Developer/CommandLineTools/SDKs/MacOSX15*.sdk; do
        if [[ -f "$sdk/usr/lib/libEndpointSecurity.tbd" ]]; then
            echo -e "  ESF SDK:          ${GREEN}found in $(basename "$sdk")${NC}"
            esf_found=true
            break
        fi
    done
    if ! $esf_found; then
        echo -e "  ESF SDK:          ${YELLOW}not found${NC} (ESF will compile as stub)"
    fi

    # SIP status
    local sip
    sip=$(csrutil status 2>&1 | grep -o "enabled\|disabled" || echo "unknown")
    if [[ "$sip" == "disabled" ]]; then
        echo -e "  SIP:              ${YELLOW}disabled${NC} (ESF testing possible)"
    else
        echo -e "  SIP:              ${GREEN}enabled${NC} (disable for local ESF testing)"
    fi

    echo ""
    if $all_ok; then
        success "System ready. Run './app.sh --build' to build."
    else
        warn "Some dependencies missing. Run './app.sh --deps' to install."
    fi
}

# --- Build ---
build() {
    info "Building onvault (development)..."
    make -C "$SCRIPT_DIR" all 2>&1

    if [[ -f "$SCRIPT_DIR/$CLI_BIN" && -f "$SCRIPT_DIR/$DAEMON_BIN" ]]; then
        success "Build complete:"
        ls -lh "$SCRIPT_DIR/$CLI_BIN" "$SCRIPT_DIR/$DAEMON_BIN"
    else
        error "Build failed."
        exit 1
    fi
}

# --- Test ---
run_tests() {
    info "Running test suite..."
    make -C "$SCRIPT_DIR" test 2>&1
    success "All tests passed."
}

# --- Distribution build ---
dist() {
    info "Building distribution binaries (static linking)..."
    make -C "$SCRIPT_DIR" dist 2>&1
    success "Distribution build complete."
}

# --- Install ---
install_bins() {
    info "Installing to /usr/local/bin/..."
    sudo install -m 755 "$SCRIPT_DIR/$CLI_BIN" /usr/local/bin/onvault
    sudo install -m 755 "$SCRIPT_DIR/$DAEMON_BIN" /usr/local/bin/onvaultd
    success "Installed: /usr/local/bin/onvault, /usr/local/bin/onvaultd"
}

# --- Uninstall ---
uninstall_bins() {
    info "Removing from /usr/local/bin/..."
    sudo rm -f /usr/local/bin/onvault /usr/local/bin/onvaultd
    success "Uninstalled."
}

# --- Run ---
run_daemon() {
    if ! [[ -f "$SCRIPT_DIR/$DAEMON_BIN" ]]; then
        info "Binary not found, building first..."
        build
    fi

    info "Starting onvaultd in foreground..."
    warn "Press Ctrl+C to stop."
    echo ""
    "$SCRIPT_DIR/$DAEMON_BIN"
}

# --- Start (background) ---
start_daemon() {
    if ! [[ -f "$SCRIPT_DIR/$DAEMON_BIN" ]]; then
        info "Binary not found, building first..."
        build
    fi

    # Check if already running
    local pid_file="$HOME/.onvault/onvaultd.pid"
    if [[ -f "$pid_file" ]]; then
        local existing_pid
        existing_pid=$(cat "$pid_file" 2>/dev/null)
        if kill -0 "$existing_pid" 2>/dev/null; then
            warn "Daemon already running (pid $existing_pid)"
            show_status
            return
        fi
    fi

    info "Starting onvaultd in background..."
    "$SCRIPT_DIR/$DAEMON_BIN" &
    sleep 3

    if [[ -f "$HOME/.onvault/http.port" ]]; then
        local port
        port=$(cat "$HOME/.onvault/http.port")
        echo ""
        success "Daemon started."
        echo -e "  ${BOLD}PID:${NC}      $(cat "$HOME/.onvault/onvaultd.pid" 2>/dev/null)"
        echo -e "  ${BOLD}Web UI:${NC}   ${CYAN}http://127.0.0.1:${port}/menubar${NC}"
        echo -e "  ${BOLD}Menu bar:${NC} Look for the lock icon"
        echo ""
        echo -e "  To unlock: ${BOLD}./onvault unlock${NC}"
    else
        error "Daemon may have failed to start. Check stderr output."
    fi
}

# --- Status ---
show_status() {
    local pid_file="$HOME/.onvault/onvaultd.pid"
    local port_file="$HOME/.onvault/http.port"

    if [[ -f "$pid_file" ]] && kill -0 "$(cat "$pid_file" 2>/dev/null)" 2>/dev/null; then
        local pid port
        pid=$(cat "$pid_file")
        port=$(cat "$port_file" 2>/dev/null || echo "?")
        echo ""
        success "Daemon is running."
        echo -e "  ${BOLD}PID:${NC}      $pid"
        echo -e "  ${BOLD}Web UI:${NC}   ${CYAN}http://127.0.0.1:${port}/menubar${NC}"
        echo -e "  ${BOLD}Socket:${NC}   ~/.onvault/onvault.sock"
        echo ""

        # Query status via CLI if unlocked
        if [[ -f "$SCRIPT_DIR/$CLI_BIN" ]]; then
            "$SCRIPT_DIR/$CLI_BIN" status 2>/dev/null || true
        fi
    else
        warn "Daemon is not running."
        echo "  Start with: ./app.sh --start"
    fi
}

# --- Stop ---
stop_daemon() {
    info "Stopping onvaultd..."
    if pkill -f onvaultd 2>/dev/null; then
        sleep 1
        success "Daemon stopped."
    else
        warn "No running daemon found."
    fi
}

# --- Execute in order ---
$DO_DEPS      && deps
$DO_CLEAN     && clean
$DO_CHECK     && check
$DO_UNINSTALL && uninstall_bins
$DO_BUILD     && build
$DO_TEST      && run_tests
$DO_DIST      && dist
$DO_INSTALL   && install_bins
$DO_STOP      && stop_daemon
$DO_STATUS    && show_status
$DO_START     && start_daemon
$DO_RUN       && run_daemon

exit 0
