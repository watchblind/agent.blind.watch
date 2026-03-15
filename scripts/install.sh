#!/bin/bash
# blind.watch agent installer
# Usage:
#   curl -sSL https://get.blind.watch/agent | bash
#
# Environment variables (set BEFORE running):
#   BW_TOKEN    - Agent authentication token (required)
#   BW_SECRET   - Provisioning secret (required)
#   BW_API_URL  - API URL (default: https://api.blind.watch)
#
# Options:
#   --upgrade              Upgrade existing installation
#   --skip-attestation     Skip SLSA attestation verification
#   --version VERSION      Install specific version (default: latest)
#   --data-dir DIR         Data directory (default: /var/lib/blindwatch)

set -euo pipefail

REPO="watchblind/agent"
BINARY_NAME="blindwatch-agent"
INSTALL_DIR="/usr/local/bin"
DATA_DIR="/var/lib/blindwatch"
SERVICE_USER="blindwatch"
SERVICE_NAME="blindwatch-agent"
API_URL="${BW_API_URL:-https://api.blind.watch}"
VERSION=""
UPGRADE=false
SKIP_ATTESTATION=false

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

info()  { echo -e "${BLUE}[info]${NC}  $*"; }
ok()    { echo -e "${GREEN}[ok]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[warn]${NC}  $*"; }
error() { echo -e "${RED}[error]${NC} $*" >&2; }
fatal() { error "$*"; exit 1; }

# --- Parse arguments ---
while [[ $# -gt 0 ]]; do
    case "$1" in
        --upgrade)       UPGRADE=true; shift ;;
        --skip-attestation) SKIP_ATTESTATION=true; shift ;;
        --version)       VERSION="$2"; shift 2 ;;
        --data-dir)      DATA_DIR="$2"; shift 2 ;;
        -h|--help)
            echo "Usage: install.sh [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --upgrade              Upgrade existing installation"
            echo "  --skip-attestation     Skip SLSA attestation verification"
            echo "  --version VERSION      Install specific version (default: latest)"
            echo "  --data-dir DIR         Data directory (default: /var/lib/blindwatch)"
            echo ""
            echo "Environment variables:"
            echo "  BW_TOKEN   Agent token (required for first install)"
            echo "  BW_SECRET  Provisioning secret (required for first install)"
            echo "  BW_API_URL API URL (default: https://api.blind.watch)"
            exit 0
            ;;
        *) fatal "Unknown option: $1" ;;
    esac
done

# --- Platform detection ---
detect_platform() {
    local os arch

    os="$(uname -s | tr '[:upper:]' '[:lower:]')"
    case "$os" in
        linux)  os="linux" ;;
        *)      fatal "Unsupported OS: $os (only Linux is supported)" ;;
    esac

    arch="$(uname -m)"
    case "$arch" in
        x86_64|amd64)   arch="amd64" ;;
        aarch64|arm64)  arch="arm64" ;;
        *)              fatal "Unsupported architecture: $arch (only amd64 and arm64 are supported)" ;;
    esac

    echo "${os}_${arch}"
}

# --- Check prerequisites ---
check_prerequisites() {
    if [[ $EUID -ne 0 ]] && [[ "$UPGRADE" == false ]]; then
        fatal "This installer must be run as root (sudo). The agent runs as an unprivileged user."
    fi

    for cmd in curl sha256sum; do
        if ! command -v "$cmd" &>/dev/null; then
            fatal "Required command not found: $cmd"
        fi
    done

    # Check systemd
    if ! command -v systemctl &>/dev/null; then
        fatal "systemd is required. SysV/OpenRC are not supported."
    fi
}

# --- Resolve version ---
resolve_version() {
    if [[ -n "$VERSION" ]]; then
        echo "$VERSION"
        return
    fi

    info "Fetching latest version..."
    local latest
    latest=$(curl -sSL -H "Accept: application/json" \
        "https://api.github.com/repos/${REPO}/releases/latest" \
        | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')

    if [[ -z "$latest" ]]; then
        fatal "Could not determine latest version. Use --version to specify."
    fi

    echo "$latest"
}

# --- Download and verify ---
download_and_verify() {
    local version="$1"
    local platform="$2"
    local archive_name="${BINARY_NAME}_${version#v}_${platform}.tar.gz"
    local download_url="https://github.com/${REPO}/releases/download/${version}/${archive_name}"
    local checksums_url="https://github.com/${REPO}/releases/download/${version}/checksums.sha256"
    local tmp_dir
    tmp_dir=$(mktemp -d)

    info "Downloading ${archive_name}..."
    curl -sSL -o "${tmp_dir}/${archive_name}" "$download_url" \
        || fatal "Download failed: ${download_url}"

    info "Downloading checksums..."
    curl -sSL -o "${tmp_dir}/checksums.sha256" "$checksums_url" \
        || fatal "Checksums download failed"

    # Verify checksum
    info "Verifying SHA-256 checksum..."
    local expected
    expected=$(grep "${archive_name}" "${tmp_dir}/checksums.sha256" | awk '{print $1}')
    if [[ -z "$expected" ]]; then
        fatal "Archive not found in checksums file"
    fi

    local actual
    actual=$(sha256sum "${tmp_dir}/${archive_name}" | awk '{print $1}')
    if [[ "$expected" != "$actual" ]]; then
        fatal "Checksum mismatch!\n  Expected: ${expected}\n  Actual:   ${actual}"
    fi
    ok "Checksum verified"

    # Verify SLSA attestation (if gh CLI available)
    if [[ "$SKIP_ATTESTATION" == false ]] && command -v gh &>/dev/null; then
        info "Verifying SLSA build provenance..."
        if gh attestation verify "${tmp_dir}/${archive_name}" --repo "${REPO}" 2>/dev/null; then
            ok "SLSA attestation verified"
        else
            warn "Attestation verification failed (binary may be from a pre-release)"
        fi
    elif [[ "$SKIP_ATTESTATION" == false ]]; then
        warn "gh CLI not found — skipping attestation verification"
        warn "Install gh (https://cli.github.com) to verify build provenance"
    fi

    # Extract binary
    info "Extracting binary..."
    tar -xzf "${tmp_dir}/${archive_name}" -C "${tmp_dir}" "${BINARY_NAME}"

    echo "${tmp_dir}/${BINARY_NAME}"
}

# --- Install binary ---
install_binary() {
    local binary_path="$1"

    if [[ "$UPGRADE" == true ]]; then
        info "Stopping ${SERVICE_NAME}..."
        systemctl stop "${SERVICE_NAME}" 2>/dev/null || true
    fi

    info "Installing binary to ${INSTALL_DIR}/${BINARY_NAME}..."
    install -m 0755 "$binary_path" "${INSTALL_DIR}/${BINARY_NAME}"
    ok "Binary installed"
}

# --- Create system user ---
create_user() {
    if id "${SERVICE_USER}" &>/dev/null; then
        return
    fi

    info "Creating system user: ${SERVICE_USER}"
    useradd --system --no-create-home --shell /usr/sbin/nologin "${SERVICE_USER}"
    ok "User created"
}

# --- Create data directory ---
create_data_dir() {
    info "Creating data directory: ${DATA_DIR}"
    mkdir -p "${DATA_DIR}/wal"
    chown -R "${SERVICE_USER}:${SERVICE_USER}" "${DATA_DIR}"
    chmod 0700 "${DATA_DIR}"
    ok "Data directory ready"
}

# --- Install systemd unit ---
install_systemd() {
    if [[ -f "/etc/systemd/system/${SERVICE_NAME}.service" ]] && [[ "$UPGRADE" == true ]]; then
        info "Systemd unit already exists, keeping current"
        return
    fi

    info "Installing systemd unit..."
    cat > "/etc/systemd/system/${SERVICE_NAME}.service" << 'UNIT'
[Unit]
Description=blind.watch monitoring agent
Documentation=https://github.com/watchblind/agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=blindwatch
Group=blindwatch
ExecStart=/usr/local/bin/blindwatch-agent --data-dir /var/lib/blindwatch --wal-dir /var/lib/blindwatch/wal
Restart=always
RestartSec=10
WatchdogSec=300

# Security hardening
LimitCORE=0
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/blindwatch
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
MemoryDenyWriteExecute=yes

[Install]
WantedBy=multi-user.target
UNIT

    systemctl daemon-reload
    ok "Systemd unit installed"
}

# --- First boot provisioning ---
run_first_boot() {
    if [[ -f "${DATA_DIR}/state.json" ]]; then
        info "Agent already provisioned, skipping first boot"
        return
    fi

    if [[ -z "${BW_TOKEN:-}" ]] || [[ -z "${BW_SECRET:-}" ]]; then
        fatal "BW_TOKEN and BW_SECRET must be set for first install"
    fi

    info "Running first-boot provisioning..."

    # Run as the service user
    sudo -u "${SERVICE_USER}" \
        BW_TOKEN="${BW_TOKEN}" \
        BW_SECRET="${BW_SECRET}" \
        BW_API_URL="${API_URL}" \
        "${INSTALL_DIR}/${BINARY_NAME}" \
            --first-boot \
            --data-dir "${DATA_DIR}" \
            --wal-dir "${DATA_DIR}/wal" \
        || fatal "First-boot provisioning failed"

    ok "Provisioning complete"
}

# --- Start service ---
start_service() {
    info "Starting ${SERVICE_NAME}..."
    systemctl enable "${SERVICE_NAME}"
    systemctl start "${SERVICE_NAME}"

    # Wait briefly and check status
    sleep 2
    if systemctl is-active --quiet "${SERVICE_NAME}"; then
        ok "Agent is running"
    else
        error "Agent failed to start. Check: journalctl -u ${SERVICE_NAME}"
        exit 1
    fi
}

# --- Main ---
main() {
    echo ""
    echo "  blind.watch agent installer"
    echo "  ==========================="
    echo ""

    check_prerequisites

    local platform version binary_path
    platform=$(detect_platform)
    info "Platform: ${platform}"

    version=$(resolve_version)
    info "Version: ${version}"

    binary_path=$(download_and_verify "$version" "$platform")

    install_binary "$binary_path"
    create_user
    create_data_dir
    install_systemd

    if [[ "$UPGRADE" == false ]]; then
        run_first_boot
    fi

    start_service

    echo ""
    ok "blind.watch agent ${version} installed and running"
    echo ""
    echo "  Status:  systemctl status ${SERVICE_NAME}"
    echo "  Logs:    journalctl -u ${SERVICE_NAME} -f"
    echo "  Version: ${BINARY_NAME} --version"
    echo ""

    # Cleanup
    rm -rf "$(dirname "$binary_path")"

    # Clear env vars
    unset BW_TOKEN BW_SECRET 2>/dev/null || true
}

main "$@"
