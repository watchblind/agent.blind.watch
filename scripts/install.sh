#!/bin/bash
# blind.watch agent installer
# Usage:
#   curl -sSL https://get.blind.watch/agent | bash -s -- --token TOKEN --secret SECRET
#
# Options:
#   --token TOKEN          Agent authentication token (required for first install)
#   --secret SECRET        Provisioning secret (required for first install)
#   --api-url URL          API URL (default: https://api.blind.watch)
#   --upgrade              Upgrade existing installation
#   --skip-attestation     Skip SLSA attestation verification
#   --version VERSION      Install specific version (default: latest)
#   --data-dir DIR         Data directory (default: /var/lib/blindwatch)

set -euo pipefail

REPO="watchblind/agent.blind.watch"
BINARY_NAME="blindwatch-agent"
INSTALL_DIR="/usr/local/bin"
DATA_DIR="/var/lib/blindwatch"
SERVICE_USER="blindwatch"
SERVICE_NAME="blindwatch-agent"
API_URL="${BW_API_URL:-https://api.blind.watch}"
BW_TOKEN="${BW_TOKEN:-}"
BW_SECRET="${BW_SECRET:-}"
VERSION=""
UPGRADE=false
SKIP_ATTESTATION=false

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

info()  { echo -e "${BLUE}[info]${NC}  $*" >&2; }
ok()    { echo -e "${GREEN}[ok]${NC}    $*" >&2; }
warn()  { echo -e "${YELLOW}[warn]${NC}  $*" >&2; }
error() { echo -e "${RED}[error]${NC} $*" >&2; }
fatal() { error "$*"; exit 1; }

# --- Parse arguments ---
while [[ $# -gt 0 ]]; do
    case "$1" in
        --token)             BW_TOKEN="$2"; shift 2 ;;
        --secret)            BW_SECRET="$2"; shift 2 ;;
        --api-url)           API_URL="$2"; shift 2 ;;
        --upgrade)           UPGRADE=true; shift ;;
        --skip-attestation)  SKIP_ATTESTATION=true; shift ;;
        --version)           VERSION="$2"; shift 2 ;;
        --data-dir)          DATA_DIR="$2"; shift 2 ;;
        -h|--help)
            echo "Usage: install.sh [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --token TOKEN          Agent token (required for first install)"
            echo "  --secret SECRET        Provisioning secret (required for first install)"
            echo "  --api-url URL          API URL (default: https://api.blind.watch)"
            echo "  --upgrade              Upgrade existing installation"
            echo "  --skip-attestation     Skip SLSA attestation verification"
            echo "  --version VERSION      Install specific version (default: latest)"
            echo "  --data-dir DIR         Data directory (default: /var/lib/blindwatch)"
            exit 0
            ;;
        *) fatal "Unknown option: $1" ;;
    esac
done

# --- Sudo helper: run a command with sudo, passing through needed vars ---
as_root() {
    if [[ $EUID -eq 0 ]]; then
        "$@"
    else
        sudo "$@"
    fi
}

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
    for cmd in sha256sum tar; do
        if ! command -v "$cmd" &>/dev/null; then
            fatal "Required command not found: $cmd"
        fi
    done

    # Need either gh (for private repo) or curl (for public repo)
    if ! command -v gh &>/dev/null && ! command -v curl &>/dev/null; then
        fatal "Either gh (GitHub CLI) or curl is required"
    fi

    # Check systemd
    if ! command -v systemctl &>/dev/null; then
        fatal "systemd is required. SysV/OpenRC are not supported."
    fi

    # Verify we can get root (prompt early so user isn't surprised later)
    if [[ $EUID -ne 0 ]]; then
        info "Root privileges required for installation. You may be prompted for your password."
        sudo -v || fatal "Could not obtain root privileges"
    fi
}

# --- Download helper: gh with curl fallback ---
# Runs as the invoking user (not root) so gh auth works
gh_download() {
    local repo="$1"
    local tag="$2"
    local asset="$3"
    local output="$4"

    if command -v gh &>/dev/null; then
        gh release download "$tag" --repo "$repo" --pattern "$asset" --output "$output" 2>/dev/null && return 0
    fi

    # Fallback to curl (works when repo is public)
    if command -v curl &>/dev/null; then
        local url="https://github.com/${repo}/releases/download/${tag}/${asset}"
        curl -sSL -o "$output" "$url" 2>/dev/null && return 0
    fi

    return 1
}

# --- Resolve version ---
# Runs as the invoking user (not root) so gh auth works
resolve_version() {
    if [[ -n "$VERSION" ]]; then
        echo "$VERSION"
        return
    fi

    info "Fetching latest version..."
    local latest

    if command -v gh &>/dev/null; then
        latest=$(gh release list --repo "${REPO}" --limit 1 --json tagName --jq '.[0].tagName' 2>/dev/null)
    fi

    if [[ -z "${latest:-}" ]] && command -v curl &>/dev/null; then
        latest=$(curl -sSL -H "Accept: application/json" \
            "https://api.github.com/repos/${REPO}/releases/latest" \
            | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')
    fi

    if [[ -z "${latest:-}" ]]; then
        fatal "Could not determine latest version. Use --version to specify."
    fi

    echo "$latest"
}

# --- Download and verify ---
# Runs as the invoking user (not root) so gh auth works
download_and_verify() {
    local version="$1"
    local platform="$2"
    local archive_name="${BINARY_NAME}_${version#v}_${platform}.tar.gz"
    local checksums_name="checksums.txt"
    local tmp_dir
    tmp_dir=$(mktemp -d)

    info "Downloading ${archive_name}..."
    gh_download "$REPO" "$version" "$archive_name" "${tmp_dir}/${archive_name}" \
        || fatal "Download failed: ${archive_name}"

    info "Downloading checksums..."
    gh_download "$REPO" "$version" "$checksums_name" "${tmp_dir}/checksums.txt" \
        || fatal "Checksums download failed"

    # Verify checksum
    info "Verifying SHA-256 checksum..."
    local expected
    expected=$(grep "${archive_name}" "${tmp_dir}/checksums.txt" | awk '{print $1}')
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

# --- Install binary (requires root) ---
install_binary() {
    local binary_path="$1"

    if [[ "$UPGRADE" == true ]]; then
        info "Stopping ${SERVICE_NAME}..."
        as_root systemctl stop "${SERVICE_NAME}" 2>/dev/null || true
    fi

    info "Installing binary to ${INSTALL_DIR}/${BINARY_NAME}..."
    as_root install -m 0755 "$binary_path" "${INSTALL_DIR}/${BINARY_NAME}"
    ok "Binary installed"
}

# --- Create system user (requires root) ---
create_user() {
    if id "${SERVICE_USER}" &>/dev/null; then
        return
    fi

    info "Creating system user: ${SERVICE_USER}"
    local nologin="/usr/sbin/nologin"
    [[ -x "/usr/bin/nologin" ]] && nologin="/usr/bin/nologin"
    as_root useradd --system --no-create-home --shell "$nologin" "${SERVICE_USER}"
    ok "User created"
}

# --- Create data directory (requires root) ---
create_data_dir() {
    info "Creating data directory: ${DATA_DIR}"
    as_root mkdir -p "${DATA_DIR}/wal"
    as_root chown -R "${SERVICE_USER}:${SERVICE_USER}" "${DATA_DIR}"
    as_root chmod 0700 "${DATA_DIR}"
    ok "Data directory ready"
}

# --- Install systemd unit (requires root) ---
install_systemd() {
    if [[ -f "/etc/systemd/system/${SERVICE_NAME}.service" ]] && [[ "$UPGRADE" == true ]]; then
        # Patch out directives that block self-update via sudo
        local svc="/etc/systemd/system/${SERVICE_NAME}.service"
        if grep -q "NoNewPrivileges=yes" "$svc" 2>/dev/null; then
            info "Patching systemd unit: removing NoNewPrivileges (required for self-update)..."
            as_root sed -i '/^NoNewPrivileges=yes$/d; /^RestrictSUIDSGID=yes$/d' "$svc"
            as_root systemctl daemon-reload
        fi
        return
    fi

    info "Installing systemd unit..."
    as_root tee "/etc/systemd/system/${SERVICE_NAME}.service" > /dev/null << UNIT
[Unit]
Description=blind.watch monitoring agent
Documentation=https://github.com/${REPO}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_USER}
ExecStart=${INSTALL_DIR}/${BINARY_NAME} --data-dir ${DATA_DIR} --wal-dir ${DATA_DIR}/wal
Restart=always
RestartSec=10
WatchdogSec=300

# Security hardening
LimitCORE=0
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=${DATA_DIR}
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
# NoNewPrivileges and RestrictSUIDSGID are omitted — agent needs sudo for self-update
# (scoped sudoers entry limits it to /usr/local/lib/blindwatch/upgrade.sh only)
# MemoryDenyWriteExecute=yes is omitted — Go runtime requires W+X memory

[Install]
WantedBy=multi-user.target
UNIT

    as_root systemctl daemon-reload
    ok "Systemd unit installed"
}

# --- First boot provisioning (requires root for sudo -u) ---
run_first_boot() {
    if as_root test -f "${DATA_DIR}/state.json"; then
        info "Agent already provisioned, skipping first boot"
        return
    fi

    if [[ -z "${BW_TOKEN}" ]] || [[ -z "${BW_SECRET}" ]]; then
        fatal "Token and secret are required for first install. Use --token and --secret flags."
    fi

    info "Running first-boot provisioning..."

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

# --- Install upgrade helper + sudoers entry (requires root) ---
install_upgrade_helper() {
    info "Installing upgrade helper..."
    as_root mkdir -p /usr/local/lib/blindwatch
    as_root tee /usr/local/lib/blindwatch/upgrade.sh > /dev/null << 'UPGRADE'
#!/bin/bash
set -euo pipefail
VERSION="${1:?Usage: upgrade.sh VERSION}"
# Validate version format (vX.Y.Z or X.Y.Z)
if [[ ! "$VERSION" =~ ^v?[0-9]+\.[0-9]+\.[0-9]+ ]]; then
    echo "Invalid version: $VERSION" >&2; exit 1
fi
# Run in a transient systemd unit so the upgrade survives the agent service being stopped.
# Without this, systemd kills all processes in the agent's cgroup (including our children)
# when the install script runs "systemctl stop blindwatch-agent".
systemd-run --unit=blindwatch-upgrade --description="blind.watch agent upgrade" \
    bash -c 'curl -sSL https://get.blind.watch/agent | bash -s -- --upgrade --version "'"$VERSION"'"'
UPGRADE
    as_root chmod 0755 /usr/local/lib/blindwatch/upgrade.sh

    # Sudoers entry — scoped to upgrade script only
    as_root tee /etc/sudoers.d/blindwatch > /dev/null << SUDOERS
${SERVICE_USER} ALL=(root) NOPASSWD: /usr/local/lib/blindwatch/upgrade.sh
SUDOERS
    as_root chmod 0440 /etc/sudoers.d/blindwatch
    ok "Upgrade helper installed"
}

# --- Start service (requires root) ---
start_service() {
    info "Starting ${SERVICE_NAME}..."
    as_root systemctl enable "${SERVICE_NAME}"
    as_root systemctl start "${SERVICE_NAME}"

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

    # Phase 1: Download & verify (runs as invoking user — gh auth works)
    local platform version binary_path
    platform=$(detect_platform)
    info "Platform: ${platform}"

    version=$(resolve_version)
    info "Version: ${version}"

    binary_path=$(download_and_verify "$version" "$platform")

    # Phase 2: Install (elevates to root via as_root helper)
    install_binary "$binary_path"
    create_user
    create_data_dir
    install_systemd

    install_upgrade_helper

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

    # Clear sensitive vars
    unset BW_TOKEN BW_SECRET 2>/dev/null || true
}

main "$@"
