#!/usr/bin/env bash
#===============================================================================
# LUVEEDU FIREWALL - ALL-IN-ONE INSTALLER
# Enterprise Grade Security Suite for Linux Servers
# 
# Usage: curl -sSL https://raw.githubusercontent.com/USER/REPO/main/install.sh | sudo bash
#
# Features:
# - Auto-detects OS and Package Manager
# - Installs Prerequisites (Go, ClamAV, rkhunter, iptables, ipset)
# - Downloads latest binaries/configs from GitHub
# - Creates Systemd Services
# - Configures Cron Jobs
# - Initializes Firewall Rules
#===============================================================================

set -euo pipefail

# Configuration
readonly GITHUB_REPO="https://raw.githubusercontent.com/Luveedu/Luveedu-Firewall/refs/heads/main/"
readonly INSTALL_DIR="/opt/luveedu-firewall"
readonly BIN_DIR="/usr/local/bin"
readonly CONFIG_DIR="/etc/luveedu-firewall"
readonly SERVICE_DIR="/etc/systemd/system"
readonly LOG_DIR="/var/log/luveedu"
readonly USER="root"
readonly VERSION="1.0.0"

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# Logging functions
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Check for root privileges
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (sudo)."
        exit 1
    fi
}

# Detect Package Manager
detect_package_manager() {
    if command -v apt-get &> /dev/null; then
        PM="apt"
        UPDATE_CMD="apt-get update -qq"
        INSTALL_CMD="apt-get install -y -qq"
    elif command -v yum &> /dev/null; then
        PM="yum"
        UPDATE_CMD="yum makecache -q"
        INSTALL_CMD="yum install -y -q"
    elif command -v dnf &> /dev/null; then
        PM="dnf"
        UPDATE_CMD="dnf makecache -q"
        INSTALL_CMD="dnf install -y -q"
    elif command -v apk &> /dev/null; then
        PM="apk"
        UPDATE_CMD="apk update -q"
        INSTALL_CMD="apk add -q"
    else
        log_error "Unsupported package manager. Cannot proceed."
        exit 1
    fi
    log_info "Detected package manager: $PM"
}

# Install Prerequisites
install_prerequisites() {
    log_info "Updating package lists..."
    $UPDATE_CMD || true # Continue even if update fails slightly

    log_info "Installing security prerequisites..."
    local packages=(
        "iptables"
        "ipset"
        "curl"
        "wget"
        "git"
        "cron"
    )

    # Add specific packages based on PM
    if [[ "$PM" == "apt" ]]; then
        packages+=("clamav" "clamav-daemon" "rkhunter" "golang-go" "systemd")
        # Ensure clamav service user exists
        id -u clamav &>/dev/null || useradd -r -s /usr/sbin/nologin clamav
    elif [[ "$PM" == "yum" ]] || [[ "$PM" == "dnf" ]]; then
        packages+=("clamav" "clamav-scanner-systemd" "rkhunter" "golang" "systemd")
    elif [[ "$PM" == "apk" ]]; then
        packages+=("clamav" "rkhunter" "go" "openrc")
    fi

    $INSTALL_CMD "${packages[@]}"
    
    log_success "Prerequisites installed."
}

# Create Directory Structure
create_directories() {
    log_info "Creating directory structure..."
    mkdir -p "$INSTALL_DIR"
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$LOG_DIR"
    mkdir -p "$CONFIG_DIR/quarantine"
    chmod 750 "$CONFIG_DIR/quarantine"
    log_success "Directories created."
}

# Download Components from GitHub
download_components() {
    log_info "Downloading components from GitHub..."
    
    # Define files to download
    local files=(
        "luvd-firewall"       # Main binary (assuming pre-compiled or script)
        "config.json"         # Configuration
        "luvd-shield.sh"      # Shield script
        "luvd-antivirus.sh"   # Antivirus script
        "update.sh"           # Updater
    )

    # If binary doesn't exist in repo, we might need to compile or use a shell wrapper
    # For this installer, we assume the repo contains the ready-to-run files or a master script
    
    for file in "${files[@]}"; do
        local url="${GITHUB_REPO}/${file}"
        log_info "Downloading ${file}..."
        if curl -sSL --fail "$url" -o "${INSTALL_DIR}/${file}"; then
            chmod +x "${INSTALL_DIR}/${file}"
        else
            log_warn "Failed to download ${file}. Skipping (might be compiled later)."
        fi
    done

    # Download the main Go source if binary wasn't found, and compile
    if [[ ! -f "${INSTALL_DIR}/luvd-firewall" ]] || [[ ! -x "${INSTALL_DIR}/luvd-firewall" ]]; then
        log_info "Binary not found or not executable. Attempting to download source and compile..."
        local go_files=("main.go" "go.mod" "go.sum")
        local downloaded_source=false
        
        for file in "${go_files[@]}"; do
            if curl -sSL --fail "${GITHUB_REPO}/${file}" -o "${INSTALL_DIR}/${file}"; then
                downloaded_source=true
            fi
        done

        if [[ "$downloaded_source" == true ]]; then
            log_info "Compiling Go binary..."
            cd "$INSTALL_DIR"
            export GOPATH=$(mktemp -d)
            go build -o luvd-firewall . || {
                log_error "Compilation failed. Ensure Go is installed correctly."
                exit 1
            }
            chmod +x luvd-firewall
            rm -f main.go go.mod go.sum # Clean up source after compile
            log_success "Binary compiled successfully."
        else
            log_error "Could not retrieve binary or source code. Check repository URL."
            exit 1
        fi
    fi

    # Create default config if missing
    if [[ ! -f "${CONFIG_DIR}/config.json" ]]; then
        cat > "${CONFIG_DIR}/config.json" <<EOF
{
    "rate_limit": {
        "burst_threshold": 15,
        "burst_window": 3,
        "sustained_threshold": 150,
        "sustained_window": 30
    },
    "block_duration": 3600,
    "log_path": "/var/log/luveedu/firewall.log",
    "api_url": "https://api.luveedu.com/threat-intel",
    "enabled_modules": ["firewall", "shield", "waf", "antivirus"]
}
EOF
        log_info "Default configuration created."
    fi
}

# Create Systemd Services
create_services() {
    log_info "Creating systemd services..."

    # Luvd Firewall Service
    cat > "${SERVICE_DIR}/luvd-firewall.service" <<EOF
[Unit]
Description=Luveedu Enterprise Firewall Engine
After=network.target iptables.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=${INSTALL_DIR}/luvd-firewall start
ExecStop=${INSTALL_DIR}/luvd-firewall stop
Restart=on-failure
RestartSec=5
EnvironmentFile=-${CONFIG_DIR}/env
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

    # Luvd Shield Service (Log Monitor)
    cat > "${SERVICE_DIR}/luvd-shield.service" <<EOF
[Unit]
Description=Luveedu Kernel Shield & Log Monitor
After=luvd-firewall.service syslog.target

[Service]
Type=simple
ExecStart=/bin/bash ${INSTALL_DIR}/luvd-shield.sh daemon
ExecStop=/bin/pkill -f "luvd-shield.sh daemon"
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    log_success "Systemd services created."
}

# Configure Cron Jobs
setup_cron() {
    log_info "Setting up automated cron jobs..."
    
    local cron_job_file="/etc/cron.d/luveedu-firewall"
    
    cat > "$cron_job_file" <<EOF
# Luveedu Firewall Automated Tasks
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Hourly Malware Scan
0 * * * * root ${INSTALL_DIR}/luvd-antivirus.sh scan --quiet >> ${LOG_DIR}/antivirus-cron.log 2>&1

# Daily Log Rotation and Cleanup
0 3 * * * root find ${LOG_DIR} -name "*.log" -mtime +7 -delete
0 4 * * * root ${INSTALL_DIR}/update.sh --check >> ${LOG_DIR}/update-check.log 2>&1
EOF

    chmod 644 "$cron_job_file"
    log_success "Cron jobs configured."
}

# Initialize Firewall Rules
init_firewall() {
    log_info "Initializing firewall rules and ipsets..."
    
    # Create IPSets
    ipset create luvd_blacklist hash:ip timeout 0 2>/dev/null || true
    ipset create luvd_whitelist hash:ip timeout 0 2>/dev/null || true
    ipset create luvd_temp_block hash:ip timeout 3600 2>/dev/null || true
    
    # Basic Protection Rules (Idempotent)
    # Note: We append rather than insert to avoid disrupting existing custom rules
    iptables -N LUVEEDU_INPUT 2>/dev/null || true
    iptables -F LUVEEDU_INPUT
    
    # Jump to our chain
    iptables -C INPUT -j LUVEEDU_INPUT 2>/dev/null || iptables -I INPUT 1 -j LUVEEDU_INPUT
    
    # Allow established
    iptables -A LUVEEDU_INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    
    # Drop blacklisted
    iptables -A LUVEEDU_INPUT -m set --match-set luvd_blacklist src -j DROP
    
    # Log and drop temp blocked
    iptables -A LUVEEDU_INPUT -m set --match-set luvd_temp_block src -j LOG --log-prefix "LUVEEDU-BLOCK: "
    iptables -A LUVEEDU_INPUT -m set --match-set luvd_temp_block src -j DROP

    log_success "Firewall rules initialized."
}

# Start Services
start_services() {
    log_info "Starting services..."
    
    systemctl enable luvd-firewall
    systemctl enable luvd-shield
    
    systemctl restart luvd-firewall
    systemctl restart luvd-shield
    
    # Verify status
    if systemctl is-active --quiet luvd-firewall; then
        log_success "Luveedu Firewall is running."
    else
        log_warn "Luveedu Firewall service failed to start. Check logs."
    fi
}

# Backup Existing Installation
backup_existing() {
    if [[ -d "$INSTALL_DIR" ]]; then
        local backup_name="${INSTALL_DIR}.bak.$(date +%Y%m%d%H%M%S)"
        log_warn "Existing installation found. Creating backup at ${backup_name}..."
        mv "$INSTALL_DIR" "$backup_name"
        
        if [[ -f "${CONFIG_DIR}/config.json" ]]; then
             mkdir -p /tmp/luveedu_backup
             cp -r "${CONFIG_DIR}"/* /tmp/luveedu_backup/
        fi
    fi
}

# Main Execution
main() {
    echo "========================================================"
    echo "  LUVEEDU ENTERPRISE FIREWALL INSTALLER v${VERSION}"
    echo "========================================================"
    
    check_root
    detect_package_manager
    backup_existing
    create_directories
    install_prerequisites
    download_components
    create_services
    setup_cron
    init_firewall
    start_services
    
    echo ""
    log_success "Installation completed successfully!"
    echo ""
    echo "Useful Commands:"
    echo "  Status:   systemctl status luvd-firewall"
    echo "  Logs:     tail -f ${LOG_DIR}/firewall.log"
    echo "  Block IP: ${INSTALL_DIR}/luvd-firewall block <IP>"
    echo "  Update:   ${INSTALL_DIR}/update.sh"
    echo ""
    echo "Documentation: https://github.com/YOUR_GITHUB_USERNAME/YOUR_REPO_NAME"
    echo "========================================================"
}

# Run Main
main "$@"
