#!/bin/bash

# ============================================================================
# LUVEEDU ENTERPRISE FIREWALL - ALL-IN-ONE INSTALLER
# ============================================================================
# One-command installation for enterprise-grade server protection
# 
# Usage: curl -sSL https://raw.githubusercontent.com/Luveedu/Luveedu-Firewall/main/install.sh | sudo bash
#
# Repository: https://github.com/Luveedu/Luveedu-Firewall
# ============================================================================

set -euo pipefail

# Configuration
readonly GITHUB_RAW_URL="https://raw.githubusercontent.com/Luveedu/Luveedu-Firewall/main"
readonly INSTALL_DIR="/opt/luveedu-firewall"
readonly LOG_DIR="/var/log/luveedu"
readonly CONFIG_FILE="$INSTALL_DIR/config.json"
readonly SERVICE_MAIN="luvd-firewall.service"
readonly SERVICE_SHIELD="luvd-shield.service"

# Colors
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m'

# Logging functions
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[✓ SUCCESS]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[⚠ WARN]${NC} $1"; }
log_error() { echo -e "${RED}[✗ ERROR]${NC} $1"; }
log_step() { echo -e "${CYAN}[→ STEP]${NC} $1"; }

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        echo ""
        echo "Usage: curl -sSL https://raw.githubusercontent.com/Luveedu/Luveedu-Firewall/main/install.sh | sudo bash"
        exit 1
    fi
}

# Detect OS and package manager
detect_os() {
    log_step "Detecting operating system..."
    
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_NAME=$NAME
        OS_VERSION=$VERSION_ID
        OS_ID=$ID
        
        case $OS_ID in
            ubuntu|debian|linuxmint)
                PKG_MANAGER="apt"
                PKG_UPDATE="apt-get update"
                PKG_INSTALL="apt-get install -y"
                ;;
            centos|rhel|rocky|almalinux)
                if command -v dnf >/dev/null 2>&1; then
                    PKG_MANAGER="dnf"
                    PKG_UPDATE="dnf check-update || true"
                    PKG_INSTALL="dnf install -y"
                else
                    PKG_MANAGER="yum"
                    PKG_UPDATE="yum check-update || true"
                    PKG_INSTALL="yum install -y"
                fi
                ;;
            alpine)
                PKG_MANAGER="apk"
                PKG_UPDATE="apk update"
                PKG_INSTALL="apk add --no-cache"
                ;;
            arch|manjaro)
                PKG_MANAGER="pacman"
                PKG_UPDATE="pacman -Sy"
                PKG_INSTALL="pacman -S --noconfirm"
                ;;
            *)
                log_error "Unsupported OS: $OS_NAME ($OS_ID)"
                exit 1
                ;;
        esac
        
        log_success "Detected: $OS_NAME $OS_VERSION ($PKG_MANAGER)"
    else
        log_error "Cannot detect operating system"
        exit 1
    fi
}

# Backup existing installation
backup_existing() {
    if [ -d "$INSTALL_DIR" ]; then
        log_step "Backing up existing installation..."
        local timestamp=$(date +%Y%m%d_%H%M%S)
        local backup_dir="/opt/luveedu-backups/backup_$timestamp"
        
        mkdir -p "$(dirname $backup_dir)"
        cp -r "$INSTALL_DIR" "$backup_dir"
        
        # Backup config if exists
        if [ -f "$CONFIG_FILE" ]; then
            cp "$CONFIG_FILE" "$backup_dir/config.json.backup"
        fi
        
        log_success "Backup created: $backup_dir"
    fi
}

# Install prerequisites
install_prerequisites() {
    log_step "Installing security prerequisites..."
    
    case $PKG_MANAGER in
        apt)
            $PKG_UPDATE -qq
            $PKG_INSTALL iptables ipset curl wget cron clamav clamav-daemon rkhunter jq systemd
            systemctl enable --now clamav-freshclam 2>/dev/null || true
            ;;
        dnf|yum)
            $PKG_UPDATE
            $PKG_INSTALL iptables ipset curl wget cronie clamav clamav-server rkhunter jq systemd
            systemctl enable --now clamav-freshclam 2>/dev/null || true
            ;;
        apk)
            $PKG_UPDATE
            $PKG_INSTALL iptables ipset curl wget openrc clamav rkhunter jq
            rc-update add crond 2>/dev/null || true
            ;;
        pacman)
            $PKG_UPDATE
            $PKG_INSTALL iptables ipset curl wget cron clamav rkhunter jq systemd
            systemctl enable --now clamav-freshclam 2>/dev/null || true
            ;;
    esac
    
    # Ensure cron is running
    if command -v systemctl >/dev/null 2>&1; then
        systemctl enable --now cron 2>/dev/null || systemctl enable --now crond 2>/dev/null || true
    fi
    
    log_success "Prerequisites installed"
}

# Create directory structure
create_directories() {
    log_step "Creating directory structure..."
    
    mkdir -p "$INSTALL_DIR"
    mkdir -p "$LOG_DIR"
    mkdir -p "$INSTALL_DIR/backups"
    mkdir -p "$INSTALL_DIR/quarantine"
    
    chmod 755 "$INSTALL_DIR"
    chmod 750 "$LOG_DIR"
    chmod 700 "$INSTALL_DIR/quarantine"
    
    log_success "Directories created"
}

# Download components from GitHub
download_components() {
    log_step "Downloading components from GitHub..."
    
    local download_count=0
    local fail_count=0
    
    # Download main binary (pre-compiled)
    log_info "Downloading luvd-firewall binary..."
    if curl -sSL -f -o "$INSTALL_DIR/luvd-firewall" "$GITHUB_RAW_URL/luvd-firewall" 2>/dev/null; then
        chmod +x "$INSTALL_DIR/luvd-firewall"
        ((download_count++))
        log_success "Downloaded: luvd-firewall"
    else
        log_warn "Binary not found (will be compiled if source available)"
        ((fail_count++))
    fi
    
    # Download configuration
    log_info "Downloading config.json..."
    if curl -sSL -f -o "$CONFIG_FILE" "$GITHUB_RAW_URL/config.json" 2>/dev/null; then
        ((download_count++))
        log_success "Downloaded: config.json"
    else
        log_info "Creating default config.json..."
        cat > "$CONFIG_FILE" << 'EOF'
{
    "version": "1.0.0",
    "rate_limit": {
        "burst_window_seconds": 3,
        "burst_max_requests": 15,
        "sustained_window_seconds": 30,
        "sustained_max_requests": 150
    },
    "block_duration_seconds": 3600,
    "whitelist_ips": [],
    "blacklist_ips": [],
    "api": {
        "enabled": true,
        "endpoint": "https://api.luveedu.com/v1/threat-intel",
        "timeout_seconds": 5,
        "cache_ttl_seconds": 300
    },
    "logging": {
        "level": "info",
        "max_size_mb": 100,
        "max_backups": 7
    },
    "waf": {
        "enabled": true,
        "block_sql_injection": true,
        "block_xss": true,
        "block_path_traversal": true,
        "block_rce": true
    },
    "scanner": {
        "enabled": true,
        "clamav_enabled": true,
        "rkhunter_enabled": true,
        "scan_schedule": "daily"
    }
}
EOF
        ((download_count++))
    fi
    
    # Download shield script
    log_info "Downloading luvd-shield.sh..."
    if curl -sSL -f -o "$INSTALL_DIR/luvd-shield.sh" "$GITHUB_RAW_URL/luvd-shield.sh" 2>/dev/null; then
        chmod +x "$INSTALL_DIR/luvd-shield.sh"
        ((download_count++))
        log_success "Downloaded: luvd-shield.sh"
    else
        log_warn "luvd-shield.sh not found"
        ((fail_count++))
    fi
    
    # Download antivirus script
    log_info "Downloading luvd-antivirus.sh..."
    if curl -sSL -f -o "$INSTALL_DIR/luvd-antivirus.sh" "$GITHUB_RAW_URL/luvd-antivirus.sh" 2>/dev/null; then
        chmod +x "$INSTALL_DIR/luvd-antivirus.sh"
        ((download_count++))
        log_success "Downloaded: luvd-antivirus.sh"
    else
        log_warn "luvd-antivirus.sh not found"
        ((fail_count++))
    fi
    
    # Download WAF script
    log_info "Downloading luvd-waf.sh..."
    if curl -sSL -f -o "$INSTALL_DIR/luvd-waf.sh" "$GITHUB_RAW_URL/luvd-waf.sh" 2>/dev/null; then
        chmod +x "$INSTALL_DIR/luvd-waf.sh"
        ((download_count++))
        log_success "Downloaded: luvd-waf.sh"
    else
        log_warn "luvd-waf.sh not found"
        ((fail_count++))
    fi
    
    # Download update script
    log_info "Downloading update.sh..."
    if curl -sSL -f -o "$INSTALL_DIR/update.sh" "$GITHUB_RAW_URL/update.sh" 2>/dev/null; then
        chmod +x "$INSTALL_DIR/update.sh"
        ((download_count++))
        log_success "Downloaded: update.sh"
    else
        log_info "Creating default update.sh..."
        cat > "$INSTALL_DIR/update.sh" << 'UPDATEEOF'
#!/bin/bash
# Luveedu Firewall Auto-Updater
set -euo pipefail
INSTALL_DIR="/opt/luveedu-firewall"
GITHUB_RAW_URL="https://raw.githubusercontent.com/Luveedu/Luveedu-Firewall/main"

echo "[INFO] Checking for updates..."

# Stop services
systemctl stop luvd-firewall luvd-shield 2>/dev/null || true

# Backup current version
cp -r "$INSTALL_DIR" "$INSTALL_DIR/backups/backup_$(date +%Y%m%d_%H%M%S)"

# Download new versions
curl -sSL -o "$INSTALL_DIR/luvd-firewall.new" "$GITHUB_RAW_URL/luvd-firewall" && \
    mv "$INSTALL_DIR/luvd-firewall.new" "$INSTALL_DIR/luvd-firewall" && \
    chmod +x "$INSTALL_DIR/luvd-firewall"

curl -sSL -o "$INSTALL_DIR/update.sh.new" "$GITHUB_RAW_URL/update.sh" && \
    mv "$INSTALL_DIR/update.sh.new" "$INSTALL_DIR/update.sh" && \
    chmod +x "$INSTALL_DIR/update.sh"

# Restart services
systemctl start luvd-firewall luvd-shield

echo "[SUCCESS] Update completed!"
UPDATEEOF
        chmod +x "$INSTALL_DIR/update.sh"
        ((download_count++))
    fi
    
    log_success "Downloaded $download_count components"
    
    if [ $fail_count -gt 0 ]; then
        log_warn "$fail_count components not found (may be compiled later)"
    fi
}

# Initialize firewall rules
setup_firewall_rules() {
    log_step "Initializing firewall rules and ipsets..."
    
    # Create ipsets
    ipset create -exist luvd_blacklist hash:ip timeout 0 2>/dev/null || true
    ipset create -exist luvd_whitelist hash:ip timeout 0 2>/dev/null || true
    ipset create -exist luvd_temp_block hash:ip timeout 3600 2>/dev/null || true
    
    # Create custom chain if not exists
    iptables -N LUVEEDU_INPUT 2>/dev/null || true
    
    # Flush existing rules in chain
    iptables -F LUVEEDU_INPUT 2>/dev/null || true
    
    # Add rules
    iptables -A LUVEEDU_INPUT -m set --match-set luvd_whitelist src -j ACCEPT 2>/dev/null || true
    iptables -A LUVEEDU_INPUT -m set --match-set luvd_blacklist src -j DROP 2>/dev/null || true
    iptables -A LUVEEDU_INPUT -m set --match-set luvd_temp_block src -j DROP 2>/dev/null || true
    iptables -A LUVEEDU_INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
    iptables -A LUVEEDU_INPUT -j RETURN 2>/dev/null || true
    
    # Insert chain into INPUT if not already there
    if ! iptables -C INPUT -j LUVEEDU_INPUT 2>/dev/null; then
        iptables -I INPUT -j LUVEEDU_INPUT 2>/dev/null || true
    fi
    
    log_success "Firewall rules initialized"
}

# Create systemd service files
create_systemd_services() {
    log_step "Creating systemd services..."
    
    # Main firewall service
    cat > /etc/systemd/system/$SERVICE_MAIN << 'EOF'
[Unit]
Description=Luveedu Enterprise Firewall
Documentation=https://github.com/Luveedu/Luveedu-Firewall
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/opt/luveedu-firewall
ExecStart=/opt/luveedu-firewall/luvd-firewall
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=luvd-firewall

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/var/log/luveedu /opt/luveedu-firewall/quarantine

[Install]
WantedBy=multi-user.target
EOF

    # Shield monitoring service
    cat > /etc/systemd/system/$SERVICE_SHIELD << 'EOF'
[Unit]
Description=Luveedu Shield - Log Monitor & Intrusion Detection
Documentation=https://github.com/Luveedu/Luveedu-Firewall
After=luvd-firewall.service
Wants=luvd-firewall.service

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/opt/luveedu-firewall
ExecStart=/opt/luveedu-firewall/luvd-shield.sh
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=luvd-shield

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/var/log/luveedu /var/log

[Install]
WantedBy=multi-user.target
EOF

    # Reload systemd
    systemctl daemon-reload
    
    log_success "Systemd services created"
}

# Configure automated cron jobs
setup_cron_jobs() {
    log_step "Setting up automated cron jobs..."
    
    cat > /etc/cron.d/luveedu-firewall << 'EOF'
# ============================================================================
# LUVEEDU FIREWALL - AUTOMATED TASKS
# ============================================================================

# Hourly malware scan with ClamAV
0 * * * * root /usr/bin/clamscan -r --move=/opt/luveedu-firewall/quarantine /var/log/luveedu >> /var/log/luveedu/clamav-cron.log 2>&1

# Daily log rotation and cleanup (remove logs older than 7 days)
0 2 * * * root find /var/log/luveedu -name "*.log" -mtime +7 -delete

# Daily threat intelligence update
0 4 * * * root /opt/luveedu-firewall/update.sh --check-only >> /var/log/luveedu/update.log 2>&1

# Weekly rootkit detection scan
0 3 * * 0 root /usr/bin/rkhunter --update && /usr/bin/rkhunter --check --sk >> /var/log/luveedu/rkhunter.log 2>&1

# Daily ClamAV virus database update
0 5 * * * root /usr/bin/freshclam >> /var/log/luveedu/freshclam.log 2>&1
EOF

    chmod 644 /etc/cron.d/luveedu-firewall
    
    log_success "Cron jobs configured"
}

# Start and enable services
start_services() {
    log_step "Starting Luveedu Firewall services..."
    
    # Enable services
    systemctl enable $SERVICE_MAIN
    systemctl enable $SERVICE_SHIELD
    
    # Start services
    systemctl start $SERVICE_MAIN
    sleep 2
    systemctl start $SERVICE_SHIELD
    
    # Wait for services to initialize
    sleep 3
    
    # Check status
    if systemctl is-active --quiet $SERVICE_MAIN; then
        log_success "Firewall service is running"
    else
        log_error "Firewall service failed to start"
        systemctl status $SERVICE_MAIN --no-pager || true
        exit 1
    fi
    
    if systemctl is-active --quiet $SERVICE_SHIELD; then
        log_success "Shield service is running"
    else
        log_warn "Shield service may need attention"
    fi
}

# Display installation summary
show_summary() {
    echo ""
    echo "============================================================================"
    echo -e "  ${GREEN}✓ LUVEEDU ENTERPRISE FIREWALL INSTALLED SUCCESSFULLY${NC}"
    echo "============================================================================"
    echo ""
    echo -e "${CYAN}Installation Details:${NC}"
    echo "  • Install Directory: $INSTALL_DIR"
    echo "  • Log Directory:     $LOG_DIR"
    echo "  • Config File:       $CONFIG_FILE"
    echo ""
    echo -e "${CYAN}Useful Commands:${NC}"
    echo "  • Status:      systemctl status luvd-firewall"
    echo "  • Logs:        journalctl -u luvd-firewall -f"
    echo "  • Block IP:    $INSTALL_DIR/luvd-firewall block <IP_ADDRESS>"
    echo "  • Unblock IP:  $INSTALL_DIR/luvd-firewall unblock <IP_ADDRESS>"
    echo "  • List Blocks: $INSTALL_DIR/luvd-firewall list"
    echo "  • Statistics:  $INSTALL_DIR/luvd-firewall stats"
    echo "  • Scan Files:  $INSTALL_DIR/luvd-antivirus.sh scan <PATH>"
    echo "  • Update:      $INSTALL_DIR/update.sh"
    echo ""
    echo -e "${CYAN}Services:${NC}"
    systemctl status $SERVICE_MAIN --no-pager | head -5
    echo ""
    systemctl status $SERVICE_SHIELD --no-pager | head -5
    echo ""
    echo -e "${CYAN}Documentation:${NC}"
    echo "  • GitHub: https://github.com/Luveedu/Luveedu-Firewall"
    echo "  • README: https://github.com/Luveedu/Luveedu-Firewall/blob/main/README.md"
    echo ""
    echo "============================================================================"
    echo -e "  ${GREEN}Your server is now protected by Luveedu Enterprise Firewall!${NC}"
    echo "============================================================================"
    echo ""
}

# Main installation function
main() {
    echo ""
    echo "============================================================================"
    echo -e "  ${BLUE}LUVEEDU ENTERPRISE FIREWALL INSTALLER v1.0.0${NC}"
    echo "============================================================================"
    echo ""
    
    check_root
    detect_os
    backup_existing
    create_directories
    install_prerequisites
    download_components
    setup_firewall_rules
    create_systemd_services
    setup_cron_jobs
    start_services
    show_summary
}

# Run installation
main "$@"
