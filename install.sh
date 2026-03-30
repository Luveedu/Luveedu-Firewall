#!/bin/bash

# =============================================================================
# Luveedu Firewall v2.0 - Enterprise Grade Installer (Non-Interactive Force Mode)
# =============================================================================
# This script installs Go, dependencies, compiles the firewall, and sets up 
# systemd services. It forces non-interactive mode to bypass all prompts 
# (including Postfix, Dovecot, etc.).
# =============================================================================

set -euo pipefail

# Force Non-Interactive Mode for ALL subprocesses
export DEBIAN_FRONTEND=noninteractive
export TZ=UTC

readonly GITHUB_REPO="https://raw.githubusercontent.com/Luveedu/Luveedu-Firewall/main"
readonly INSTALL_DIR="/opt/luveedu-firewall"
readonly LOG_DIR="/var/log/luveedu"
readonly DATA_DIR="/opt/luveedu-firewall/data"
readonly QUARANTINE_DIR="/opt/luveedu-firewall/quarantine"
readonly BACKUP_DIR="/opt/luveedu-firewall-backups"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

check_root() {
    [[ $EUID -ne 0 ]] && { log_error "Must run as root"; exit 1; }
}

detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$NAME
        case $ID in
            ubuntu|debian) PKG_MANAGER="apt" ;;
            centos|rhel|fedora) PKG_MANAGER=$(command -v dnf >/dev/null && echo "dnf" || echo "yum") ;;
            alpine) PKG_MANAGER="apk" ;;
            arch) PKG_MANAGER="pacman" ;;
            *) log_error "Unsupported OS: $ID"; exit 1 ;;
        esac
        log_info "Detected: $OS with $PKG_MANAGER"
    fi
}

wait_for_apt() {
    # Only for apt-based systems
    [[ "$PKG_MANAGER" != "apt" ]] && return
    
    log_info "Waiting for apt locks..."
    local count=0
    while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || \
          fuser /var/lib/apt/lists/lock >/dev/null 2>&1 || \
          fuser /var/cache/apt/archives/lock >/dev/null 2>&1; do
        count=$((count + 1))
        if [ $count -gt 60 ]; then
            log_error "Timeout waiting for apt lock"
        fi
        log_warn "Waiting for package manager... ($count/60)"
        sleep 5
    done
}

install_prerequisites() {
    log_info "Installing prerequisites (force non-interactive)..."
    
    case $PKG_MANAGER in
        apt)
            wait_for_apt
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -qq
            
            # Pre-seed Postfix to avoid interactive prompts
            debconf-set-selections <<< "postfix postfix/main_mailer_type select Internet Site"
            debconf-set-selections <<< "postfix postfix/mailname string localhost.localdomain"
            debconf-set-selections <<< "postfix postfix/mydestination string localhost.localdomain, localhost"
            
            # Install all packages with force options to skip prompts
            apt-get install -y -qq \
                iptables ipset curl wget git cron \
                clamav clamav-daemon rkhunter golang-go jq \
                build-essential debconf-utils postfix mailutils \
                --no-install-recommends \
                -o Dpkg::Options::="--force-confdef" \
                -o Dpkg::Options::="--force-confold"
            
            # Force reconfigure postfix non-interactively
            dpkg-reconfigure -f noninteractive postfix || true
            
            # Configure ClamAV
            systemctl enable clamav-freshclam
            systemctl enable clamav-daemon
            systemctl start clamav-freshclam
            systemctl start clamav-daemon || true
            ;;
        dnf|yum)
            $PKG_MANAGER install -y iptables ipset curl wget git cronie clamav clamav-server rkhunter golang jq postfix
            systemctl enable --now clamd-update 2>/dev/null || true
            systemctl enable --now clamd@scan 2>/dev/null || true
            ;;
        apk)
            apk add --no-cache iptables ipset curl wget git openrc cronie clamav rkhunter go jq postfix
            rc-update add clamav-freshclam
            rc-update add clamav
            ;;
        pacman)
            pacman -Sy --noconfirm --needed iptables ipset curl wget git cron clamav rkhunter go jq postfix
            systemctl enable --now clamav-freshclam.service 2>/dev/null || true
            systemctl enable --now clamav-daemon.service 2>/dev/null || true
            ;;
    esac
    
    log_success "Prerequisites installed"
}

backup_existing() {
    [ -d "$INSTALL_DIR" ] && {
        mkdir -p "$BACKUP_DIR"
        cp -r "$INSTALL_DIR" "$BACKUP_DIR/backup_$(date +%Y%m%d_%H%M%S)/"
        log_warn "Backed up existing installation"
    }
}

download_components() {
    log_info "Downloading from GitHub..."
    mkdir -p "$INSTALL_DIR/$LOG_DIR" "$DATA_DIR" "$QUARANTINE_DIR"
    cd "$INSTALL_DIR"
    
    curl -sSL -o go.mod "$GITHUB_REPO/go.mod" || true
    mkdir -p cmd internal/config internal/engine internal/waf internal/scanner
    curl -sSL -o cmd/main.go "$GITHUB_REPO/cmd/main.go" || true
    curl -sSL -o internal/config/config.go "$GITHUB_REPO/internal/config/config.go" || true
    curl -sSL -o internal/engine/engine.go "$GITHUB_REPO/internal/engine/engine.go" || true
    curl -sSL -o internal/waf/waf.go "$GITHUB_REPO/internal/waf/waf.go" || true
    curl -sSL -o internal/scanner/scanner.go "$GITHUB_REPO/internal/scanner/scanner.go" || true
    curl -sSL -o config.json "$GITHUB_REPO/config.json" || true
    curl -sSL -o VERSION "$GITHUB_REPO/VERSION" || echo "1.0.0" > VERSION
    curl -sSL -o update.sh "$GITHUB_REPO/update.sh" && chmod +x update.sh || true
    
    log_success "Components downloaded"
}

build_binary() {
    log_info "Building binary..."
    cd "$INSTALL_DIR"
    export GOPATH="$INSTALL_DIR/gopath"
    go mod download
    go build -o luvd-firewall ./cmd/main.go
    chmod +x luvd-firewall
    rm -rf gopath
    log_success "Binary built"
}

setup_firewall_rules() {
    log_info "Setting up firewall..."
    ipset create -exist luvd_blacklist hash:ip timeout 0 2>/dev/null || true
    ipset create -exist luvd_whitelist hash:ip timeout 0 2>/dev/null || true
    ipset create -exist luvd_temp_block hash:ip timeout 3600 2>/dev/null || true
    iptables -N LUVEEDU_INPUT 2>/dev/null || true
    iptables -F LUVEEDU_INPUT 2>/dev/null || true
    iptables -A LUVEEDU_INPUT -m set --match-set luvd_whitelist src -j ACCEPT
    iptables -A LUVEEDU_INPUT -m set --match-set luvd_blacklist src -j DROP
    iptables -A LUVEEDU_INPUT -m set --match-set luvd_temp_block src -j DROP
    iptables -A LUVEEDU_INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    iptables -A LUVEEDU_INPUT -j RETURN
    iptables -C INPUT -j LUVEEDU_INPUT 2>/dev/null || iptables -I INPUT 1 -j LUVEEDU_INPUT
    log_success "Firewall configured"
}

create_services() {
    log_info "Creating systemd services..."
    cat > /etc/systemd/system/luvd-firewall.service << 'EOF'
[Unit]
Description=Luveedu Firewall Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/luveedu-firewall
ExecStart=/opt/luveedu-firewall/luvd-firewall
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    cat > /etc/systemd/system/luvd-shield.service << 'EOF'
[Unit]
Description=Luveedu Shield Monitor
After=luvd-firewall.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/luveedu-firewall
ExecStart=/opt/luveedu-firewall/luvd-firewall monitor
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable luvd-firewall luvd-shield
    log_success "Services created"
}

create_crons() {
    log_info "Creating cron jobs..."
    cat > /etc/cron.d/luveedu-firewall << 'EOF'
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
0 2 * * * root /opt/luveedu-firewall/luvd-firewall scan /var/www >> /var/log/luveedu/cron.log 2>&1
0 3 * * 0 root rkhunter --update && rkhunter --check --sk >> /var/log/luveedu/cron.log 2>&1
0 4 * * * root /opt/luveedu-firewall/update.sh --check >> /var/log/luveedu/cron.log 2>&1
0 * * * * root find /var/log/luveedu -name "*.log" -mtime +7 -delete
EOF
    chmod 644 /etc/cron.d/luveedu-firewall
    log_success "Cron jobs created"
}

start_services() {
    log_info "Starting services..."
    systemctl start luvd-firewall luvd-shield
    sleep 3
    systemctl is-active --quiet luvd-firewall && log_success "Services started" || { log_error "Failed to start"; exit 1; }
}

show_status() {
    echo -e "\n${GREEN}========================================================${NC}"
    echo -e "${GREEN}  LUVEEDU FIREWALL INSTALLATION COMPLETE${NC}"
    echo -e "${GREEN}========================================================${NC}\n"
    echo "Commands:"
    echo "  Status:   systemctl status luvd-firewall"
    echo "  Logs:     tail -f /var/log/luveedu/firewall.log"
    echo "  Block IP: luvd-firewall block <IP>"
    echo "  List:     luvd-firewall list"
    echo "  Stats:    luvd-firewall stats"
    echo "  Scan:     luvd-firewall scan /path"
    echo "  Test WAF: luvd-firewall test-waf"
    echo "  Update:   /opt/luveedu-firewall/update.sh"
    echo -e "\nConfig: $INSTALL_DIR/config.json"
    echo "Docs: https://github.com/Luveedu/Luveedu-Firewall"
    echo -e "${GREEN}========================================================${NC}\n"
}

main() {
    echo -e "${BLUE}========================================================${NC}"
    echo -e "${BLUE}  LUVEEDU ENTERPRISE FIREWALL v2.0 INSTALLER${NC}"
    echo -e "${BLUE}  (Non-Interactive Force Mode)${NC}"
    echo -e "${BLUE}========================================================${NC}\n"
    
    check_root
    detect_os
    backup_existing
    install_prerequisites
    download_components
    build_binary
    setup_firewall_rules
    create_services
    create_crons
    start_services
    show_status
    
    log_success "Installation completed!"
}

main "$@"
