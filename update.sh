#!/bin/bash

# Luveedu Firewall - Auto-Update Script
set -euo pipefail

GITHUB_REPO="https://raw.githubusercontent.com/Luveedu/Luveedu-Firewall/main"
INSTALL_DIR="/opt/luveedu-firewall"
BACKUP_DIR="/opt/luveedu-firewall-backups"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

check_version() {
    local current_version=$(cat "$INSTALL_DIR/VERSION" 2>/dev/null || echo "unknown")
    local remote_version=$(curl -sSL "$GITHUB_REPO/VERSION" 2>/dev/null || echo "")
    
    if [ -z "$remote_version" ]; then
        log_error "Cannot fetch remote version"
        return 1
    fi
    
    echo "Current: $current_version | Latest: $remote_version"
    
    if [ "$current_version" = "$remote_version" ]; then
        return 1
    fi
    return 0
}

backup_current() {
    mkdir -p "$BACKUP_DIR"
    cp -r "$INSTALL_DIR" "$BACKUP_DIR/update_backup_$(date +%Y%m%d_%H%M%S)/"
    log_info "Backup created"
}

download_update() {
    cd "$INSTALL_DIR"
    
    curl -sSL -o go.mod "$GITHUB_REPO/go.mod" || true
    curl -sSL -o cmd/main.go "$GITHUB_REPO/cmd/main.go" || true
    curl -sSL -o internal/config/config.go "$GITHUB_REPO/internal/config/config.go" || true
    curl -sSL -o internal/engine/engine.go "$GITHUB_REPO/internal/engine/engine.go" || true
    curl -sSL -o internal/waf/waf.go "$GITHUB_REPO/internal/waf/waf.go" || true
    curl -sSL -o internal/scanner/scanner.go "$GITHUB_REPO/internal/scanner/scanner.go" || true
    curl -sSL -o config.json "$GITHUB_REPO/config.json" || true
    curl -sSL -o VERSION "$GITHUB_REPO/VERSION" || true
    
    log_success "Files downloaded"
}

rebuild_binary() {
    log_info "Rebuilding binary..."
    cd "$INSTALL_DIR"
    export GOPATH="$INSTALL_DIR/gopath"
    
    go mod download
    go build -o luvd-firewall ./cmd/main.go
    chmod +x luvd-firewall
    rm -rf gopath
    
    log_success "Binary rebuilt"
}

restart_services() {
    log_info "Restarting services..."
    systemctl restart luvd-firewall luvd-shield
    sleep 2
    
    if systemctl is-active --quiet luvd-firewall; then
        log_success "Services restarted"
    else
        log_error "Failed to restart services"
        return 1
    fi
}

show_changelog() {
    local current_version=$(cat "$INSTALL_DIR/VERSION" 2>/dev/null || echo "")
    
    if [ -f "$INSTALL_DIR/CHANGELOG.md" ]; then
        echo -e "\n${BLUE}=== CHANGELOG ===${NC}"
        grep -A 20 "^## \[$current_version\]" "$INSTALL_DIR/CHANGELOG.md" || true
        echo
    fi
}

main() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}  Luveedu Firewall Updater${NC}"
    echo -e "${BLUE}========================================${NC}\n"
    
    if [[ "${1:-}" == "--check" ]]; then
        if check_version; then
            echo "Update available!"
            exit 0
        else
            echo "Already up to date"
            exit 0
        fi
    fi
    
    if ! check_version; then
        log_success "Already running latest version"
        exit 0
    fi
    
    log_info "Update available, starting update..."
    
    backup_current
    download_update
    rebuild_binary
    restart_services
    show_changelog
    
    local new_version=$(cat "$INSTALL_DIR/VERSION")
    log_success "Updated to version $new_version!"
}

main "$@"
