#!/bin/bash

# Luveedu Firewall - Automated Installer
# Enterprise-Grade Security Suite for Linux Servers

set -e

echo "=============================================="
echo "  Luveedu Firewall - Enterprise Installer"
echo "=============================================="
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: Please run as root (sudo ./INSTALL.sh)${NC}"
    exit 1
fi

# Detect package manager
if command -v apt-get &> /dev/null; then
    PKG_MANAGER="apt-get"
elif command -v yum &> /dev/null; then
    PKG_MANAGER="yum"
elif command -v dnf &> /dev/null; then
    PKG_MANAGER="dnf"
else
    echo -e "${RED}Error: Unsupported package manager${NC}"
    exit 1
fi

echo -e "${YELLOW}[1/6] Installing system dependencies...${NC}"
if [ "$PKG_MANAGER" = "apt-get" ]; then
    apt-get update
    apt-get install -y golang-go iptables ipset clamav rkhunter wget curl
elif [ "$PKG_MANAGER" = "yum" ] || [ "$PKG_MANAGER" = "dnf" ]; then
    $PKG_MANAGER install -y golang iptables ipset clamav rkhunter wget curl
fi

echo ""
echo -e "${YELLOW}[2/6] Creating directories...${NC}"
mkdir -p /etc/luveedu
mkdir -p /var/luveedu/quarantine
mkdir -p /var/log/luveedu
chmod 750 /var/luveedu/quarantine

echo ""
echo -e "${YELLOW}[3/6] Building Luveedu Firewall...${NC}"
cd /workspace/luveedu
go build -o luveedu-firewall ./cmd
cp luveedu-firewall /usr/local/bin/
chmod +x /usr/local/bin/luveedu-firewall

echo ""
echo -e "${YELLOW}[4/6] Creating configuration...${NC}"
cat > /etc/luveedu/config.json << 'EOF'
{
  "log_file": "/var/log/openlitespeed/access.log",
  "syslog_file": "/var/log/syslog",
  "block_duration_minutes": 60,
  "rate_limit_burst": 15,
  "rate_limit_sustain": 150,
  "waf_enabled": true,
  "scan_enabled": true,
  "api_endpoint": "https://api.luveedu.com/v1/threat",
  "api_timeout_seconds": 5,
  "ipset_name": "luveedu_blocklist",
  "quarantine_dir": "/var/luveedu/quarantine",
  "whitelist": ["127.0.0.1", "::1"],
  "listen_port": 8080,
  "max_workers": 4
}
EOF
chmod 644 /etc/luveedu/config.json

echo ""
echo -e "${YELLOW}[5/6] Creating systemd service...${NC}"
cat > /etc/systemd/system/luveedu-firewall.service << 'EOF'
[Unit]
Description=Luveedu Firewall Security Suite
After=network.target iptables.service

[Service]
Type=simple
ExecStart=/usr/local/bin/luveedu-firewall -config /etc/luveedu/config.json -action start
Restart=on-failure
RestartSec=5
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

echo ""
echo -e "${YELLOW}[6/6] Initializing ipset and updating signatures...${NC}"
# Initialize ipset
ipset destroy luveedu_blocklist 2>/dev/null || true
ipset create luveedu_blocklist hash:ip timeout 3600

# Add iptables rule if not exists
iptables -C INPUT -m set --match-set luveedu_blocklist src -j DROP 2>/dev/null || \
    iptables -I INPUT -m set --match-set luveedu_blocklist src -j DROP

# Update ClamAV signatures
if command -v freshclam &> /dev/null; then
    freshclam --quiet 2>/dev/null || echo "Note: freshclam update skipped (may require internet)"
fi

echo ""
echo -e "${GREEN}=============================================="
echo "  Installation Complete!"
echo "==============================================${NC}"
echo ""
echo "Next steps:"
echo "  1. Review configuration: /etc/luveedu/config.json"
echo "  2. Start the firewall: sudo systemctl start luveedu-firewall"
echo "  3. Enable on boot: sudo systemctl enable luveedu-firewall"
echo "  4. Check status: sudo systemctl status luveedu-firewall"
echo ""
echo "Quick commands:"
echo "  luveedu-firewall -action status     # Check status"
echo "  luveedu-firewall -action block -ip <IP>  # Block an IP"
echo "  luveedu-firewall -action scan -scan-path /var/www  # Scan for malware"
echo "  luveedu-firewall -action update     # Update signatures"
echo "  luveedu-firewall -action test-waf   # Test WAF patterns"
echo ""
echo -e "${YELLOW}Documentation: /workspace/luveedu/README.md${NC}"
echo ""
