#!/bin/bash
#===============================================================================
# Luveedu Firewall Suite - Installation Script
# Version: 2.0.0
#===============================================================================

set -euo pipefail

readonly VERSION="2.0.0"
readonly INSTALL_DIR="/usr/local/bin"
readonly LOG_DIR="/var/log"
readonly STATE_DIR="/var/lib"

echo "=============================================="
echo "Luveedu Firewall Suite v$VERSION Installer"
echo "=============================================="
echo ""

# Check root
if [ "$EUID" -ne 0 ]; then
    echo "Error: Please run as root (sudo ./INSTALL.sh)"
    exit 1
fi

# Detect OS
if [ -f /etc/debian_version ]; then
    OS="debian"
    PKG_MANAGER="apt"
elif [ -f /etc/redhat-release ]; then
    OS="redhat"
    PKG_MANAGER="yum"
else
    echo "Warning: Unsupported OS, continuing anyway..."
    OS="unknown"
fi

echo "[1/6] Installing dependencies..."
case "$OS" in
    debian)
        apt-get update -qq
        apt-get install -y -qq iptables ipset curl wget logrotate git >/dev/null 2>&1 || true
        ;;
    redhat)
        yum install -y -q iptables ipset curl wget logrotate git >/dev/null 2>&1 || true
        ;;
esac

# Install ClamAV if not present
if ! command -v clamscan &>/dev/null; then
    echo "Installing ClamAV..."
    case "$OS" in
        debian)
            apt-get install -y -qq clamav clamav-daemon >/dev/null 2>&1 || echo "ClamAV installation failed"
            ;;
        redhat)
            yum install -y -q clamav clamav-scanner >/dev/null 2>&1 || echo "ClamAV installation failed"
            ;;
    esac
fi

# Install rkhunter if not present
if ! command -v rkhunter &>/dev/null; then
    echo "Installing rkhunter..."
    case "$OS" in
        debian)
            apt-get install -y -qq rkhunter >/dev/null 2>&1 || echo "rkhunter installation failed"
            ;;
        redhat)
            yum install -y -q rkhunter >/dev/null 2>&1 || echo "rkhunter installation failed"
            ;;
    esac
fi

echo "[2/6] Creating directories..."
mkdir -p "$STATE_DIR/luvd-firewall" "$STATE_DIR/luvd-shield" "$STATE_DIR/luvd-waf"
mkdir -p /etc/iptables /var/tmp /var/run /var/lock
touch /var/log/luvd-firewall.log /var/log/luvd-shield.log /var/log/luvd-waf.log
chmod 644 /var/log/luvd-*.log

echo "[3/6] Installing scripts..."
cp /workspace/luvd-firewall.sh "$INSTALL_DIR/luvd-firewall"
cp /workspace/luvd-shield.sh "$INSTALL_DIR/luvd-shield"
cp /workspace/luvd-waf.sh "$INSTALL_DIR/luvd-waf"
cp /workspace/luvd-antivirus.sh "$INSTALL_DIR/luvd-antivirus"

chmod +x "$INSTALL_DIR"/luvd-*

echo "[4/6] Configuring iptables..."
# Initialize ipsets
ipset create luveedu_blocked hash:ip timeout 0 2>/dev/null || true
ipset save > /etc/ipset.conf 2>/dev/null || true

# Basic firewall rules
iptables -C INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || \
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

iptables-save > /etc/iptables/rules.v4

echo "[5/6] Setting up log rotation..."
cat > /etc/logrotate.d/luveedu << 'LOGROTATE'
/var/log/luvd-*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 644 root root
}
LOGROTATE

echo "[6/6] Creating systemd services..."

# luvd-firewall service
cat > /etc/systemd/system/luvd-firewall.service << 'SYSTEMD'
[Unit]
Description=Luveedu Firewall - DoS/DDoS Protection
After=network.target iptables.service
Before=network-online.target

[Service]
Type=forking
ExecStart=/usr/local/bin/luvd-firewall --start
ExecStop=/usr/local/bin/luvd-firewall --stop
ExecReload=/usr/local/bin/luvd-firewall --restart
PIDFile=/var/run/luvd-firewall.pid
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
SYSTEMD

# luvd-shield service
cat > /etc/systemd/system/luvd-shield.service << 'SYSTEMD'
[Unit]
Description=Luveedu Shield - Kernel-Level Protection
After=network.target luvd-firewall.service

[Service]
Type=forking
ExecStart=/usr/local/bin/luvd-shield --start
ExecStop=/usr/local/bin/luvd-shield --stop
ExecReload=/usr/local/bin/luvd-shield --restart
PIDFile=/var/run/luvd-shield.pid
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
SYSTEMD

# luvd-waf service
cat > /etc/systemd/system/luvd-waf.service << 'SYSTEMD'
[Unit]
Description=Luveedu WAF - Web Application Firewall
After=network.target luvd-shield.service

[Service]
Type=forking
ExecStart=/usr/local/bin/luvd-waf --start
ExecStop=/usr/local/bin/luvd-waf --stop
ExecReload=/usr/local/bin/luvd-waf --restart
PIDFile=/var/run/luvd-waf.pid
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
SYSTEMD

# Reload systemd
systemctl daemon-reload

echo ""
echo "=============================================="
echo "Installation Complete!"
echo "=============================================="
echo ""
echo "Available commands:"
echo "  luvd-firewall --start     # Start DoS/DDoS protection"
echo "  luvd-shield --start       # Start kernel-level protection"
echo "  luvd-waf --start          # Start web application firewall"
echo "  luvd-antivirus --scan     # Scan for malware"
echo ""
echo "Enable on boot:"
echo "  systemctl enable luvd-firewall luvd-shield luvd-waf"
echo ""
echo "Start all services:"
echo "  systemctl start luvd-firewall luvd-shield luvd-waf"
echo ""
echo "Check status:"
echo "  luvd-firewall --status"
echo "  luvd-shield --status"
echo "  luvd-waf --status"
echo ""
echo "=============================================="
