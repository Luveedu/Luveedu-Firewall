#!/bin/bash

# start.sh - Installation script for Luveedu Firewall

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run this script as root (e.g., sudo ./start.sh)"
    exit 1
fi

# Function to check OS type
check_os() {
    if [ -f /etc/debian_version ]; then
        echo "Debian-based OS detected"
        PKG_MANAGER="apt"
    elif [ -f /etc/redhat-release ]; then
        echo "RHEL-based OS detected"
        PKG_MANAGER="dnf"
    else
        echo "Unsupported OS. This script supports Debian-based (apt) or RHEL-based (dnf) systems only."
        exit 1
    fi
}

# Function to update system
update_system() {
    echo "Updating system..."
    if [ "$PKG_MANAGER" = "apt" ]; then
        apt update
    elif [ "$PKG_MANAGER" = "dnf" ]; then
        dnf clean all
        dnf check-update
    fi
}

# Function to install dependencies
install_dependencies() {
    echo "Installing dependencies: iptables, wget, curl, figlet..."
    if [ "$PKG_MANAGER" = "apt" ]; then
        apt install -y iptables wget curl figlet
    elif [ "$PKG_MANAGER" = "dnf" ]; then
        dnf install -y iptables wget curl figlet
    fi
}

# Function to check if OpenLiteSpeed is installed
check_openlitespeed() {
    if [ -d "/usr/local/lsws" ] && [ -x "/usr/local/lsws/bin/lshttpd" ]; then
        echo "OpenLiteSpeed detected"
    else
        echo "OpenLiteSpeed not found. This script requires OpenLiteSpeed to be installed."
        exit 1
    fi
}

# Function to download and install/update luvd-firewall
install_luvd_firewall() {
    local url="https://raw.githubusercontent.com/Luveedu/Luveedu-Firewall/refs/heads/main/luvd-firewall.sh"
    local target="/usr/local/bin/luvd-firewall"
    
    if [ -f "$target" ]; then
        echo "Existing luvd-firewall found, updating with latest version..."
        wget -O "$target" "$url" 2>/dev/null || { echo "Failed to update script"; exit 1; }
        # Convert Windows CRLF to Unix LF
        sudo sed -i 's/\r$//' "$target"
        chmod +x "$target"
        echo "luvd-firewall updated at $target"
        # Just reset since it already existed
        echo "Running luvd-firewall --reset..."
        sleep 5
        "$target" --reset
        figlet "Updated"
        echo "Luveedu Firewall updated successfully!"
        sleep 2
        systemctl restart luvd-firewall.service
        exit 0
    else
        echo "Installing luvd-firewall script..."
        wget -O "$target" "$url" 2>/dev/null || { echo "Failed to download script"; exit 1; }
        # Convert Windows CRLF to Unix LF
        sudo sed -i 's/\r$//' "$target"
        chmod +x "$target"
        echo "luvd-firewall installed at $target"
    fi
}

# Function to create and enable luvd-firewall service
create_service() {
    local service_file="/etc/systemd/system/luvd-firewall.service"
    
    echo "Creating luvd-firewall.service..."
    cat <<EOF > "$service_file"
[Unit]
Description=Luveedu Firewall Service
After=network.target

[Service]
ExecStart=/usr/local/bin/luvd-firewall --start
ExecStop=/usr/local/bin/luvd-firewall --stop
Restart=always
RestartSec=5s
StartLimitIntervalSec=60s
StartLimitBurst=3
Type=forking
PIDFile=/var/run/luvd-firewall.pid
TimeoutStartSec=30
TimeoutStopSec=30

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable luvd-firewall.service
    echo "luvd-firewall.service created and enabled"
}

# Function to check system requirements and start service (only runs for new install)
check_and_start() {
    echo "Checking system requirements..."
    
    echo "1. OS: $PKG_MANAGER-based system - OK"
    echo "2. OpenLiteSpeed: Installed - OK"
    
    if systemctl is-enabled luvd-firewall.service >/dev/null 2>&1; then
        echo "3. Service: luvd-firewall enabled - OK"
    else
        echo "3. Service: luvd-firewall not enabled - FAILED"
        exit 1
    fi
    
    sleep 5
    echo "4. Starting luvd-firewall service..."
    systemctl restart luvd-firewall.service
    
    sleep 2
    if systemctl is-active luvd-firewall.service >/dev/null 2>&1; then
        echo "5. Service: luvd-firewall active - OK"
    else
        echo "5. Service: luvd-firewall not active - FAILED"
        exit 1
    fi
    
    if pgrep -f "luvd-firewall" >/dev/null; then
        echo "6. Process: luvd-firewall running - OK"
    else
        echo "6. Process: luvd-firewall not running - FAILED"
        exit 1
    fi
    
    echo "7. Running luvd-firewall --fix-logs..."
    /usr/local/bin/luvd-firewall --fix-logs
    echo "Completed luvd-firewall --fix-logs"
    
    echo "8. Running luvd-firewall --reset..."
    /usr/local/bin/luvd-firewall --reset
    
    figlet "Done"
    echo "Successfully Installed Luveedu Firewall and It is protecting your server from DoS/DDoS Attacks!"
    echo "Check the Logs: luvd-firewall --check-logs"
}

# Main execution
check_os
update_system
install_dependencies
check_openlitespeed
install_luvd_firewall
# These only run if it's a new install (install_luvd_firewall doesn't exit)
create_service
check_and_start