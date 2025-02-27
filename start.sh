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
        apt update && apt upgrade -y
    elif [ "$PKG_MANAGER" = "dnf" ]; then
        dnf update -y
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

# Function to download and install luvd-firewall
install_luvd_firewall() {
    local url="https://raw.githubusercontent.com/Luveedu/Luveedu-Firewall/refs/heads/main/luvd-firewall.sh"
    local target="/usr/local/bin/luvd-firewall"
    
    echo "Downloading luvd-firewall from $url..."
    if [ -f "$target" ]; then
        echo "Updating existing luvd-firewall script..."
        wget -O "$target" "$url" 2>/dev/null || { echo "Failed to download script"; exit 1; }
    else
        echo "Installing luvd-firewall script..."
        wget -O "$target" "$url" 2>/dev/null || { echo "Failed to download script"; exit 1; }
    fi
    
    # Convert Windows CRLF to Unix LF
    sed -i 's/\r$//' "$target"
    
    chmod +x "$target"
    echo "luvd-firewall installed/updated at $target"
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
Type=simple
ExecStart=/usr/local/bin/luvd-firewall --start
ExecStop=/usr/local/bin/luvd-firewall --stop
Restart=on-failure
User=root

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable luvd-firewall.service
    echo "luvd-firewall.service created and enabled"
}

# Function to check system requirements and start service
check_and_start() {
    echo "Checking system requirements..."
    
    # 1. OS Check (already done)
    echo "1. OS: $PKG_MANAGER-based system - OK"
    
    # 2. OpenLiteSpeed Check (already done)
    echo "2. OpenLiteSpeed: Installed - OK"
    
    # 3. Service Enabled
    if systemctl is-enabled luvd-firewall.service >/dev/null 2>&1; then
        echo "3. Service: luvd-firewall enabled - OK"
    else
        echo "3. Service: luvd-firewall not enabled - FAILED"
        exit 1
    fi
    
    # 4. Start Service
    echo "4. Starting luvd-firewall service..."
    systemctl start luvd-firewall.service
    
    # 5. Check if Service is Active
    if systemctl is-active luvd-firewall.service >/dev/null 2>&1; then
        echo "5. Service: luvd-firewall active - OK"
    else
        echo "5. Service: luvd-firewall not active - FAILED"
        exit 1
    fi
    
    # 6. Check if Process is Running
    if pgrep -f "luvd-firewall" >/dev/null; then
        echo "6. Process: luvd-firewall running - OK"
    else
        echo "6. Process: luvd-firewall not running - FAILED"
        exit 1
    fi
    
    # 7. Run --fix-logs
    echo "7. Running luvd-firewall --fix-logs..."
    /usr/local/bin/luvd-firewall --fix-logs
    echo "Completed luvd-firewall --fix-logs"
    
    # 8. Run --reset
    echo "8. Running luvd-firewall --reset..."
    /usr/local/bin/luvd-firewall --reset
    
    # 9. Display Success Message
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
create_service
check_and_start