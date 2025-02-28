#!/bin/bash

# start.sh - Installation script for Luveedu Firewall and Shield

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
        wget -O "$target" "$url" 2>/dev/null || { echo "Failed to update luvd-firewall"; exit 1; }
        sudo sed -i 's/\r$//' "$target"  # Convert CRLF to LF
        chmod +x "$target"
        echo "luvd-firewall updated at $target"
        echo "Running luvd-firewall --reset..."
        sleep 5
        "$target" --reset
        figlet "Updated"
        echo "Luveedu Firewall updated successfully!"
        # Don't exit here to allow luvd-shield installation
    else
        echo "Installing luvd-firewall script..."
        wget -O "$target" "$url" 2>/dev/null || { echo "Failed to download luvd-firewall"; exit 1; }
        sudo sed -i 's/\r$//' "$target"  # Convert CRLF to LF
        chmod +x "$target"
        echo "luvd-firewall installed at $target"
    fi
}

# Function to download and install/update luvd-shield
install_luvd_shield() {
    local url="https://raw.githubusercontent.com/Luveedu/Luveedu-Firewall/refs/heads/main/luvd-shield.sh"
    local target="/usr/local/bin/luvd-shield"
    
    if [ -f "$target" ]; then
        echo "Existing luvd-shield found, updating with latest version..."
        wget -O "$target" "$url" 2>/dev/null || { echo "Failed to update luvd-shield"; exit 1; }
        sudo sed -i 's/\r$//' "$target"  # Convert CRLF to LF
        chmod +x "$target"
        echo "luvd-shield updated at $target"
        echo "Running luvd-shield --reset..."
        sleep 5
        "$target" --reset
        figlet "Updated"
        echo "Luveedu Shield updated successfully!"
        # Don't exit here to allow full install/update process
    else
        echo "Installing luvd-shield script..."
        wget -O "$target" "$url" 2>/dev/null || { echo "Failed to download luvd-shield"; exit 1; }
        sudo sed -i 's/\r$//' "$target"  # Convert CRLF to LF
        chmod +x "$target"
        echo "luvd-shield installed at $target"
    fi
}

# Function to set iptables rules for luvd-shield
set_iptables_rules() {
    echo "Setting iptables rules for luvd-shield..."
    SERVER_IP=$(curl -s --max-time 2 https://ipv4.icanhazip.com/ 2>/dev/null || ip -4 addr show $(ip route | grep default | awk '{print $5}' | head -n 1) | grep -oP '(?<=inet\s)\d+\.\d+\.\d+\.\d+' | head -n 1)
    if [ -z "$SERVER_IP" ]; then
        echo "Failed to determine server IP for iptables rules"
        exit 1
    fi

    iptables -F INPUT
    iptables -N LOG_EXTERNAL 2>/dev/null || iptables -F LOG_EXTERNAL
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A INPUT -s 127.0.0.1 -j ACCEPT
    iptables -A INPUT -s "$SERVER_IP" -j ACCEPT
    iptables -A INPUT -m state --state NEW -j LOG_EXTERNAL
    iptables -A LOG_EXTERNAL -j LOG --log-prefix "NEW_CONNECTION: "
    echo "iptables rules set for luvd-shield (Server IP: $SERVER_IP)"
}

# Function to create and enable luvd-firewall service
create_firewall_service() {
    local service_file="/etc/systemd/system/luvd-firewall.service"
    
    if [ -f "$service_file" ]; then
        echo "Existing luvd-firewall.service found, updating..."
    else
        echo "Creating luvd-firewall.service..."
    fi
    
    cat <<EOF > "$service_file"
[Unit]
Description=Luveedu Firewall Service
After=network.target

[Service]
ExecStart=/usr/local/bin/luvd-firewall --start
ExecStop=/usr/local/bin/luvd-firewall --stop
Restart=on-failure
Type=forking 
PIDFile=/var/run/luvd-firewall.pid
TimeoutStartSec=30
TimeoutStopSec=30

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable luvd-firewall.service
    sleep 5
    systemctl start luvd-firewall.service
    sleep 7
    echo "luvd-firewall.service created/updated and enabled"
}

# Function to create and enable luvd-shield service
create_shield_service() {
    local service_file="/etc/systemd/system/luvd-shield.service"
    
    if [ -f "$service_file" ]; then
        echo "Existing luvd-shield.service found, updating..."
    else
        echo "Creating luvd-shield.service..."
    fi
    
    cat <<EOF > "$service_file"
[Unit]
Description=Luveedu Shield - A Realtime Bad Bots and IP Blocking Solution
After=network.target

[Service]
ExecStart=/usr/local/bin/luvd-shield --start
ExecStop=/usr/local/bin/luvd-shield --stop
Restart=on-failure
Type=forking 
PIDFile=/var/run/luvd-shield.pid
TimeoutStartSec=30
TimeoutStopSec=30

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable luvd-shield.service
    sleep 6
    systemctl start luvd-shield.service
    echo "luvd-shield.service created/updated and enabled"
}

# Function to check system requirements and start services (only runs for new install)
check_and_start() {
    echo "Checking system requirements..."
    
    echo "1. OS: $PKG_MANAGER-based system - OK"
    echo "2. OpenLiteSpeed: Installed - OK"
    
    # Check luvd-firewall service
    if systemctl is-enabled luvd-firewall.service >/dev/null 2>&1; then
        echo "3. Service: luvd-firewall enabled - OK"
    else
        echo "3. Service: luvd-firewall not enabled - FAILED"
        exit 1
    fi
    
    if systemctl is-active luvd-firewall.service >/dev/null 2>&1; then
        echo "4. Service: luvd-firewall active - OK"
    else
        echo "4. Service: luvd-firewall not active - FAILED"
        exit 1
    fi
    
    if pgrep -f "luvd-firewall" >/dev/null; then
        echo "5. Process: luvd-firewall running - OK"
    else
        echo "5. Process: luvd-firewall not running - FAILED"
        exit 1
    fi
    
    # Check luvd-shield service
    if systemctl is-enabled luvd-shield.service >/dev/null 2>&1; then
        echo "6. Service: luvd-shield enabled - OK"
    else
        echo "6. Service: luvd-shield not enabled - FAILED"
        exit 1
    fi
    
    if systemctl is-active luvd-shield.service >/dev/null 2>&1; then
        echo "7. Service: luvd-shield active - OK"
    else
        echo "7. Service: luvd-shield not active - FAILED"
        exit 1
    fi
    
    if pgrep -f "luvd-shield" >/dev/null; then
        echo "8. Process: luvd-shield running - OK"
    else
        echo "8. Process: luvd-shield not running - FAILED"
        exit 1
    fi
    
    echo "9. Running luvd-firewall --fix-logs..."
    /usr/local/bin/luvd-firewall --fix-logs
    echo "Completed luvd-firewall --fix-logs"
    
    echo "10. Running luvd-firewall --reset..."
    /usr/local/bin/luvd-firewall --reset
    
    echo "11. Running luvd-shield --reset..."
    /usr/local/bin/luvd-shield --reset
    
    figlet "Done"
    echo "Successfully Installed Luveedu Firewall and Shield!"
    echo "They are protecting your server from DoS/DDoS Attacks and Bad Bots!"
    echo "Check Firewall Logs: luvd-firewall --check-logs"
    echo "Check Blocked IPs: luvd-shield --blocked-list"
}

# Main execution
check_os
update_system
install_dependencies
check_openlitespeed
install_luvd_firewall
install_luvd_shield
set_iptables_rules
# These only run if it's a new install (install functions don't exit unless updating)
create_firewall_service
create_shield_service
check_and_start