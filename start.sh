#!/bin/bash

# start.sh - Installation script for Luveedu Firewall, Shield, and Antivirus

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run this script as root (e.g., sudo ./start.sh)"
    exit 1
fi

# Log file setup
LOG_FILE="luvd-firewall-installation-$(date '+%Y-%m-%d_%H-%M-%S').log"
exec > >(tee -a "$LOG_FILE") 2>&1

# Function to display header
display_header() {
    echo "----------------------------------------------------------"
    echo "                   Luveedu Firewall System                "
    echo "----------------------------------------------------------"
    echo
}

# Function to display step
display_step() {
    echo -n "[ ] $1..."
}

# Function to mark step as done
mark_done() {
    echo -e "\r[\e[32m✔\e[0m] $1...Done"
}

# Function to mark step as failed
mark_failed() {
    echo -e "\r[\e[31m✘\e[0m] $1...Failed"
    exit 1
}

# Function to display completion
display_completion() {
    echo
    echo "//////////// COMPLETED \\\\\\\\\\\\\\\"
    echo "For more information visit: https://github.com/Luveedu/Luveedu-Firewall"
    echo "Installation Log saved in: $LOG_FILE"
}

# Function to display failure
display_failure() {
    echo
    echo "//////////////// FAILED \\\\\\\\\\\\\\\\\\\"
    echo "Installation failed. Check the log for details: $LOG_FILE"
    exit 1
}

# Function to check OS type
check_os() {
    display_step "Checking the System Requirements"
    if [ -f /etc/debian_version ]; then
        echo "Debian-based OS detected" >> "$LOG_FILE"
        PKG_MANAGER="apt"
    elif [ -f /etc/redhat-release ]; then
        echo "RHEL-based OS detected" >> "$LOG_FILE"
        PKG_MANAGER="dnf"
    else
        echo "Unsupported OS" >> "$LOG_FILE"
        mark_failed "Checking the System Requirements"
    fi
    mark_done "Checking the System Requirements"
}

# Function to update system
update_system() {
    display_step "Updating Linux System"
    if [ "$PKG_MANAGER" = "apt" ]; then
        apt update || mark_failed "Updating Linux System"
    elif [ "$PKG_MANAGER" = "dnf" ]; then
        dnf clean all && dnf check-update || mark_failed "Updating Linux System"
    fi
    mark_done "Updating Linux System"
}

# Function to install dependencies
install_dependencies() {
    display_step "Installing Dependencies"
    echo "Installing iptables, wget, curl, figlet..." >> "$LOG_FILE"
    if [ "$PKG_MANAGER" = "apt" ]; then
        apt install -y iptables wget curl figlet || mark_failed "Installing Dependencies"
    elif [ "$PKG_MANAGER" = "dnf" ]; then
        dnf install -y iptables wget curl figlet || mark_failed "Installing Dependencies"
    fi
    mark_done "Installing Dependencies"
}

# Function to check if OpenLiteSpeed is installed
check_openlitespeed() {
    display_step "Checking OpenLiteSpeed"
    if [ -d "/usr/local/lsws" ] && [ -x "/usr/local/lsws/bin/lshttpd" ]; then
        echo "OpenLiteSpeed detected" >> "$LOG_FILE"
    else
        echo "OpenLiteSpeed not found" >> "$LOG_FILE"
        mark_failed "Checking OpenLiteSpeed"
    fi
    mark_done "Checking OpenLiteSpeed"
}

# Function to download and install/update luvd-firewall
install_luvd_firewall() {
    display_step "Installing Luveedu Firewall"
    local url="https://raw.githubusercontent.com/Luveedu/Luveedu-Firewall/refs/heads/main/luvd-firewall.sh"
    local target="/usr/local/bin/luvd-firewall"
    
    if [ -f "$target" ]; then
        echo "Existing luvd-firewall found, updating..." >> "$LOG_FILE"
        read -p "Would You Like to Re-configure vHost Logging? (y/N): " choice
        case "$choice" in
            y|Y)
                echo "User chose to re-configure vHost logging" >> "$LOG_FILE"
                ;;
            *)
                echo "Skipping vHost re-configuration" >> "$LOG_FILE"
                ;;
        esac
        wget -O "$target" "$url" 2>/dev/null || { echo "Failed to update luvd-firewall" >> "$LOG_FILE"; mark_failed "Installing Luveedu Firewall"; }
        sudo sed -i 's/\r$//' "$target"
        chmod +x "$target"
        echo "luvd-firewall updated at $target" >> "$LOG_FILE"
        "$target" --reset || mark_failed "Installing Luveedu Firewall"
        figlet "Updated" >> "$LOG_FILE"
        echo "Luveedu Firewall updated successfully!" >> "$LOG_FILE"
    else
        echo "Installing luvd-firewall script..." >> "$LOG_FILE"
        wget -O "$target" "$url" 2>/dev/null || { echo "Failed to download luvd-firewall" >> "$LOG_FILE"; mark_failed "Installing Luveedu Firewall"; }
        sudo sed -i 's/\r$//' "$target"
        chmod +x "$target"
        echo "luvd-firewall installed at $target" >> "$LOG_FILE"
    fi
    mark_done "Installing Luveedu Firewall"
}

# Function to download and install/update luvd-shield
install_luvd_shield() {
    display_step "Installing Luveedu Shield"
    local url="https://raw.githubusercontent.com/Luveedu/Luveedu-Firewall/refs/heads/main/luvd-shield.sh"
    local target="/usr/local/bin/luvd-shield"
    
    if [ -f "$target" ]; then
        echo "Existing luvd-shield found, updating..." >> "$LOG_FILE"
        wget -O "$target" "$url" 2>/dev/null || { echo "Failed to update luvd-shield" >> "$LOG_FILE"; mark_failed "Installing Luveedu Shield"; }
        sudo sed -i 's/\r$//' "$target"
        chmod +x "$target"
        echo "luvd-shield updated at $target" >> "$LOG_FILE"
        "$target" --reset || mark_failed "Installing Luveedu Shield"
        figlet "Updated" >> "$LOG_FILE"
        echo "Luveedu Shield updated successfully!" >> "$LOG_FILE"
    else
        echo "Installing luvd-shield script..." >> "$LOG_FILE"
        wget -O "$target" "$url" 2>/dev/null || { echo "Failed to download luvd-shield" >> "$LOG_FILE"; mark_failed "Installing Luveedu Shield"; }
        sudo sed -i 's/\r$//' "$target"
        chmod +x "$target"
        echo "luvd-shield installed at $target" >> "$LOG_FILE"
    fi
    mark_done "Installing Luveedu Shield"
}

# Function to set iptables rules (simplified)
set_iptables_rules() {
    display_step "Setting iptables Rules"
    echo "Setting simplified iptables rules..." >> "$LOG_FILE"
    iptables -F  # Clear existing rules
    iptables -A INPUT -m state --state NEW -j LOG --log-prefix "LUVEEDU-SHIELD: " || { echo "Failed to set iptables rules" >> "$LOG_FILE"; mark_failed "Setting iptables Rules"; }
    echo "iptables rules set successfully" >> "$LOG_FILE"
    mark_done "Setting iptables Rules"
}

# Function to create and enable luvd-firewall service
create_firewall_service() {
    display_step "Configuring Luveedu Firewall Service"
    local service_file="/etc/systemd/system/luvd-firewall.service"
    
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
    systemctl enable luvd-firewall.service || mark_failed "Configuring Luveedu Firewall Service"
    systemctl start luvd-firewall.service || mark_failed "Configuring Luveedu Firewall Service"
    echo "luvd-firewall.service created/updated and enabled" >> "$LOG_FILE"
    mark_done "Configuring Luveedu Firewall Service"
}

# Function to create and enable luvd-shield service
create_shield_service() {
    display_step "Configuring Luveedu Shield Service"
    local service_file="/etc/systemd/system/luvd-shield.service"
    
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
    systemctl enable luvd-shield.service || mark_failed "Configuring Luveedu Shield Service"
    systemctl start luvd-shield.service || mark_failed "Configuring Luveedu Shield Service"
    echo "luvd-shield.service created/updated and enabled" >> "$LOG_FILE"
    mark_done "Configuring Luveedu Shield Service"
}

# Function to install antivirus dependencies
install_antivirus_dependencies() {
    display_step "Installing Antivirus Dependencies"
    echo "Installing clamav, clamav-daemon, rkhunter..." >> "$LOG_FILE"
    if [ "$PKG_MANAGER" = "apt" ]; then
        apt install -y clamav clamav-daemon rkhunter || mark_failed "Installing Antivirus Dependencies"
        systemctl stop clamav-freshclam
        freshclam || mark_failed "Installing Antivirus Dependencies"
        systemctl start clamav-freshclam
        systemctl enable clamav-freshclam
    elif [ "$PKG_MANAGER" = "dnf" ]; then
        dnf install -y clamav clamd rkhunter || mark_failed "Installing Antivirus Dependencies"
        systemctl stop clamav-freshclam
        freshclam || mark_failed "Installing Antivirus Dependencies"
        systemctl start clamav-freshclam
        systemctl enable clamav-freshclam
    fi
    mark_done "Installing Antivirus Dependencies"
}

# Function to download and install/update luvd-antivirus
install_luvd_antivirus() {
    display_step "Installing Luveedu Antivirus"
    local url="https://raw.githubusercontent.com/Luveedu/Luveedu-Firewall/refs/heads/main/luvd-antivirus.sh"
    local target="/usr/local/bin/luvd-antivirus"
    
    if [ -f "$target" ]; then
        echo "Existing luvd-antivirus found, updating..." >> "$LOG_FILE"
        wget -O "$target" "$url" 2>/dev/null || { echo "Failed to update luvd-antivirus" >> "$LOG_FILE"; mark_failed "Installing Luveedu Antivirus"; }
        sudo sed -i 's/\r$//' "$target"
        chmod +x "$target"
        echo "luvd-antivirus updated at $target" >> "$LOG_FILE"
        "$target" --reset || mark_failed "Installing Luveedu Antivirus"
        figlet "Updated" >> "$LOG_FILE"
        echo "Luveedu Antivirus updated successfully!" >> "$LOG_FILE"
    else
        echo "Installing luvd-antivirus script..." >> "$LOG_FILE"
        wget -O "$target" "$url" 2>/dev/null || { echo "Failed to download luvd-antivirus" >> "$LOG_FILE"; mark_failed "Installing Luveedu Antivirus"; }
        sudo sed -i 's/\r$//' "$target"
        chmod +x "$target"
        echo "luvd-antivirus installed at $target" >> "$LOG_FILE"
    fi
    mark_done "Installing Luveedu Antivirus"
}

# Function to create and enable luvd-antivirus service
create_antivirus_service() {
    display_step "Configuring Luveedu Antivirus Service"
    local service_file="/etc/systemd/system/luvd-antivirus.service"
    
    cat <<EOF > "$service_file"
[Unit]
Description=Luveedu Antivirus Service
After=network.target

[Service]
ExecStart=/usr/local/bin/luvd-antivirus --start
ExecStop=/usr/local/bin/luvd-antivirus --stop
Restart=on-failure
Type=forking 
PIDFile=/var/run/luvd-antivirus.pid
TimeoutStartSec=30
TimeoutStopSec=30

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable luvd-antivirus.service || mark_failed "Configuring Luveedu Antivirus Service"
    systemctl start luvd-antivirus.service || mark_failed "Configuring Luveedu Antivirus Service"
    echo "luvd-antivirus.service created/updated and enabled" >> "$LOG_FILE"
    mark_done "Configuring Luveedu Antivirus Service"
}

# Function to finalize installation
finalize_installation() {
    display_step "Finalizing the Installer"
    # Basic checks to ensure services are running
    if ! systemctl is-active luvd-firewall.service >/dev/null 2>&1 || ! systemctl is-active luvd-shield.service >/dev/null 2>&1 || ! systemctl is-active luvd-antivirus.service >/dev/null 2>&1; then
        echo "One or more services failed to start" >> "$LOG_FILE"
        mark_failed "Finalizing the Installer"
    fi
    mark_done "Finalizing the Installer"
}

# Main execution
display_header
check_os
update_system
install_dependencies
install_antivirus_dependencies
check_openlitespeed
install_luvd_firewall
install_luvd_shield
install_luvd_antivirus
set_iptables_rules
create_firewall_service
create_shield_service
create_antivirus_service
finalize_installation
display_completion