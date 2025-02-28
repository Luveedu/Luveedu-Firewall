#!/bin/bash
# File: /usr/local/bin/luvd-shield
# Luveedu Shield - A Realtime Bad Bots and IP Blocking Solution

CHECK_API="https://waf.luveedu.cloud/checkip.php?ip="
SHIELD_BLOCKED_IPS_FILE="/var/tmp/luvd-shield-blocked-ips.txt"
SHIELD_LOG="/var/log/luvd-shield.log"
FIREWALL_LOG="/var/log/luvd-firewall.log"  # Defined but unused here
PID_FILE="/var/run/luvd-shield.pid"
BLOCK_DURATION=$((60*60*24*7))  # 7 days in seconds
ROTATION_INTERVAL=300  # 5 minutes in seconds

# Ensure required files exist
touch "$SHIELD_BLOCKED_IPS_FILE" "$SHIELD_LOG"

# Function to log messages to luvd-shield.log
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') $1" >> "$SHIELD_LOG"
}

# Function to block IP on all ports
block_ip() {
    local ip="$1"
    if ! iptables -C INPUT -s "$ip" -j DROP 2>/dev/null; then
        iptables -A INPUT -s "$ip" -j DROP
        echo "$ip $(date +%s)" >> "$SHIELD_BLOCKED_IPS_FILE"
        log "Blocked IP $ip on all ports"
    fi
}

# Function to unblock expired IPs
unblock_expired() {
    local now=$(date +%s)
    while read -r ip timestamp; do
        if [ $((now - timestamp)) -ge $BLOCK_DURATION ]; then
            iptables -D INPUT -s "$ip" -j DROP 2>/dev/null
            sed -i "/^$ip /d" "$SHIELD_BLOCKED_IPS_FILE"
            log "Unblocked expired IP: $ip"
        fi
    done < "$SHIELD_BLOCKED_IPS_FILE"
}

# Function to rotate logs every 5 minutes
rotate_logs() {
    local now=$(date +%s)
    local last_rotation_file="/var/tmp/luvd-shield-last-rotation.txt"
    local last_rotation=0

    if [ ! -f "$last_rotation_file" ]; then
        echo "$now" > "$last_rotation_file"
    else
        last_rotation=$(cat "$last_rotation_file")
    fi

    if [ $((now - last_rotation)) -ge $ROTATION_INTERVAL ]; then
        log "Rotating logs..."
        > "$SHIELD_LOG"  # Clear luvd-shield.log
        if [ -f "/var/log/syslog" ] && [ "$LOG_FILE" = "/var/log/syslog" ]; then
            > "/var/log/syslog"
            log "Cleared /var/log/syslog"
        elif [ -f "/var/log/messages" ] && [ "$LOG_FILE" = "/var/log/messages" ]; then
            > "/var/log/messages"
            log "Cleared /var/log/messages"
        elif [ -f "/var/log/kern.log" ] && [ "$LOG_FILE" = "/var/log/kern.log" ]; then
            > "/var/log/kern.log"
            log "Cleared /var/log/kern.log"
        fi
        echo "$now" > "$last_rotation_file"
        log "Log rotation completed"
    fi
}

# Function to display blocked IPs in real-time
blocked_list() {
    while true; do
        printf "\033c"  # Clear screen
        echo "Luveedu Shield - Realtime Block Malicious IPs (Refreshes every 10 second)"
        echo "----------------------------------------------------"
        echo "IP Address         | Blocked Since"
        echo "----------------------------------------------------"
        if [ -s "$SHIELD_BLOCKED_IPS_FILE" ]; then
            while read -r ip timestamp; do
                blocked_time=$(date -d "@$timestamp" '+%Y-%m-%d %H:%M:%S')
                printf "%-18s | %s\n" "$ip" "$blocked_time"
            done < "$SHIELD_BLOCKED_IPS_FILE"
        else
            echo "No IPs are currently blocked."
        fi
        sleep 10
    done
}

# Function to monitor connections
monitor() {
    # Dynamically determine the server's public IP (for logging purposes)
    SERVER_IP=$(curl -s --max-time 5 http://icanhazip.com 2>/dev/null)
    if [ -z "$SERVER_IP" ]; then
        SERVER_IP=$(ip -4 addr show $(ip route | grep default | awk '{print $5}' | head -n 1) | grep -oP '(?<=inet\s)\d+\.\d+\.\d+\.\d+' | head -n 1)
        if [ -z "$SERVER_IP" ]; then
            log "Failed to determine server IP. Exiting."
            exit 1
        fi
        log "Using fallback server IP: $SERVER_IP"
    else
        log "Detected server IP: $SERVER_IP"
    fi

    # Detect kernel log file
    if [ -f "/var/log/syslog" ]; then
        LOG_FILE="/var/log/syslog"
    elif [ -f "/var/log/messages" ]; then
        LOG_FILE="/var/log/messages"
    elif [ -f "/var/log/kern.log" ]; then
        LOG_FILE="/var/log/kern.log"
    else
        log "No kernel log file found. Configure logging or use journalctl."
        exit 1
    fi
    log "Using log file: $LOG_FILE"

    # Monitor new connections (external only, due to iptables filtering)
    trap 'log "Monitoring stopped by signal (PID: $$)"; exit' SIGTERM SIGINT
    log "Luveedu Shield started. Monitoring: $LOG_FILE (PID: $$)"
    while [ -f "$PID_FILE" ]; do
        tail -f "$LOG_FILE" | grep "NEW_CONNECTION" | awk '{print $10}' | sed 's/SRC=//' | while read -r ip; do
            if ! grep -q "^$ip " "$SHIELD_BLOCKED_IPS_FILE"; then
                response=$(curl -s --max-time 2 "$CHECK_API$ip")
                if [ "$response" = "BLACKLIST" ]; then
                    block_ip "$ip"
                else
                    log "IP $ip not blacklisted (response: $response)"
                fi
            fi
        done
        unblock_expired
        rotate_logs
        sleep 60  # Check for expired IPs and rotate logs every minute
    done
    log "Monitoring stopped due to stop command (PID: $$)"
}

# Start function
start() {
    if [ -f "$PID_FILE" ]; then
        pid=$(cat "$PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            echo "Luveedu Shield is already running (PID: $pid)"
            exit 1
        else
            rm -f "$PID_FILE"
        fi
    fi
    monitor &>>"$SHIELD_LOG" &
    pid=$!
    echo "$pid" > "$PID_FILE"
    echo "Luveedu Shield started (PID: $pid)"
    log "Service started manually with PID: $pid"
}

# Stop function
stop() {
    if [ -f "$PID_FILE" ]; then
        pid=$(cat "$PID_FILE")
        if kill -TERM "$pid" 2>/dev/null; then
            log "Stopping Luveedu Shield (PID: $pid)"
            rm -f "$PID_FILE"
            attempts=0
            while kill -0 "$pid" 2>/dev/null && [ $attempts -lt 5 ]; do
                sleep 1
                ((attempts++))
            done
            if kill -0 "$pid" 2>/dev/null; then
                log "Force killing Luveedu Shield (PID: $pid)"
                kill -9 "$pid" 2>/dev/null
            fi
            echo "Luveedu Shield stopped"
        else
            echo "Luveedu Shield process (PID: $pid) not found"
            rm -f "$PID_FILE"
            exit 1
        fi
    else
        echo "Luveedu Shield is not running"
        exit 1
    fi
}

# Reset function
reset() {
    log "Resetting Luveedu Shield..."
    if [ -f "$PID_FILE" ]; then
        stop
    fi

    # Release all blocked IPs
    while read -r ip timestamp; do
        iptables -D INPUT -s "$ip" -j DROP 2>/dev/null
        log "Released IP: $ip"
    done < "$SHIELD_BLOCKED_IPS_FILE"

    # Clear logs and blocked IPs file
    > "$SHIELD_BLOCKED_IPS_FILE"
    > "$SHIELD_LOG"
    if [ -f "/var/log/syslog" ]; then
        > "/var/log/syslog"
        log "Cleared /var/log/syslog"
    elif [ -f "/var/log/messages" ]; then
        > "/var/log/messages"
        log "Cleared /var/log/messages"
    elif [ -f "/var/log/kern.log" ]; then
        > "/var/log/kern.log"
        log "Cleared /var/log/kern.log"
    fi
    sleep 2
    # Restart the service
    start
    log "Luveedu Shield reset complete and restarted."
    echo "Luveedu Shield reset complete."
}

# Function to fix and ensure iptables rules are properly set
fix_all() {
    log "Fixing iptables rules for Luveedu Shield..."
    SERVER_IP=$(curl -s --max-time 2 https://ipv4.icanhazip.com/ 2>/dev/null || ip -4 addr show $(ip route | grep default | awk '{print $5}' | head -n 1) | grep -oP '(?<=inet\s)\d+\.\d+\.\d+\.\d+' | head -n 1)
    if [ -z "$SERVER_IP" ]; then
        log "Failed to determine server IP for iptables rules"
        echo "Failed to determine server IP for iptables rules"
        exit 1
    fi

    # Check if rules exist, if not add them
    iptables -F INPUT
    if ! iptables -L LOG_EXTERNAL -n 2>/dev/null; then
        iptables -N LOG_EXTERNAL
    else
        iptables -F LOG_EXTERNAL
    fi
    iptables -A INPUT -i lo -j ACCEPT
    if ! iptables -C INPUT -s 127.0.0.1 -j ACCEPT 2>/dev/null; then
        iptables -A INPUT -s 127.0.0.1 -j ACCEPT
    fi
    if ! iptables -C INPUT -s "$SERVER_IP" -j ACCEPT 2>/dev/null; then
        iptables -A INPUT -s "$SERVER_IP" -j ACCEPT
    fi
    if ! iptables -C INPUT -m state --state NEW -j LOG_EXTERNAL 2>/dev/null; then
        iptables -A INPUT -m state --state NEW -j LOG_EXTERNAL
    fi
    if ! iptables -C LOG_EXTERNAL -j LOG --log-prefix "NEW_CONNECTION: " 2>/dev/null; then
        iptables -A LOG_EXTERNAL -j LOG --log-prefix "NEW_CONNECTION: "
    fi
    
    log "iptables rules verified and set for luvd-shield (Server IP: $SERVER_IP)"
    echo "iptables rules set for luvd-shield (Server IP: $SERVER_IP)"
}

# Function to update script from GitHub and reset
update() {
    log "Updating Luveedu Shield script from GitHub..."
    local github_url="https://raw.githubusercontent.com/Luveedu/Luveedu-Firewall/refs/heads/main/luvd-shield.sh"
    local script_path="/usr/local/bin/luvd-shield"
    
    # Fetch new script content
    if curl -s --max-time 10 "$github_url" > "$script_path.tmp"; then
        # Replace current script with new content
        mv "$script_path.tmp" "$script_path"
        sudo sed -i 's/\r$//' "$script_path"
        chmod +x "$script_path"
        log "Script updated successfully!"
        echo "Script updated successfully!"
        
        # Wait and reset
        sleep 2
        "$script_path" --reset
    else
        log "Failed to update script! API ERROR!"
        echo "Failed to update script! API ERROR!"
        exit 1
    fi
}

# CLI handling
case "$1" in
    --start)
        start
        ;;
    --stop)
        stop
        ;;
    --reset)
        reset
        ;;
    --blocked-list)
        blocked_list
        ;;
    --fix-all)
        fix_all
        ;;
    --update)
        update
        ;;
    *)
        echo "Usage: luvd-shield [--start | --stop | --reset | --blocked-list | --fix-all | --update]"
        exit 1
        ;;
esac