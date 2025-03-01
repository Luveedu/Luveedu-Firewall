#!/bin/bash
# File: /usr/local/bin/luvd-shield
# Luveedu Shield - A Realtime Bad Bots and IP Blocking Solution

CHECK_API="https://waf.luveedu.cloud/checkip.php?ip="
SHIELD_BLOCKED_IPS_FILE="/var/tmp/luvd-shield-blocked-ips.txt"
SHIELD_LOG="/var/log/luvd-shield.log"
PID_FILE="/var/run/luvd-shield.pid"
BLOCK_DURATION=$((60*60*24*7))  # 7 days in seconds
ROTATION_INTERVAL=300  # 5 minutes in seconds
UNBLOCK_INTERVAL=$((60*60*24*7))  # 7 days in seconds
IPTABLES_RULES_FILE="/etc/iptables/rules.v4"

# Ensure required files and directories exist
touch "$SHIELD_BLOCKED_IPS_FILE" "$SHIELD_LOG"
mkdir -p /etc/iptables  # Create directory if it doesn’t exist
[ -f "$IPTABLES_RULES_FILE" ] || touch "$IPTABLES_RULES_FILE"  # Create empty rules file if missing

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
        iptables-save > "$IPTABLES_RULES_FILE"  # Save rules to persist
        log "Blocked IP $ip on all ports"
    else
        log "IP $ip already blocked"
    fi
}

# Function to unblock expired IPs (runs every 7 days)
unblock_expired() {
    local now=$(date +%s)
    while read -r ip timestamp; do
        if [ -n "$ip" ] && [ $((now - timestamp)) -ge $BLOCK_DURATION ]; then
            iptables -D INPUT -s "$ip" -j DROP 2>/dev/null
            sed -i "/^$ip /d" "$SHIELD_BLOCKED_IPS_FILE"
            iptables-save > "$IPTABLES_RULES_FILE"  # Save updated rules
            log "Unblocked expired IP: $ip"
        fi
    done < "$SHIELD_BLOCKED_IPS_FILE"
}

# Function to rotate logs every 5 minutes
rotate_logs() {
    log "Rotating logs..."
    > "$SHIELD_LOG"  # Clear luvd-shield.log
    if [ -f "$LOG_FILE" ]; then
        > "$LOG_FILE"  # Clear kernel log file
        log "Cleared kernel log: $LOG_FILE"
    fi
    log "Log rotation completed (both $SHIELD_LOG and $LOG_FILE cleared)"
}

# Function to display blocked IPs in real-time
blocked_list() {
    while true; do
        printf "\033c"  # Clear screen
        echo "Luveedu Shield - Realtime Block Malicious IPs (Refreshes every 10 seconds)"
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
    if [ -f "/var/log/syslog" ]; then
        LOG_FILE="/var/log/syslog"
    elif [ -f "/var/log/messages" ]; then
        LOG_FILE="/var/log/messages"
    elif [ -f "/var/log/kern.log" ]; then
        LOG_FILE="/var/log/kern.log"
    else
        log "No kernel log file found."
        exit 1
    fi
    
    log "Using log file: $LOG_FILE"

    trap 'log "Monitoring stopped by signal (PID: $$)"; kill $TAIL_PID 2>/dev/null; exit' SIGTERM SIGINT
    log "Luveedu Shield started. Monitoring: $LOG_FILE (PID: $$)"

    local last_unblock=0
    local last_rotation=0

    # Start tail -f in the background and process its output
    tail -f "$LOG_FILE" 2>/dev/null | while true; do
        read -r line || { log "tail -f pipeline failed or EOF reached"; break; }
        ip=$(echo "$line" | grep "NEW_CONNECTION" | awk '{print $10}' | sed 's/SRC=//')
        if [ -n "$ip" ] && ! grep -q "^$ip " "$SHIELD_BLOCKED_IPS_FILE"; then
            log "Checking IP: $ip"
            response=$(curl -s --max-time 2 "$CHECK_API$ip")
            if [ "$response" = "BLACKLIST" ]; then
                block_ip "$ip"
            else
                log "IP $ip not blacklisted (response: $response)"
            fi
        fi
    done &
    TAIL_PID=$!  # Store the PID of the background tail process

    while [ -f "$PID_FILE" ]; do
        if [ ! -r "$LOG_FILE" ]; then
            log "Log file $LOG_FILE is not readable or missing. Exiting."
            kill $TAIL_PID 2>/dev/null
            exit 1
        fi

        local now=$(date +%s)

        # Rotate logs every 5 minutes
        if [ $((now - last_rotation)) -ge $ROTATION_INTERVAL ]; then
            rotate_logs
            last_rotation=$now
            # Restart tail -f after log rotation since the file is cleared
            kill $TAIL_PID 2>/dev/null
            tail -f "$LOG_FILE" 2>/dev/null | while true; do
                read -r line || { log "tail -f pipeline failed or EOF reached"; break; }
                ip=$(echo "$line" | grep "NEW_CONNECTION" | awk '{print $10}' | sed 's/SRC=//')
                if [ -n "$ip" ] && ! grep -q "^$ip " "$SHIELD_BLOCKED_IPS_FILE"; then
                    log "Checking IP: $ip"
                    response=$(curl -s --max-time 2 "$CHECK_API$ip")
                    if [ "$response" = "BLACKLIST" ]; then
                        block_ip "$ip"
                    else
                        log "IP $ip not blacklisted (response: $response)"
                    fi
                fi
            done &
            TAIL_PID=$!
        fi
        sleep 1
    done
    log "Monitoring stopped due to stop command (PID: $$)"
    kill $TAIL_PID 2>/dev/null  # Clean up tail process on exit
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
    # Restore rules only if the file exists and is not empty
    if [ -s "$IPTABLES_RULES_FILE" ]; then
        iptables-restore < "$IPTABLES_RULES_FILE" || log "Failed to restore iptables rules from $IPTABLES_RULES_FILE"
    else
        log "No existing iptables rules file found at $IPTABLES_RULES_FILE, starting fresh"
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
                killall -9 luvd-shield
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
    if [ -f "/var/log/syslog" ]; then
        LOG_FILE="/var/log/syslog"
    elif [ -f "/var/log/messages" ]; then
        LOG_FILE="/var/log/messages"
    elif [ -f "/var/log/kern.log" ]; then
        LOG_FILE="/var/log/kern.log"
    else
        log "No kernel log file found."
        exit 1
    fi

    log "Resetting Luveedu Shield..."

    while read -r ip timestamp; do
        iptables -D INPUT -s "$ip" -j DROP 2>/dev/null
        log "Released IP: $ip"
    done < "$SHIELD_BLOCKED_IPS_FILE"

    > "$SHIELD_BLOCKED_IPS_FILE"
    > "$SHIELD_LOG"
    > "$LOG_FILE"
    echo "Log Filed also Removed!"
    rm -f /var/tmp/luvd-shield-last-pos-*
    sleep 2
    fix_all
    sleep 2
    systemctl restart luvd-shield
    start
    sleep 3
    log "Luveedu Shield reset complete and restarted."
    echo "Luveedu Shield reset complete."
}

# Function to fix and ensure iptables rules are properly set
fix_all() {
    echo "Fixing Syslog.."
    touch /var/log/messages
    chown root:adm /var/log/messages
    sleep 1
    service rsyslog restart
    sleep 2
    echo "Fixing iptables rules for Luveedu Shield... (Called at $(date '+%Y-%m-%d %H:%M:%S'))"
    log "Fixing iptables rules for Luveedu Shield... (Called at $(date '+%Y-%m-%d %H:%M:%S'))"
    SERVER_IP=$(curl -s --max-time 2 https://ipv4.icanhazip.com/ 2>/dev/null || ip -4 addr show $(ip route | grep default | awk '{print $5}' | head -n 1) | grep -oP '(?<=inet\s)\d+\.\d+\.\d+\.\d+' | head -n 1)

    if [ -z "$SERVER_IP" ]; then
        log "Failed to determine server IP for iptables rules"
        echo "Failed to determine server IP for iptables rules"
        exit 1
    fi

    iptables -A INPUT -i lo -j ACCEPT
    if ! iptables -L LOG_EXTERNAL -n 2>/dev/null; then
        iptables -N LOG_EXTERNAL
    else
        iptables -F LOG_EXTERNAL
    fi
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
    
    iptables-save > "$IPTABLES_RULES_FILE"  # Save rules
    log "iptables rules verified and set for luvd-shield (Server IP: $SERVER_IP)"
    echo "iptables rules set for luvd-shield (Server IP: $SERVER_IP)"
}

# Function to update script from GitHub and reset
update() {
    echo "Updating Luveedu Shield script from API"
    log "Updating Luveedu Shield script from GitHub..."
    local github_url="https://raw.githubusercontent.com/Luveedu/Luveedu-Firewall/refs/heads/main/luvd-shield.sh"
    local script_path="/usr/local/bin/luvd-shield"
    
    if curl -s --max-time 10 "$github_url" > "$script_path.tmp"; then
        mv "$script_path.tmp" "$script_path"
        sudo sed -i 's/\r$//' "$script_path"
        chmod +x "$script_path"
        sleep 2
        "$script_path" --reset
        log "Script updated successfully!"
        echo "Script updated successfully!"
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