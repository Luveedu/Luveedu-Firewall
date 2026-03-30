#!/bin/bash
# File: /usr/local/bin/luvd-shield
# Luveedu Shield - A Realtime Bad Bots and IP Blocking Solution

UNDER_ATTACK_MODE=0

CHECK_API="https://waf.luveedu.cloud/checkip.php?ip="
SHIELD_BLOCKED_IPS_FILE="/var/tmp/luvd-shield-blocked-ips.txt"
SHIELD_LOG="/var/log/luvd-shield.log"
PID_FILE="/var/run/luvd-shield.pid"
BLOCK_DURATION=$((60 * 60 * 24 * 7)) # 7 days in seconds
ROTATION_INTERVAL=600                # 10 minutes in seconds
IPTABLES_RULES_FILE="/etc/iptables/rules.v4"
SERVER_IP="" # Will be set in fix_all

# Ensure required files and directories exist
touch "$SHIELD_BLOCKED_IPS_FILE" "$SHIELD_LOG"
mkdir -p /etc/iptables
[ -f "$IPTABLES_RULES_FILE" ] || touch "$IPTABLES_RULES_FILE"

# Function to log messages
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') $1" >>"$SHIELD_LOG"
}

# Function to toggle under attack mode
toggle_under_attack() {
    local mode="$1"
    if [ "$mode" = "1" ] || [ "$mode" = "on" ]; then
        UNDER_ATTACK_MODE=1
        log "Under Attack Mode ENABLED - All new connections will be blocked immediately"
        echo "Under Attack Mode ENABLED"
    elif [ "$mode" = "0" ] || [ "$mode" = "off" ]; then
        UNDER_ATTACK_MODE=0
        log "Under Attack Mode DISABLED - Returning to normal operation"
        echo "Under Attack Mode DISABLED"
    else
        echo "Current Under Attack Mode: $UNDER_ATTACK_MODE (0=off, 1=on)"
        echo "Usage: luvd-shield --under-attack [on|off|1|0]"
        return 1
    fi
}

# Function to block IP
block_ip() {
    local ip="$1"
    if grep -q "^$ip " "/var/tmp/luvd-blocked-ips.txt"; then
        log "IP $ip already blocked by luvd-firewall, skipping"
        return
    fi
    if ! iptables -C INPUT -s "$ip" -j DROP 2>/dev/null; then
        iptables -A INPUT -s "$ip" -j DROP
        echo "$ip $(date +%s)" >>"$SHIELD_BLOCKED_IPS_FILE"
        iptables-save >"$IPTABLES_RULES_FILE"
        log "Blocked IP $ip on all ports"
    else
        log "IP $ip already blocked"
    fi
}
# Function to unblock expired IPs without removing LOG rule
unblock_expired() {
    local now=$(date +%s)
    local temp_file=$(mktemp)
    cp "$SHIELD_BLOCKED_IPS_FILE" "$temp_file"
    while read -r ip timestamp; do
        if [ -n "$ip" ] && [ $((now - timestamp)) -ge $BLOCK_DURATION ]; then
            iptables -D INPUT -s "$ip" -j DROP 2>/dev/null
            grep -v "^$ip " "$temp_file" >"$SHIELD_BLOCKED_IPS_FILE"
            # Ensure LOG rule persists
            if ! iptables -C INPUT -m state --state NEW -j LOG --log-prefix "LUVEEDU-SHIELD: " 2>/dev/null; then
                iptables -A INPUT -m state --state NEW -j LOG --log-prefix "LUVEEDU-SHIELD: "
                log "Re-added LOG rule to iptables"
            fi
            iptables-save >"$IPTABLES_RULES_FILE"
            log "Unblocked expired IP: $ip"
        fi
    done <"$temp_file"
    rm -f "$temp_file"
}

# Function to rotate logs every 10 minutes
rotate_logs() {
    log "Rotating logs..."
    >"$SHIELD_LOG"
    if [ -f "$LOG_FILE" ]; then
        >"$LOG_FILE"
        log "Cleared kernel log: $LOG_FILE"
    fi
    log "Log rotation completed"
}

# Function to display blocked IPs
blocked_list() {
    while true; do
        printf "\033c"
        echo "Luveedu Shield - Realtime Block Malicious IPs (Refreshes every 10 seconds)"
        echo "----------------------------------------------------"
        echo "IP Address         | Blocked Since"
        echo "----------------------------------------------------"
        if [ -s "$SHIELD_BLOCKED_IPS_FILE" ]; then
            while read -r ip timestamp; do
                blocked_time=$(date -d "@$timestamp" '+%Y-%m-%d %H:%M:%S')
                printf "%-18s | %s\n" "$ip" "$blocked_time"
            done <"$SHIELD_BLOCKED_IPS_FILE"
        else
            echo "No IPs are currently blocked."
        fi
        sleep 10
    done
}

# Function to monitor connections
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

    local last_rotation=0

    stdbuf -o0 tail -F "$LOG_FILE" 2>/dev/null | while true; do
        read -r line || {
            log "tail pipeline failed or EOF reached"
            break
        }
        # Extract IP from SRC= field explicitly
        ip=$(echo "$line" | grep "LUVEEDU-SHIELD:" | awk -F 'SRC=' '{print $2}' | awk '{print $1}' | sed 's/DST=.*//')
        if [ -n "$ip" ] && [ "$ip" != "$SERVER_IP" ] && [ "$ip" != "127.0.0.1" ] && ! grep -q "^$ip " "$SHIELD_BLOCKED_IPS_FILE"; then
            if [ "$UNDER_ATTACK_MODE" -eq 1 ]; then
                # In under attack mode, block immediately without API check
                block_ip "$ip"
                log "Under Attack Mode: Immediately blocked IP $ip"
            else
                # Normal mode with API check
                response=$(curl -s --max-time 2 "$CHECK_API$ip")
                if [ "$response" = "BLACKLIST" ]; then
                    block_ip "$ip"
                else
                    log "IP $ip not blacklisted (response: $response)"
                fi
            fi
        fi
    done &
    TAIL_PID=$!

    while [ -f "$PID_FILE" ]; do
        if [ ! -r "$LOG_FILE" ]; then
            log "Log file $LOG_FILE is not readable or missing. Exiting."
            kill $TAIL_PID 2>/dev/null
            exit 1
        fi

        local now=$(date +%s)
        if [ $((now - last_rotation)) -ge $ROTATION_INTERVAL ]; then
            rotate_logs
            last_rotation=$now
            kill $TAIL_PID 2>/dev/null
            stdbuf -o0 tail -F "$LOG_FILE" 2>/dev/null | while true; do
                read -r line || {
                    log "tail pipeline failed or EOF reached"
                    break
                }
                # Extract IP from SRC= field explicitly
                ip=$(echo "$line" | grep "LUVEEDU-SHIELD:" | awk -F 'SRC=' '{print $2}' | awk '{print $1}' | sed 's/DST=.*//')
                if [ -n "$ip" ] && [ "$ip" != "$SERVER_IP" ] && [ "$ip" != "127.0.0.1" ] && ! grep -q "^$ip " "$SHIELD_BLOCKED_IPS_FILE"; then
                    if [ "$UNDER_ATTACK_MODE" -eq 1 ]; then
                        # In under attack mode, block immediately without API check
                        block_ip "$ip"
                        log "Under Attack Mode: Immediately blocked IP $ip"
                    else
                        # Normal mode with API check
                        response=$(curl -s --max-time 2 "$CHECK_API$ip")
                        if [ "$response" = "BLACKLIST" ]; then
                            block_ip "$ip"
                        else
                            log "IP $ip not blacklisted (response: $response)"
                        fi
                    fi
                fi
            done &
            TAIL_PID=$!
        fi
        sleep 1
    done
    log "Monitoring stopped due to stop command (PID: $$)"
    kill $TAIL_PID 2>/dev/null
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
    if [ -s "$IPTABLES_RULES_FILE" ]; then
        iptables-restore <"$IPTABLES_RULES_FILE" || log "Failed to restore iptables rules"
    fi
    if [ -z "$SERVER_IP" ]; then
        fix_all
    fi
    monitor &>>"$SHIELD_LOG" &
    pid=$!
    echo "$pid" >"$PID_FILE"
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
                pkill -9 luvd-shield
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

# Reset function (Updated to preserve LOG rule)
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
    local temp_file=$(mktemp)
    cp "$SHIELD_BLOCKED_IPS_FILE" "$temp_file"
    while read -r ip timestamp; do
        iptables -D INPUT -s "$ip" -j DROP 2>/dev/null
        grep -v "^$ip " "$temp_file" >"$SHIELD_BLOCKED_IPS_FILE"
        log "Released IP: $ip"
        # Ensure LOG rule persists
        if ! iptables -C INPUT -m state --state NEW -j LOG --log-prefix "LUVEEDU-SHIELD: " 2>/dev/null; then
            iptables -A INPUT -m state --state NEW -j LOG --log-prefix "LUVEEDU-SHIELD: "
            log "Re-added LOG rule to iptables during reset"
        fi
    done <"$temp_file"
    rm -f "$temp_file"

    >"$SHIELD_BLOCKED_IPS_FILE"
    >"$SHIELD_LOG"
    >"$LOG_FILE"
    rm -f /var/tmp/luvd-shield-last-pos-*
    fix_all
    sleep 2
    systemctl restart luvd-shield 2>/dev/null || start
    sleep 3
    log "Luveedu Shield reset complete and restarted."
    echo "Luveedu Shield reset complete."
}

# Function to fix iptables rules
fix_all() {
    echo "Fixing iptables rules for Luveedu Shield..."
    log "Fixing iptables rules for Luveedu Shield..."

    SERVER_IP=$(curl -s --max-time 2 https://ipv4.icanhazip.com/ 2>/dev/null || ip -4 addr show $(ip route | grep default | awk '{print $5}' | head -n 1) | grep -oP '(?<=inet\s)\d+\.\d+\.\d+\.\d+' | head -n 1)

    if [ -z "$SERVER_IP" ]; then
        log "Failed to determine server IP"
        echo "Failed to determine server IP"
        exit 1
    fi

    # Preserve existing rules, only ensure LOG rule exists
    if ! iptables -C INPUT -m state --state NEW -j LOG --log-prefix "LUVEEDU-SHIELD: " 2>/dev/null; then
        iptables -A INPUT -m state --state NEW -j LOG --log-prefix "LUVEEDU-SHIELD: "
    fi

    iptables-save >/etc/iptables/rules.v4
    log "iptables rules set to log all new connections (Server IP: $SERVER_IP)"
    echo "iptables rules set to log all new connections (Server IP: $SERVER_IP)"
}


# Function to update script
update() {
    echo "Updating Luveedu Shield script..."
    log "Updating Luveedu Shield script..."
    local github_url="https://raw.githubusercontent.com/Luveedu/Luveedu-Firewall/refs/heads/main/luvd-shield.sh"
    local script_path="/usr/local/bin/luvd-shield"

    if curl -s --max-time 10 "$github_url" >"$script_path.tmp"; then
        mv "$script_path.tmp" "$script_path"
        sed -i 's/\r$//' "$script_path"
        chmod +x "$script_path"
        "$script_path" --reset
        log "Script updated successfully!"
        echo "Script updated successfully!"
    else
        log "Failed to update script!"
        echo "Failed to update script!"
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
    echo "Usage: luvd-shield [OPTION] [ARGUMENT]"
    echo " --start         - It starts the Blocking Engine"
    echo " --stop          - It stops the Blocking Engine"
    echo " --blocked-list  - Check the Blocked IPs"
    echo " --fix-all       - Fix the Issues related to logging & iptables"
    echo " --reset         - If the Shield is not Working Simply Reset the Configuration"
    echo " --update        - Update the Script to the Latest Version from Github"
    exit 1
    ;;
esac
