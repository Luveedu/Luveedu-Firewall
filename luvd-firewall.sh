#!/bin/bash

# Luveedu Firewall - DoS Prevention Tool for OpenLiteSpeed
# File: /usr/local/bin/luvd-firewall

# Configuration
ACCESS_LOG="/usr/local/lsws/logs/access.log"
VH_CONF_PATTERN="/usr/local/lsws/conf/vhosts/*/vhost.conf"
BLOCK_DURATION=$((60 * 60 * 24)) # 1 day in seconds

# SET THESE NUMBERS FOR DOS ATTACK STOPPING
REQUEST_LIMIT_PER_WINDOW=100     # Max requests per 30-second window
WINDOW_DURATION=30               # Window duration in seconds

# SET THESE NUMBERS FOR DDOS ATTACK STOPPING
REQUEST_LIMIT_PER_SEC=15         # Max requests per short time window
SEC_WINDOW_DURATION=3            # Short time window duration in seconds

CHECK_INTERVAL=1                 # Check every 1 second
PID_FILE="/var/run/luvd-firewall.pid"
BLOCKED_IPS_FILE="/var/tmp/luvd-blocked-ips.txt"
DESIRED_LOG_FORMAT='%h %l %u %t "%r" %>s %b "%{X-Forwarded-For}i" "%{User-Agent}i"'
FIREWALL_LOG="/var/log/luvd-firewall.log"
TEMP_LOG="/tmp/luvd-firewall-temp.log"
LAST_LINE_FILE="/var/tmp/luvd-firewall-last-line.txt"
CHECK_API="https://waf.luveedu.cloud/checkip.php?ip="

# Ensure required files exist
touch "$BLOCKED_IPS_FILE" "$FIREWALL_LOG" "$LAST_LINE_FILE"

# Function to validate IP address
is_valid_ip() {
    local ip="$1"
    if echo "$ip" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
        IFS='.' read -r a b c d <<<"$ip"
        if [ "$a" -le 255 ] && [ "$b" -le 255 ] && [ "$c" -le 255 ] && [ "$d" -le 255 ]; then
            return 0 # Valid IP
        fi
    fi
    return 1 # Invalid IP
}

# Function to extract IPs from OLS log line
get_ips() {
    local line="$1"
    local main_ip=$(echo "$line" | awk '{print $2}')
    local xff=$(echo "$line" | sed -E 's/.*"([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)" "[^"]+"$/\1/' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$')
    echo "$(date '+%Y-%m-%d %H:%M:%S') Debug: xff extracted=$xff" >>"$FIREWALL_LOG"

    if is_valid_ip "$main_ip"; then
        echo "$main_ip"
    else
        echo ""
    fi

    if [ -n "$xff" ] && [ "$xff" != "-" ] && is_valid_ip "$xff"; then
        echo "$xff"
    else
        echo ""
    fi
}

# Function to check IP via API without caching
in_list() {
    local ip="$1"
    local list_type="$2" # "WHITELIST" or "BLACKLIST"
    local response

    response=$(curl -s --max-time 5 "$CHECK_API$ip" 2>/dev/null)
    if [ $? -ne 0 ] || [ -z "$response" ]; then
        echo "$(date '+%Y-%m-%d %H:%M:%S') API check for IP $ip failed or timed out, assuming UNAVAILABLE" >>"$FIREWALL_LOG"
        return 1 # Assume unavailable if API fails
    fi

    echo "$(date '+%Y-%m-%d %H:%M:%S') API check for IP $ip: $response" >>"$FIREWALL_LOG"
    case "$response" in
    "WHITELIST")
        [ "$list_type" = "WHITELIST" ] && return 0 || return 1
        ;;
    "BLACKLIST")
        [ "$list_type" = "BLACKLIST" ] && return 0 || return 1
        ;;
    "UNAVAILABLE" | "INVALID")
        return 1
        ;;
    *)
        echo "$(date '+%Y-%m-%d %H:%M:%S') Unexpected API response for IP $ip: $response, assuming UNAVAILABLE" >>"$FIREWALL_LOG"
        return 1
        ;;
    esac
}

# Function to check IP or CIDR via API
check_ip() {
    local input="$1"
    if [[ "$input" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        ip="$input"
        if ! is_valid_ip "$ip"; then
            echo "Error: $ip is not a valid IP address"
            exit 1
        fi
        echo "Checking single IP: $ip"
        response=$(curl -s --max-time 5 "$CHECK_API$ip" 2>/dev/null)
        if [ $? -ne 0 ] || [ -z "$response" ]; then
            echo "$(date '+%Y-%m-%d %H:%M:%S') API check for IP $ip failed or timed out" >>"$FIREWALL_LOG"
            if grep -q "^$ip " "$BLOCKED_IPS_FILE"; then
                echo "IP $ip is currently blocked"
            else
                echo "API unavailable, cannot determine status of IP $ip (assumed not in whitelist or blacklist)"
            fi
        else
            case "$response" in
            "WHITELIST")
                echo "IP $ip is explicitly whitelisted by the API"
                ;;
            "BLACKLIST")
                echo "IP $ip is explicitly blacklisted by the API"
                ;;
            "UNAVAILABLE")
                if grep -q "^$ip " "$BLOCKED_IPS_FILE"; then
                    echo "IP $ip is currently blocked but not explicitly listed by the API"
                else
                    echo "IP $ip is not explicitly whitelisted or blacklisted by the API"
                fi
                ;;
            "INVALID")
                echo "IP $ip is considered invalid by the API"
                ;;
            *)
                echo "Unexpected API response for IP $ip: $response"
                ;;
            esac
        fi
    elif [[ "$input" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]]; then
        echo "Checking CIDR range: $input"
        response=$(curl -s --max-time 5 "$CHECK_API$input" 2>/dev/null)
        if [ $? -ne 0 ] || [ -z "$response" ]; then
            echo "$(date '+%Y-%m-%d %H:%M:%S') API check for CIDR $input failed or timed out" >>"$FIREWALL_LOG"
            IFS='/' read -r range mask <<<"$input"
            start_num=$(ip_to_num "$range")
            mask_bits=$mask
            mask_num=$((0xFFFFFFFF << (32 - mask_bits)))
            end_num=$((start_num | ~mask_num & 0xFFFFFFFF))
            found=false
            for ((i = start_num; i <= end_num; i++)); do
                ip=$(num_to_ip "$i")
                if grep -q "^$ip " "$BLOCKED_IPS_FILE"; then
                    echo "IP $ip from range $input is currently blocked"
                    found=true
                fi
            done
            if ! $found; then
                echo "API unavailable, cannot determine status of CIDR $input (no IPs blocked)"
            fi
        else
            case "$response" in
            "WHITELIST")
                echo "CIDR $input is fully whitelisted by the API"
                ;;
            "BLACKLIST")
                echo "CIDR $input is fully blacklisted by the API"
                ;;
            "UNAVAILABLE")
                IFS='/' read -r range mask <<<"$input"
                start_num=$(ip_to_num "$range")
                mask_bits=$mask
                mask_num=$((0xFFFFFFFF << (32 - mask_bits)))
                end_num=$((start_num | ~mask_num & 0xFFFFFFFF))
                found=false
                for ((i = start_num; i <= end_num; i++)); do
                    ip=$(num_to_ip "$i")
                    if grep -q "^$ip " "$BLOCKED_IPS_FILE"; then
                        echo "IP $ip from range $input is currently blocked"
                        found=true
                    fi
                done
                if ! $found; then
                    echo "CIDR $input is not explicitly whitelisted or blacklisted by the API"
                fi
                ;;
            "INVALID")
                echo "CIDR $input is invalid according to the API"
                ;;
            *)
                echo "Unexpected API response for CIDR $input: $response"
                ;;
            esac
        fi
    else
        echo "Invalid IP or CIDR format. Use --check-ip <IP> or --check-ip <IP/CIDR>"
        exit 1
    fi
}

# IP conversion functions
ip_to_num() {
    local ip="$1"
    IFS='.' read -r a b c d <<<"$ip"
    echo $(((a << 24) + (b << 16) + (c << 8) + d))
}

num_to_ip() {
    local num="$1"
    echo "$((num >> 24 & 255)).$((num >> 16 & 255)).$((num >> 8 & 255)).$((num & 255))"
}

# Function to block an IP or CIDR with REJECT
block_ip() {
    local ip="$1"
    local reason="$2"
    local rate="$3"
    if [ -z "$ip" ]; then
        return
    fi

    if [ "$reason" = "rate-limit-per-window" ] && [[ "$ip" =~ \.0$ ]]; then
        local cidr="${ip%.*}.0/24"
        if ! iptables -C INPUT -s "$cidr" -j REJECT --reject-with icmp-host-prohibited 2>/dev/null; then
            echo "$(date '+%Y-%m-%d %H:%M:%S') Attempting to reject CIDR: $cidr | Reason: $reason | Rate: $rate | PID: $$" >>"$FIREWALL_LOG"
            iptables -A INPUT -s "$cidr" -j REJECT --reject-with icmp-host-prohibited
            echo "$cidr $(date +%s)" >>"$BLOCKED_IPS_FILE"
            iptables-save >/etc/iptables/rules.v4 # Persist rules
            echo "$(date '+%Y-%m-%d %H:%M:%S') Rejected CIDR: $cidr | Reason: $reason | Rate: $rate | PID: $$" >>"$FIREWALL_LOG"
        fi
    else
        if ! iptables -C INPUT -s "$ip" -j REJECT --reject-with icmp-host-prohibited 2>/dev/null; then
            echo "$(date '+%Y-%m-%d %H:%M:%S') Attempting to reject IP: $ip | Reason: $reason | Rate: $rate | PID: $$" >>"$FIREWALL_LOG"
            iptables -A INPUT -s "$ip" -j REJECT --reject-with icmp-host-prohibited
            echo "$ip $(date +%s)" >>"$BLOCKED_IPS_FILE"
            iptables-save >/etc/iptables/rules.v4 # Persist rules
            echo "$(date '+%Y-%m-%d %H:%M:%S') Rejected IP: $ip | Reason: $reason | Rate: $rate | PID: $$" >>"$FIREWALL_LOG"
        fi
    fi
}

# Function to block blacklist IPs
block_blacklist() {
    while read -r ip timestamp; do
        if ! in_list "$ip" "WHITELIST" && in_list "$ip" "BLACKLIST"; then
            block_ip "$ip" "blacklist" "0"
        fi
    done <"$BLOCKED_IPS_FILE"
}

# Function to preserve and restore the LUVEEDU-SHIELD LOG rule
preserve_log_rule() {
    if iptables -C INPUT -m state --state NEW -j LOG --log-prefix "LUVEEDU-SHIELD: " 2>/dev/null; then
        LOG_RULE_EXISTS=true
        echo "$(date '+%Y-%m-%d %H:%M:%S') Preserving LUVEEDU-SHIELD LOG rule" >>"$FIREWALL_LOG"
    else
        LOG_RULE_EXISTS=false
    fi
}

restore_log_rule() {
    if [ "$LOG_RULE_EXISTS" = true ]; then
        if ! iptables -C INPUT -m state --state NEW -j LOG --log-prefix "LUVEEDU-SHIELD: " 2>/dev/null; then
            iptables -A INPUT -m state --state NEW -j LOG --log-prefix "LUVEEDU-SHIELD: "
            echo "$(date '+%Y-%m-%d %H:%M:%S') Restored LUVEEDU-SHIELD LOG rule" >>"$FIREWALL_LOG"
        fi
    fi
}

# Function to unblock expired IPs and CIDRs
unblock_expired() {
    local now=$(date +%s)
    preserve_log_rule
    while read -r entry timestamp; do
        if [ $((now - timestamp)) -ge $BLOCK_DURATION ]; then
            iptables -D INPUT -s "$entry" -j REJECT --reject-with icmp-host-prohibited 2>/dev/null
            sed -i "/^$entry /d" "$BLOCKED_IPS_FILE"
            iptables-save >/etc/iptables/rules.v4 # Persist rules
            if [[ "$entry" =~ /24$ ]]; then
                echo "$(date '+%Y-%m-%d %H:%M:%S') Unblocked expired CIDR: $entry" >>"$FIREWALL_LOG"
            else
                echo "$(date '+%Y-%m-%d %H:%M:%S') Unblocked expired IP: $entry" >>"$FIREWALL_LOG"
            fi
        fi
    done <"$BLOCKED_IPS_FILE"
    restore_log_rule
}

# Function to release all blocked IPs and clear logs
release_all() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') Releasing all blocked IPs and clearing logs..." >>"$FIREWALL_LOG"
    preserve_log_rule
    while read -r entry timestamp; do
        iptables -D INPUT -s "$entry" -j REJECT --reject-with icmp-host-prohibited 2>/dev/null # Delete specific rule
        if [[ "$entry" =~ /24$ ]]; then
            echo "$(date '+%Y-%m-%d %H:%M:%S') Released CIDR: $entry" >>"$FIREWALL_LOG"
        else
            echo "$(date '+%Y-%m-%d %H:%M:%S') Released IP: $entry" >>"$FIREWALL_LOG"
        fi
    done <"$BLOCKED_IPS_FILE"
    >"$BLOCKED_IPS_FILE"
    >"$FIREWALL_LOG"
    >"$ACCESS_LOG"
    >"$LAST_LINE_FILE"
    iptables-save >/etc/iptables/rules.v4 # Persist rules
    restore_log_rule
    echo "$(date '+%Y-%m-%d %H:%M:%S') All IPs released from iptables and blocklist, logs cleared." >>"$FIREWALL_LOG"
}

# Function to release a specific IP or CIDR
release_ip() {
    local input="$1"
    if [ -z "$input" ]; then
        echo "Please provide an IP or CIDR to release (e.g., --release-ip 8.8.8.8 or --release-ip 8.8.8.8/24)"
        exit 1
    fi

    preserve_log_rule
    if [[ "$input" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]]; then
        # Handle CIDR
        if iptables -D INPUT -s "$input" -j REJECT --reject-with icmp-host-prohibited 2>/dev/null; then
            sed -i "/^$input /d" "$BLOCKED_IPS_FILE"
            echo "$(date '+%Y-%m-%d %H:%M:%S') Released CIDR: $input from iptables and blocklist" >>"$FIREWALL_LOG"
        else
            echo "$(date '+%Y-%m-%d %H:%M:%S') CIDR $input was not blocked" >>"$FIREWALL_LOG"
        fi
    elif [[ "$input" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        # Handle single IP
        if iptables -D INPUT -s "$input" -j REJECT --reject-with icmp-host-prohibited 2>/dev/null; then
            sed -i "/^$input /d" "$BLOCKED_IPS_FILE"
            echo "$(date '+%Y-%m-%d %H:%M:%S') Released IP: $input from iptables and blocklist" >>"$FIREWALL_LOG"
        elif iptables -D INPUT -s "${input%.*}.0/24" -j REJECT --reject-with icmp-host-prohibited 2>/dev/null; then
            sed -i "/${input%.*}.0\/24/d" "$BLOCKED_IPS_FILE"
            echo "$(date '+%Y-%m-%d %H:%M:%S') Released CIDR: ${input%.*}.0/24 from iptables and blocklist" >>"$FIREWALL_LOG"
        else
            echo "$(date '+%Y-%m-%d %H:%M:%S') IP $input was not blocked" >>"$FIREWALL_LOG"
        fi
    else
        echo "Invalid IP or CIDR format. Use --release-ip <IP> or --release-ip <IP/CIDR> (e.g., --release-ip 8.8.8.8 or --release-ip 8.8.8.8/24)"
        exit 1
    fi
    restore_log_rule
}

# Function to reset the firewall service
reset() {
    echo "Resetting Luveedu Firewall..."
    systemctl stop luvd-firewall 2>/dev/null || echo "Systemd stop failed, continuing..."
    if [ -f "$PID_FILE" ]; then
        local pid=$(cat "$PID_FILE")
        if kill -TERM "$pid" 2>/dev/null; then
            echo "$(date '+%Y-%m-%d %H:%M:%S') Stopped firewall process (PID: $pid)" >>"$FIREWALL_LOG"
            rm -f "$PID_FILE"
            sleep 6
        else
            echo "Failed to stop firewall process (PID: $pid), proceeding anyway..."
        fi
    fi

    systemctl daemon-reload
    echo "Clearing all Luveedu Firewall logs and resetting data..."
    >"$FIREWALL_LOG"
    >"$ACCESS_LOG"
    >"$BLOCKED_IPS_FILE"
    >"$LAST_LINE_FILE"

    systemctl restart lsws
    echo "Restarted OpenLiteSpeed Webserver"

    preserve_log_rule
    iptables -F INPUT 2>/dev/null
    while read -r entry timestamp; do
        iptables -D INPUT -s "$entry" -j REJECT --reject-with icmp-host-prohibited 2>/dev/null
    done <"$BLOCKED_IPS_FILE"
    >"$BLOCKED_IPS_FILE"
    restore_log_rule

    echo "$(date '+%Y-%m-%d %H:%M:%S') All IPs released and logs cleared." >>"$FIREWALL_LOG"

    systemctl start luvd-firewall 2>/dev/null || echo "Service start failed, check systemd configuration."
    echo "Luveedu Firewall reset complete."
}

# Function to display blocked IP list
blocked_list() {
    echo "Luveedu Firewall - Blocked IP List for DoS / DDoS Attack"
    if [ -s "$BLOCKED_IPS_FILE" ]; then
        echo "IP Address/CIDR   Blocked Since"
        echo "------------------  -------------------"
        while read -r entry timestamp; do
            blocked_time=$(date -d "@$timestamp" '+%Y-%m-%d %H:%M:%S')
            printf "%-18s  %s\n" "$entry" "$blocked_time"
        done <"$BLOCKED_IPS_FILE"
    else
        echo "No IPs are currently blocked."
    fi
}

# Function to clear all logs (only log files, not iptables or blocked IPs)
clear_logs() {
    echo "Clearing all Luveedu Firewall logs..."
    preserve_log_rule
    >"$FIREWALL_LOG"  # Clear firewall log
    >"$ACCESS_LOG"    # Clear access log
    >"$LAST_LINE_FILE" # Clear last line file
    restore_log_rule
    echo "All logs cleared."
}

# Function to fix log formats
fix_logs() {
    echo "Updating all vhost configurations to use a single access log file: $ACCESS_LOG..."
    local changed=0
    for conf in $VH_CONF_PATTERN; do
        if [ -f "$conf" ]; then
            echo "Processing $conf"
            sudo cp "$conf" "$conf.bak.$(date +%F_%T)"
            if grep -q "accesslog" "$conf"; then
                sudo sed -i '/accesslog .* {/,/}/d' "$conf"
            fi
            echo -e "accesslog $ACCESS_LOG {\n  useServer               1\n  logFormat               \"$DESIRED_LOG_FORMAT\"\n  logHeaders              7\n  keepDays                7\n  compressArchive         0\n}" | sudo tee -a "$conf" >/dev/null
            changed=1
        fi
    done
    if [ $changed -eq 1 ]; then
        echo "Reloading OpenLiteSpeed to apply changes..."
        sudo systemctl reload lsws
        echo "Log formats and access log location updated in all vhosts."
    else
        echo "No vhost configurations found to update."
    fi
}

# Enhanced check_logs function with improved reset intervals
check_logs() {
    echo "Luveedu Firewall - DoS / DDoS Blocking (Realtime)"
    echo "------------------------------------------------------------"
    echo "IP Address        | Requests/${WINDOW_DURATION}s | Requests/${SEC_WINDOW_DURATION}s | Status"
    echo "------------------------------------------------------------"

    declare -A ip_status
    declare -A ip_win_count          # For 100/30s
    declare -A ip_sec_count          # For configurable short window
    local last_win_reset=$(date +%s) # Last reset for 30s window
    local last_sec_reset=$(date +%s) # Last reset for short window

    # Helper function to check if an IP is within a blocked CIDR
    is_ip_in_blocked_cidr() {
        local check_ip="$1"
        while read -r entry _; do
            if [[ "$entry" =~ /24$ ]]; then
                local cidr_base="${entry%/24}"
                local ip_base="${check_ip%.*}"
                if [ "$cidr_base" = "$ip_base" ]; then
                    return 0
                fi
            fi
        done <"$BLOCKED_IPS_FILE"
        while read -r entry _; do
            if [ "$entry" = "$check_ip" ]; then
                return 0
            fi
        done <"/var/tmp/luvd-shield-blocked-ips.txt"
        return 1
    }

    tail -n 1000 -f "$FIREWALL_LOG" | while read -r line; do
        local now=$(date +%s)
        local cutoff=$(date -d "-$WINDOW_DURATION seconds" '+%s') # 30s cutoff
        local sec_cutoff=$(date -d "-$SEC_WINDOW_DURATION seconds" '+%s') # Configurable short window cutoff

        # Reset Requests/30s every 30 seconds
        if [ $((now - last_win_reset)) -ge 30 ]; then
            for ip in "${!ip_win_count[@]}"; do
                if [[ "${ip_status[$ip]}" != Blocked* ]]; then
                    ip_win_count[$ip]=0
                fi
            done
            last_win_reset=$now
            echo "$(date '+%Y-%m-%d %H:%M:%S') Reset Requests/30s counters" >>"$FIREWALL_LOG"
        fi

        # Reset Requests/short window every SEC_WINDOW_DURATION + 1 seconds
        if [ $((now - last_sec_reset)) -ge $((SEC_WINDOW_DURATION + 1)) ]; then
            for ip in "${!ip_sec_count[@]}"; do
                if [[ "${ip_status[$ip]}" != Blocked* ]]; then
                    ip_sec_count[$ip]=0
                fi
            done
            last_sec_reset=$now
            echo "$(date '+%Y-%m-%d %H:%M:%S') Reset Requests/${SEC_WINDOW_DURATION}s counters" >>"$FIREWALL_LOG"
        fi

        # Parse log lines for IP and status updates
        if echo "$line" | grep -q "Blocked IP"; then
            ip=$(echo "$line" | grep -oE 'Blocked IP: [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | cut -d' ' -f3)
            if [ -n "$ip" ]; then
                reason=$(echo "$line" | grep -oE 'Reason: [^|]+' | cut -d' ' -f2-)
                rate=$(echo "$line" | grep -oE 'Rate: [^|]+' | cut -d' ' -f2-)
                ip_status[$ip]="Blocked ($reason $rate)"
                ip_win_count[$ip]="-"
                ip_sec_count[$ip]="-"
            fi
        elif echo "$line" | grep -q "Rejected "; then
            ip=$(echo "$line" | grep -oE 'Rejected (IP|CIDR): [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/24)?' | cut -d' ' -f3)
            if [ -n "$ip" ]; then
                reason=$(echo "$line" | grep -oE 'Reason: [^|]+' | cut -d' ' -f2-)
                rate=$(echo "$line" | grep -oE 'Rate: [^|]+' | cut -d' ' -f2-)
                ip_status[$ip]="Blocked ($reason $rate)"
                ip_win_count[$ip]="-"
                ip_sec_count[$ip]="-"
            fi
        elif echo "$line" | grep -q "Request logged"; then
            ip=$(echo "$line" | grep -oE 'for IP [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | cut -d' ' -f3)
            timestamp=$(echo "$line" | grep -oE '^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}')
            if [ -n "$ip" ] && [ -n "$timestamp" ]; then
                ts_seconds=$(date -d "$timestamp" +%s 2>/dev/null)
                if [ -n "$ts_seconds" ]; then
                    if is_ip_in_blocked_cidr "$ip"; then
                        ip_status[$ip]="Blocked (within CIDR)"
                        ip_win_count[$ip]="-"
                        ip_sec_count[$ip]="-"
                    elif [[ -z "${ip_status[$ip]}" || "${ip_status[$ip]}" != Blocked* ]]; then
                        if in_list "$ip" "WHITELIST"; then
                            ip_status[$ip]="Whitelisted"
                        else
                            ip_status[$ip]="Processing"
                        fi
                        # Update 30-second window count
                        if [ "$ts_seconds" -ge "$cutoff" ]; then
                            ip_win_count[$ip]=$((${ip_win_count[$ip]:-0} + 1))
                        fi
                        # Update short window count
                        if [ "$ts_seconds" -ge "$sec_cutoff" ]; then
                            ip_sec_count[$ip]=$((${ip_sec_count[$ip]:-0} + 1))
                        fi
                    fi
                else
                    echo "$(date '+%Y-%m-%d %H:%M:%S') Failed to parse timestamp from: $line" >>"$FIREWALL_LOG"
                fi
            else
                echo "$(date '+%Y-%m-%d %H:%M:%S') Failed to parse IP or timestamp from: $line" >>"$FIREWALL_LOG"
            fi
        fi

        # Clear the screen and display updated table
        printf "\033c"
        echo "Luveedu Firewall - DoS / DDoS Blocking (Realtime)"
        echo "------------------------------------------------------------"
        echo "IP Address        | Requests/${WINDOW_DURATION}s | Requests/${SEC_WINDOW_DURATION}s | Status"
        echo "------------------------------------------------------------"
        if [ ${#ip_status[@]} -eq 0 ]; then
            echo "No activity detected yet."
        else
            for ip in "${!ip_status[@]}"; do
                win_count="${ip_win_count[$ip]:-0}"
                sec_count="${ip_sec_count[$ip]:-0}"
                if [ "$win_count" != "0" ] || [ "$sec_count" != "0" ] || [[ "${ip_status[$ip]}" == Blocked* ]]; then
                    printf "%-17s | %-12s | %-11s | %s\n" "$ip" "$win_count" "$sec_count" "${ip_status[$ip]}"
                fi
            done
        fi
    done
}

# Function to rotate logs every 5 minutes using clear_logs
rotate_logs() {
    local now=$(date +%s)
    local last_rotation_file="/var/tmp/luvd-firewall-last-rotation.txt"
    local last_rotation=0

    if [ ! -f "$last_rotation_file" ]; then
        echo "$now" >"$last_rotation_file"
    else
        last_rotation=$(cat "$last_rotation_file")
    fi

    if [ $((now - last_rotation)) -ge 300 ]; then
        echo "$(date '+%Y-%m-%d %H:%M:%S') Initiating log rotation..." >>"$FIREWALL_LOG"
        clear_logs
        echo "$now" >"$last_rotation_file"
        echo "$(date '+%Y-%m-%d %H:%M:%S') Log rotation completed: All logs cleared" >>"$FIREWALL_LOG"
    fi
}

# Monitoring function with strict rate limiting and CDN handling
monitor_requests() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') Luveedu Firewall started. Monitoring: $ACCESS_LOG (PID: $$)" >>"$FIREWALL_LOG"
    trap 'echo "$(date "+%Y-%m-%d %H:%M:%S") Monitoring terminated by signal (PID: $$)" >> "$FIREWALL_LOG"; exit' SIGTERM SIGINT

    local last_lines_processed=0
    if [ -s "$LAST_LINE_FILE" ]; then
        last_lines_processed=$(cat "$LAST_LINE_FILE")
    fi

    declare -A ip_counts_by_window
    declare -A ip_timestamps

    # Helper function to check if an IP is within a blocked CIDR
    is_ip_in_blocked_cidr() {
        local check_ip="$1"
        while read -r entry _; do
            if [[ "$entry" =~ /24$ ]]; then
                local cidr_base="${entry%/24}"
                local ip_base="${check_ip%.*}"
                if [ "$cidr_base" = "$ip_base" ]; then
                    return 0 # IP is within blocked CIDR
                fi
            fi
        done <"$BLOCKED_IPS_FILE"
        return 1 # IP not within any blocked CIDR
    }

    while [ -f "$PID_FILE" ]; do
        if [ -f "$ACCESS_LOG" ]; then
            echo "$(date '+%Y-%m-%d %H:%M:%S') Checking access log: $ACCESS_LOG" >>"$FIREWALL_LOG"
            if [ ! -r "$ACCESS_LOG" ]; then
                echo "$(date '+%Y-%m-%d %H:%M:%S') Error: Cannot read $ACCESS_LOG" >>"$FIREWALL_LOG"
                touch "$ACCESS_LOG" || {
                    echo "Failed to create $ACCESS_LOG"
                    exit 1
                }
                chown root:root "$ACCESS_LOG"
            fi

            local cutoff=$(date -d "-$WINDOW_DURATION seconds" '+%s')
            local total_lines=$(wc -l <"$ACCESS_LOG")
            local lines_to_process=$((total_lines - last_lines_processed))
            local lines_processed=0

            echo "$(date '+%Y-%m-%d %H:%M:%S') Cutoff timestamp: $cutoff" >>"$FIREWALL_LOG"

            if [ "$lines_to_process" -gt 0 ]; then
                tail -n "$lines_to_process" "$ACCESS_LOG" | while IFS= read -r line; do
                    lines_processed=$((lines_processed + 1))

                    if echo "$line" | grep -qE '^\["[^"]+"\] [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+'; then
                        main_ip=$(get_ips "$line" | head -n 1)
                        xff_ip=$(get_ips "$line" | tail -n 1)
                        echo "$(date '+%Y-%m-%d %H:%M:%S') Parsed: main_ip=$main_ip, xff_ip=$xff_ip" >>"$FIREWALL_LOG"

                        if [ -n "$main_ip" ]; then
                            if grep -q "^$main_ip " "$BLOCKED_IPS_FILE" || is_ip_in_blocked_cidr "$main_ip"; then
                                echo "$(date '+%Y-%m-%d %H:%M:%S') Main IP $main_ip already blocked or in blocked CIDR, skipping" >>"$FIREWALL_LOG"
                                continue
                            fi

                            timestamp=$(echo "$line" | grep -oP '\[\K\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4}')
                            if [ -n "$timestamp" ]; then
                                ts_reformat=$(echo "$timestamp" | sed 's|/| |g; s/:/ /; s/ \([+-]\)/ \1/')
                                ts_seconds=$(date -d "$ts_reformat" +%s 2>/dev/null)
                                if [ -n "$ts_seconds" ] && [ "$ts_seconds" -ge "$cutoff" ]; then
                                    ip_to_monitor="$main_ip"
                                    ip_to_block="$main_ip"
                                    if in_list "$main_ip" "WHITELIST" && [ -n "$xff_ip" ]; then
                                        ip_to_monitor="$xff_ip"
                                        ip_to_block="$xff_ip"
                                        echo "$(date '+%Y-%m-%d %H:%M:%S') Main IP $main_ip whitelisted, switching to X-Forwarded-For IP $xff_ip" >>"$FIREWALL_LOG"
                                    fi

                                    if grep -q "^$ip_to_block " "$BLOCKED_IPS_FILE" || is_ip_in_blocked_cidr "$ip_to_block"; then
                                        echo "$(date '+%Y-%m-%d %H:%M:%S') IP $ip_to_block already blocked or in blocked CIDR, skipping" >>"$FIREWALL_LOG"
                                        continue
                                    fi

                                    ip_win_key="$ip_to_monitor"

                                    if in_list "$ip_to_block" "BLACKLIST"; then
                                        block_ip "$ip_to_block" "blacklist" "0"
                                        unset ip_counts_by_window["$ip_win_key"]
                                        unset ip_timestamps["$ip_win_key,"*]
                                        continue
                                    fi

                                    if ! in_list "$ip_to_block" "WHITELIST"; then
                                        ip_counts_by_window["$ip_win_key"]=$((${ip_counts_by_window[$ip_win_key]:-0} + 1))
                                        ip_timestamps["$ip_win_key,$ts_seconds"]=1
                                        echo "$(date '+%Y-%m-%d %H:%M:%S') Request logged for IP $ip_to_monitor | Window count: ${ip_counts_by_window[$ip_win_key]} | PID: $$" >>"$FIREWALL_LOG"

                                        if [ "${ip_counts_by_window[$ip_win_key]}" -gt "$REQUEST_LIMIT_PER_WINDOW" ]; then
                                            block_ip "$ip_to_block" "rate-limit-per-window" "${ip_counts_by_window[$ip_win_key]} req/30s"
                                            unset ip_counts_by_window["$ip_win_key"]
                                            unset ip_timestamps["$ip_win_key,"*]
                                            continue
                                        fi
                                    else
                                        echo "$(date '+%Y-%m-%d %H:%M:%S') IP $ip_to_block not monitored (whitelisted)" >>"$FIREWALL_LOG"
                                    fi
                                fi
                            fi
                        fi
                    fi
                done
                echo "$(date '+%Y-%m-%d %H:%M:%S') Processed $lines_processed new lines from access log (total lines: $total_lines)" >>"$FIREWALL_LOG"
                last_lines_processed=$total_lines
                echo "$last_lines_processed" >"$LAST_LINE_FILE"
            else
                echo "$(date '+%Y-%m-%d %H:%M:%S') Processed $lines_processed new lines from access log (total lines: $total_lines)" >>"$FIREWALL_LOG"
            fi

            for key in "${!ip_timestamps[@]}"; do
                IFS=',' read -r ip ts <<<"$key"
                if [ "$ts" -lt "$cutoff" ]; then
                    ip_counts_by_window["$ip"]=$((ip_counts_by_window["$ip"] - 1))
                    if [ "${ip_counts_by_window[$ip]}" -le 0 ]; then
                        unset ip_counts_by_window["$ip"]
                    fi
                    unset ip_timestamps["$key"]
                fi
            done

            for ip in "${!ip_counts_by_window[@]}"; do
                win_rate="${ip_counts_by_window[$ip]}"
                if [ "$win_rate" -gt "$REQUEST_LIMIT_PER_WINDOW" ] && ! in_list "$ip" "WHITELIST"; then
                    block_ip "$ip" "rate-limit-per-window" "$win_rate req/30s"
                    unset ip_counts_by_window["$ip"]
                    unset ip_timestamps["$ip,"*]
                fi
            done

            rotate_logs
        else
            echo "$(date '+%Y-%m-%d %H:%M:%S') Access log $ACCESS_LOG not found" >>"$FIREWALL_LOG"
        fi

        unblock_expired
        block_blacklist
        sleep "$CHECK_INTERVAL"
    done
    echo "$(date '+%Y-%m-%d %H:%M:%S') Monitoring stopped due to stop command (PID: $$)" >>"$FIREWALL_LOG"
    exit 0
}

# Function to monitor requests per short time window (e.g., 15/3s)
monitor_per_second_rate() {
    local ip="$1"
    local timestamp="$2"
    local ip_to_block="$3"
    
    # Use a single key combining IP and short time window
    local window_start=$((timestamp - (timestamp % SEC_WINDOW_DURATION)))  # Align to SEC_WINDOW_DURATION
    local sec_key="$ip,$window_start"

    # Increment count for this IP in this short time window
    ip_per_sec_counts["$sec_key"]=$((${ip_per_sec_counts[$sec_key]:-0} + 1))
    ip_per_sec_timestamps["$sec_key"]="$window_start"

    # Check if rate exceeds the configured limit for the short time window
    if [ "${ip_per_sec_counts[$sec_key]}" -gt "$REQUEST_LIMIT_PER_SEC" ]; then
        if ! in_list "$ip_to_block" "WHITELIST"; then
            block_ip "$ip_to_block" "rate-limit-per-$SEC_WINDOW_DURATION-seconds" "${ip_per_sec_counts[$sec_key]} req/${SEC_WINDOW_DURATION}s"
            echo "$(date '+%Y-%m-%d %H:%M:%S') IP $ip_to_block exceeded $REQUEST_LIMIT_PER_SEC req/${SEC_WINDOW_DURATION}s limit: ${ip_per_sec_counts[$sec_key]} requests" >>"$FIREWALL_LOG"
            return 1 # Indicate block occurred
        fi
    fi
    return 0 # No block needed
}



# Modified monitor_requests function with new per-3-second rate limiting
monitor_requests() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') Luveedu Firewall started. Monitoring: $ACCESS_LOG (PID: $$)" >>"$FIREWALL_LOG"
    trap 'echo "$(date "+%Y-%m-%d %H:%M:%S") Monitoring terminated by signal (PID: $$)" >> "$FIREWALL_LOG"; exit' SIGTERM SIGINT

    local last_lines_processed=0
    if [ -s "$LAST_LINE_FILE" ]; then
        last_lines_processed=$(cat "$LAST_LINE_FILE")
    fi

    declare -A ip_counts_by_window
    declare -A ip_timestamps
    declare -A ip_per_sec_counts
    declare -A ip_per_sec_timestamps

    # Helper function to check if an IP is within a blocked CIDR
    is_ip_in_blocked_cidr() {
        local check_ip="$1"
        while read -r entry _; do
            if [[ "$entry" =~ /24$ ]]; then
                local cidr_base="${entry%/24}"
                local ip_base="${check_ip%.*}"
                if [ "$cidr_base" = "$ip_base" ]; then
                    return 0 # IP is within blocked CIDR
                fi
            fi
        done <"$BLOCKED_IPS_FILE"
        return 1 # IP not within any blocked CIDR
    }

    while [ -f "$PID_FILE" ]; do
        if [ -f "$ACCESS_LOG" ]; then
            echo "$(date '+%Y-%m-%d %H:%M:%S') Checking access log: $ACCESS_LOG" >>"$FIREWALL_LOG"
            if [ ! -r "$ACCESS_LOG" ]; then
                echo "$(date '+%Y-%m-%d %H:%M:%S') Error: Cannot read $ACCESS_LOG" >>"$FIREWALL_LOG"
                touch "$ACCESS_LOG" || {
                    echo "Failed to create $ACCESS_LOG"
                    exit 1
                }
                chown root:root "$ACCESS_LOG"
            fi

            local cutoff=$(date -d "-$WINDOW_DURATION seconds" '+%s')
            local sec_cutoff=$(date -d "-$SEC_WINDOW_DURATION seconds" '+%s')  # Use configurable short window
            local total_lines=$(wc -l <"$ACCESS_LOG")
            local lines_to_process=$((total_lines - last_lines_processed))
            local lines_processed=0

            echo "$(date '+%Y-%m-%d %H:%M:%S') Cutoff timestamp: $cutoff" >>"$FIREWALL_LOG"

            if [ "$lines_to_process" -gt 0 ]; then
                tail -n "$lines_to_process" "$ACCESS_LOG" | while IFS= read -r line; do
                    lines_processed=$((lines_processed + 1))

                    if echo "$line" | grep -qE '^\["[^"]+"\] [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+'; then
                        main_ip=$(get_ips "$line" | head -n 1)
                        xff_ip=$(get_ips "$line" | tail -n 1)
                        echo "$(date '+%Y-%m-%d %H:%M:%S') Parsed: main_ip=$main_ip, xff_ip=$xff_ip" >>"$FIREWALL_LOG"

                        if [ -n "$main_ip" ]; then
                            if grep -q "^$main_ip " "$BLOCKED_IPS_FILE" || is_ip_in_blocked_cidr "$main_ip"; then
                                echo "$(date '+%Y-%m-%d %H:%M:%S') Main IP $main_ip already blocked or in blocked CIDR, skipping" >>"$FIREWALL_LOG"
                                continue
                            fi

                            timestamp=$(echo "$line" | grep -oP '\[\K\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4}')
                            if [ -n "$timestamp" ]; then
                                ts_reformat=$(echo "$timestamp" | sed 's|/| |g; s/:/ /; s/ \([+-]\)/ \1/')
                                ts_seconds=$(date -d "$ts_reformat" +%s 2>/dev/null)
                                if [ -n "$ts_seconds" ] && [ "$ts_seconds" -ge "$cutoff" ]; then
                                    ip_to_monitor="$main_ip"
                                    ip_to_block="$main_ip"
                                    if in_list "$main_ip" "WHITELIST" && [ -n "$xff_ip" ]; then
                                        ip_to_monitor="$xff_ip"
                                        ip_to_block="$xff_ip"
                                        echo "$(date '+%Y-%m-%d %H:%M:%S') Main IP $main_ip whitelisted, switching to X-Forwarded-For IP $xff_ip" >>"$FIREWALL_LOG"
                                    fi

                                    if grep -q "^$ip_to_block " "$BLOCKED_IPS_FILE" || is_ip_in_blocked_cidr "$ip_to_block"; then
                                        echo "$(date '+%Y-%m-%d %H:%M:%S') IP $ip_to_block already blocked or in blocked CIDR, skipping" >>"$FIREWALL_LOG"
                                        continue
                                    fi

                                    ip_win_key="$ip_to_monitor"

                                    if in_list "$ip_to_block" "BLACKLIST"; then
                                        block_ip "$ip_to_block" "blacklist" "0"
                                        unset ip_counts_by_window["$ip_win_key"]
                                        unset ip_timestamps["$ip_win_key,"*]
                                        unset ip_per_sec_counts["$ip_win_key,"*]
                                        unset ip_per_sec_timestamps["$ip_win_key,"*]
                                        continue
                                    fi

                                    if ! in_list "$ip_to_block" "WHITELIST"; then
                                        # Check per-short-window rate limit first
                                        if [ "$ts_seconds" -ge "$sec_cutoff" ]; then
                                            monitor_per_second_rate "$ip_to_monitor" "$ts_seconds" "$ip_to_block"
                                            if [ $? -eq 1 ]; then
                                                unset ip_counts_by_window["$ip_win_key"]
                                                unset ip_timestamps["$ip_win_key,"*]
                                                unset ip_per_sec_counts["$ip_win_key,"*]
                                                unset ip_per_sec_timestamps["$ip_win_key,"*]
                                                continue
                                            fi
                                        fi

                                        # 100/30s rate limiting
                                        ip_counts_by_window["$ip_win_key"]=$((${ip_counts_by_window[$ip_win_key]:-0} + 1))
                                        ip_timestamps["$ip_win_key,$ts_seconds"]=1
                                        echo "$(date '+%Y-%m-%d %H:%M:%S') Request logged for IP $ip_to_monitor | Window count: ${ip_counts_by_window[$ip_win_key]} | PID: $$" >>"$FIREWALL_LOG"

                                        if [ "${ip_counts_by_window[$ip_win_key]}" -gt "$REQUEST_LIMIT_PER_WINDOW" ]; then
                                            block_ip "$ip_to_block" "rate-limit-per-window" "${ip_counts_by_window[$ip_win_key]} req/30s"
                                            unset ip_counts_by_window["$ip_win_key"]
                                            unset ip_timestamps["$ip_win_key,"*]
                                            unset ip_per_sec_counts["$ip_win_key,"*]
                                            unset ip_per_sec_timestamps["$ip_win_key,"*]
                                            continue
                                        fi
                                    else
                                        echo "$(date '+%Y-%m-%d %H:%M:%S') IP $ip_to_block not monitored (whitelisted)" >>"$FIREWALL_LOG"
                                    fi
                                fi
                            fi
                        fi
                    fi
                done
                echo "$(date '+%Y-%m-%d %H:%M:%S') Processed $lines_processed new lines from access log (total lines: $total_lines)" >>"$FIREWALL_LOG"
                last_lines_processed=$total_lines
                echo "$last_lines_processed" >"$LAST_LINE_FILE"
            else
                echo "$(date '+%Y-%m-%d %H:%M:%S') Processed $lines_processed new lines from access log (total lines: $total_lines)" >>"$FIREWALL_LOG"
            fi

            # Clean up expired timestamps
            for key in "${!ip_timestamps[@]}"; do
                IFS=',' read -r ip ts <<<"$key"
                if [ "$ts" -lt "$cutoff" ]; then
                    ip_counts_by_window["$ip"]=$((ip_counts_by_window["$ip"] - 1))
                    if [ "${ip_counts_by_window[$ip]}" -le 0 ]; then
                        unset ip_counts_by_window["$ip"]
                    fi
                    unset ip_timestamps["$key"]
                fi
            done

            for key in "${!ip_per_sec_timestamps[@]}"; do
                IFS=',' read -r ip ts <<<"$key"
                if [ "$ts" -lt "$sec_cutoff" ]; then
                    unset ip_per_sec_counts["$key"]
                    unset ip_per_sec_timestamps["$key"]
                fi
            done

            # Check 100/30s limit
            for ip in "${!ip_counts_by_window[@]}"; do
                win_rate="${ip_counts_by_window[$ip]}"
                if [ "$win_rate" -gt "$REQUEST_LIMIT_PER_WINDOW" ] && ! in_list "$ip" "WHITELIST"; then
                    block_ip "$ip" "rate-limit-per-window" "$win_rate req/30s"
                    unset ip_counts_by_window["$ip"]
                    unset ip_timestamps["$ip,"*]
                    unset ip_per_sec_counts["$ip,"*]
                    unset ip_per_sec_timestamps["$ip,"*]
                fi
            done

            rotate_logs
        else
            echo "$(date '+%Y-%m-%d %H:%M:%S') Access log $ACCESS_LOG not found" >>"$FIREWALL_LOG"
        fi

        unblock_expired
        block_blacklist
        sleep "$CHECK_INTERVAL"
    done
    echo "$(date '+%Y-%m-%d %H:%M:%S') Monitoring stopped due to stop command (PID: $$)" >>"$FIREWALL_LOG"
    exit 0
}

# Start the firewall
start() {
    if [ -f "$PID_FILE" ]; then
        echo "Luveedu Firewall is already running (PID: $(cat $PID_FILE))"
    fi
    if [ -s "/etc/iptables/rules.v4" ]; then
        iptables-restore </etc/iptables/rules.v4 || echo "Failed to restore iptables rules"
    fi
    monitor_requests &>>"$FIREWALL_LOG" &
    local pid=$!
    echo $pid >"$PID_FILE"
    echo "Luveedu Firewall started (PID: $pid)"
}

# Stop the firewall
stop() {
    if [ -f "$PID_FILE" ]; then
        local pid=$(cat "$PID_FILE")
        echo "$(date '+%Y-%m-%d %H:%M:%S') Stopping Luveedu Firewall (PID: $pid)..." >>"$FIREWALL_LOG"
        kill -TERM "$pid" 2>/dev/null
        rm -f "$PID_FILE"
        local attempts=0
        while kill -0 "$pid" 2>/dev/null && [ $attempts -lt 5 ]; do
            sleep 1
            ((attempts++))
        done
        if kill -0 "$pid" 2>/dev/null; then
            echo "$(date '+%Y-%m-%d %H:%M:%S') Force killing firewall process (PID: $pid)..." >>"$FIREWALL_LOG"
            kill -9 "$pid" 2>/dev/null
        fi
        echo "Luveedu Firewall stopped"
    else
        echo "Luveedu Firewall is not running"
        exit 1
    fi
}

# Function to update the script from GitHub and reset
update() {
    local script_path="/usr/local/bin/luvd-firewall"
    local github_url="https://raw.githubusercontent.com/Luveedu/Luveedu-Firewall/refs/heads/main/luvd-firewall.sh"
    local temp_file="/tmp/luvd-firewall-update.sh"

    echo "Updating Luveedu Firewall from GitHub..."
    echo "$(date '+%Y-%m-%d %H:%M:%S') Starting update process from $github_url" >>"$FIREWALL_LOG"

    # Download the latest version
    if curl -s --max-time 10 "$github_url" -o "$temp_file" 2>/dev/null; then
        if [ -s "$temp_file" ]; then
            # Verify it's a valid bash script
            if head -n 1 "$temp_file" | grep -q '^#!/bin/bash'; then
                # Backup current script
                cp "$script_path" "$script_path.bak.$(date +%F_%T)"
                echo "$(date '+%Y-%m-%d %H:%M:%S') Backed up current script to $script_path.bak.$(date +%F_%T)" >>"$FIREWALL_LOG"

                # Install new version
                chmod +x "$temp_file"
                mv "$temp_file" "$script_path"
                echo "$(date '+%Y-%m-%d %H:%M:%S') Successfully updated script from GitHub" >>"$FIREWALL_LOG"

                # Perform reset
                echo "Performing reset after update..."
                reset

                echo "Update and reset completed successfully."
            else
                echo "Error: Downloaded file is not a valid bash script"
                echo "$(date '+%Y-%m-%d %H:%M:%S') Update failed: Downloaded file is not a valid bash script" >>"$FIREWALL_LOG"
                rm -f "$temp_file"
                exit 1
            fi
        else
            echo "Error: Downloaded file is empty"
            echo "$(date '+%Y-%m-%d %H:%M:%S') Update failed: Downloaded file is empty" >>"$FIREWALL_LOG"
            rm -f "$temp_file"
            exit 1
        fi
    else
        echo "Error: Failed to download update from GitHub"
        echo "$(date '+%Y-%m-%d %H:%M:%S') Update failed: Could not download from $github_url" >>"$FIREWALL_LOG"
        rm -f "$temp_file"
        exit 1
    fi
}

# CLI handling
case "$1" in
--start) start ;;
--stop) stop ;;
--fix-logs) fix_logs ;;
--release-all) release_all ;;
--release-ip)
    [ -z "$2" ] && {
        echo "Please provide an IP or CIDR (e.g., --release-ip 8.8.8.8 or --release-ip 8.8.8.8/24)"
        exit 1
    }
    release_ip "$2"
    ;;
--check-logs) check_logs ;;
--check-ip)
    [ -z "$2" ] && {
        echo "Please provide an IP or CIDR (e.g., --check-ip 8.8.8.8)"
        exit 1
    }
    check_ip "$2"
    ;;
--blocked-list) blocked_list ;;
--clear-logs) clear_logs ;;
--reset) reset ;;
--update) update ;;
*)
    echo "Usage: luvd-firewall [OPTION] [ARGUMENT]"
    echo " --start              - It starts the Firewall"
    echo " --stop               - It stops the Firewall"
    echo " --check-logs         - Monitor the Rate Limiting Stats"
    echo " --blocked-list       - Check the Blocked IPs"
    echo " --fix-logs           - Fix the vHosts to log in access.log file"
    echo " --reset              - If the Firewall is not Working Simply Reset the Configuration"
    echo " --update             - Update the Script to the Latest Version from Github"
    echo " --release-all       - Unblock all the IPs from iptables"
    echo " --release-ip 8.8.8.8 - Unblock any particular IP or Range"
    echo " --check-ip 8.8.8.8   - It will detect if the IP is BLACKLISTED OR WHITELISTED OR NONE"
    echo " --clear-logs         - It will clear all the previous logs"
    exit 1
    ;;
esac