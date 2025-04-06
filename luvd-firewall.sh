#!/bin/bash

# Luveedu Firewall - DoS Prevention Tool for OpenLiteSpeed
# File: /usr/local/bin/luvd-firewall

# Configuration
ACCESS_LOG="/usr/local/lsws/logs/access.log"
VH_CONF_PATTERN="/usr/local/lsws/conf/vhosts/*/vhost.conf"
BLOCK_DURATION=$((60 * 60 * 24)) # 1 day in seconds

# Rate Limits - DoS
REQUEST_LIMIT_PER_WINDOW=150 # Max requests per 30-second window
WINDOW_DURATION=30           # Window duration in seconds

# Rate Limits - DDoS
REQUEST_LIMIT_PER_SEC=15     # Max requests per 3-second window
SEC_WINDOW_DURATION=3        # Short window duration in seconds

CHECK_INTERVAL=1
PID_FILE="/var/run/luvd-firewall.pid"
BLOCKED_IPS_FILE="/var/tmp/luvd-blocked-ips.txt"
DESIRED_LOG_FORMAT='%h %l %u %t "%r" %>s %b "%{X-Forwarded-For}i" "%{User-Agent}i"'
FIREWALL_LOG="/var/log/luvd-firewall.log"
TEMP_LOG="/tmp/luvd-firewall-temp.log"
LAST_LINE_FILE="/var/tmp/luvd-firewall-last-line.txt"
CHECK_API="https://waf.luveedu.cloud/checkip.php?ip="

MALICIOUS_UA_REGEX=(
    ".*(bot|crawl|spider|slurp|archiver|curl|wget|python-requests|scrapy|httpclient).*"  # Common bots and scrapers
    ".*(sqlmap|nikto|burp|owasp|acunetix|netsparker).*"  # Security scanners
    ".*(masscan|nmap|zmap).*"  # Port scanners
    ".*(Mozilla/5\.0 \(compatible; .*; .*Googlebot.*\)).*"  # Fake Googlebot
)

MALICIOUS_REF_REGEX=(
    ".*(semalt\.com|buttons-for-website\.com|darodar\.com).*"  # Known spam referrers
    ".*(sql\.inject|union.*select|eval\(|\.\./\.\.).*"  # Basic injection attempts
    ".*(viagra|cialis|porn|casino|xanax).*"  # Common spam keywords
    ".*([0-9]{5,}\.com).*"  # Numeric domains with 5+ digits
)

# Ensure required files exist
touch "$BLOCKED_IPS_FILE" "$FIREWALL_LOG" "$LAST_LINE_FILE"

# Simplified function to extract main IP from OLS log line (no validation)
get_ips() {
    local line="$1"
    local first_field=$(echo "$line" | awk '{print $1}')
    
    # Check if the first field is a hostname in brackets (e.g., ["krownlinks.com"])
    if [[ "$first_field" =~ ^\[.*\]$ ]]; then
        # Extract the second field as the IP
        local ip=$(echo "$line" | awk '{print $2}')
    else
        # Use the first field as the IP (for logs without hostname prefix)
        local ip="$first_field"
    fi
    
    # Validate IP (IPv4 or IPv6)
    if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "$ip"
    elif [[ "$ip" =~ ^([0-9a-fA-F]{0,4}:){7}[0-9a-fA-F]{0,4}$ ]]; then
        echo "$ip"
    else
        echo "$(date '+%Y-%m-%d %H:%M:%S') Invalid IP extracted: $ip from line: $line" >>"$FIREWALL_LOG"
        echo ""  # Return empty string for invalid IPs
    fi
}

# Function to check IP via API without caching
in_list() {
    local ip="$1"
    local list_type="$2" # "WHITELIST" or "BLACKLIST"
    local response

    response=$(curl -s --max-time 5 "$CHECK_API$ip" 2>/dev/null)
    if [ $? -ne 0 ] || [ -z "$response" ]; then
        return 1
    fi
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
        return 1
        ;;
    esac
}

# Function to check IP via API (simplified, no CIDR)
check_ip() {
    local ip="$1"
    if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "Checking single IP: $ip"
        response=$(curl -s --max-time 5 "$CHECK_API$ip" 2>/dev/null)
        if [ $? -ne 0 ] || [ -z "$response" ]; then
            echo "$(date '+%Y-%m-%d %H:%M:%S') API Check for IP $ip failed or timed out" >>"$FIREWALL_LOG"
            if grep -q "^$ip " "$BLOCKED_IPS_FILE"; then
                echo "IP $ip is currently blocked"
            else
                echo "API unavailable, cannot determine status of IP $ip"
            fi
        else
            case "$response" in
            "WHITELIST") echo "IP $ip is explicitly whitelisted by the API" ;;
            "BLACKLIST") echo "IP $ip is explicitly blacklisted by the API" ;;
            "UNAVAILABLE")
                grep -q "^$ip " "$BLOCKED_IPS_FILE" && echo "IP $ip is currently blocked" || echo "IP $ip is not explicitly listed"
                ;;
            "INVALID") echo "IP $ip is considered invalid by the API" ;;
            *) echo "Unexpected API response for IP $ip: $response" ;;
            esac
        fi
    else
        echo "Invalid IP format. Use --check-ip <IP> (e.g., --check-ip 8.8.8.8)"
        exit 1
    fi
}

# Function to block an IP with REJECT (no CIDR handling)
block_ip() {
    local ip="$1"
    local reason="$2"
    local rate="$3"
    if [ -z "$ip" ]; then
        return
    fi
    
    # Check if IP is IPv4 or IPv6
    if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        # IPv4
        if ! iptables -C INPUT -s "$ip" -j REJECT --reject-with icmp-host-prohibited 2>/dev/null; then
            echo "$(date '+%Y-%m-%d %H:%M:%S') Attempting to reject IPv4: $ip | Reason: $reason | Rate: $rate | PID: $$" >>"$FIREWALL_LOG"
            iptables -A INPUT -s "$ip" -j REJECT --reject-with icmp-host-prohibited
            echo "$ip $(date +%s)" >>"$BLOCKED_IPS_FILE"
            iptables-save >/etc/iptables/rules.v4
            echo "$(date '+%Y-%m-%d %H:%M:%S') Rejected IPv4: $ip | Reason: $reason | Rate: $rate | PID: $$" >>"$FIREWALL_LOG"
        fi
    elif [[ "$ip" =~ ^([0-9a-fA-F]{0,4}:){7}[0-9a-fA-F]{0,4}$ ]]; then
        # IPv6
        if ! ip6tables -C INPUT -s "$ip" -j REJECT 2>/dev/null; then
            echo "$(date '+%Y-%m-%d %H:%M:%S') Attempting to reject IPv6: $ip | Reason: $reason | Rate: $rate | PID: $$" >>"$FIREWALL_LOG"
            ip6tables -A INPUT -s "$ip" -j REJECT
            echo "$ip $(date +%s)" >>"$BLOCKED_IPS_FILE"
            ip6tables-save >/etc/ip6tables/rules.v6 2>/dev/null || echo "$(date '+%Y-%m-%d %H:%M:%S') Warning: ip6tables-save failed" >>"$FIREWALL_LOG"
            echo "$(date '+%Y-%m-%d %H:%M:%S') Rejected IPv6: $ip | Reason: $reason | Rate: $rate | PID: $$" >>"$FIREWALL_LOG"
        fi
    fi
}

# Function to block blacklist IPs
block_blacklist() {
    while read -r ip timestamp; do
        if iptables -C INPUT -s "$ip" -j REJECT --reject-with icmp-host-prohibited 2>/dev/null; then
            continue
        fi
        if ! in_list "$ip" "WHITELIST" && in_list "$ip" "BLACKLIST"; then
            block_ip "$ip" "blacklist" "0"
        fi
    done <"$BLOCKED_IPS_FILE"
}

# Function to preserve and restore the LUVEEDU-SHIELD LOG rule
preserve_log_rule() {
    if iptables -C INPUT -m state --state NEW -j LOG --log-prefix "LUVEEDU-SHIELD: " 2>/dev/null; then
        LOG_RULE_EXISTS=true
    else
        LOG_RULE_EXISTS=false
    fi
}

restore_log_rule() {
    if [ "$LOG_RULE_EXISTS" = true ] && ! iptables -C INPUT -m state --state NEW -j LOG --log-prefix "LUVEEDU-SHIELD: " 2>/dev/null; then
        iptables -A INPUT -m state --state NEW -j LOG --log-prefix "LUVEEDU-SHIELD: "
    fi
}

# Function to unblock expired IPs
unblock_expired() {
    local now=$(date +%s)
    preserve_log_rule
    while read -r ip timestamp; do
        if [ $((now - timestamp)) -ge $BLOCK_DURATION ]; then
            if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                iptables -D INPUT -s "$ip" -j REJECT --reject-with icmp-host-prohibited 2>/dev/null
                iptables-save >/etc/iptables/rules.v4
            elif [[ "$ip" =~ ^([0-9a-fA-F]{0,4}:){7}[0-9a-fA-F]{0,4}$ ]]; then
                ip6tables -D INPUT -s "$ip" -j REJECT 2>/dev/null
                ip6tables-save >/etc/ip6tables/rules.v6 2>/dev/null
            fi
            sed -i "/^$ip /d" "$BLOCKED_IPS_FILE"
            echo "$(date '+%Y-%m-%d %H:%M:%S') Unblocked expired IP: $ip" >>"$FIREWALL_LOG"
        fi
    done <"$BLOCKED_IPS_FILE"
    restore_log_rule
}



# Function to release all blocked IPs and clear logs
release_all() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') Releasing all REJECT blocked IPs and clearing logs..." >>"$FIREWALL_LOG"
    preserve_log_rule
    iptables -S INPUT | awk '/-s/ && /REJECT/ {for(i=1;i<=NF;i++) if($i=="-s") print $(i+1)}' | while read -r source; do
        if [ -n "$source" ] && iptables -D INPUT -s "$source" -j REJECT --reject-with icmp-host-prohibited 2>/dev/null; then
            echo "$(date '+%Y-%m-%d %H:%M:%S') Released REJECT rule for: $source" >>"$FIREWALL_LOG"
        fi
    done
    >"$BLOCKED_IPS_FILE"
    >"$FIREWALL_LOG"
    >"$ACCESS_LOG"
    >"$LAST_LINE_FILE"
    iptables-save >/etc/iptables/rules.v4
    restore_log_rule
    echo "$(date '+%Y-%m-%d %H:%M:%S') All REJECT IPs released and logs cleared." >>"$FIREWALL_LOG"
}

# Function to release a specific IP
release_ip() {
    local ip="$1"
    if [ -z "$ip" ]; then
        echo "Please provide an IP (e.g., --release-ip 8.8.8.8)"
        exit 1
    fi
    preserve_log_rule
    if iptables -D INPUT -s "$ip" -j REJECT --reject-with icmp-host-prohibited 2>/dev/null; then
        sed -i "/^$ip /d" "$BLOCKED_IPS_FILE"
        iptables-save >/etc/iptables/rules.v4
        echo "$(date '+%Y-%m-%d %H:%M:%S') Released IP: $ip" >>"$FIREWALL_LOG"
    else
        echo "$(date '+%Y-%m-%d %H:%M:%S') IP $ip was not blocked" >>"$FIREWALL_LOG"
    fi
    restore_log_rule
}

# Function to reset the firewall service
# Function to reset the firewall
reset() {
    echo "Resetting Luveedu Firewall..."
    echo "$(date '+%Y-%m-%d %H:%M:%S') Initiating firewall reset..." >>"$FIREWALL_LOG"

    # Clear logs and reset data
    echo "$(date '+%Y-%m-%d %H:%M:%S') Clearing logs and resetting data..." >>"$FIREWALL_LOG"
    >"$FIREWALL_LOG"
    >"$ACCESS_LOG"
    >"$BLOCKED_IPS_FILE"
    >"$LAST_LINE_FILE"

    # Restart OpenLiteSpeed
    systemctl restart lsws 2>/dev/null && echo "Restarted OpenLiteSpeed Webserver" || echo "Failed to restart OpenLiteSpeed"

    # Reset iptables (preserve DROP rules, remove REJECT rules)
    preserve_log_rule
    iptables -S INPUT | awk '/-s/ && /REJECT/ {for(i=1;i<=NF;i++) if($i=="-s") print $(i+1)}' | while read -r source; do
        iptables -D INPUT -s "$source" -j REJECT --reject-with icmp-host-prohibited 2>/dev/null
    done
    iptables-save >/etc/iptables/rules.v4
    restore_log_rule
    echo "$(date '+%Y-%m-%d %H:%M:%S') iptables reset complete (REJECT rules removed)" >>"$FIREWALL_LOG"

    # Restart the firewall by calling start
    echo "$(date '+%Y-%m-%d %H:%M:%S') Restarting firewall..." >>"$FIREWALL_LOG"
    systemctl restart luvd-firewall
    echo "Luveedu Firewall reset and restarted successfully."
}

# Function to display blocked IP list
blocked_list() {
    echo "Luveedu Firewall - Blocked IP List"
    if [ -s "$BLOCKED_IPS_FILE" ]; then
        echo "IP Address        Blocked Since"
        echo "------------------  -------------------"
        while read -r ip timestamp; do
            blocked_time=$(date -d "@$timestamp" '+%Y-%m-%d %H:%M:%S')
            printf "%-18s  %s\n" "$ip" "$blocked_time"
        done <"$BLOCKED_IPS_FILE"
    else
        echo "No IPs are currently blocked."
    fi
}

# Function to clear logs
clear_logs() {
    preserve_log_rule
    >"$FIREWALL_LOG"
    >"$ACCESS_LOG"
    >"$LAST_LINE_FILE"
    restore_log_rule
    echo "All Firewall Logs Cleared"
}

# Function to fix log formats
fix_logs() {
    if [ "$1" = "--domains" ]; then
        echo "Scanning domains in /home..."
        declare -A domain_map
        local domain_list=()
        local index=1
        for dir in /home/*; do
            if [ -d "$dir" ]; then
                local basename=$(basename "$dir")
                if [[ "$basename" =~ \. ]]; then
                    domain_list+=("$basename")
                    domain_map[$index]="$basename"
                    echo "$index. $basename"
                    ((index++))
                fi
            fi
        done
        if [ ${#domain_list[@]} -eq 0 ]; then
            echo "No domains found in /home"
            exit 1
        fi
        echo -n "> "
        read selection
        if ! [[ "$selection" =~ ^[0-9]+$ ]] || [ "$selection" -lt 1 ] || [ "$selection" -ge "$index" ]; then
            echo "Invalid selection."
            exit 1
        fi
        local selected_domain="${domain_map[$selection]}"
        local conf="/usr/local/lsws/conf/vhosts/$selected_domain/vhost.conf"
        if [ -f "$conf" ]; then
            sudo cp "$conf" "$conf.bak.$(date +%F_%T)"
            sudo sed -i '/accesslog .* {/,/}/d' "$conf"
            echo -e "accesslog $ACCESS_LOG {\n  useServer               1\n  logFormat               \"$DESIRED_LOG_FORMAT\"\n  logHeaders              7\n  keepDays                7\n  compressArchive         0\n}" | sudo tee -a "$conf" >/dev/null
            sudo systemctl reload lsws
            echo "Log format updated for $selected_domain"
        else
            echo "Error: Vhost config not found for $selected_domain"
            exit 1
        fi
    else
        echo "Updating all vhost configurations..."
        local changed=0
        for conf in $VH_CONF_PATTERN; do
            if [ -f "$conf" ]; then
                sudo cp "$conf" "$conf.bak.$(date +%F_%T)"
                sudo sed -i '/accesslog .* {/,/}/d' "$conf"
                echo -e "accesslog $ACCESS_LOG {\n  useServer               1\n  logFormat               \"$DESIRED_LOG_FORMAT\"\n  logHeaders              7\n  keepDays                7\n  compressArchive         0\n}" | sudo tee -a "$conf" >/dev/null
                changed=1
            fi
        done
        if [ $changed -eq 1 ]; then
            sudo systemctl reload lsws
            echo "Log formats updated in all vhosts."
        else
            echo "No vhost configurations found."
        fi
    fi
}

# Function to check request URL for malicious patterns
check_url() {
    local line="$1"
    local ip="$2"
    
    # Extract the request field (e.g., "GET /?=tgXycUSu HTTP/1.1")
    local request=$(echo "$line" | awk -F'"' '{print $2}')
    
    # Debug logging
    echo "$(date '+%Y-%m-%d %H:%M:%S') Checking request: $request for IP: $ip" >>"$FIREWALL_LOG"
    
    # Check for /?= pattern
    if [[ "$request" =~ /\?= ]]; then
        block_ip "$ip" "malicious-url" "URL: $request"
        echo "$(date '+%Y-%m-%d %H:%M:%S') Blocked IP $ip due to URL match: $request (Pattern: /\?=)" >>"$FIREWALL_LOG"
        return 0
    fi
    
    return 1
}

# Function to check User-Agent and Referrer against regex patterns
check_ua_referrer() {
    local line="$1"
    local ip="$2"
    
    # Extract fields by quotes
    local ua=$(echo "$line" | awk -F'"' '{print $(NF-1)}')
    local referrer=$(echo "$line" | awk -F'"' '{if (NF >= 5) print $(NF-3); else print ""}' | grep -v "^-")
    
    # Debug logging for every line
    echo "$(date '+%Y-%m-%d %H:%M:%S') Checking UA: $ua | Referrer: $referrer for IP: $ip" >>"$FIREWALL_LOG"
    
    # Check User-Agent
    for pattern in "${MALICIOUS_UA_REGEX[@]}"; do
        if [[ "$ua" =~ $pattern ]]; then
            block_ip "$ip" "malicious-user-agent" "UA: $ua"
            echo "$(date '+%Y-%m-%d %H:%M:%S') Blocked IP $ip due to User-Agent match: $ua (Pattern: $pattern)" >>"$FIREWALL_LOG"
            return 0
        fi
    done
    
    # Check Referrer
    if [ -n "$referrer" ]; then
        for pattern in "${MALICIOUS_REF_REGEX[@]}"; do
            echo "$(date '+%Y-%m-%d %H:%M:%S') Testing referrer $referrer against pattern $pattern" >>"$FIREWALL_LOG"
            if [[ "$referrer" =~ $pattern ]]; then
                block_ip "$ip" "malicious-referrer" "Ref: $referrer"
                echo "$(date '+%Y-%m-%d %H:%M:%S') Blocked IP $ip due to Referrer match: $referrer (Pattern: $pattern)" >>"$FIREWALL_LOG"
                return 0
            fi
        done
    fi
    
    return 1
}


# Function to check logs (unchanged)
check_logs() {
    echo "Luveedu Firewall - DoS / DDoS Blocking (Realtime)"
    echo "------------------------------------------------------------"
    echo "IP Address        | Requests/${WINDOW_DURATION}s | Requests/${SEC_WINDOW_DURATION}s | Status"
    echo "------------------------------------------------------------"

    declare -A ip_status
    declare -A ip_win_count
    declare -A ip_sec_count
    local last_win_reset=$(date +%s)
    local last_sec_reset=$(date +%s)

    tail -f -n 500 "$FIREWALL_LOG" | while read -r line; do
        local now=$(date +%s)
        local cutoff=$(date -d "-$WINDOW_DURATION seconds" '+%s')
        local sec_cutoff=$(date -d "-$SEC_WINDOW_DURATION seconds" '+%s')

        if [ $((now - last_win_reset)) -ge 30 ]; then
            for ip in "${!ip_win_count[@]}"; do
                if [[ "${ip_status[$ip]}" != Blocked* ]]; then
                    ip_win_count[$ip]=0
                fi
            done
            last_win_reset=$now
            echo "$(date '+%Y-%m-%d %H:%M:%S') Reset Requests/30s counters" >>"$FIREWALL_LOG"
        fi

        if [ $((now - last_sec_reset)) -ge $((SEC_WINDOW_DURATION + 1)) ]; then
            for ip in "${!ip_sec_count[@]}"; do
                if [[ "${ip_status[$ip]}" != Blocked* ]]; then
                    ip_sec_count[$ip]=0
                fi
            done
            last_sec_reset=$now
            echo "$(date '+%Y-%m-%d %H:%M:%S') Reset Requests/${SEC_WINDOW_DURATION}s counters" >>"$FIREWALL_LOG"
        fi

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
            ip=$(echo "$line" | grep -oE 'Rejected IP: [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | cut -d' ' -f3)
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
                    if grep -q "^$ip " "$BLOCKED_IPS_FILE"; then
                        ip_status[$ip]="Blocked"
                        ip_win_count[$ip]="-"
                        ip_sec_count[$ip]="-"
                    elif [[ -z "${ip_status[$ip]}" || "${ip_status[$ip]}" != Blocked* ]]; then
                        if in_list "$ip" "WHITELIST"; then
                            ip_status[$ip]="Whitelisted"
                        else
                            ip_status[$ip]="Processing"
                        fi
                        if [ "$ts_seconds" -ge "$cutoff" ]; then
                            ip_win_count[$ip]=$((${ip_win_count[$ip]:-0} + 1))
                        fi
                        if [ "$ts_seconds" -ge "$sec_cutoff" ]; then
                            ip_sec_count[$ip]=$((${ip_sec_count[$ip]:-0} + 1))
                        fi
                    fi
                fi
            fi
        fi

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

# Function to rotate logs every minute
rotate_logs() {
    local now=$(date +%s)
    local last_rotation_file="/var/tmp/luvd-firewall-last-rotation.txt"
    local last_rotation=0

    [ -f "$last_rotation_file" ] && last_rotation=$(cat "$last_rotation_file") || echo "$now" >"$last_rotation_file"

    if [ $((now - last_rotation)) -ge 60 ]; then
        echo "$(date '+%Y-%m-%d %H:%M:%S') Initiating log rotation..." >>"$FIREWALL_LOG"
        clear_logs
        sleep 2
        echo "$now" >"$last_rotation_file"
        echo "$(date '+%Y-%m-%d %H:%M:%S') Log rotation completed" >>"$FIREWALL_LOG"
    fi
}


# Replace the existing monitor_3s_requests function with this:
monitor_3s_requests() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') Started 3s monitoring (PID: $$)" >>"$FIREWALL_LOG"
    trap 'echo "$(date "+%Y-%m-%d %H:%M:%S") 3s monitoring terminated (PID: $$)" >> "$FIREWALL_LOG"; exit' SIGTERM SIGINT

    local last_lines_processed=0
    [ -s "$LAST_LINE_FILE" ] && last_lines_processed=$(cat "$LAST_LINE_FILE")

    declare -A ip_counts
    declare -A ip_timestamps

    while [ -f "$PID_FILE" ]; do
        if [ -f "$ACCESS_LOG" ] && [ -r "$ACCESS_LOG" ]; then
            local cutoff=$(date -d "-$SEC_WINDOW_DURATION seconds" '+%s')
            local total_lines=$(wc -l <"$ACCESS_LOG")
            local lines_to_process=$((total_lines - last_lines_processed))

            if [ "$lines_to_process" -gt 0 ]; then
                tail -n "$lines_to_process" "$ACCESS_LOG" | while IFS= read -r line; do
                    main_ip=$(get_ips "$line")
                    if [ -n "$main_ip" ] && [[ "$main_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && ! grep -q "^$main_ip " "$BLOCKED_IPS_FILE"; then
                        # Check User-Agent and Referrer first
                        if check_ua_referrer "$line" "$main_ip"; then
                            continue  # Skip to next line if blocked
                        fi
                        # Check URL pattern
                        if check_url "$line" "$main_ip"; then
                            continue  # Skip to next line if blocked
                        fi
                        
                        timestamp=$(echo "$line" | grep -oP '\[\K\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4}')
                        if [ -n "$timestamp" ]; then
                            ts_reformat=$(echo "$timestamp" | sed 's|/| |g; s/:/ /; s/ \([+-]\)/ \1/')
                            ts_seconds=$(date -d "$ts_reformat" +%s 2>/dev/null)
                            if [ -n "$ts_seconds" ] && [ "$ts_seconds" -ge "$cutoff" ]; then
                                if ! in_list "$main_ip" "WHITELIST"; then
                                    ip_counts["$main_ip"]=$((${ip_counts[$main_ip]:-0} + 1))
                                    ip_timestamps["$main_ip,$ts_seconds"]=1
                                    echo "$(date '+%Y-%m-%d %H:%M:%S') Request logged for IP $main_ip | 3s count: ${ip_counts[$main_ip]}" >>"$FIREWALL_LOG"
                                    if [ "${ip_counts[$main_ip]}" -gt "$REQUEST_LIMIT_PER_SEC" ]; then
                                        block_ip "$main_ip" "rate-limit-3s" "${ip_counts[$main_ip]} req/3s"
                                        unset ip_counts["$main_ip"]
                                        unset ip_timestamps["$main_ip,"*]
                                    fi
                                fi
                            fi
                        fi
                    fi
                done
                last_lines_processed=$total_lines
                echo "$last_lines_processed" >"$LAST_LINE_FILE"
            fi

            for key in "${!ip_timestamps[@]}"; do
                IFS=',' read -r ip ts <<<"$key"
                if [ "$ts" -lt "$cutoff" ]; then
                    ip_counts["$ip"]=$((ip_counts["$ip"] - 1))
                    [ "${ip_counts[$ip]}" -le 0 ] && unset ip_counts["$ip"]
                    unset ip_timestamps["$key"]
                fi
            done
        fi
        unblock_expired
        block_blacklist
        sleep "$CHECK_INTERVAL"
    done
}


# Replace the existing monitor_30s_requests function with this:
monitor_30s_requests() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') Started 30s monitoring (PID: $$)" >>"$FIREWALL_LOG"
    trap 'echo "$(date "+%Y-%m-%d %H:%M:%S") 30s monitoring terminated (PID: $$)" >> "$FIREWALL_LOG"; exit' SIGTERM SIGINT

    local last_lines_processed=0
    [ -s "$LAST_LINE_FILE" ] && last_lines_processed=$(cat "$LAST_LINE_FILE")

    declare -A ip_counts
    declare -A ip_timestamps

    while [ -f "$PID_FILE" ]; do
        if [ -f "$ACCESS_LOG" ] && [ -r "$ACCESS_LOG" ]; then
            local cutoff=$(date -d "-$WINDOW_DURATION seconds" '+%s')
            local total_lines=$(wc -l <"$ACCESS_LOG")
            local lines_to_process=$((total_lines - last_lines_processed))

            if [ "$lines_to_process" -gt 0 ]; then
                tail -n "$lines_to_process" "$ACCESS_LOG" | while IFS= read -r line; do
                    main_ip=$(get_ips "$line")
                    if [ -n "$main_ip" ] && [[ "$main_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && ! grep -q "^$main_ip " "$BLOCKED_IPS_FILE"; then
                        # Check User-Agent and Referrer first
                        if check_ua_referrer "$line" "$main_ip"; then
                            continue  # Skip to next line if blocked
                        fi
                        # Check URL pattern
                        if check_url "$line" "$main_ip"; then
                            continue  # Skip to next line if blocked
                        fi
                        
                        timestamp=$(echo "$line" | grep -oP '\[\K\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4}')
                        if [ -n "$timestamp" ]; then
                            ts_reformat=$(echo "$timestamp" | sed 's|/| |g; s/:/ /; s/ \([+-]\)/ \1/')
                            ts_seconds=$(date -d "$ts_reformat" +%s 2>/dev/null)
                            if [ -n "$ts_seconds" ] && [ "$ts_seconds" -ge "$cutoff" ]; then
                                if ! in_list "$main_ip" "WHITELIST"; then
                                    ip_counts["$main_ip"]=$((${ip_counts[$main_ip]:-0} + 1))
                                    ip_timestamps["$main_ip,$ts_seconds"]=1
                                    echo "$(date '+%Y-%m-%d %H:%M:%S') Request logged for IP $main_ip | 30s count: ${ip_counts[$main_ip]}" >>"$FIREWALL_LOG"
                                    if [ "${ip_counts[$main_ip]}" -gt "$REQUEST_LIMIT_PER_WINDOW" ]; then
                                        block_ip "$main_ip" "rate-limit-30s" "${ip_counts[$main_ip]} req/30s"
                                        unset ip_counts["$main_ip"]
                                        unset ip_timestamps["$main_ip,"*]
                                    fi
                                fi
                            fi
                        fi
                    fi
                done
                last_lines_processed=$total_lines
                echo "$last_lines_processed" >"$LAST_LINE_FILE"
            fi

            for key in "${!ip_timestamps[@]}"; do
                IFS=',' read -r ip ts <<<"$key"
                if [ "$ts" -lt "$cutoff" ]; then
                    ip_counts["$ip"]=$((ip_counts["$ip"] - 1))
                    [ "${ip_counts[$ip]}" -le 0 ] && unset ip_counts["$ip"]
                    unset ip_timestamps["$key"]
                fi
            done
        fi
        unblock_expired
        block_blacklist
        sleep "$CHECK_INTERVAL"
    done
}



# Start the firewall with both monitors
start() {
    if [ -f "$PID_FILE" ]; then
        echo "Luveedu Firewall is already running (PID: $(cat $PID_FILE))"
        exit 1
    fi
    if [ -s "/etc/iptables/rules.v4" ]; then
        iptables-restore </etc/iptables/rules.v4
    fi
    monitor_3s_requests &>>"$FIREWALL_LOG" &
    local pid_3s=$!
    monitor_30s_requests &>>"$FIREWALL_LOG" &
    local pid_30s=$!
    echo "$pid_3s" >"$PID_FILE" # Store 3s PID as primary
    echo "$(date '+%Y-%m-%d %H:%M:%S') Started firewall with 3s PID: $pid_3s, 30s PID: $pid_30s" >>"$FIREWALL_LOG"
    echo "Luveedu Firewall started (3s PID: $pid_3s, 30s PID: $pid_30s)"
}

# Stop the firewall
stop() {
    if [ -f "$PID_FILE" ]; then
        local pid=$(cat "$PID_FILE")
        echo "$(date '+%Y-%m-%d %H:%M:%S') Stopping Luveedu Firewall (PID: $pid)..." >>"$FIREWALL_LOG"
        kill -TERM "$pid" 2>/dev/null
        # Kill all instances of the script
        pkill -f "bash .*luvd-firewall" 2>/dev/null
        rm -f "$PID_FILE"
        local attempts=0
        while kill -0 "$pid" 2>/dev/null && [ $attempts -lt 5 ]; do
            sleep 1
            ((attempts++))
        done
        if kill -0 "$pid" 2>/dev/null; then
            kill -9 "$pid" 2>/dev/null
        fi
        echo "Luveedu Firewall stopped"
    else
        echo "Luveedu Firewall is not running"
        exit 1
    fi
}

# Function to update the script (unchanged)
update() {
    local script_path="/usr/local/bin/luvd-firewall"
    local github_url="https://raw.githubusercontent.com/Luveedu/Luveedu-Firewall/refs/heads/main/luvd-firewall.sh"
    local temp_file="/tmp/luvd-firewall-update.sh"

    echo "Updating Luveedu Firewall from GitHub..."
    if curl -s --max-time 10 "$github_url" -o "$temp_file" 2>/dev/null && [ -s "$temp_file" ] && head -n 1 "$temp_file" | grep -q '^#!/bin/bash'; then
        cp "$script_path" "$script_path.bak.$(date +%F_%T)"
        sed -i 's/\r$//' "$temp_file"
        chmod +x "$temp_file"
        mv "$temp_file" "$script_path"
        echo "$(date '+%Y-%m-%d %H:%M:%S') Successfully updated script" >>"$FIREWALL_LOG"
        reset
        echo "Update and reset completed."
    else
        echo "Error: Update failed"
        rm -f "$temp_file"
        exit 1
    fi
}

# CLI handling
case "$1" in
--start) start ;;
--stop) stop ;;
--fix-logs)
    if [ "$2" = "--domains" ]; then
        fix_logs "--domains"
    else
        fix_logs
    fi
    ;;
--release-all) release_all ;;
--release-ip) release_ip "$2" ;;
--check-logs) check_logs ;;
--check-ip) check_ip "$2" ;;
--blocked-list) blocked_list ;;
--clear-logs) clear_logs ;;
--reset) reset ;;
--update) update ;;
*)
    echo "Usage: luvd-firewall [OPTION] [ARGUMENT]"
    echo " --start              - Start the Firewall"
    echo " --stop               - Stop the Firewall"
    echo " --check-logs         - Monitor Rate Limiting Stats"
    echo " --blocked-list       - Check Blocked IPs"
    echo " --fix-logs           - Fix vHosts logging"
    echo " --fix-logs --domains - Fix logs for a specific domain"
    echo " --reset              - Reset the Firewall"
    echo " --update             - Update from Github"
    echo " --release-all       - Unblock all IPs"
    echo " --release-ip 8.8.8.8 - Unblock a specific IP"
    echo " --check-ip 8.8.8.8   - Check IP status"
    echo " --clear-logs         - Clear logs"
    exit 1
    ;;
esac
