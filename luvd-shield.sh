#!/bin/bash
#===============================================================================
# Luveedu Shield - Advanced Kernel-Level Threat Protection
# File: /usr/local/bin/luvd-shield
# Version: 2.0.0 (Complete Rewrite)
# Description: Real-time kernel log monitoring for DDoS, port scans, and 
#              connection-based attacks with iptables integration
#===============================================================================

set -euo pipefail

#-------------------------------------------------------------------------------
# Configuration
#-------------------------------------------------------------------------------
readonly VERSION="2.0.0"
readonly SCRIPT_NAME="luvd-shield"
readonly PID_FILE="/var/run/luvd-shield.pid"
readonly BLOCKED_IPS_FILE="/var/tmp/luvd-shield-blocked-ips.txt"
readonly SHIELD_LOG="/var/log/luvd-shield.log"
readonly IPTABLES_RULES="/etc/iptables/rules.v4"
readonly STATE_DIR="/var/lib/luvd-shield"
readonly LOCK_FILE="/var/lock/luvd-shield.lock"

# Timing
readonly BLOCK_DURATION="${BLOCK_DURATION:-604800}"  # 7 days
readonly CHECK_INTERVAL="${CHECK_INTERVAL:-1}"
readonly ROTATION_INTERVAL="${ROTATION_INTERVAL:-600}"

# API
readonly CHECK_API="${WAF_API:-https://waf.luveedu.cloud/checkip.php?ip=}"
readonly API_TIMEOUT="${API_TIMEOUT:-3}"
readonly API_CACHE_TTL="${API_CACHE_TTL:-300}"

# Under attack mode
UNDER_ATTACK_MODE=0

# Server IP
SERVER_IP=""

#-------------------------------------------------------------------------------
# Initialization
#-------------------------------------------------------------------------------
init() {
    mkdir -p "$STATE_DIR" "$(dirname "$BLOCKED_IPS_FILE")" "$(dirname "$SHIELD_LOG")" /etc/iptables
    touch "$BLOCKED_IPS_FILE" "$SHIELD_LOG"
    exec 200>"$LOCK_FILE"
    
    # Detect server IP
    SERVER_IP=$(curl -s --max-time 5 https://ipv4.icanhazip.com/ 2>/dev/null || \
                ip route get 1 | awk '{print $7; exit}' || \
                hostname -I | awk '{print $1}')
    
    log INFO "Shield initialized (Server IP: $SERVER_IP, PID: $$)"
}

#-------------------------------------------------------------------------------
# Logging
#-------------------------------------------------------------------------------
log() {
    local level="$1"; shift
    local msg="$*"
    local ts=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$ts] [$level] $msg" >> "$SHIELD_LOG"
    logger -t "$SCRIPT_NAME" "$msg" 2>/dev/null || true
    [ -t 1 ] && echo "[$ts] [$level] $msg"
}

log_info() { log INFO "$@"; }
log_warning() { log WARNING "$@"; }
log_error() { log ERROR "$@"; }

#-------------------------------------------------------------------------------
# API Integration
#-------------------------------------------------------------------------------
declare -A API_CACHE
declare -A API_CACHE_TIME

check_api() {
    local ip="$1"
    local now=$(date +%s)
    local cache_key="$ip"
    
    # Check cache
    if [ -n "${API_CACHE[$cache_key]:-}" ]; then
        local age=$((now - ${API_CACHE_TIME[$cache_key]:-0}))
        [ "$age" -lt "$API_CACHE_TTL" ] && { echo "${API_CACHE[$cache_key]}"; return 0; }
    fi
    
    # Query API
    local response
    response=$(curl -s --max-time "$API_TIMEOUT" "${CHECK_API}${ip}" 2>/dev/null) || response="ERROR"
    
    # Cache result
    API_CACHE[$cache_key]="$response"
    API_CACHE_TIME[$cache_key]=$now
    
    echo "$response"
}

is_blacklisted() {
    [ "$(check_api "$1")" = "BLACKLIST" ]
}

is_whitelisted() {
    [ "$(check_api "$1")" = "WHITELIST" ]
}

#-------------------------------------------------------------------------------
# IP Blocking
#-------------------------------------------------------------------------------
block_ip() {
    local ip="$1"
    local reason="${2:-shield}"
    
    [ -z "$ip" ] && return 1
    [ "$ip" = "$SERVER_IP" ] || [ "$ip" = "127.0.0.1" ] && return 0
    grep -q "^$ip " "$BLOCKED_IPS_FILE" 2>/dev/null && return 0
    grep -q "^$ip " /var/tmp/luvd-blocked-ips.txt 2>/dev/null && return 0
    
    # Block with iptables
    if ! iptables -C INPUT -s "$ip" -j DROP 2>/dev/null; then
        iptables -A INPUT -s "$ip" -j DROP
        log_info "Blocked IP: $ip | Reason: $reason"
    fi
    
    # Add to ipset if available
    if command -v ipset &>/dev/null; then
        ipset add luveedu_blocked "$ip" timeout "$BLOCK_DURATION" 2>/dev/null || true
    fi
    
    # Record
    echo "$ip $(date +%s) $reason" >> "$BLOCKED_IPS_FILE"
    
    # Persist
    save_rules
    
    return 0
}

unblock_ip() {
    local ip="$1"
    
    iptables -D INPUT -s "$ip" -j DROP 2>/dev/null || true
    command -v ipset &>/dev/null && ipset del luveedu_blocked "$ip" 2>/dev/null || true
    sed -i "/^$ip /d" "$BLOCKED_IPS_FILE"
    save_rules
    
    log_info "Unblocked IP: $ip"
}

unblock_expired() {
    local now=$(date +%s)
    while read -r ip timestamp reason; do
        [ -z "$ip" ] && continue
        [[ "$timestamp" =~ ^[0-9]+$ ]] || continue
        [ $((now - timestamp)) -ge "$BLOCK_DURATION" ] && unblock_ip "$ip"
    done < "$BLOCKED_IPS_FILE"
}

save_rules() {
    iptables-save > "$IPTABLES_RULES" 2>/dev/null || true
}

#-------------------------------------------------------------------------------
# Kernel Log Monitoring
#-------------------------------------------------------------------------------
find_log_file() {
    for log in /var/log/syslog /var/log/messages /var/log/kern.log; do
        [ -f "$log" ] && [ -r "$log" ] && { echo "$log"; return 0; }
    done
    return 1
}

extract_ip_from_log() {
    local line="$1"
    local ip=""
    
    # Extract from SRC= field (iptables log format)
    if [[ "$line" =~ SRC=([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+) ]]; then
        ip="${BASH_REMATCH[1]}"
    elif [[ "$line" =~ SRC=([0-9a-fA-F:]+) ]]; then
        ip="${BASH_REMATCH[1]}"
    fi
    
    # Validate
    if [ -n "$ip" ] && [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ || "$ip" =~ : ]]; then
        echo "$ip"
    fi
}

detect_attack_patterns() {
    local line="$1"
    local ip="$2"
    
    # Port scan detection
    if [[ "$line" =~ (SYN|XMAS|NULL|FIN) ]] || [[ "$line" =~ DPT=[0-9]+.*DPT=[0-9]+ ]]; then
        log_warning "Port scan detected from $ip"
        block_ip "$ip" "port-scan"
        return 0
    fi
    
    # Connection flood detection
    if [[ "$line" =~ (CONNLIMIT|RATELIMIT) ]]; then
        log_warning "Connection flood from $ip"
        block_ip "$ip" "conn-flood"
        return 0
    fi
    
    # Invalid packet detection
    if [[ "$line" =~ (INVALID|BAD|MALFORMED) ]]; then
        log_warning "Invalid packets from $ip"
        block_ip "$ip" "invalid-packets"
        return 0
    fi
    
    return 1
}

monitor_kernel_logs() {
    local log_file="$1"
    log_info "Monitoring kernel log: $log_file (PID: $$)"
    
    trap 'log_info "Monitor stopped"; exit 0' SIGTERM SIGINT
    
    local last_clean=0
    local last_pos=0
    
    # Use tail -F for log rotation handling
    tail -n 0 -F "$log_file" 2>/dev/null | while IFS= read -r line; do
        local now=$(date +%s)
        
        # Periodic cleanup
        if [ $((now - last_clean)) -ge 60 ]; then
            unblock_expired
            last_clean=$now
        fi
        
        # Only process LUVEEDU-SHIELD logged packets or new connections
        if [[ "$line" =~ LUVEEDU-SHIELD ]] || [[ "$line" =~ NEW.*IN= ]]; then
            local ip=$(extract_ip_from_log "$line")
            
            [ -z "$ip" ] && continue
            [ "$ip" = "$SERVER_IP" ] || [ "$ip" = "127.0.0.1" ] && continue
            
            # Under attack mode - block everything
            if [ "$UNDER_ATTACK_MODE" -eq 1 ]; then
                is_whitelisted "$ip" || grep -q "^$ip " "$BLOCKED_IPS_FILE" 2>/dev/null || block_ip "$ip" "under-attack"
                continue
            fi
            
            # Skip already blocked
            grep -q "^$ip " "$BLOCKED_IPS_FILE" 2>/dev/null && continue
            
            # Check attack patterns
            detect_attack_patterns "$line" "$ip" && continue
            
            # Check API blacklist
            if is_blacklisted "$ip"; then
                block_ip "$ip" "api-blacklist"
            fi
        fi
    done
}

#-------------------------------------------------------------------------------
# Service Management
#-------------------------------------------------------------------------------
start_service() {
    if [ -f "$PID_FILE" ] && kill -0 "$(cat $PID_FILE)" 2>/dev/null; then
        echo "Shield already running (PID: $(cat $PID_FILE))"
        exit 1
    fi
    rm -f "$PID_FILE"
    
    init
    
    # Restore rules
    [ -f "$IPTABLES_RULES" ] && iptables-restore < "$IPTABLES_RULES" 2>/dev/null || true
    
    # Ensure LOG rule exists
    iptables -C INPUT -m state --state NEW -j LOG --log-prefix "LUVEEDU-SHIELD: " 2>/dev/null || \
        iptables -A INPUT -m state --state NEW -j LOG --log-prefix "LUVEEDU-SHIELD: "
    
    save_rules
    
    # Find log file
    local log_file
    log_file=$(find_log_file) || { log_error "No kernel log found"; exit 1; }
    
    # Start monitor
    nohup bash -c "$(declare -f); monitor_kernel_logs '$log_file'" >> "$SHIELD_LOG" 2>&1 &
    local pid=$!
    
    echo "$pid" > "$PID_FILE"
    log_info "Started (PID: $pid, Log: $log_file)"
    echo "Luveedu Shield started (PID: $pid)"
}

stop_service() {
    if [ ! -f "$PID_FILE" ]; then
        echo "Shield not running"
        exit 1
    fi
    
    local pid=$(cat "$PID_FILE")
    kill -TERM "$pid" 2>/dev/null || true
    sleep 2
    kill -9 "$pid" 2>/dev/null || true
    pkill -f "luvd-shield.*monitor" 2>/dev/null || true
    
    rm -f "$PID_FILE"
    log_info "Stopped"
    echo "Stopped"
}

restart_service() {
    stop_service 2>/dev/null || true
    sleep 2
    start_service
}

#-------------------------------------------------------------------------------
# CLI Commands
#-------------------------------------------------------------------------------
show_status() {
    echo "=== Luveedu Shield Status ==="
    [ -f "$PID_FILE" ] && kill -0 "$(cat $PID_FILE)" 2>/dev/null && echo "Status: Running" || echo "Status: Stopped"
    echo "Server IP: $SERVER_IP"
    echo "Blocked IPs: $(wc -l < "$BLOCKED_IPS_FILE" 2>/dev/null || echo 0)"
    echo ""
    echo "Recent blocks:"
    tail -n 5 "$BLOCKED_IPS_FILE" 2>/dev/null | awk '{print "  "$1" - "$3}'
}

show_blocked() {
    echo "=== Blocked IPs ==="
    [ ! -s "$BLOCKED_IPS_FILE" ] && { echo "None"; return; }
    printf "%-20s %-20s %s\n" "IP" "Time" "Reason"
    while read -r ip ts reason; do
        [ -n "$ip" ] && printf "%-20s %-20s %s\n" "$ip" "$(date -d @$ts '+%Y-%m-%d %H:%M')" "${reason:-N/A}"
    done < "$BLOCKED_IPS_FILE"
}

release_all() {
    while read -r ip rest; do
        [ -n "$ip" ] && unblock_ip "$ip"
    done < "$BLOCKED_IPS_FILE"
    > "$BLOCKED_IPS_FILE"
    save_rules
    echo "All released"
}

check_ip() {
    local ip="$1"
    [ -z "$ip" ] && { echo "Usage: --check-ip <IP>"; exit 1; }
    
    echo "IP: $ip"
    grep -q "^$ip " "$BLOCKED_IPS_FILE" && echo "  Local: BLOCKED" || echo "  Local: Not blocked"
    is_blacklisted "$ip" && echo "  API: BLACKLISTED"
    is_whitelisted "$ip" && echo "  API: WHITELISTED"
}

enable_under_attack() {
    case "$1" in
        on|1)
            UNDER_ATTACK_MODE=1
            log_warning "Under Attack Mode ENABLED"
            echo "Under Attack Mode: ON"
            ;;
        off|0)
            UNDER_ATTACK_MODE=0
            log_info "Under Attack Mode DISABLED"
            echo "Under Attack Mode: OFF"
            ;;
        *)
            echo "Mode: $([ $UNDER_ATTACK_MODE -eq 1 ] && echo ON || echo OFF)"
            ;;
    esac
}

fix_iptables() {
    echo "Fixing iptables rules..."
    
    # Add LOG rule
    iptables -C INPUT -m state --state NEW -j LOG --log-prefix "LUVEEDU-SHIELD: " 2>/dev/null || \
        iptables -A INPUT -m state --state NEW -j LOG --log-prefix "LUVEEDU-SHIELD: "
    
    save_rules
    log_info "iptables rules fixed"
    echo "Fixed"
}

update_script() {
    local url="https://raw.githubusercontent.com/Luveedu/Luveedu-Firewall/main/luvd-shield.sh"
    echo "Updating..."
    
    if curl -s --max-time 10 "$url" -o /tmp/luvd-shield.new && [ -s /tmp/luvd-shield.new ]; then
        cp /usr/local/bin/luvd-shield /usr/local/bin/luvd-shield.bak.$(date +%F)
        mv /tmp/luvd-shield.new /usr/local/bin/luvd-shield
        chmod +x /usr/local/bin/luvd-shield
        restart_service
        echo "Updated"
    else
        echo "Update failed"
        exit 1
    fi
}

reset_shield() {
    echo "Resetting Shield..."
    stop_service 2>/dev/null || true
    
    > "$BLOCKED_IPS_FILE"
    > "$SHIELD_LOG"
    
    # Remove all shield DROP rules
    iptables -S INPUT | grep "DROP" | grep -v "LUVEEDU" | while read -r rule; do
        local ip=$(echo "$rule" | grep -oP '(?<=-s )\S+')
        [ -n "$ip" ] && iptables -D INPUT -s "$ip" -j DROP 2>/dev/null
    done
    
    save_rules
    start_service
    echo "Reset complete"
}

show_help() {
    cat << EOF
Luveedu Shield v$VERSION - Kernel-Level Protection

Usage: luvd-shield [OPTION]

Service:
  --start       Start shield
  --stop        Stop shield
  --restart     Restart shield
  --status      Show status

IP Management:
  --blocked-list    List blocked IPs
  --release-ip IP   Unblock specific IP
  --release-all     Unblock all
  --check-ip IP     Check IP status

Security:
  --under-attack on|off  Enable attack mode

Maintenance:
  --fix-all       Fix iptables rules
  --update        Update script
  --reset         Reset everything
  --help          Show this help

EOF
}

#-------------------------------------------------------------------------------
# Main
#-------------------------------------------------------------------------------
[ "$EUID" -ne 0 ] && { echo "Run as root"; exit 1; }

case "${1:-}" in
    --start) start_service ;;
    --stop) stop_service ;;
    --restart) restart_service ;;
    --status) show_status ;;
    --blocked-list) show_blocked ;;
    --release-ip) release_all; [ -n "$2" ] && unblock_ip "$2" ;;
    --release-all) release_all ;;
    --check-ip) check_ip "$2" ;;
    --under-attack) enable_under_attack "$2" ;;
    --fix-all) fix_iptables ;;
    --update) update_script ;;
    --reset) reset_shield ;;
    --help|-h) show_help ;;
    *) show_help; exit 1 ;;
esac
