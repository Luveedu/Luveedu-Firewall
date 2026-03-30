#!/bin/bash
#===============================================================================
# Luveedu Firewall - Professional Grade Web Server Protection Suite
# File: /usr/local/bin/luvd-firewall
# Version: 2.0.0 (Complete Rewrite)
# Description: Advanced DoS/DDoS protection with rate limiting, behavioral 
#              analysis, and real-time threat intelligence
#===============================================================================

set -euo pipefail

#-------------------------------------------------------------------------------
# Configuration & Constants
#-------------------------------------------------------------------------------
readonly VERSION="2.0.0"
readonly SCRIPT_NAME="luvd-firewall"
readonly LOG_FACILITY="local0"

# File paths
readonly ACCESS_LOG="${ACCESS_LOG:-/usr/local/lsws/logs/access.log}"
readonly PID_FILE="/var/run/luvd-firewall.pid"
readonly BLOCKED_IPS_FILE="/var/tmp/luvd-blocked-ips.txt"
readonly FIREWALL_LOG="/var/log/luvd-firewall.log"
readonly STATE_DIR="/var/lib/luvd-firewall"
readonly LOCK_FILE="/var/lock/luvd-firewall.lock"

# Rate limiting configuration
readonly REQUEST_LIMIT_PER_WINDOW="${RATE_LIMIT_WINDOW:-150}"
readonly WINDOW_DURATION="${WINDOW_DURATION:-30}"
readonly REQUEST_LIMIT_PER_SEC="${RATE_LIMIT_BURST:-15}"
readonly SEC_WINDOW_DURATION="${BURST_WINDOW:-3}"
readonly CHECK_INTERVAL="${CHECK_INTERVAL:-1}"

# API configuration
readonly CHECK_API="${WAF_API:-https://waf.luveedu.cloud/checkip.php?ip=}"
readonly API_TIMEOUT="${API_TIMEOUT:-5}"
readonly API_CACHE_TTL="${API_CACHE_TTL:-300}"
readonly API_MAX_FAILURES="${API_MAX_FAILURES:-3}"
readonly API_COOLDOWN="${API_COOLDOWN:-60}"

# Under attack mode
UNDER_ATTACK_MODE=0

# Logging
declare -A LOG_LEVELS=([DEBUG]=7 [INFO]=6 [NOTICE]=5 [WARNING]=4 [ERROR]=3 [CRIT]=2)
CURRENT_LOG_LEVEL=${LOG_LEVEL:-6}

#-------------------------------------------------------------------------------
# Malicious Pattern Detection
#-------------------------------------------------------------------------------
readonly MALICIOUS_UA_REGEX=(
    '.*(bot|crawl|spider|slurp|archiver|curl|wget|python-requests|scrapy|httpclient).*'
    '.*(sqlmap|nikto|burp|owasp|acunetix|netsparker|nuclei).*'
    '.*(masscan|nmap|zmap|fscan).*'
)

readonly SQL_INJECTION_PATTERNS=(
    "union.*select" "select.*from" "insert.*into"
    "update.*set" "delete.*from" "drop.*table"
)

readonly XSS_PATTERNS=(
    "<script[^>]*>" "javascript:" "on(load|error|click)="
)

readonly PATH_TRAVERSAL_PATTERNS=(
    "\.\./\.\." "%2e%2e%2f" "/etc/passwd" "boot\.ini"
)

#-------------------------------------------------------------------------------
# Initialization
#-------------------------------------------------------------------------------
init() {
    mkdir -p "$STATE_DIR" "$(dirname "$BLOCKED_IPS_FILE")" "$(dirname "$FIREWALL_LOG")"
    touch "$BLOCKED_IPS_FILE" "$FIREWALL_LOG"
    exec 200>"$LOCK_FILE"
    
    if command -v ipset &>/dev/null; then
        ipset create luveedu_blocked hash:ip timeout 0 2>/dev/null || true
    fi
    
    log INFO "Firewall initialized (PID: $$)"
}

#-------------------------------------------------------------------------------
# Logging Functions
#-------------------------------------------------------------------------------
log() {
    local level="$1"; shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $message" >> "$FIREWALL_LOG"
    logger -t "$SCRIPT_NAME" "$message" 2>/dev/null || true
    [ -t 1 ] && echo "[$timestamp] [$level] $message"
}

log_info() { log INFO "$@"; }
log_warning() { log WARNING "$@"; }
log_error() { log ERROR "$@"; }

#-------------------------------------------------------------------------------
# IP Extraction & Validation
#-------------------------------------------------------------------------------
extract_ip() {
    local line="$1"
    local ip=""
    
    if [[ "$line" =~ ^\[?([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\]? ]]; then
        ip="${BASH_REMATCH[1]}"
    elif [[ "$line" =~ ^([0-9a-fA-F:]+:[0-9a-fA-F:]+:[0-9a-fA-F:]+:[0-9a-fA-F]+) ]]; then
        ip="${BASH_REMATCH[1]}"
    else
        ip=$(echo "$line" | awk '{print $1}' | tr -d '[]')
    fi
    
    if is_valid_ip "$ip"; then
        echo "$ip"
    fi
}

is_valid_ip() {
    local ip="$1"
    [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || [[ "$ip" =~ ^[0-9a-fA-F:]+$ ]]
}

is_private_ip() {
    local ip="$1"
    [[ "$ip" =~ ^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.|127\.) ]]
}

#-------------------------------------------------------------------------------
# API Integration with Caching
#-------------------------------------------------------------------------------
declare -A API_CACHE
declare -A API_CACHE_TIME
API_FAILURE_COUNT=0

query_api() {
    local ip="$1" list_type="$2"
    local now=$(date +%s)
    local cache_key="${ip}:${list_type}"
    
    # Check cache
    if [ -n "${API_CACHE[$cache_key]:-}" ]; then
        local age=$((now - ${API_CACHE_TIME[$cache_key]:-0}))
        [ "$age" -lt "$API_CACHE_TTL" ] && return $([ "${API_CACHE[$cache_key]}" = "true" ] && echo 0 || echo 1)
    fi
    
    # Circuit breaker
    [ "$API_FAILURE_COUNT" -ge "$API_MAX_FAILURES" ] && return 1
    
    # Make request
    local response
    response=$(curl -s --max-time "$API_TIMEOUT" "${CHECK_API}${ip}" 2>/dev/null) || {
        ((API_FAILURE_COUNT++))
        return 1
    }
    
    API_FAILURE_COUNT=0
    local result=1
    [ "$response" = "$list_type" ] && result=0
    
    API_CACHE[$cache_key]=$([ $result -eq 0 ] && echo "true" || echo "false")
    API_CACHE_TIME[$cache_key]=$now
    return $result
}

in_whitelist() { query_api "$1" "WHITELIST"; }
in_blacklist() { query_api "$1" "BLACKLIST"; }

#-------------------------------------------------------------------------------
# IP Blocking
#-------------------------------------------------------------------------------
block_ip() {
    local ip="$1" reason="${2:-manual}" rate="${3:-N/A}"
    
    [ -z "$ip" ] && return 1
    is_private_ip "$ip" && [ "${BLOCK_PRIVATE:-0}" -ne 1 ] && return 0
    grep -q "^$ip " "$BLOCKED_IPS_FILE" 2>/dev/null && return 0
    
    if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        iptables -C INPUT -s "$ip" -j DROP 2>/dev/null || {
            iptables -A INPUT -s "$ip" -j DROP
            log_info "Blocked IPv4: $ip | Reason: $reason"
        }
    elif [[ "$ip" =~ : ]]; then
        ip6tables -C INPUT -s "$ip" -j DROP 2>/dev/null || {
            ip6tables -A INPUT -s "$ip" -j DROP
            log_info "Blocked IPv6: $ip | Reason: $reason"
        }
    fi
    
    command -v ipset &>/dev/null && ipset add luveedu_blocked "$ip" timeout "$BLOCK_DURATION" 2>/dev/null || true
    echo "$ip $(date +%s) $reason" >> "$BLOCKED_IPS_FILE"
    save_iptables_rules
}

unblock_ip() {
    local ip="$1"
    iptables -D INPUT -s "$ip" -j DROP 2>/dev/null || true
    ip6tables -D INPUT -s "$ip" -j DROP 2>/dev/null || true
    command -v ipset &>/dev/null && ipset del luveedu_blocked "$ip" 2>/dev/null || true
    sed -i "/^$ip /d" "$BLOCKED_IPS_FILE"
    save_iptables_rules
    log_info "Unblocked IP: $ip"
}

unblock_expired() {
    local now=$(date +%s)
    while read -r ip timestamp reason; do
        [ -z "$ip" ] && continue
        [[ "$timestamp" =~ ^[0-9]+$ ]] || continue
        [ $((now - timestamp)) -ge "${BLOCK_DURATION:-86400}" ] && unblock_ip "$ip"
    done < "$BLOCKED_IPS_FILE"
}

save_iptables_rules() {
    mkdir -p /etc/iptables
    iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
}

#-------------------------------------------------------------------------------
# Threat Detection
#-------------------------------------------------------------------------------
detect_threats() {
    local line="$1" ip="$2"
    
    local request=$(echo "$line" | awk -F'"' '{print $2}')
    local ua=$(echo "$line" | awk -F'"' '{print $(NF-1)}')
    local referrer=$(echo "$line" | awk -F'"' '{if (NF >= 5) print $(NF-3); else print "-"}')
    
    # Check User-Agent
    for pattern in "${MALICIOUS_UA_REGEX[@]}"; do
        [[ "$ua" =~ $pattern ]] && { block_ip "$ip" "malicious-ua" "$ua"; return 0; }
    done
    
    # Check URL patterns
    [[ "$request" =~ /\?= ]] && { block_ip "$ip" "suspicious-url" "$request"; return 0; }
    
    # SQL Injection
    for pattern in "${SQL_INJECTION_PATTERNS[@]}"; do
        [[ "$request" =~ $pattern ]] && { block_ip "$ip" "sql-injection" "$request"; return 0; }
    done
    
    # XSS
    for pattern in "${XSS_PATTERNS[@]}"; do
        [[ "$request" =~ $pattern ]] && { block_ip "$ip" "xss-attempt" "$request"; return 0; }
    done
    
    # Path Traversal
    for pattern in "${PATH_TRAVERSAL_PATTERNS[@]}"; do
        [[ "$request" =~ $pattern ]] && { block_ip "$ip" "path-traversal" "$request"; return 0; }
    done
    
    return 1
}

#-------------------------------------------------------------------------------
# Rate Limiting
#-------------------------------------------------------------------------------
declare -A RATE_3S RATE_30S RATE_TS

cleanup_rates() {
    local now=$(date +%s)
    for key in "${!RATE_TS[@]}"; do
        [ "${RATE_TS[$key]}" -lt $((now - SEC_WINDOW_DURATION)) ] && {
            unset "RATE_3S[$key]" "RATE_TS[$key]"
        }
    done
}

check_rate() {
    local ip="$1"
    in_whitelist "$ip" && return 1
    
    if [ "${RATE_3S[$ip]:-0}" -ge "$REQUEST_LIMIT_PER_SEC" ]; then
        block_ip "$ip" "rate-burst" "${RATE_3S[$ip]} req/${SEC_WINDOW_DURATION}s"
        return 0
    fi
    
    if [ "${RATE_30S[$ip]:-0}" -ge "$REQUEST_LIMIT_PER_WINDOW" ]; then
        block_ip "$ip" "rate-window" "${RATE_30S[$ip]} req/${WINDOW_DURATION}s"
        return 0
    fi
    return 1
}

update_rate() {
    local ip="$1"
    RATE_3S[$ip]=$((${RATE_3S[$ip]:-0} + 1))
    RATE_30S[$ip]=$((${RATE_30S[$ip]:-0} + 1))
    RATE_TS[$ip]=$(date +%s)
}

#-------------------------------------------------------------------------------
# Log Monitoring
#-------------------------------------------------------------------------------
monitor_logs() {
    log_info "Starting monitor (PID: $$)"
    local last_count=0 last_clean=0
    
    [ ! -f "$ACCESS_LOG" ] && { log_error "Log not found: $ACCESS_LOG"; return 1; }
    trap 'log_info "Monitor stopped"; exit 0' SIGTERM SIGINT
    
    while [ -f "$PID_FILE" ]; do
        local now=$(date +%s)
        [ $((now - last_clean)) -ge 60 ] && { cleanup_rates; unblock_expired; last_clean=$now; }
        
        local count=$(wc -l < "$ACCESS_LOG" 2>/dev/null || echo 0)
        if [ "$count" -gt "$last_count" ]; then
            tail -n $((count - last_count)) "$ACCESS_LOG" 2>/dev/null | while IFS= read -r line; do
                process_line "$line"
            done
            last_count=$count
        fi
        sleep "$CHECK_INTERVAL"
    done
}

process_line() {
    local line="$1"
    local ip=$(extract_ip "$line")
    [ -z "$ip" ] && return
    
    if [ "$UNDER_ATTACK_MODE" -eq 1 ]; then
        in_whitelist "$ip" || grep -q "^$ip " "$BLOCKED_IPS_FILE" 2>/dev/null || block_ip "$ip" "under-attack"
        return
    fi
    
    grep -q "^$ip " "$BLOCKED_IPS_FILE" 2>/dev/null && return
    detect_threats "$line" "$ip" && return
    update_rate "$ip"
    check_rate "$ip"
}

#-------------------------------------------------------------------------------
# Service Management
#-------------------------------------------------------------------------------
start_service() {
    [ -f "$PID_FILE" ] && kill -0 "$(cat $PID_FILE)" 2>/dev/null && { echo "Already running"; exit 1; }
    rm -f "$PID_FILE"
    
    init
    [ -f /etc/iptables/rules.v4 ] && iptables-restore < /etc/iptables/rules.v4 2>/dev/null || true
    
    nohup bash -c "$(declare -f); monitor_logs" > "$FIREWALL_LOG" 2>&1 &
    echo "$!" > "$PID_FILE"
    log_info "Started (PID: $!)"
    echo "Luveedu Firewall started (PID: $!)"
}

stop_service() {
    [ ! -f "$PID_FILE" ] && { echo "Not running"; exit 1; }
    local pid=$(cat "$PID_FILE")
    kill -TERM "$pid" 2>/dev/null || true
    sleep 2
    kill -9 "$pid" 2>/dev/null || true
    pkill -f "luvd-firewall.*monitor" 2>/dev/null || true
    rm -f "$PID_FILE"
    log_info "Stopped"
    echo "Stopped"
}

restart_service() { stop_service 2>/dev/null; sleep 2; start_service; }

#-------------------------------------------------------------------------------
# CLI Commands
#-------------------------------------------------------------------------------
show_status() {
    echo "=== Luveedu Firewall Status ==="
    [ -f "$PID_FILE" ] && kill -0 "$(cat $PID_FILE)" 2>/dev/null && echo "Status: Running" || echo "Status: Stopped"
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
        [ -n "$ip" ] && printf "%-20s %-20s %s\n" "$ip" "$(date -d @$ts '+%Y-%m-%d %H:%M' 2>/dev/null)" "${reason:-N/A}"
    done < "$BLOCKED_IPS_FILE"
}

release_all() {
    while read -r ip rest; do [ -n "$ip" ] && unblock_ip "$ip"; done < "$BLOCKED_IPS_FILE"
    > "$BLOCKED_IPS_FILE"
    save_iptables_rules
    echo "All released"
}

check_ip() {
    local ip="$1"
    [ -z "$ip" ] && { echo "Usage: --check-ip <IP>"; exit 1; }
    echo "IP: $ip"
    grep -q "^$ip " "$BLOCKED_IPS_FILE" && echo "  Status: BLOCKED" || echo "  Status: Not blocked"
    in_whitelist "$ip" && echo "  API: WHITELISTED"
    in_blacklist "$ip" && echo "  API: BLACKLISTED"
}

under_attack() {
    case "$1" in
        on|1) UNDER_ATTACK_MODE=1; log_warning "Under Attack ON"; echo "Under Attack Mode: ON" ;;
        off|0) UNDER_ATTACK_MODE=0; log_info "Under Attack OFF"; echo "Under Attack Mode: OFF" ;;
        *) echo "Mode: $([ $UNDER_ATTACK_MODE -eq 1 ] && echo ON || echo OFF)" ;;
    esac
}

update_script() {
    local url="https://raw.githubusercontent.com/Luveedu/Luveedu-Firewall/main/luvd-firewall.sh"
    echo "Updating..."
    curl -s --max-time 10 "$url" -o /tmp/luvd-firewall.new && {
        cp /usr/local/bin/luvd-firewall /usr/local/bin/luvd-firewall.bak.$(date +%F)
        mv /tmp/luvd-firewall.new /usr/local/bin/luvd-firewall
        chmod +x /usr/local/bin/luvd-firewall
        restart_service
        echo "Updated"
    } || { echo "Update failed"; exit 1; }
}

show_help() {
    cat << EOF
Luveedu Firewall v$VERSION

Usage: luvd-firewall [OPTION]

Service:
  --start       Start firewall
  --stop        Stop firewall
  --restart     Restart firewall
  --status      Show status

IP Management:
  --blocked-list    List blocked IPs
  --release-ip IP   Unblock IP
  --release-all     Unblock all
  --check-ip IP     Check IP status

Security:
  --under-attack on|off  Enable attack mode

Other:
  --update      Update script
  --clear-logs  Clear logs
  --reset       Reset everything
  --help        Show this help

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
    --under-attack) under_attack "$2" ;;
    --update) update_script ;;
    --clear-logs) > "$FIREWALL_LOG"; echo "Logs cleared" ;;
    --reset) stop_service 2>/dev/null; > "$BLOCKED_IPS_FILE"; iptables -F INPUT 2>/dev/null; start_service ;;
    --help|-h) show_help ;;
    *) show_help; exit 1 ;;
esac
