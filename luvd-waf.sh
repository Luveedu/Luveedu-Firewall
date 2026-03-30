#!/bin/bash
#===============================================================================
# Luveedu WAF - Web Application Firewall
# File: /usr/local/bin/luvd-waf
# Version: 2.0.0
# Description: Advanced WAF with OWASP Top 10 protection, virtual patching,
#              and real-time request inspection
#===============================================================================

set -euo pipefail

#-------------------------------------------------------------------------------
# Configuration
#-------------------------------------------------------------------------------
readonly VERSION="2.0.0"
readonly SCRIPT_NAME="luvd-waf"
readonly PID_FILE="/var/run/luvd-waf.pid"
readonly WAF_LOG="/var/log/luvd-waf.log"
readonly BLOCKED_IPS_FILE="/var/tmp/luvd-blocked-ips.txt"
readonly STATE_DIR="/var/lib/luvd-waf"
readonly LOCK_FILE="/var/lock/luvd-waf.lock"

# Access log
readonly ACCESS_LOG="${ACCESS_LOG:-/usr/local/lsws/logs/access.log}"

# API
readonly CHECK_API="${WAF_API:-https://waf.luveedu.cloud/checkip.php?ip=}"
readonly API_TIMEOUT="${API_TIMEOUT:-3}"

# Under attack mode
UNDER_ATTACK_MODE=0

#-------------------------------------------------------------------------------
# OWASP Top 10 Attack Patterns
#-------------------------------------------------------------------------------
readonly SQL_INJECTION=(
    "(\%27)|(\')|(\-\-)|(\%23)|(#)"
    "((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))"
    "\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))"
    "union.*select"
    "select.*from.*where"
    "insert.*into"
    "update.*set.*where"
    "delete.*from"
    "drop.*(table|database)"
    "exec.*xp_"
    "waitfor.*delay"
    "benchmark\s*\("
    "sleep\s*\("
    "having\s+[0-9]"
    "group\s+by.*having"
)

readonly XSS_ATTACKS=(
    "<script[^>]*>"
    "</script>"
    "javascript:"
    "vbscript:"
    "on(load|error|click|mouse|focus|blur|change|submit|keyup|keydown|keypress)="
    "expression\s*\("
    "alert\s*\("
    "confirm\s*\("
    "prompt\s*\("
    "document\.(cookie|location|write)"
    "window\.(location|open)"
    "eval\s*\("
    "String\.fromCharCode"
)

readonly PATH_TRAVERSAL=(
    "\.\./\.\."
    "\.\.\\\.\.\\"
    "%2e%2e%2f"
    "%2e%2e/"
    "..%2f"
    "%252e%252e%252f"
    "/etc/passwd"
    "/etc/shadow"
    "/proc/self"
    "boot\.ini"
    "win\.ini"
    "system32"
)

readonly RCE_ATTACKS=(
    ";\s*(cat|ls|wget|curl|bash|sh|nc|netcat|python|perl|ruby|php)"
    "\|\s*(cat|ls|wget|curl|bash|sh)"
    "`[^`]+`"
    "\$\([^)]+\)"
    "system\s*\("
    "passthru\s*\("
    "shell_exec\s*\("
    "exec\s*\("
    "popen\s*\("
    "proc_open\s*\("
)

readonly FILE_INCLUSION=(
    "(https?|ftp|php|file|data|expect|phar)://"
    "include\s*\("
    "require\s*\("
    "include_once\s*\("
    "require_once\s*\("
)

#-------------------------------------------------------------------------------
# Initialization
#-------------------------------------------------------------------------------
init() {
    mkdir -p "$STATE_DIR" "$(dirname "$WAF_LOG")"
    touch "$WAF_LOG"
    exec 200>"$LOCK_FILE"
    
    log INFO "WAF initialized (PID: $$)"
}

#-------------------------------------------------------------------------------
# Logging
#-------------------------------------------------------------------------------
log() {
    local level="$1"; shift
    local msg="$*"
    local ts=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$ts] [$level] $msg" >> "$WAF_LOG"
    logger -t "$SCRIPT_NAME" "$msg" 2>/dev/null || true
}

log_info() { log INFO "$@"; }
log_warning() { log WARNING "$@"; }
log_error() { log ERROR "$@"; }
log_attack() { log CRIT "$@"; }

#-------------------------------------------------------------------------------
# URL Decoding
#-------------------------------------------------------------------------------
url_decode() {
    local url="$1"
    printf '%b' "${url//%/\\x}"
}

full_decode() {
    local data="$1"
    local decoded="$data"
    local prev=""
    
    # Double decode to catch encoded encoding
    while [ "$decoded" != "$prev" ]; do
        prev="$decoded"
        decoded=$(url_decode "$decoded")
    done
    
    echo "$decoded"
}

#-------------------------------------------------------------------------------
# Attack Detection Functions
#-------------------------------------------------------------------------------
detect_sql_injection() {
    local request="$1"
    local decoded=$(full_decode "$request")
    
    for pattern in "${SQL_INJECTION[@]}"; do
        if [[ "$decoded" =~ $pattern ]] || [[ "$request" =~ $pattern ]]; then
            log_attack "SQL Injection detected: Pattern='$pattern' Request='${request:0:200}'"
            return 0
        fi
    done
    return 1
}

detect_xss() {
    local request="$1"
    local decoded=$(full_decode "$request")
    
    for pattern in "${XSS_ATTACKS[@]}"; do
        if [[ "$decoded" =~ $pattern ]] || [[ "$request" =~ $pattern ]]; then
            log_attack "XSS attempt detected: Pattern='$pattern' Request='${request:0:200}'"
            return 0
        fi
    done
    return 1
}

detect_path_traversal() {
    local request="$1"
    local decoded=$(full_decode "$request")
    
    for pattern in "${PATH_TRAVERSAL[@]}"; do
        if [[ "$decoded" =~ $pattern ]] || [[ "$request" =~ $pattern ]]; then
            log_attack "Path traversal detected: Pattern='$pattern' Request='${request:0:200}'"
            return 0
        fi
    done
    return 1
}

detect_rce() {
    local request="$1"
    local decoded=$(full_decode "$request")
    
    for pattern in "${RCE_ATTACKS[@]}"; do
        if [[ "$decoded" =~ $pattern ]] || [[ "$request" =~ $pattern ]]; then
            log_attack "RCE attempt detected: Pattern='$pattern' Request='${request:0:200}'"
            return 0
        fi
    done
    return 1
}

detect_file_inclusion() {
    local request="$1"
    local decoded=$(full_decode "$request")
    
    for pattern in "${FILE_INCLUSION[@]}"; do
        if [[ "$decoded" =~ $pattern ]] || [[ "$request" =~ $pattern ]]; then
            log_attack "File inclusion attempt detected: Pattern='$pattern' Request='${request:0:200}'"
            return 0
        fi
    done
    return 1
}

#-------------------------------------------------------------------------------
# Request Analysis
#-------------------------------------------------------------------------------
analyze_request() {
    local line="$1"
    local ip="$2"
    
    # Extract components
    local request=$(echo "$line" | awk -F'"' '{print $2}')
    local uri=$(echo "$request" | awk '{print $2}')
    local query_string=$(echo "$uri" | grep -oP '\?.*' || echo "")
    local method=$(echo "$request" | awk '{print $1}')
    local ua=$(echo "$line" | awk -F'"' '{print $(NF-1)}')
    local referrer=$(echo "$line" | awk -F'"' '{if (NF >= 5) print $(NF-3); else print "-"}')
    local status=$(echo "$line" | awk '{print $(NF-1)}')
    
    local blocked=0
    local block_reason=""
    
    # Check URI and query string
    if detect_sql_injection "$uri$query_string"; then
        blocked=1
        block_reason="sql-injection"
    elif detect_xss "$uri$query_string"; then
        blocked=1
        block_reason="xss-attempt"
    elif detect_path_traversal "$uri$query_string"; then
        blocked=1
        block_reason="path-traversal"
    elif detect_rce "$uri$query_string"; then
        blocked=1
        block_reason="rce-attempt"
    elif detect_file_inclusion "$uri$query_string"; then
        blocked=1
        block_reason="file-inclusion"
    fi
    
    # Check User-Agent
    if [[ "$ua" =~ (sqlmap|nikto|burp|acunetix|nuclei|nmap|masscan) ]]; then
        blocked=1
        block_reason="malicious-ua"
    fi
    
    # Check Referrer
    if [[ "$referrer" =~ (semalt\.com|darodar\.com|buttons-for-website) ]]; then
        blocked=1
        block_reason="spam-referrer"
    fi
    
    # Block suspicious HTTP methods
    if [[ "$method" =~ ^(TRACE|TRACK|DEBUG) ]]; then
        blocked=1
        block_reason="dangerous-method"
    fi
    
    # Check for unusually long requests (potential buffer overflow)
    if [ ${#request} -gt 8192 ]; then
        blocked=1
        block_reason="oversized-request"
    fi
    
    if [ $blocked -eq 1 ]; then
        log_warning "Blocked $ip - Reason: $block_reason - Request: ${request:0:100}"
        block_ip "$ip" "$block_reason"
        return 0
    fi
    
    return 1
}

#-------------------------------------------------------------------------------
# IP Blocking
#-------------------------------------------------------------------------------
block_ip() {
    local ip="$1"
    local reason="${2:-waf}"
    
    [ -z "$ip" ] && return 1
    grep -q "^$ip " "$BLOCKED_IPS_FILE" 2>/dev/null && return 0
    
    # Block with iptables
    if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        iptables -C INPUT -s "$ip" -j DROP 2>/dev/null || {
            iptables -A INPUT -s "$ip" -j DROP
            log_info "WAF blocked IPv4: $ip | Reason: $reason"
        }
    fi
    
    # Record
    echo "$ip $(date +%s) waf-$reason" >> "$BLOCKED_IPS_FILE"
    
    # Persist
    mkdir -p /etc/iptables
    iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
}

#-------------------------------------------------------------------------------
# Log Monitoring
#-------------------------------------------------------------------------------
monitor_logs() {
    log_info "Starting WAF monitor (PID: $$)"
    
    [ ! -f "$ACCESS_LOG" ] && { log_error "Access log not found: $ACCESS_LOG"; return 1; }
    
    trap 'log_info "WAF stopped"; exit 0' SIGTERM SIGINT
    
    local last_count=0
    
    while [ -f "$PID_FILE" ]; do
        local count=$(wc -l < "$ACCESS_LOG" 2>/dev/null || echo 0)
        
        if [ "$count" -gt "$last_count" ]; then
            tail -n $((count - last_count)) "$ACCESS_LOG" 2>/dev/null | while IFS= read -r line; do
                process_request "$line"
            done
            last_count=$count
        fi
        
        sleep 1
    done
}

process_request() {
    local line="$1"
    
    # Extract IP
    local ip=""
    if [[ "$line" =~ ^\[?([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\]? ]]; then
        ip="${BASH_REMATCH[1]}"
    else
        ip=$(echo "$line" | awk '{print $1}' | tr -d '[]')
    fi
    
    [ -z "$ip" ] && return
    [ "$ip" = "127.0.0.1" ] && return
    
    # Under attack mode
    if [ "$UNDER_ATTACK_MODE" -eq 1 ]; then
        grep -q "^$ip " "$BLOCKED_IPS_FILE" 2>/dev/null || block_ip "$ip" "under-attack"
        return
    fi
    
    # Skip blocked IPs
    grep -q "^$ip " "$BLOCKED_IPS_FILE" 2>/dev/null && return
    
    # Analyze request
    analyze_request "$line" "$ip"
}

#-------------------------------------------------------------------------------
# Service Management
#-------------------------------------------------------------------------------
start_service() {
    if [ -f "$PID_FILE" ] && kill -0 "$(cat $PID_FILE)" 2>/dev/null; then
        echo "WAF already running"
        exit 1
    fi
    
    init
    
    nohup bash -c "$(declare -f); monitor_logs" >> "$WAF_LOG" 2>&1 &
    echo "$!" > "$PID_FILE"
    
    log_info "Started (PID: $!)"
    echo "Luveedu WAF started (PID: $!)"
}

stop_service() {
    [ ! -f "$PID_FILE" ] && { echo "Not running"; exit 1; }
    
    local pid=$(cat "$PID_FILE")
    kill -TERM "$pid" 2>/dev/null || true
    sleep 2
    kill -9 "$pid" 2>/dev/null || true
    
    rm -f "$PID_FILE"
    log_info "Stopped"
    echo "Stopped"
}

restart_service() { stop_service 2>/dev/null; sleep 2; start_service; }

#-------------------------------------------------------------------------------
# CLI Commands
#-------------------------------------------------------------------------------
show_status() {
    echo "=== Luveedu WAF Status ==="
    [ -f "$PID_FILE" ] && kill -0 "$(cat $PID_FILE)" 2>/dev/null && echo "Status: Running" || echo "Status: Stopped"
    echo "Blocked by WAF: $(grep "waf-" "$BLOCKED_IPS_FILE" 2>/dev/null | wc -l)"
    echo ""
    echo "Recent WAF blocks:"
    grep "waf-" "$BLOCKED_IPS_FILE" 2>/dev/null | tail -n 5 | awk '{print "  "$1" - "$3}'
}

show_help() {
    cat << EOF
Luveedu WAF v$VERSION - Web Application Firewall

Usage: luvd-waf [OPTION]

Service:
  --start       Start WAF
  --stop        Stop WAF
  --restart     Restart WAF
  --status      Show status

Other:
  --update      Update script
  --clear-logs  Clear logs
  --help        Show this help

Protection:
  - SQL Injection (OWASP Top 10)
  - Cross-Site Scripting (XSS)
  - Path Traversal / LFI / RFI
  - Remote Code Execution (RCE)
  - Malicious User-Agents
  - Dangerous HTTP Methods

EOF
}

update_script() {
    local url="https://raw.githubusercontent.com/Luveedu/Luveedu-Firewall/main/luvd-waf.sh"
    echo "Updating..."
    curl -s --max-time 10 "$url" -o /tmp/luvd-waf.new && {
        cp /usr/local/bin/luvd-waf /usr/local/bin/luvd-waf.bak.$(date +%F)
        mv /tmp/luvd-waf.new /usr/local/bin/luvd-waf
        chmod +x /usr/local/bin/luvd-waf
        restart_service
        echo "Updated"
    } || { echo "Update failed"; exit 1; }
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
    --update) update_script ;;
    --clear-logs) > "$WAF_LOG"; echo "Logs cleared" ;;
    --help|-h) show_help ;;
    *) show_help; exit 1 ;;
esac
