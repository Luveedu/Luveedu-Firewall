# Luveedu Firewall Suite v2.0.0

Professional-grade web server protection suite with multi-layered defense against DDoS, DoS, malware, and web application attacks.

## Components

### 1. **luvd-firewall** - DoS/DDoS Protection
- Real-time access log monitoring
- Dual-window rate limiting (3s burst + 30s sustained)
- Malicious User-Agent detection
- URL pattern analysis
- API-based threat intelligence integration
- IPv4/IPv6 support
- ipset integration for high-performance blocking

### 2. **luvd-shield** - Kernel-Level Protection
- Kernel log monitoring for connection-based attacks
- Port scan detection
- Connection flood protection
- Invalid packet filtering
- iptables LOG rule integration
- Automatic IP reputation checking

### 3. **luvd-waf** - Web Application Firewall
- OWASP Top 10 protection:
  - SQL Injection detection & blocking
  - Cross-Site Scripting (XSS) prevention
  - Path Traversal / LFI / RFI protection
  - Remote Code Execution (RCE) blocking
  - File inclusion attack prevention
- Malicious bot/scanner detection
- Dangerous HTTP method blocking
- Request size limits

### 4. **luvd-antivirus** - Malware Scanner
- ClamAV integration for file scanning
- rkhunter for rootkit detection
- Quarantine management
- Scheduled scanning support
- Mail server scanning

## Quick Start

### Installation
```bash
sudo ./INSTALL.sh
```

### Start All Services
```bash
systemctl start luvd-firewall
systemctl start luvd-shield
systemctl start luvd-waf
```

### Enable on Boot
```bash
systemctl enable luvd-firewall luvd-shield luvd-waf
```

## Usage

### Firewall Commands
```bash
luvd-firewall --start          # Start firewall
luvd-firewall --stop           # Stop firewall
luvd-firewall --status         # Check status
luvd-firewall --blocked-list   # View blocked IPs
luvd-firewall --release-ip 8.8.8.8    # Unblock IP
luvd-firewall --release-all    # Unblock all
luvd-firewall --check-ip 8.8.8.8      # Check IP status
luvd-firewall --under-attack on       # Enable emergency mode
```

### Shield Commands
```bash
luvd-shield --start            # Start shield
luvd-shield --stop             # Stop shield
luvd-shield --status           # Check status
luvd-shield --fix-all          # Fix iptables rules
```

### WAF Commands
```bash
luvd-waf --start               # Start WAF
luvd-waf --stop                # Stop WAF
luvd-waf --status              # Check status
```

### Antivirus Commands
```bash
luvd-antivirus --scan                  # Full scan
luvd-antivirus --scan --folder /path   # Scan folder
luvd-antivirus --scan --domains        # Scan domains
luvd-antivirus --scan --rootkit        # Rootkit scan
luvd-antivirus --check-logs            # View scan progress
luvd-antivirus --infected-files        # List infected files
```

## Configuration

### Environment Variables
```bash
# Rate limiting
export RATE_LIMIT_WINDOW=150      # Requests per 30s
export RATE_LIMIT_BURST=15        # Requests per 3s

# Block duration
export BLOCK_DURATION=86400       # Seconds (24 hours)

# API endpoint
export WAF_API=https://waf.luveedu.cloud/checkip.php?ip=
```

### Log Files
- `/var/log/luvd-firewall.log` - Firewall logs
- `/var/log/luvd-shield.log` - Shield logs
- `/var/log/luvd-waf.log` - WAF logs
- `/var/log/luvd-antivirus.log` - Antivirus logs

### Blocked IPs
- `/var/tmp/luvd-blocked-ips.txt` - Main blocklist
- `/var/tmp/luvd-shield-blocked-ips.txt` - Shield blocklist

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Incoming Traffic                      │
└─────────────────────┬───────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────┐
│                   luvd-shield                            │
│         (Kernel-level, port scans, conn floods)          │
└─────────────────────┬───────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────┐
│                 luvd-firewall                            │
│        (Rate limiting, DoS/DDoS, bad bots)               │
└─────────────────────┬───────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────┐
│                   luvd-waf                               │
│     (SQLi, XSS, RCE, path traversal, file inclusion)     │
└─────────────────────┬───────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────┐
│              OpenLiteSpeed Web Server                    │
└─────────────────────────────────────────────────────────┘
```

## Features

### Advanced Protection
- ✅ Multi-layered defense (network + application)
- ✅ Real-time threat detection
- ✅ Automatic IP blocking
- ✅ Configurable rate limits
- ✅ Threat intelligence API integration
- ✅ Circuit breaker for API failures
- ✅ Response caching to reduce API calls

### Performance
- ✅ Efficient log parsing
- ✅ Memory-conscious rate limiting
- ✅ ipset integration for fast blocking
- ✅ Minimal latency impact
- ✅ Background processing

### Management
- ✅ Systemd service integration
- ✅ Comprehensive logging
- ✅ Log rotation configured
- ✅ Easy CLI interface
- ✅ Auto-update capability
- ✅ Status monitoring

## Requirements

- Linux (Debian/Ubuntu/RHEL/CentOS)
- Root/sudo access
- iptables
- ipset (recommended)
- curl
- OpenLiteSpeed (for log monitoring)

## License

Proprietary - Luveedu

## Support

For issues and feature requests, please contact support.
