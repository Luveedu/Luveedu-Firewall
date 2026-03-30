# Luveedu Firewall - Enterprise-Grade Security Solution

[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://github.com/Luveedu/Luveedu-Firewall/releases)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go)](https://golang.org/)

## 🚀 Quick Start

**One-Line Installation:**

```bash
curl -sSL https://raw.githubusercontent.com/Luveedu/Luveedu-Firewall/main/install.sh | sudo bash
```

That's it! Your enterprise-grade firewall is now running with:
- ✅ DDoS/DoS protection
- ✅ Web Application Firewall (WAF)
- ✅ Malware scanning (ClamAV + rkhunter)
- ✅ Real-time log monitoring
- ✅ Automated updates

---

## ✨ Features

### 🔥 Core Protection
- **Rate Limiting**: Dual-window (3s burst + 30s sustained)
- **IP Blocking**: High-performance ipset-based (O(1) lookup)
- **DDoS Protection**: Connection flood detection
- **Port Scan Detection**: SYN, XMAS, NULL, FIN scans

### 🛡️ Web Application Firewall (WAF)
- SQL Injection, XSS, Path Traversal
- Remote Code Execution (RCE)
- File Inclusion (LFI/RFI)

### 🦠 Malware Scanning
- ClamAV Integration
- rkhunter Rootkit Detection
- Automatic Quarantine

---

## 📦 Installation

```bash
# Clone and install
git clone https://github.com/Luveedu/Luveedu-Firewall.git
cd Luveedu-Firewall
sudo ./install.sh
```

---

## 💻 Usage

```bash
# Block IP
/opt/luveedu-firewall/luvd-firewall block 192.168.1.100

# List blocked
/opt/luveedu-firewall/luvd-firewall list

# Stats
/opt/luveedu-firewall/luvd-firewall stats

# Scan
/opt/luveedu-firewall/luvd-firewall scan /var/www

# Test WAF
/opt/luveedu-firewall/luvd-firewall test-waf

# Update
/opt/luveedu-firewall/update.sh
```

---

## ⚙️ Configuration

Edit `/opt/luveedu-firewall/config.json`:

```json
{
  "log_level": "info",
  "block_duration": 3600,
  "rate_limit": {
    "burst_limit": 15,
    "sustained_limit": 150
  },
  "waf": { "enabled": true },
  "scanner": { "enabled": true },
  "whitelist": [],
  "blacklist": []
}
```

---

## 🏗️ Architecture

```
Luveedu Firewall
├── Engine (Rate Limit, IP Sets, Log Monitor)
├── WAF (SQLi, XSS, RCE, Path Traversal)
├── Scanner (ClamAV, rkhunter, Quarantine)
└── Config Manager
        ↓
   iptables/ipset
        ↓
   Network Traffic
```

---

## 📊 Performance

| Metric | Value |
|--------|-------|
| Requests/sec | 100,000+ |
| Memory | ~50MB |
| IP Lookup | O(1) |
| Startup | <0.1s |

---

## 🔧 Troubleshooting

```bash
# Check logs
sudo journalctl -u luvd-firewall -f

# Check status
systemctl status luvd-firewall

# View blocked IPs
sudo ipset list luvd_blacklist
```

---

## 📄 License

MIT License

---

## 📞 Support

- **Issues**: https://github.com/Luveedu/Luveedu-Firewall/issues
- **Docs**: https://github.com/Luveedu/Luveedu-Firewall/wiki

**Made with ❤️ by Luveedu Team**
