# Luveedu Firewall - Opensource & Free DoS WAF

Luveedu Firewall is a lightweight and efficient tool designed to protect your OpenLiteSpeed web server from Denial of Service (DoS) attacks. It monitors server logs, detects suspicious activity, and blocks malicious IPs using *iptables*. This README provides an overview of the tool, its benefits, how it works, and instructions for installation and usage.


&nbsp;
# 2. Benefits of this Tool

Luveedu Firewall offers several advantages for protecting your OpenLiteSpeed server:
- **Real-time Monitoring**: Continuously monitors access logs to detect unusual traffic patterns.
- **Rate Limiting**: Blocks IPs that exceed a predefined number of requests within a specified time window.
- **Whitelist/Blacklist Support**: Integrates with an external API to whitelist trusted IPs and blacklist malicious ones.
- **CIDR Blocking**: Automatically blocks entire IP ranges if a specific IP exceeds limits.
- **Log Rotation**: Ensures logs do not grow indefinitely, maintaining system performance.
- **Lightweight**: Designed to run efficiently without consuming excessive server resources.
- **Customizable**: Easily configurable thresholds for request limits, block durations, and more.


&nbsp;
# 3. How it Works

Luveedu Firewall operates by analyzing the OpenLiteSpeed access log (`access.log`) in real-time. Here's a high-level overview of its workflow:

1. **Log Parsing**:
   - The tool reads new entries from the access log every second.
   - It extracts both the client IP (`%h`) and the `X-Forwarded-For` header (if present) to identify the true source of requests.

2. **Rate Limiting**:
   - For each IP, it tracks the number of requests made within a sliding 30-second window.
   - If an IP exceeds the configured request limit (default: 100 requests per 30 seconds), it is flagged as suspicious.

3. **IP Validation**:
   - Before blocking, the tool checks if the IP is whitelisted or blacklisted via an external API.
   - Whitelisted IPs are exempt from rate limiting, while blacklisted IPs are blocked immediately.

4. **Blocking Mechanism**:
   - Suspicious IPs are blocked using `iptables` with the `REJECT` rule.
   - Entire CIDR ranges (e.g., `/24`) can be blocked if necessary.

5. **Unblocking Expired IPs**:
   - Blocked IPs are automatically unblocked after a specified duration (default: 1 day).

6. **Log Management**:
   - Access logs and firewall logs are rotated every 5 minutes to prevent excessive disk usage.


&nbsp;
# 4. How it Blocks DoS Attacks

Luveedu Firewall employs multiple strategies to mitigate DoS attacks effectively:

- **Rate-Based Blocking**:
  - IPs exceeding the request limit within a 30-second window are blocked.
  - This prevents attackers from overwhelming the server with high-frequency requests.

- **CIDR Blocking**:
  - If an IP ending in `.0` exceeds the limit, the entire `/24` range is blocked.
  - This is particularly useful for mitigating attacks originating from botnets.

- **External API Integration**:
  - The tool queries an external API (`https://waf.luveedu.cloud/checkip.php`) to determine if an IP is whitelisted or blacklisted.
  - Whitelisted IPs are ignored, while blacklisted IPs are blocked immediately.

- **Graceful Handling of CDN Traffic**:
  - When the `X-Forwarded-For` header is present, the tool prioritizes the original client IP over the proxy IP.
  - This ensures accurate identification of malicious clients behind CDNs.

- **Automatic Cleanup**:
  - Expired blocks are removed automatically, ensuring that legitimate users regain access after the block duration expires.


&nbsp;
# 5. Installation

To install Luveedu Firewall, simply run the following command on your server:

### Requirements

1. Cyberpanel and Openlitespeed
2. Min 1vCore & 1Gb Ram
3. Any Linux Distro ( Debian Based and RHEL Based )

&nbsp;
```
wget -qO- https://raw.githubusercontent.com/Luveedu/Luveedu-Firewall/refs/heads/main/start.sh | sudo bash
```
> It will change the Access Logging Settings for all vHosts, so try carefully : )

&nbsp;
# Luveedu Firewall - Usage Options

Below is a detailed explanation of the available CLI options for managing and monitoring the Luveedu Firewall tool.

---

### Start the Firewall ( Use any of them )

```
systemctl start luvd-firewall
```
```
systemctl restart luvd-firewall
```
```
luvd-firewall --start
```
Starts the firewall service. Logs will be written to `/var/log/luvd-firewall.log`.

---

### Stop the Firewall ( Use any of them )

```
systemctl stop luvd-firewall
```
```
luvd-firewall --stop
```
Stops the firewall service gracefully. All active blocks remain in place until they expire.

---

### Fix Log Formats

```
luvd-firewall --fix-logs
```
Updates all virtual host configurations to use a standardized access log format. This ensures compatibility with the firewall's parsing logic.

---

### Release All Blocked IPs

```
luvd-firewall --release-all
```
Unblocks all currently blocked IPs and clears the firewall logs. Use this option to reset the firewall state.

---

### Release a Specific IP or CIDR

```
luvd-firewall --release-ip <IP_OR_CIDR>
```
Unblocks a specific IP or CIDR range. For example:
```luvd-firewall --release-ip 8.8.8.8```
```luvd-firewall --release-ip 192.168.1.0/24```

---

### Check Logs

```
luvd-firewall --check-logs
```
Monitors the firewall logs in real-time, displaying the current status of IPs (e.g., blocked, whitelisted, or processing).

---

### Check an IP or CIDR

```
luvd-firewall --check-ip <IP_OR_CIDR>
```
Queries the external API to check the status of a specific IP or CIDR. For example:
```luvd-firewall --check-ip 8.8.8.8```
```luvd-firewall --check-ip 192.168.1.0/24```

---

### View Blocked IPs

```
luvd-firewall --blocked-list
```
Displays a list of currently blocked IPs and CIDRs, along with the timestamp when they were blocked.

---

### Clear Logs

```
luvd-firewall --clear-logs
```
Clears all firewall logs and resets the tool's internal state. Use this option with caution.

---

### Reset the Firewall

```
luvd-firewall --reset
```
Performs a full reset of the firewall, including stopping the service, clearing logs, and reloading OpenLiteSpeed.


&nbsp;
# Future Plans

We are improving it day by day, we will implement so many things. Some of our thoughts.

1. Improved Layout
2. Web Dashboard
3. Faster Processing
4. Faster Blocking
5. Proper Blocking WAF using ModSecurity
6. SQL and XSS Prevention
7. Bruteforce Prevention
8. Antivirus & Malware Scanning
9. DDoS Protection Layer 7 ( Recaptcha Based )


&nbsp;
# Support & Feedback

Currently, we are accepting your feedbacks and error requests by

> support[@]luveedu.com

> https://www.luveedu.com/contact/

> Create Issue in Github

> Create Forums in Cyberpanel or LiteSpeed