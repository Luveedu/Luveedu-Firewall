# Luveedu Firewall - Open Source & Free
Luveedu Firewall is a lightweight and efficient tool designed to protect your OpenLiteSpeed web server from Denial of Service (DoS) attacks. It monitors server logs, detects suspicious activity, and blocks malicious IPs using *iptables*. 

✅ Realtime Blocking

✅ Faster Blocking

✅ Realtime Antivirus & Malware Scanning

✅ API Based Access & Scanning

✅ Rate Limiting

✅ More Coming Soon!

&nbsp;

## 2. Benefits of this Tool

Luveedu Firewall offers several advantages for protecting your OpenLiteSpeed server:

-  **Real-time Monitoring**: Continuously monitors access logs to detect unusual traffic patterns.

-  **Rate Limiting**: Blocks IPs that exceed a predefined number of requests within a specified time window.

-  **Whitelist/Blacklist Support**: Integrates with an Luveedu Cloud API to whitelist trusted IPs and blacklist malicious ones. It will never Block Google Bots, Bing Bots, Yahoo Bots, Any Known Search Bots, All Popular CDN IPs and Scanners. It will Block IPs rated Spam by Spamhaus and Comodo. ( Request API: https://waf.luveedu.cloud/checkip.php?ip=1.1.1.1 ) - Maintained by [Luveedu Cloud](https://cloud.luveedu.com) & Free to Use.

-  **CIDR Blocking**: Automatically blocks entire IP ranges if a specific IP exceeds limits.

-  **Log Rotation**: Ensures logs do not grow indefinitely, maintaining system performance.

-  **Lightweight**: Designed to run efficiently without consuming excessive server resources.

  


&nbsp;

## 3. How it Works

Luveedu Firewall operates by analyzing the OpenLiteSpeed access log (`access.log`) in real-time.

It Continuously monitors the access.log file and syslog files to detect the IP and hence, it detects the Number of requests sent by the IP in a 30 second threshold if it cross the threshold, we will verify the IP if it is a Good IP like Googlebot, Bingbot or Cloudflare then we will not block it else, we will do a quick block for a Period of Time using iptables and ipset.


&nbsp;
## 4. Installation

#### Requirements

  

1. Cyberpanel and Openlitespeed
2. Min 1vCore & 1Gb Ram
3. Any Linux Distro ( Debian Based and RHEL Based )

  
&nbsp;
```
wget -qO- https://raw.githubusercontent.com/Luveedu/Luveedu-Firewall/refs/heads/main/start.sh | sudo bash
```

***It will change the Access Logging Settings for all vHosts***

  

&nbsp;

### Luveedu Firewall - Usage Options

  

Below is a detailed explanation of the available CLI options for managing and monitoring the Luveedu Firewall tool.

**Main Usage**

```luvd-firewall --start``` - It starts the Firewall

```luvd-firewall --stop``` - It stops the Firewall

```luvd-firewall --check-logs``` - Monitor the Rate Limiting Stats

```luvd-firewall --blocked-list``` - Check the Blocked IPs

```luvd-firewall --fix-logs``` - Fix the vHosts to log in access.log file

```luvd-firewall --reset``` - If the Firewall is not Working Simply Reset the Configuration

```luvd-firewall --update``` - Update the Script to the Latest Version from Github


&nbsp;

**Basic Usage**

```luvd-firewall --release-all``` - Unblock all the IPs from iptables

```luvd-firewall --release-ip 8.8.8.8``` - Unblock any particular IP or Range

```luvd-firewall --check-ip 8.8.8.8``` - It will detect if the IP is BLACKLISTED OR WHITELISTED OR NONE

```luvd-firewall --clear-logs``` - It will clear all the previous logs



&nbsp;

### Luveedu Shield - Realtime Block Malicious Bots & Reduce Load

Luveedu Shield is a Addon for Luveedu Firewall, Which runs in background and scanns the syslog file to detect the IPs those are rated as malicious and we use Comodo and OSWAP to find the Blacklisted BOT IPs and Block them directly from the Kernal, hence you are totally safe and it will reduce server Load.

Below is a detailed explanation of the available CLI options for managing and monitoring the Luveedu Shield tool.

**Main Usage**

```luvd-shield --start``` - It starts the Blocking Engine

```luvd-shield --stop``` - It stops the Blocking Engine

```luvd-shield --blocked-list``` - Check the Blocked IPs

```luvd-shield --fix-all``` - Fix the Issues related to logging & iptables

```luvd-shield --reset``` - If the Shield is not Working Simply Reset the Configuration

```luvd-shield --update``` - Update the Script to the Latest Version from Github


&nbsp;

## 5. Future Plans

  

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

## 6. Support & Feedback

  

Currently, we are accepting your feedbacks and error requests by

```
1. support[@]luveedu.com
2. https://www.luveedu.com/contact/
3. Create Issue in Github
4. Create Forums in Cyberpanel or LiteSpeed
```