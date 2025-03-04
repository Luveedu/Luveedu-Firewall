```
COMING SOON: New Luveedu WAF Addon Powered by ModSecurity.
```

# Luveedu Firewall - Open Source & Free
The Luveedu Firewall is a robust DoS and DDoS prevention tool designed for OpenLiteSpeed servers. This Bash script monitors the access log in real-time, enforcing strict rate limits—100 requests per 30 seconds and 15 requests per 3 seconds—to block malicious IPs using iptables. It supports whitelisting and blacklisting via an API, handles X-Forwarded-For headers for CDN compatibility, and logs all actions for transparency.

✅ Realtime Blocking

✅ DDoS Blocking - Rate Limited

✅ Faster Blocking

✅ Realtime Antivirus & Malware Scanning

✅ API Based Access & Scanning

✅ Rate Limiting

✅ More Coming Soon!

&nbsp;

### Guides & Installation
[Installation](https://github.com/Luveedu/Luveedu-Firewall/tree/main?tab=readme-ov-file#4-installation)

Guides for: [Luveedu Firewall](https://github.com/Luveedu/Luveedu-Firewall/tree/main?tab=readme-ov-file#luveedu-firewall---ddos--dos-blocking--super-powerful-)
//
[Luveedu Shield](https://github.com/Luveedu/Luveedu-Firewall/tree/main?tab=readme-ov-file#luveedu-shield---realtime-block-malicious-bots--reduce-load--addon-)
//
[Luveedu Antivirus](https://github.com/Luveedu/Luveedu-Firewall/tree/main?tab=readme-ov-file#luveedu-antivirus---malware-scanning--removal--addon-)

[Support & Feedback](https://github.com/Luveedu/Luveedu-Firewall/tree/main?tab=readme-ov-file#6-support--feedback)


&nbsp;

## 2. Benefits of this Tool

Luveedu Firewall offers a powerful suite of features to protect your OpenLiteSpeed server from DoS and DDoS attacks. Below are its key benefits:

- **Real-time Monitoring**  
  Continuously scans the OpenLiteSpeed access log (`/usr/local/lsws/logs/access.log`) to detect unusual traffic patterns and potential threats instantly. This proactive approach ensures rapid identification of attacks, minimizing downtime and maintaining server availability. Detailed logs are written to `/var/log/luvd-firewall.log`, enabling real-time or retrospective analysis by administrators.

- **Rate Limiting**  
  Enforces dual-layer rate limits—100 requests per 30 seconds and 15 requests per 3 seconds—to block IPs exceeding these thresholds. This granular control mitigates both sustained and burst attack attempts, intelligently adjusting to traffic spikes to protect legitimate users. Blocked IPs are added to `iptables` with a 24-hour expiration, balancing security and flexibility.

- **Whitelist/Blacklist Support**  
  Integrates seamlessly with the Luveedu Cloud API (`https://waf.luveedu.cloud/checkip.php?ip=`) for dynamic IP management. Whitelists trusted IPs, ensuring uninterrupted access for Google Bots, Bing Bots, Yahoo Bots, known search crawlers, popular CDN IPs (e.g., Cloudflare, Akamai), and legitimate scanners. Blacklists IPs flagged as spam by trusted sources like Spamhaus and Comodo. Maintained by [Luveedu Cloud](https://cloud.luveedu.com), this free API provides up-to-date threat intelligence at no cost.

- **CIDR Blocking**  
  Automatically blocks entire IP ranges (e.g., /24 subnets) when a single IP exceeds rate limits and ends in `.0`, effectively targeting botnets and coordinated attacks. This reduces false positives by focusing on broader malicious patterns while preserving access for unrelated IPs. Use the `--release-ip` command to manually unblock specific IPs or ranges for precise control.

- **Log Rotation**  
  Implements automated log rotation every 5 minutes via the `rotate_logs` function, clearing logs like `/var/log/luvd-firewall.log` and `/usr/local/lsws/logs/access.log` to prevent disk space exhaustion. This maintains system performance and keeps logs manageable, with backups preserving critical data for long-term analysis.

- **Lightweight**  
  Engineered as a Bash script, it runs efficiently with minimal resource overhead, ideal for resource-constrained environments. Leveraging tools like `iptables` and `curl`, it avoids heavy dependencies. With a 1-second check interval (`CHECK_INTERVAL=1`), it balances responsiveness with low CPU/memory usage, ensuring OpenLiteSpeed performance remains uncompromised.

- **Additional Benefits**  
  - **CDN Compatibility**: Respects `X-Forwarded-For` headers to identify real client IPs behind CDNs or proxies, ensuring accurate rate limiting without blocking legitimate traffic.  
  - **Flexible Management**: Offers a rich CLI with commands like `--start`, `--stop`, `--check-logs`, `--blocked-list`, `--release-all`, and `--update`. The `--check-logs` feature provides a real-time dashboard of IP activity, including `Requests/30s` and `Requests/3s` metrics.  
  - **Self-Updating**: The `--update` command fetches the latest version from GitHub, keeping the firewall current with emerging threats, followed by an automatic reset for seamless updates.  
  - **Customizable Configuration**: Allows tweaking of parameters like `BLOCK_DURATION`, `REQUEST_LIMIT_PER_WINDOW`, and `WINDOW_DURATION` directly in the script, tailoring protection to specific server needs without external tools.

These features make Luveedu Firewall a comprehensive, efficient, and user-friendly solution for safeguarding OpenLiteSpeed servers, ensuring robust security and operational flexibility.

  


&nbsp;

## 3. How it Works

Luveedu Firewall operated by analyzing the OpenLiteSpeed access log (`access.log`) & (`syslog`) in real-time.

 Features include automatic log rotation, expired block removal after 24 hours, and commands to start, stop, reset, or check stats. With its configurable settings and real-time monitoring, Luveedu Firewall ensures server security against denial-of-service attacks. 


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

## Luveedu Firewall - DDoS / DoS Blocking ( Super Powerful )

  

Below is a detailed explanation of the available CLI options for managing and monitoring the Luveedu Firewall tool.

**Main Usage**

```luvd-firewall --start``` - It starts the Firewall

```luvd-firewall --stop``` - It stops the Firewall

```luvd-firewall --check-logs``` - Monitor the Rate Limiting Stats

```luvd-firewall --blocked-list``` - Check the Blocked IPs

```luvd-firewall --fix-logs``` - Fix the vHosts to log in access.log file

```luvd-firewall --fix-logs --domains``` - Fix the vHosts to log in access.log file for Specific Domain

```luvd-firewall --reset``` - If the Firewall is not Working Simply Reset the Configuration

```luvd-firewall --update``` - Update the Script to the Latest Version from Github


&nbsp;

**Basic Usage**

```luvd-firewall --release-all``` - Unblock all the IPs from iptables

```luvd-firewall --release-ip 8.8.8.8``` - Unblock any particular IP or Range

```luvd-firewall --check-ip 8.8.8.8``` - It will detect if the IP is BLACKLISTED OR WHITELISTED OR NONE

```luvd-firewall --clear-logs``` - It will clear all the previous logs



&nbsp;

## Luveedu Shield - Realtime Block Malicious Bots & Reduce Load ( Addon )

Luveedu Shield is a Addon for Luveedu Firewall, Which runs in background and scanns the syslog file to detect the IPs those are rated as malicious and we use Comodo and OSWAP to find the Blacklisted BOT IPs and Block them directly from the Kernal, hence you are totally safe and it will reduce server Load.

Below is a detailed explanation of the available CLI options for managing and monitoring the Luveedu Shield tool.


**Main Usage**

```luvd-shield --start``` - It starts the Blocking Engine

```luvd-shield --stop``` - It stops the Blocking Engine

```luvd-shield --blocked-list``` - Check the Blocked IPs

```luvd-shield --fix-all``` - Fix the Issues related to logging & iptables

```luvd-shield --reset``` - If the Shield is not Working Simply Reset the Configuration

```luvd-shield --update``` - Update the Script to the Latest Version from Github


=================

Tail the Logs of Shield & Monitor in more details, BTW, everything is Automatic.

```
tail -f /var/log/luvd-shield.log
```



&nbsp;

## Luveedu Antivirus - Malware Scanning & Removal ( Addon )

Luveedu AV ( Antivirus ) is a powerful and super strong malware scanning and removal tool by Luveedu Firewall. You can easily scan, detect, disinfect and remove malicious files. Its that simple and easy. You can always try system scanning, mail scanning, Database Scanning, 100+ File types support & automatically move infected files to Quarantine, which you can view later easily. Custom Comodo ClamAV Signatures for refinement. Best Positive Rate & Great Way to Resolve all malware issues.

Below is a detailed explanation of the available CLI options for managing and monitoring the Luveedu Antivirus tool.

**Main Usage**

```luvd-antivirus --start``` - It starts the Scanning Engine & Do a Initial Scan

```luvd-antivirus --stop``` - It stops the Running Scans & the Scannng Engine

```luvd-antivirus --check-logs``` - Check the Running Scanning Logs

```luvd-antivirus --check-logs --rkhunter``` - Current Scanning Logs of RKHUNTER ( Rookit Injections )

```luvd-antivirus --check-stats``` - Last 10 Scanning Results


&nbsp;

**Scanning Usage**

```luvd-antivirus --scan``` - It will Start Scanning the Entire Home Directory

```luvd-antivirus --scan --domains``` - It will only scan any selected domain

```luvd-antivirus --scan --main``` - It will Only Scan the Emails & Attachments

```luvd-antivirus --scan --folder /home/customer-folder``` - It will Only Scan the Specified Folder inside /home/

```luvd-antivirus --scan --rootkit``` - It will do a force scan using RKHUNTER for Rootkits

```luvd-antivirus --stop-scan``` - It will immediately Stop the Scanning

```luvd-antivirus --infected-files``` - Check the Infected Files currently in Quarantine

```luvd-antivirus --remove-all``` - You can permanantly delete all Infected files from Quarantine

```luvd-antivirus --restore filename.png``` - It can restore the Quarantine Files to its actual Location


&nbsp;

**Basic Usage**

```luvd-antivirus --update``` - It will update the Luveedu Antivirus Script

```luvd-antivirus --clear-logs``` - It can clear all Unwanted Luveedu Antivirus Logs

&nbsp;

----------

### Try DDoS and DoS Attacks

Our Testing Domain using our Luveedu Firewall ( No Cloudflare, No CDN - Let's Try )

```
https://test.luveedu.com/
``` 

&nbsp;

## 5. Future Plans

We are improving it day by day, we will implement so many things. Some of our thoughts.

```
1. GUI Layout
2. Web Dashboard
3. Proper Blocking WAF using ModSecurity
4. SQL and XSS Prevention
5. Bruteforce Prevention
6. Support for all Panels and Standalone servers
```

  

&nbsp;

## 6. Support & Feedback

  

Currently, we are accepting your feedbacks and error requests by

```
1. support[@]luveedu.com
2. https://www.luveedu.com/contact/?utm-source=Github.com
3. Create Issue in Github
4. Create Forums in Cyberpanel or LiteSpeed
```

&nbsp;

## 6. Credits & Funding

  

It is managed by Luveedu Cloud Team & Build by [Ariyan Debnath](https://www.linkedin.com/in/ariyan-debnath)

**Credits**

```
© Webxenith Technologies LLP
Managed by Luveedu Cloud Team | 100% FREE FOR ALL

-- Thanks to ClamAV
-- Thanks to Comodo
-- Thanks to Github always
```

**Sponsership & Funding**

```
- Currently No Sponsorer

You can fund this project to make it a full fledge enterprise level Open source Malware Scanning & WAF.

We need Your time and experience.
```
