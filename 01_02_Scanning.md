# 1.2 Scanning & Enumeration

Scanning adalah proses aktif mengidentifikasi hosts, services, dan vulnerabilities dalam network target. Ini adalah langkah krusial untuk memahuni attack surface dan planning exploitation.

## Scanning Methodology

### 1. Network Discovery
- Host discovery
- Port scanning
- Service fingerprinting

### 2. Service Enumeration
- Version detection
- Banner grabbing
- Configuration review

### 3. Vulnerability Identification
- Default credentials
- Known vulnerabilities
- Configuration weaknesses

## Network Discovery

### Host Discovery Techniques

```bash
# ICMP Echo Request (ping sweep)
nmap -sn 192.168.1.0/24

# ARP Discovery (more reliable untuk local networks)
nmap -PR 192.168.1.0/24

# TCP SYN Ping
nmap -PS22,80,443 192.168.1.0/24

# TCP ACK Ping
nmap -PA80,443 192.168.1.0/24

# UDP Ping
nmap -PU53,161 192.168.1.0/24

# IP Protocol Ping
nmap -PO 192.168.1.0/24

# List scan (no packets sent)
nmap -sL 192.168.1.0/24
```

### Advanced Host Discovery

```bash
# Multiple discovery methods
nmap -PE -PP -PS80,443 -PA3389 192.168.1.0/24

# Custom discovery script
nmap --script hostmap-crtsh target.com

# Custom timing
nmap -sn -T2 192.168.1.0/24  # Polite scan
nmap -sn -T5 192.168.1.0/24  # Insane scan

# Exclude hosts
nmap -sn 192.168.1.0/24 --exclude 192.168.1.1,192.168.1.100
```

### Live Host Verification

```bash
# Fping untuk fast ping sweep
fping -a -g 192.168.1.0/24 2>/dev/null

# Masscan untuk large networks
masscan -p80,443,22 192.168.0.0/16 --rate=1000

# Nmap ping sweep dengan output
nmap -sn -oG live_hosts.txt 192.168.1.0/24
grep "Up" live_hosts.txt | cut -d" " -f2 > live_ips.txt
```

## Port Scanning Fundamentals

### TCP Scanning Methods

```bash
# TCP Connect Scan (full three-way handshake)
nmap -sT target.com
# Most reliable, easily detectable

# TCP SYN Scan (half-open)
nmap -sS target.com
# Stealthier, requires root

# TCP ACK Scan (firewall detection)
nmap -sA target.com
# Determines if firewall is stateful

# TCP Window Scan
nmap -sW target.com
# Similar to ACK but can detect open ports

# TCP Maimon Scan
nmap -sM target.com
# Uses FIN/ACK combination
```

### UDP Scanning

```bash
# Basic UDP Scan
nmap -sU target.com
# Slow due to UDP reliability issues

# UDP Common Ports
nmap -sU -p 53,161,137,138,139,69,123,162 target.com

# UDP Top Ports
nmap -sU --top-ports 100 target.com

# UDP Scan dengan version detection
nmap -sU -sV target.com

# UDP Scan with aggressive timing
nmap -sU -T4 -p 161,162 target.com
```

### Advanced Scanning Options

```bash
# FIN Scan
nmap -sF target.com
# Sends FIN packet

# NULL Scan
nmap -sN target.com
# Sends packet with no flags set

# Xmas Scan
nmap -sX target.com
# Sends FIN, PSH, URG flags

# FTP Bounce Scan
nmap -b ftp_user:ftp_pass@ftp.server.com target.com
# Routes scan through FTP server

# Idle Scan (Zombie)
nmap -sI zombie_host target.com
# Uses zombie host for stealth

# Decoy Scan
nmap -D RND:10 target.com  # 10 random decoys
nmap -D ME,192.168.1.1,10.0.0.1 target.com  # Specific decoys
```

### Port Specification and Targeting

```bash
# Specific ports
nmap -p 21,22,23,80,443,3389 target.com

# Port ranges
nmap -p 1-1024 target.com
nmap -p 1000-2000 target.com

# Fast scan (top 100 ports)
nmap -F target.com

# All 65535 ports
nmap -p- target.com

# Random port order
nmap -r -p- target.com
```

## Service Detection and Version Scanning

### Version Detection

```bash
# Basic version detection
nmap -sV target.com

# Intensity level (0-9)
nmap -sV --version-intensity 9 target.com

# Light version detection
nmap -sV --version-intensity 0 target.com

# Version all probes
nmap -sV --version-all target.com

# Version light
nmap -sV --version-light target.com

# TCP dan UDP version scan
nmap -sV -sU target.com
```

### Service and OS Fingerprinting

```bash
# OS Detection
nmap -O target.com

# OS detection dengan limitations
nmap -O --osscan-limit target.com

# OS guess only
nmap -O --osscan-guess target.com

# Aggressive scan (OS + version + scripts)
nmap -A target.com

# Service info scan
nmap -sV --version-intensity 7 -A target.com
```

### Banner Grabbing

```bash
# Netcat banner grabbing
nc -nv target.com 80
nc -nv target.com 21
nc -nv target.com 22

# Telnet banner grabbing
telnet target.com 23
telnet target.com 25

# Netcat dengan timeout
nc -nv -w 3 target.com 80

# Automated banner grabbing
nmap -sV --script=banner target.com
```

## Specific Service Enumeration

### Web Server Enumeration

```bash
# HTTP title detection
nmap -p80 --script http-title target.com

# HTTP server headers
nmap -p80 --script http-server-header target.com

# HTTP methods detection
nmap -p80 --script http-methods target.com

# HTTP technologies
nmap -p80 --script http-enum target.com

# Nginx/Apache specific enumeration
nmap -p80 --script http-apache-server-status,http-nginx-status target.com

# Web application fingerprinting
nmap -p80 --script http-vhosts,http-userdir,http-robots target.com
```

### SMB/Samba Enumeration

```bash
# SMB version detection
nmap -p445 --script smb-protocols target.com

# SMB signing check
nmap -p445 --script smb2-security-mode target.com

# SMB shares enumeration
nmap -p445 --script smb-enum-shares target.com

# SMB users enumeration
nmap -p445 --script smb-enum-users target.com

# SMB domain information
nmap -p445 --script smb-enum-domains target.com

# SMB vulnerabilities
nmap -p445 --script smb-vuln-ms17-010 target.com
nmap -p445 --script smb-vuln-ms08-067 target.com
nmap -p445 --script smb-vuln-cve2017-7494 target.com
```

### SSH Enumeration

```bash
# SSH version
nmap -p22 --script ssh2-enum-algos target.com

# SSH hostkey
nmap -p22 --script ssh-hostkey target.com

# SSH auth methods
nmap -p22 --script ssh-auth-methods target.com

# SSH publickey check
nmap -p22 --script ssh-publickey target.com

# SSH run command (if auth available)
nmap -p22 --script ssh-run target.com
```

### Database Enumeration

```bash
# MySQL enumeration
nmap -p3306 --script mysql-info,mysql-variables,mysql-databases target.com
nmap -p3306 --script mysql-users,mysql-empty-password target.com

# MSSQL enumeration
nmap -p1433 --script ms-sql-info,ms-sql-config target.com
nmap -p1433 --script ms-sql-dump-hashes,ms-sql-empty-password target.com

# PostgreSQL enumeration
nmap -p5432 --script pgsql-info,pgsql-databases target.com

# Oracle enumeration
nmap -p1521 --script oracle-enum-users target.com
```

### FTP Enumeration

```bash
# Anonymous FTP check
nmap -p21 --script ftp-anon target.com

# FTP bounce check
nmap -p21 --script ftp-bounce target.com

# FTP brute force
nmap -p21 --script ftp-brute target.com

# FTP libopie vulnerability
nmap -p21 --script ftp-libopie target.com

# FTP ProFTPD backdoor
nmap -p21 --script ftp-proftpd-backdoor target.com
```

### SNMP Enumeration

```bash
# SNMP public community
nmap -sU -p161 --script snmp-interfaces target.com
nmap -sU -p161 --script snmp-sysdescr target.com

# SNMP processes
nmap -sU -p161 --script snmp-processes target.com

# SNMP users (Windows)
nmap -sU -p161 --script snmp-win32-users target.com

# SNMP services (Windows)
nmap -sU -p161 --script snmp-win32-services target.com

# SNMP brute force
nmap -sU -p161 --script snmp-brute target.com
```

## Nmap Scripting Engine (NSE)

### Using NSE Categories

```bash
# Safe scripts
nmap --script safe target.com

# Intrusive scripts
nmap --script intrusive target.com

# Vulnerability scripts
nmap --script vuln target.com

# Exploit scripts
nmap --script exploit target.com

# Discovery scripts
nmap --script discovery target.com

# Auth scripts
nmap --script auth target.com

# Malware detection
nmap --script malware target.com

# External scripts (require internet)
nmap --script external target.com
```

### Custom Script Selection

```bash
# Specific scripts
nmap --script ssh2-enum-algos,http-title target.com

# Script with wildcard
nmap --script "http-*" target.com
nmap --script "*-enum-*" target.com

# Script arguments
nmap --script http-enum --script-args http-enum.basepath=/admin target.com

# Multiple script arguments
nmap --script smb-brute --script-args userdb=users.txt,passdb=pass.txt target.com
```

### Script Output and Formatting

```bash
# Script output ke file
nmap -p80 --script http-enum -oN http_enum.txt target.com

# Script output XML
nmap -p80 --script http-enum -oX http_enum.xml target.com

# Script output grepable
nmap -p80 --script http-enum -oG http_enum.gnmap target.com

# Script output all formats
nmap -p80 --script http-enum -oA http_enum target.com

# Verbose script output
nmap -p80 --script http-enum --script-trace target.com
```

## Timing and Performance

### Timing Templates

```bash
# T0 - Paranoid (very slow)
nmap -T0 target.com
# Serialized, 5 minute delay

# T1 - Sneaky (slow)
nmap -T1 target.com
# Serialized, 15 second delay

# T2 - Polite (slower)
nmap -T2 target.com
# Parallelize, reduce scan delay

# T3 - Normal (default)
nmap -T3 target.com
# Parallelize, automatic delays

# T4 - Aggressive (faster)
nmap -T4 target.com
# Reduce timeouts

# T5 - Insane (fastest)
nmap -T5 target.com
# No delays, 5ms timeout
```

### Performance Tuning

```bash
# Set max parallelism
nmap --max-parallelism 100 target.com

# Set host timeout
nmap --host-timeout 30m target.com

# Set scan delay
nmap --scan-delay 1s target.com

# Set max retries
nmap --max-retries 3 target.com

# Set min rate
nmap --min-rate 50 target.com

# Set max rate
nmap --max-rate 1000 target.com

# Set initial RTT timeout
nmap --initial-rtt-timeout 500ms target.com
```

## Output and Reporting

### Output Formats

```bash
# Normal output
nmap -oN normal.txt target.com

# XML output
nmap -oX output.xml target.com

# Grepable output
nmap -oG output.gnmap target.com

# All formats
nmap -oA all_formats target.com

# Append to file
nmap -oN normal.txt --append-output target.com

# Output hanya open ports
nmap -oG - target.com | grep "open"
```

### Verbose and Debug Output

```bash
# Verbose output
nmap -v target.com

# Very verbose output
nmap -vv target.com

# Debug output
nmap -d target.com

# Packet tracing
nmap --packet-trace target.com

# Interface listing
nmap --iflist

# Reason for port state
nmap --reason target.com
```

## Scanning Automation

### Custom Scanning Script

```bash
#!/bin/bash
# comprehensive_scan.sh

TARGET=$1
DATE=$(date +%Y%m%d_%H%M%S)
BASE_DIR="scans_${TARGET}_${DATE}"
mkdir -p $BASE_DIR

echo "[*] Starting comprehensive scan for $TARGET"

# Initial port scan
echo "[+] Running initial port scan..."
nmap -sS -p- -T4 -oN $BASE_DIR/all_ports.txt $TARGET

# Extract open ports
OPEN_PORTS=$(grep "open" $BASE_DIR/all_ports.txt | cut -d'/' -f1 | tr '\n' ',' | sed 's/,$//')

# Detailed service scan
echo "[+] Running detailed service scan..."
nmap -sV -sC -p $OPEN_PORTS -oN $BASE_DIR/detailed.txt $TARGET

# Top 100 UDP ports
echo "[+] Scanning UDP top 100..."
nmap -sU --top-ports 100 -oN $BASE_DIR/udp_top100.txt $TARGET

# Save scan summary
echo "[+] Generating summary..."
cat > $BASE_DIR/summary.txt << EOF
Scan Summary for $TARGET
Date: $(date)

Total TCP ports scanned: 65535
Open TCP ports: $(grep -c "open" $BASE_DIR/all_ports.txt)
Open UDP ports: $(grep -c "open" $BASE_DIR/udp_top100.txt)

Interesting findings:
EOF

# Add interesting findings to summary
grep -i "open" $BASE_DIR/detailed.txt | grep -E "(http|ftp|ssh|telnet|mysql|mssql)" >> $BASE_DIR/summary.txt

echo "[+] Scan complete. Results in $BASE_DIR"
```

### Mass Scanning Script

```python
#!/usr/bin/env python3
# mass_scanner.py

import subprocess
import sys
import concurrent.futures
import os
from datetime import datetime

def scan_target(target, output_dir):
    """Scan individual target"""
    try:
        output_file = os.path.join(output_dir, f"{target}.nmap")

        # Run comprehensive scan
        result = subprocess.run([
            'nmap', '-sS', '-sV', '-O', '-A', '-T4',
            '-oN', output_file, target
        ], capture_output=True, text=True)

        if result.returncode == 0:
            return f"[*] Scan completed for {target}"
        else:
            return f"[!] Scan failed for {target}: {result.stderr}"

    except Exception as e:
        return f"[!] Error scanning {target}: {str(e)}"

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <targets_file>")
        sys.exit(1)

    targets_file = sys.argv[1]
    output_dir = f"mass_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    os.makedirs(output_dir)

    # Read targets
    with open(targets_file) as f:
        targets = [line.strip() for line in f if line.strip()]

    print(f"[*] Starting mass scan of {len(targets)} targets")
    print(f"[*] Output directory: {output_dir}")

    # Parallel scanning
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(scan_target, target, output_dir) for target in targets]

        for future in concurrent.futures.as_completed(futures):
            print(future.result())

    print("[*] All scans complete")

if __name__ == "__main__":
    main()
```

## Evasion Techniques

### Scan Evasion

```bash
# Decoy scan
nmap -D RND:10 target.com
nmap -D 192.168.1.1,192.168.1.2,ME target.com

# Source port manipulation
nmap -g 53 target.com  # Use DNS as source port
nmap -source-port 80 target.com

# Fragmentation
nmap -f target.com
nmap --mtu 8 target.com

# Randomize hosts
nmap --randomize-hosts target_list.txt

# Timing randomization
nmap --scan-delay 100ms --max-retries 2 target.com
```

### Firewall/IDS Evasion

```bash
# ACK scan for stateless firewalls
nmap -sA target.com

# FIN scan for some firewalls
nmap -sF target.com

# Custom packet construction
nmap -p 80 --script "http-enum" --data "GET / HTTP/1.0\r\n\r\n" target.com

# IP protocol scan
nmap -sO target.com

# Idle scan untuk ultimate stealth
nmap -sI zombie_host target.com
```

## Best Practices

### Scanning Ethics

1. **Scope Limitation** - Only scan authorized targets
2. **Rate Limiting** - Don't overwhelm systems
3. **Timing** - Scan during maintenance windows
4. **Notification** - Alert system owners
5. **Documentation** - Record all activities

### Operational Security

```bash
# Use proxies or VPN
export http_proxy=http://proxy:8080
export https_proxy=https://proxy:8080

# Rotate user agents
nmap --script http-enum --script-args http.useragent="Mozilla/5.0 (compatible; Googlebot/2.1)" target.com

# Use random delays
for target in $(cat targets.txt); do
    nmap -sS -F $target
    sleep $((RANDOM % 60 + 30))  # Random 30-90 second delay
done
```

## Common Issues and Solutions

### Issue: Slow UDP Scanning

```bash
# Solution: Limit UDP ports and use faster timing
nmap -sU --top-ports 50 -T4 target.com

# Use specific known UDP services
nmap -sU -p 53,161,123,137,138 target.com
```

### Issue: False Positives

```bash
# Solution: Verify with multiple tools
nmap -sV target.com
nc -nv target.com port
# Compare results
```

### Issue: Network Congestion

```bash
# Solution: Adjust timing and parallelism
nmap -T2 --max-parallelism 10 target.com

# Scan in smaller batches
for i in {1..254}; do
    nmap -sn 192.168.1.$i
    sleep 1
done
```

Scanning dan enumeration adalah foundation untuk understanding target systems. Comprehensive scanning akan reveal attack surface yang digunakan untuk exploitation planning. Always scan responsibly dan document findings thoroughly.