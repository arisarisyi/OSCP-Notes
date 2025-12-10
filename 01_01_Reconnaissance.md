# 1.1 Reconnaissance

Reconnaissance adalah fase awal dari penetration testing di mana attacker mengumpulkan informasi tentang target tanpa melakukan interaksi langsung (passive) atau dengan interaksi terbatas (active). Ini adalah langkah krusial untuk memahami target infrastructure dan membangun attack surface mapping.

## Mengapa Reconnaissance Penting?

1. **Target Profiling** - Memahami business dan technology stack target
2. **Attack Surface Identification** - Menemukan potential entry points
3. **Attack Vector Planning** - Menentukan cara terbaik untuk compromise target
4. **Risk Assessment** - Mengidentifikasi high-value assets
5. **Social Engineering Preparation** - Mengumpulkan informasi untuk spear phishing

## Passive Reconnaissance

Passive reconnaissance tidak meninggalkan traces dan tidak dapat dideteksi oleh target.

### OSINT (Open Source Intelligence)

#### Whois Information Gathering

```bash
# Basic whois lookup
whois target.com

# Extended whois
whois -H target.com > whois_output.txt

# Multiple domain whois
for domain in $(cat domains.txt); do
    echo "=== $domain ===" >> whois_report.txt
    whois $domain >> whois_report.txt
done

# Extract email addresses dari whois
whois target.com | grep -E "@.*\." | sort | uniq
```

#### DNS Enumeration

```bash
# Basic DNS records
dig target.com ANY
dig target.com A
dig target.com MX
dig target.com TXT
dig target.com NS

# DNS zone transfer (jika vulnerable)
dig axfr @ns1.target.com target.com
dig axfr @ns2.target.com target.com

# Advanced DNS enumeration dengan dnsenum
dnsenum target.com

# DNSRecon untuk comprehensive enumeration
dnsrecon -d target.com -t std -o dnsrecon_standard.txt
dnsrecon -d target.com -t axfr -o dnsrecon_zone.txt
dnsrecon -d target.com -t brte -D /usr/share/wordlists/dnsrecon.txt -o dnsrecon_brute.txt

# Fierce domain scanner
fierce -dns target.com
```

#### Subdomain Enumeration

```bash
# Sublist3r - Python subdomain enumeration
python3 sublist3r.py -d target.com -o subdomains.txt
python3 sublist3r.py -d target.com -b google,bing,yahoo,virustotal

# Amass - Advanced subdomain enumeration
amass enum -passive -d target.com
amass enum -active -d target.com
amass enum -active -d target.com -config amass.ini

# Subfinder - Fast subdomain enumeration
subfinder -d target.com -o subfinder.txt
subfinder -d target.com -o subfinder.txt -silent

# Assetfinder - Modern subdomain discovery
assetfinder --subs-only target.com

# HTTP probing untuk valid subdomains
cat subdomains.txt | httpx -status-code -title -tech-detect -o valid_subdomains.txt

# CRT.SH certificate transparency log
curl -s https://crt.sh/?q=%25.target.com | grep ".*target.com" | sed 's/<[^>]*>//g' | sort -u
```

#### Search Engine Enumeration (Google Dorking)

```bash
# Basic Google dorking patterns
site:target.com
site:target.com filetype:pdf
site:target.com inurl:admin
site:target.com intitle:"index of"
site:target.com "password"
site:target.com "confidential"

# Advanced dorking untuk specific information
site:target.com ext:sql | ext:dbf | ext:mdb
site:target.com "internal use only"
site:target.com "employee handbook"
site:target.com "VPN access"
site:target.com "network diagram"

# GitHub dorking
site:github.com target.com password
site:github.com target.com "api key"
site:github.com target.com "private key"

# Finding exposed documents
site:target.com filetype:doc OR filetype:docx OR filetype:pdf
site:target.com "confidential" filetype:pdf
```

#### Email Harvesting

```bash
# TheHarvester - Email dan subdomain harvesting
theHarvester -d target.com -l 500 -b google,bing,linkedin
theHarvester -d target.com -l 1000 -b all -f theharvester_output.html

# Hunter.io (API required)
curl "https://api.hunter.io/v2/domain-search?domain=target.com&api_key=YOUR_API_KEY"

# Email format guessing
python3 email_guesser.py target.com

# Extract emails dari website
wget -q -O - http://target.com | grep -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" | sort | uniq
```

#### Social Media Analysis

```bash
# Sherlock - Find username across social networks
python3 sherlock user123

# Install sherlock
pip3 install sherlock
sherlock user123 --site twitter --site linkedin

# Social analyzer - Advanced OSINT tool
python3 social-analyzer.py --username "user123" --websites

# WhatsMyName - Username enumeration
./whatsmyname -u target_user
```

#### Technology Stack Identification

```bash
# BuiltWith via API
curl "https://builtwith.com/target.com?KEY=YOUR_API_KEY"

# Wappalyzer browser extension usage
# Install di Chrome/Firefox dan visit target website

# Netcraft
curl https://toolbar.netcraft.com/site_report?url=http://target.com

# WhatWeb - Technology identification
whatweb target.com
whatweb -v target.com  # Verbose output
whatweb --log-xml=whatweb.xml target.com
```

#### Metadata Extraction

```bash
# Exiftool untuk document metadata
exiftool document.pdf
exiftool *.docx
exiftool -a -u *.jpg

# Metadetect - Web-based metadata extraction
metadetect https://target.com/document.pdf

# FOCA (Windows tool)
# Scan target domain untuk metadata dari public documents

# Extract metadata dari Office documents
python3 oletools/olemeta.py document.doc
```

## Active Reconnaissance

Active reconnaissance melibatkan interaksi langsung dengan target untuk mengumpulkan informasi lebih lanjut.

### Network Mapping

```bash
# Ping sweep untuk discover live hosts
nmap -sn 192.168.1.0/24

# ARP scanning (lebih reliable dari ping sweep)
nmap -PR 192.168.1.0/24

# Host discovery dengan multiple techniques
nmap -PE -PP -PS80,443,22,21 192.168.1.0/24

# Fping untuk fast ping sweep
fping -a -g 192.168.1.0/24 2>/dev/null

# Masscan untuk internet-scale scanning
masscan -p80,443 0.0.0.0/0 --rate=1000 --excludefile exclude.txt
```

### Port Scanning Fundamentals

```bash
# TCP Connect scan (full handshake, detectable)
nmap -sT target.com

# SYN Stealth scan (half-open, less detectable)
nmap -sS target.com

# UDP scan (slow dan noisy)
nmap -sU target.com

# Version detection
nmap -sV target.com

# OS detection
nmap -O target.com

# Aggressive scan (semua features)
nmap -A target.com
```

### Advanced Scanning Techniques

```bash
# TCP ACK scan (firewall enumeration)
nmap -sA target.com

# Window scan
nmap -sW target.com

# FIN scan untuk stealth
nmap -sF target.com

# Null scan
nmap -sN target.com

# Xmas scan
nmap -sX target.com

# Idle scan (zombie attack)
nmap -sI zombie_host target.com

# Decoy scan
nmap -D RND:10 target.com
nmap -D ME,192.168.1.1,10.0.0.1 target.com

# IP protocol scan
nmap -sO target.com

# FTP bounce attack
nmap -b ftp_user:ftp_pass@ftp.server.com target.com
```

### Service Detection

```bash
# Version detection dengan intensity level
nmap -sV --version-intensity 9 target.com
nmap -sV --version-all target.com

# Banner grabbing dengan netcat
nc -nv target.com 80
nc -nv target.com 21

# Telnet banner grabbing
telnet target.com 25
telnet target.com 23

# SSL/TLS certificate inspection
openssl s_client -connect target.com:443
openssl s_client -connect target.com:25 -starttls smtp

# Service specific enumeration
nmap -p21 --script ftp-anon target.com
nmap -p22 --script ssh2-enum-algos target.com
nmap -p80 --script http-title target.com
```

## Specialized Enumeration Tools

### HTTP Enumeration

```bash
# Nikto - Web server scanner
nikto -h http://target.com
nikto -h https://target.com:8443 -o nikto_output.html -Format htm

# Dirb/Dirbuster - Directory enumeration
dirb http://target.com /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
dirb http://target.com -X .php,.asp,.aspx,.jsp

# Gobuster - Modern directory scanner
gobuster dir -u http://target.com -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
gobuster dir -u http://target.com -x php,html -t 50

# Ffuf - Fast web fuzzer
ffuf -w wordlist.txt:FUZZ -u http://target.com/FUZZ
ffuf -w wordlist.txt -u http://target.com/FUZZ -mc 200,204,301,302

# Wfuzz - Web application fuzzer
wfuzz -w /usr/share/wordlists/dirb/common.txt --hc 404 http://target.com/FUZZ

# Dirsearch - Python directory scanner
python3 dirsearch.py -u http://target.com -e php,asp,aspx -x 403,404
```

### SMB Enumeration

```bash
# enum4linux-ng - Modern SMB enumeration
enum4linux-ng -A target.com
enum4linux-ng -S target.com  # Share enumeration only
enum4linux-ng -U target.com  # User enumeration only

# smbmap - SMB share enumeration
smbmap -H target.com
smbmap -H target.com -R  # Recursive listing
smbmap -H target.com -u user -p pass
smbmap -H target.com -u guest -p "" -d domain

# smbclient - SMB client
smbclient -L \\\\target.com\\ -N
smbclient \\\\target.com\\share -N

# RPC client
rpcclient -U "" -N target.com
# Commands: enumdomusers, enumdomgroups, querydominfo, netshareenum
```

### SNMP Enumeration

```bash
# onesixtyone - Fast SNMP scanner
onesixtyone target.com
onesixtyone -c community.txt targets.txt

# snmpwalk - SNMP information gathering
snmpwalk -c public -v1 target.com
snmpwalk -c private -v2c target.com
snmpwalk -v3 -l authPriv -u admin -a MD5 -A pass -x DES -X privpass target.com

# snmp-check - SNMP enumeration script
snmp-check target.com
snmp-check -c public target.com
snmp-check -c private target.com

# SNMP MIB browser
# Use dengan GUI tools seperti iReasoning MIB Browser
```

### FTP Enumeration

```bash
# FTP banner grabbing
nc -nv target.com 21
telnet target.com 21

# Anonymous FTP access test
ftp target.com
# Username: anonymous
# Password: anonymous@email.com

# Automated FTP enum dengan nmap
nmap -p21 --script ftp-anon,ftp-bounce,ftp-proftpd-backdoor target.com

# FTP user enumeration (jika available)
nmap -p21 --script ftp-brute target.com
```

### SMTP Enumeration

```bash
# SMTP banner grabbing
nc -nv target.com 25
telnet target.com 25

# SMTP commands
HELO test.com
VRFY username
EXPN mailing-list
HELP

# SMTP user enumeration
smtp-user-enum -M VRFY -U users.txt -t target.com
smtp-user-enum -M EXPN -D target.com -U users.txt -t target.com

# Nmap SMTP scripts
nmap -p25 --script smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344 target.com
```

## Automation Scripts

### Comprehensive Recon Script

```bash
#!/bin/bash
# recon.sh - Comprehensive reconnaissance script

TARGET=$1
OUTPUT_DIR="recon_${TARGET}_$(date +%Y%m%d_%H%M%S)"
mkdir -p $OUTPUT_DIR

echo "[*] Starting reconnaissance for $TARGET"

# Passive reconnaissance
echo "[*] Starting passive reconnaissance..."

# Whois lookup
echo "[+] Performing whois lookup..."
whois $TARGET > $OUTPUT_DIR/whois.txt

# DNS enumeration
echo "[+] Performing DNS enumeration..."
dig $TARGET ANY > $OUTPUT_DIR/dns_any.txt
dig $TARGET MX > $OUTPUT_DIR/dns_mx.txt
dig $TARGET TXT > $OUTPUT_DIR/dns_txt.txt
nslookup $TARGET > $OUTPUT_DIR/nslookup.txt

# Subdomain enumeration
echo "[+] Enumerating subdomains..."
subfinder -d $TARGET -o $OUTPUT_DIR/subdomains.txt
amass enum -passive -d $TARGET -o $OUTPUT_DIR/subdomains_amass.txt
cat $OUTPUT_DIR/subdomains.txt $OUTPUT_DIR/subdomains_amass.txt | sort -u > $OUTPUT_DIR/all_subdomains.txt

# Search for subdomain takeover opportunities
subjack -w $OUTPUT_DIR/all_subdomains.txt -t 100 -ssl -a -v -o $OUTPUT_DIR/subjack_results.txt

# Port scanning
echo "[*] Starting port scanning..."

# Nmap scan
echo "[+] Performing nmap scan..."
nmap -sS -sV -O -A -T4 -oA $OUTPUT_DIR/nmap_full $TARGET
nmap -p- -T4 -oN $OUTPUT_DIR/nmap_all_ports $TARGET
nmap -sU --top-ports 100 -oN $OUTPUT_DIR/nmap_udp_top100 $TARGET

# Web enumeration
echo "[+] Performing web enumeration..."
gobuster dir -u http://$TARGET -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o $OUTPUT_DIR/gobuster_http.txt
gobuster dir -u https://$TARGET -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o $OUTPUT_DIR/gobuster_https.txt

# Nikto scan
nikto -h http://$TARGET -o $OUTPUT_DIR/nikto_http.html -Format htm
nikto -h https://$TARGET -o $OUTPUT_DIR/nikto_https.html -Format htm

# Technology identification
echo "[+] Identifying technologies..."
whatweb -v $TARGET > $OUTPUT_DIR/whatweb.txt
curl -I http://$TARGET > $OUTPUT_DIR/http_headers.txt

# Generate summary
echo "[*] Generating summary..."
cat > $OUTPUT_DIR/summary.txt << EOF
Reconnaissance Summary for $TARGET
Date: $(date)

1. Subdomains Found: $(wc -l < $OUTPUT_DIR/all_subdomains.txt)
2. Open TCP Ports: $(grep "open" $OUTPUT_DIR/nmap_full.nmap | wc -l)
3. Open UDP Ports: $(grep "open" $OUTPUT_DIR/nmap_udp_top100.nmap | wc -l)
4. Web Directories Found: $(grep "Status:" $OUTPUT_DIR/gobuster_http.txt | grep "200" | wc -l)

Key Findings:
- Check for subdomain takeover in subjack_results.txt
- Review interesting ports in nmap scans
- Analyze web directories in gobuster results
EOF

echo "[+] Reconnaissance complete. Results saved in $OUTPUT_DIR"
```

### Targeted Domain Scanner

```python
#!/usr/bin/env python3
# domain_scanner.py - Advanced domain reconnaissance

import requests
import subprocess
import dns.resolver
import sys
import re
import concurrent.futures
from urllib.parse import urlparse

class DomainScanner:
    def __init__(self, domain):
        self.domain = domain
        self.results = {
            'subdomains': set(),
            'ips': set(),
            'technologies': set(),
            'open_ports': [],
            'emails': set()
        }

    def enumerate_subdomains(self):
        """Enumerate subdomains menggunakan multiple sources"""
        sources = [
            self._sublist3r,
            self._amass,
            self._crtsh
        ]

        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            executor.map(lambda func: func(), sources)

    def _sublist3r(self):
        try:
            result = subprocess.run(['python3', 'sublist3r.py', '-d', self.domain, '-o', 'temp_sub.txt'],
                                  capture_output=True, text=True)
            if result.returncode == 0:
                with open('temp_sub.txt') as f:
                    self.results['subdomains'].update([line.strip() for line in f])
        except:
            pass

    def _amass(self):
        try:
            result = subprocess.run(['amass', 'enum', '-passive', '-d', self.domain, '-o', 'temp_amass.txt'],
                                  capture_output=True, text=True)
            if result.returncode == 0:
                with open('temp_amass.txt') as f:
                    self.results['subdomains'].update([line.strip() for line in f])
        except:
            pass

    def _crtsh(self):
        try:
            url = f"https://crt.sh/?q=%.{self.domain}"
            response = requests.get(url)
            subdomains = re.findall(r'([a-zA-Z0-9.-]+' + re.escape(self.domain) + r')', response.text)
            self.results['subdomains'].update(subdomains)
        except:
            pass

    def resolve_subdomains(self):
        """Resolve subdomains ke IP addresses"""
        for subdomain in self.results['subdomains']:
            try:
                dns.resolver.resolve(subdomain, 'A')
                ip = dns.resolver.resolve(subdomain, 'A')[0].to_text()
                self.results['ips'].add(ip)
            except:
                pass

    def scan_ports(self, ip, ports="22,80,443,8080,8443"):
        """Scan common ports"""
        try:
            result = subprocess.run(['nmap', '-p', ports, ip, '-oG', '-'],
                                  capture_output=True, text=True)
            open_ports = re.findall(r'(\d+)/open/tcp', result.stdout)
            self.results['open_ports'].extend([(ip, port) for port in open_ports])
        except:
            pass

    def detect_technologies(self, url):
        """Detect web technologies"""
        try:
            response = requests.get(url, timeout=5)
            # Check common technology signatures
            if 'X-Powered-By' in response.headers:
                self.results['technologies'].add(response.headers['X-Powered-By'])
            if 'Server' in response.headers:
                self.results['technologies'].add(response.headers['Server'])

            # Check for common frameworks
            if 'wp-content' in response.text or 'wp-json' in response.text:
                self.results['technologies'].add('WordPress')
            if 'Powered by Drupal' in response.text:
                self.results['technologies'].add('Drupal')
            if 'joomla' in response.text.lower():
                self.results['technologies'].add('Joomla')
        except:
            pass

    def extract_emails(self, url):
        """Extract email addresses dari website"""
        try:
            response = requests.get(url, timeout=5)
            emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b', response.text)
            self.results['emails'].update(emails)
        except:
            pass

    def run(self):
        """Run full reconnaissance"""
        print(f"[*] Starting reconnaissance for {self.domain}")

        print("[+] Enumerating subdomains...")
        self.enumerate_subdomains()

        print("[+] Resolving subdomains...")
        self.resolve_subdomains()

        print("[+] Scanning ports...")
        for ip in self.results['ips']:
            self.scan_ports(ip)

        print("[+] Detecting technologies...")
        for subdomain in list(self.results['subdomains'])[:10]:  # Limit untuk speed
            try:
                url = f"http://{subdomain}"
                self.detect_technologies(url)
                self.extract_emails(url)
            except:
                pass

        return self.results

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <domain>")
        sys.exit(1)

    domain = sys.argv[1]
    scanner = DomainScanner(domain)
    results = scanner.run()

    print("\n[*] Results:")
    print(f"Subdomains found: {len(results['subdomains'])}")
    print(f"IP addresses: {len(results['ips'])}")
    print(f"Open ports: {len(results['open_ports'])}")
    print(f"Technologies: {results['technologies']}")
    print(f"Emails: {results['emails']}")

if __name__ == "__main__":
    main()
```

## Best Practices

### Legal and Ethical Considerations

1. **Authorization** - Pastikan ada written permission
2. **Scope Definition** - Tetapkan jelas scope testing
3. **Rate Limiting** - Jangan overwhelms target systems
4. **Privacy Compliance** - Hati-hati dengan personal data
5. **Responsible Disclosure** - Report vulnerabilities dengan benar

### Operational Security (OPSEC)

```bash
# Use VPN atau proxy untuk hide IP
# Configure dengan:
vpn_config="/path/to/vpn.conf"
openvpn $vpn_config

# Use user agent rotation
user_agents=(
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
    "Mozilla/5.0 (X11; Linux x86_64)"
)

# Random delays antar requests
sleep $((RANDOM % 5 + 1))

# Use different source ports untuk evasion
nmap -g 53 target.com  # Use DNS source port
nmap -sI attacker.com target.com  # Use idle scan
```

### Documentation and Reporting

```bash
# Organize hasil reconnaissance
mkdir -p recon_results/{whois,dns,subdomains,ports,web}
mv whois.txt recon_results/whois/
mv dns_*.txt recon_results/dns/
mv subdomains.txt recon_results/subdomains/
mv nmap_*.nmap recon_results/ports/
mv gobuster_*.txt recon_results/web/

# Create timeline documentation
echo "Reconnaissance Timeline for $TARGET" > recon_timeline.txt
echo "$(date): Started reconnaissance" >> recon_timeline.txt
echo "$(date): Completed whois lookup" >> recon_timeline.txt
echo "$(date): Completed subdomain enumeration" >> recon_timeline.txt
# ... continue adding milestones
```

## Common Pitfalls and Solutions

### Issue: DNS Rate Limiting

```bash
# Solution: Use multiple sources dan delays
# Implement delay di enumeration script
sleep 1  # Wait 1 second antar DNS queries
# Use resolvers yang berbeda
dig @8.8.8.8 target.com
dig @1.1.1.1 target.com
dig @9.9.9.9 target.com
```

### Issue: WAF/IDS Detection

```bash
# Solution: Use stealth techniques
nmap -sS -Pn -n --randomize-hosts target.com
nmap -D RND:10 -f target.com  # Decoy dan fragmentation

# Use timing templates
nmap -T0 target.com  # Paranoid (very slow)
nmap -T1 target.com  # Sneaky (slow)
```

### Issue: Invalid Certificates

```bash
# Skip certificate verification
curl -k https://target.com
nmap -p 443 --script ssl-enum-ciphers --script-args ssl.default_protocols target.com
```

Reconnaissance adalah foundation untuk seluruh penetration testing process. Informasi yang dikumpulkan di fase ini akan memandu exploitation strategies dan menentukan success rate dari engagement. Selalu thorough dalam reconnaissance - "you miss 100% of the shots you don't take."