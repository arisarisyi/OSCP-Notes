# 1. Information Gathering

## 1.1 Reconnaissance

### Passive Reconnaissance
Passive reconnaissance adalah proses mengumpulkan informasi tentang target tanpa melakukan interaksi langsung dengan sistem target.

#### Tools & Techniques:

**OSINT Framework Gathering:**
```bash
# Whois lookup
whois target.com

# DNS enumeration
dig target.com ANY
nslookup target.com
host -t any target.com

# Google Dorking
site:target.com
site:target.com filetype:pdf
site:target.com inurl:admin
site:github.com target.com password
```

**Subdomain Enumeration:**
```bash
# Sublist3r
python3 sublist3r.py -d target.com -o subdomains.txt

# Amass (need API keys for better results)
amass enum -d target.com -o amass_output.txt

# DNSRecon
dnsrecon -d target.com -t std -o dnsrecon.txt

# Subfinder
subfinder -d target.com -o subfinder.txt

# VirtualHost discovery
gobuster vhost -u target.com -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

**Email & Employee Enumeration:**
```bash
# TheHarvester
theHarvester -d target.com -l 500 -b google,linkedin

# Hunter.io (web interface)
https://hunter.io/

# Email format guessing
python3 ./email_guesser.py target.com
```

**Social Media Analysis:**
```bash
# Sherlock - Find usernames across social networks
python3 sherlock target_username

# Maltego (GUI tool)
# Create graph for target organization
```

**Metadata Extraction:**
```bash
# Exiftool for document metadata
exiftool document.pdf

# Metadetect
metadetect target_website.com

# FOCA (Windows tool)
# Analyze metadata from public documents
```

### Active Reconnaissance
Active reconnaissance melibatkan interaksi langsung dengan target untuk mendapatkan informasi lebih lanjut.

#### Port Scanning:

**Nmap - Basic Scanning:**
```bash
# Quick scan of top ports
nmap -T4 target.com

# Full TCP scan
nmap -p- -T4 -oN full_tcp_scan.txt target.com

# UDP scan (slow)
nmap -sU -T4 -oN udp_scan.txt target.com

# Version detection
nmap -sV -oN version_detection.txt target.com

# OS detection
nmap -O -oN os_detection.txt target.com

# Aggressive scan (all features)
nmap -A -T4 -oN aggressive_scan.txt target.com

# Script scanning
nmap -sC --script=default -oN script_scan.txt target.com

# Custom scan with specific scripts
nmap --script "smb-vuln-ms17-010.nse,smb-vuln-ms08-067.nse" target.com
```

**Advanced Nmap Options:**
```bash
# Scan with specific timing (stealthy to insane)
nmap -T0 -sS target.com  # Paranoid
nmap -T1 -sS target.com  # Sneaky
nmap -T5 -sS target.com  # Insane

# Custom port ranges
nmap -p 21-25,80,443,3389 target.com

# Exclude ports
nmap -p- --exclude-port 9100 target.com

# Output formats
nmap -oA target_scan target.com  # All formats
nmap -oX scan.xml target.com     # XML
nmap -oG scan.gnmap target.com   # Greppable

# Source port manipulation
nmap -g 53 target.com  # Use DNS as source port
```

**Masscan:**
```bash
# Mass scanning of internet
masscan -p80,443 0.0.0.0/0 --rate=1000

# Specific target range
masscan -p1-65535 target_range --rate=10000
```

**Zenmap (GUI):**
- Launch: `zenmap`
- Profile selection based on scan type
- Compare scan results
- Topology view

#### Service Detection:

**Service-Specific Scanning:**
```bash
# SMB enumeration
nmap --script smb-enum-shares.nse,smb-enum-users.nse target.com
enum4linux-ng -A target.com
smbclient -L \\\\target.com\\

# HTTP enumeration
nmap --script=http-enum target.com
gobuster dir -u http://target.com -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
feroxbuster -u http://target.com -w /usr/share/seclists/Discovery/Web-Content/common.txt

# FTP enumeration
nmap --script=ftp-anon,ftp-bounce target.com
ftp target.com

# SSH enumeration
nmap --script=ssh2-enum-algos target.com

# SNMP enumeration
nmap -sU -p161 --script=snmp-brute,snmp-sysdescr target.com
snmpwalk -c public -v1 target.com
```

#### Web Application Information Gathering:

**Web Technology Identification:**
```bash
# WhatWeb
whatweb target.com

# Wappalyzer (browser extension)
# Visit target website

# BuiltWith
curl https://builtwith.com/target.com

# Netcraft
curl https://toolbar.netcraft.com/site_report?url=target.com
```

**Directory & File Brute Forcing:**
```bash
# Dirb
dirb http://target.com /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

# Dirbuster (GUI)
java -jar DirBuster-1.0-RC1.jar -H

# Gobuster
gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt -x php,asp,aspx,jsp,html

# Ffuf
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://target.com/FUZZ

# Wfuzz
wfuzz -w wordlist.txt --hc 404 http://target.com/FUZZ
```

**Web Application Vulnerability Scanning:**
```bash
# Nikto
nikto -h http://target.com

# Skipfish
skipfish -o skipfish_output http://target.com

# Arachni (GUI)
arachni http://target.com
```

#### DNS Enumeration:

```bash
# DNS enumeration
dnsenum target.com

# DNSmap
dnsmap target.com -w /usr/share/dnsmap/wordlist.txt

# fierce
fierce -dns target.com

# DNS Recon
dnsrecon -d target.com -t axfr
dnsrecon -d target.com -t std
dnsrecon -d target.com -t zone

# Zone transfer attempt
dig axfr @ns1.target.com target.com
```

#### Email Harvesting:

```bash
# TheHarvester comprehensive search
theHarvester -d target.com -l 500 -b google,bing,linkedin,pgp,keybase

# Metagoofil
python3 metagoofil.py -d target.com -l 20 -f pdf,doc,xls,ppt -o /tmp/

# Recovery email addresses from breach databases
# HaveIBeenPwned API
curl "https://haveibeenpwned.com/api/v2/breachedaccount/target@domain.com"
```

## 1.2 Scanning & Enumeration

### Network Scanning

**Comprehensive Network Discovery:**
```bash
# Ping sweep of network
nmap -sn 192.168.1.0/24

# ARP scanning (faster than ping sweep)
nmap -PR 192.168.1.0/24

# List scan without pinging
nmap -sL 192.168.1.0/24

# Sweep for specific ports across network
nmap -p 445,3389 192.168.1.0/24
```

**Advanced Host Discovery:**
```bash
# Multiple host discovery techniques
nmap -PP -PE -PS80,443 -PA3389 192.168.1.0/24

# Custom host discovery scripts
nmap --script hostmap-crtsh target.com
nmap --script dns-brute target.com
```

### Port Scanning Techniques

**TCP Scanning Methods:**
```bash
# TCP Connect scan (full handshake)
nmap -sT target.com

# SYN Stealth scan (half open)
nmap -sS target.com

# FIN, NULL, Xmas scans (for evasion)
nmap -sF target.com
nmap -sN target.com
nmap -sX target.com

# Maimon scan
nmap -sM target.com

# TCP ACK scan (firewall detection)
nmap -sA target.com

# Window scan
nmap -sW target.com
```

**UDP Scanning:**
```bash
# UDP scan
nmap -sU target.com

# UDP scan with version detection
nmap -sU -sV target.com

# Common UDP ports
nmap -sU -p 53,161,137,138,139,69,123,162 target.com
```

**Advanced Scanning Options:**
```bash
# IP protocol scan
nmap -sO target.com

# FTP bounce scan
nmap -b user:pass@ftp.server.com target.com

# Idle scan (zombie)
nmap -sI zombie_host target.com

# Decoy scan
nmap -D RND:10 target.com  # Use 10 random decoys
nmap -D ME,192.168.1.10,10.0.0.1 target.com  # Specific decoys
```

### Service & Version Detection

**Intensive Version Scanning:**
```bash
# Version detection with intensity level
nmap -sV --version-intensity 9 target.com

# Light version detection
nmap -sV --version-intensity 0 target.com

# Version light
nmap -sV --version-light target.com

# Version all (try every probe)
nmap -sV --version-all target.com
```

**Service Fingerprinting:**
```bash
# Banner grabbing
nc -nv target.com 80
telnet target.com 21

# SSL/TLS certificate inspection
openssl s_client -connect target.com:443

# Service specific scripts
nmap --script=http-title target.com
nmap --script=http-server-header target.com
nmap --script=ssh-hostkey target.com
```

### OS Detection

**OS Fingerprinting:**
```bash
# OS detection
nmap -O target.com

# OS detection with limit TTL
nmap -O --osscan-limit target.com

# OS detection guess only
nmap -O --osscan-guess target.com

# Aggressive OS detection
nmap -A target.com  # Includes OS detection
```

**Advanced OS Detection:**
```bash
# TTL fingerprinting
ping target.com
# TTL 64 = Linux
# TTL 128 = Windows
# TTL 255 = Cisco/Network device

# TCP/IP stack fingerprinting
hping3 -S target.com -p 80 -c 5
```

### Vulnerability Scanning

**Nmap Scripting Engine (NSE):**
```bash
# All vulnerability scripts
nmap --script vuln target.com

# Specific vulnerability categories
nmap --script "auth,brute" target.com
nmap --script "exploit" target.com
nmap --script "discovery" target.com

# SMB vulnerability scanning
nmap --script smb-vuln-ms17-010 target.com
nmap --script smb-vuln-ms08-067 target.com
nmap --script smb-vuln-cve2017-7494 target.com

# HTTP vulnerability scanning
nmap --script http-sql-injection target.com
nmap --script http-xssed target.com
nmap --script http-csrf target.com
```

**Specialized Vulnerability Scanners:**
```bash
# Nessus (GUI/Web interface)
# Professional vulnerability scanner
# Access via https://localhost:8834

# OpenVAS (Open-source alternative to Nessus)
# Web interface for vulnerability management

# Nikto (web vulnerability scanner)
nikto -h http://target.com -o nikto_output.html -Format htm

# Uniscan (web vulnerability scanner)
uniscan -u http://target.com -qweds
```

## 1.3 Enumeration Techniques

### SMB Enumeration

**SMB Share Enumeration:**
```bash
# Enum4linux-ng (modern version)
enum4linux-ng -A target.com
enum4linux-ng -S target.com  # Share enumeration only
enum4linux-ng -U target.com  # User enumeration only

# smbclient
smbclient -L \\\\target.com\\ -N
smbclient \\\\target.com\\share -N

# smbmap
smbmap -H target.com
smbmap -H target.com -R  # Recursive listing
smbmap -H target.com -u "user" -p "password"
```

**SMB Null Session:**
```bash
# Null session connection
rpcclient -U "" -N target.com

# Once connected
enumdomusers
enumdomgroups
querydominfo
netshareenum
netshareenumall
```

**SMB Vulnerability Testing:**
```bash
# MS17-010 (EternalBlue)
nmap --script smb-vuln-ms17-010 target.com

# MS08-067
nmap --script smb-vuln-ms08-067 target.com

# SMB signing check
nmap -p445 --script smb2-security-mode target.com
```

### SMTP Enumeration

**SMTP Commands:**
```bash
# Connect to SMTP
nc target.com 25
telnet target.com 25

# Commands within SMTP session
HELO test.com
VRFY username
EXPN mailing-list
RCPT TO: recipient@target.com
```

**SMTP Enumeration Tools:**
```bash
# smtp-user-enum
smtp-user-enum -M VRFY -U users.txt -t target.com
smtp-user-enum -M EXPN -D target.com -U users.txt -t target.com

# Netcat for banner grabbing
nc -nv target.com 25
```

### SNMP Enumeration

**SNMP Community String Brute Force:**
```bash
# onesixtyone (fast SNMP scanner)
onesixtyone target.com

# snmpwalk with community strings
snmpwalk -c public -v1 target.com
snmpwalk -c private -v1 target.com
snmpwalk -c manager -v2c target.com

# snmp-check
snmp-check target.com
```

**SNMP Enumeration Scripts:**
```bash
# Nmap SNMP scripts
nmap -sU -p161 --script snmp-brute target.com
nmap -sU -p161 --script snmp-sysdescr target.com
nmap -sU -p161 --script snmp-processes target.com
nmap -sU -p161 --script snmp-win32-users target.com

# Custom SNMP queries
snmpwalk -c public -v1 target.com 1.3.6.1.2.1.25.1.6.0  # Running processes
snmpwalk -c public -v1 target.com 1.3.6.1.2.1.25.4.2.1.2  # Software installed
```

### FTP Enumeration

**Anonymous FTP Login:**
```bash
# Anonymous login
ftp target.com
Username: anonymous
Password: anonymous@email.com

# Commands after login
ls -la
get file.txt
mget *.txt
put localfile.txt
```

**FTP Enumeration Commands:**
```bash
# Banner grabbing
nc -nv target.com 21

# Automated FTP enum
nmap -p21 --script=ftp-anon,ftp-bounce target.com

# FTP brute force
hydra -L users.txt -P passwords.txt ftp://target.com
medusa -u admin -P passwords.txt -h target.com -M ftp
```

### Web Application Enumeration

**HTTP Header Analysis:**
```bash
# curl for headers
curl -I http://target.com
curl -v http://target.com

# Nikto for web server info
nikto -host http://target.com -o nikto_output.txt
```

**Technology Stack Identification:**
```bash
# Wappalyzer browser extension
# Chrome/Firefox extension

# BuiltWith online tool
curl https://builtwith.com/target.com

# WhatWeb
whatweb target.com
whatweb -v target.com  # Verbose output
```

**Directory & File Discovery:**
```bash
# Dirb with extensions
dirb http://target.com /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -X .php,.asp,.aspx,.jsp

# Gobuster with status codes
gobuster dir -u http://target.com -w wordlist.txt -x php,html -t 50

# Ffuf with filters
ffuf -w wordlist.txt:FUZZ -u http://target.com/FUZZ -mc 200,204,301,302

# Dirsearch
python3 dirsearch.py -u http://target.com -e php,asp,aspx -x 403,404
```

**Web Application Firewall Detection:**
```bash
# WAFW00F
wafw00f http://target.com

# Nmap WAF detection
nmap --script http-waf-detect target.com
```

### Database Enumeration

**MySQL Enumeration:**
```bash
# Nmap MySQL scripts
nmap -p3306 --script mysql-brute,mysql-info,mysql-users target.com

# MySQL connection
mysql -h target.com -u root -p

# Commands within MySQL
SHOW DATABASES;
SHOW TABLES;
SELECT user FROM mysql.user;
```

**MSSQL Enumeration:**
```bash
# Nmap MSSQL scripts
nmap -p1433 --script ms-sql-info,ms-sql-empty-password,ms-sql-brute target.com

# sqsh command line
sqsh -S target.com -U sa -P password

# PowerShell for MSSQL
Invoke-Sqlcmd -ServerInstance target.com -Query "SELECT name FROM sys.databases"
```

### Active Directory Enumeration

**Domain Information:**
```bash
# BloodHound data collection
# From Windows:
SharpHound.exe -c All
SharpHound.exe -c Session,LoggedOn

# Impacket tools
python3 GetUserSPNs.py target.com/domainuser:password
python3 GetUserSPNs.py target.com/ -dc-ip DC_IP

# LDAP enumeration
ldapsearch -x -H ldap://target.com -D "domainuser" -W -b "DC=target,DC=com"
```

**Domain Controller Enumeration:**
```bash
# Nmap AD scripts
nmap -p88,389,445 --script smb-os-discovery target.com

# Kerberos enumeration
nmap -p88 --script krb5-enum-users target.com

# Domain trust discovery
nmap -p445 --script smb-enum-domains target.com
```

## Important Notes

1. **Stealth Considerations:**
   - Use timing templates appropriately (T0-T5)
   - Implement delays between scans
   - Use decoys and spoofed IP addresses
   - Consider scan order (UDP before TCP)

2. **Documentation:**
   - Save all scan results in organized folders
   - Use consistent naming conventions
   - Document findings with timestamps
   - Create network maps and diagrams

3. **False Positives:**
   - Always validate findings manually
   - Cross-reference with multiple tools
   - Consider network conditions
   - Verify exploitability before reporting

4. **Rate Limiting:**
   - Respect target system resources
   - Implement delays in scripts
   - Monitor for IDS/IPS responses
   - Use evasion techniques when necessary

## Common Pitfalls & Solutions

**Issue: ICMP blocked, can't ping sweep**
```bash
# Solution: Use ARP scanning
nmap -PR 192.168.1.0/24

# Or use TCP ACK scan for host discovery
nmap -PA80,443 192.168.1.0/24
```

**Issue: Scans taking too long**
```bash
# Solution: Adjust timing and limit ports
nmap -T4 --max-retries 1 -oX scan.xml target.com
nmap --top-ports 1000 target.com
```

**Issue: IDS/IPS detection**
```bash
# Solution: Use decoys and fragmentation
nmap -D RND:10 -f target.com

# Or source port manipulation
nmap -g 53 target.com  # Use DNS source port
```