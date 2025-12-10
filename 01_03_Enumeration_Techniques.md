# 1.3 Enumeration Techniques

Enumeration adalah proses mengumpulkan informasi detail tentang services, shares, users, dan resources yang available di target system. Ini adalah langkah aktif untuk memahuni how system works dan mencari exploitation vectors.

## Enumeration Methodology

### 1. Service Identification
- Determine running services
- Identify service versions
- Check configuration

### 2. Resource Discovery
- Find shared resources
- Identify user accounts
- Locate sensitive files

### 3. Vulnerability Mapping
- Map configurations to vulnerabilities
- Identify misconfigurations
- Document exploitation paths

## SMB Enumeration

### Basic SMB Commands

```bash
# SMB version detection
nmap -p445 --script smb-protocols target.com
nmap -p445 --script smb2-security-mode target.com

# Null session check
nmap -p445 --script smb-null-sessions target.com

# SMB signing check
nmap -p445 --script smb2-security-mode target.com
```

### Enum4linux-ng (Modern SMB Enumeration)

```bash
# Full enumeration
enum4linux-ng -A target.com
# -A untuk all options

# Share enumeration only
enum4linux-ng -S target.com

# User enumeration only
enum4linux-ng -U target.com

# Workgroup enumeration
enum4linux-ng -W target.com

# Password policy enumeration
enum4linux-ng -P target.com

# OS information
enum4linux-ng -o target.com

# Detailed share listing
enum4linux-ng -s target.com
```

### SMB Client Tools

```bash
# smbclient - Command line SMB client
# Connect ke target
smbclient -L \\\\target.com\\ -N  # Null session

# Connect ke specific share
smbclient \\\\target.com\\IPC$ -N
smbclient \\\\target.com\\C$ -U user

# Commands dalam smbclient session
ls        # List files
cd        # Change directory
get       # Download file
put       # Upload file
pwd       # Print working directory
```

### SMBMap - SMB Share Enumeration

```bash
# Basic share listing
smbmap -H target.com

# Recursive listing
smbmap -H target.com -R

# With credentials
smbmap -H target.com -u "user" -p "password"

# Domain authentication
smbmap -H target.com -u "domain\\user" -p "password"

# Download semua files
smbmap -H target.com -R -A "download"

# Find interesting files
smbmap -H target.com -R -A "find,-iname,*pass*"

# Specific depth
smbmap -H target.com -R -A "ls -la" -d 3
```

### RPC Client

```bash
# Connect dengan null session
rpcclient -U "" -N target.com

# Available commands setelah connect
srvinfo                # Server information
enumdomusers           # Enumerate domain users
enumdomgroups          # Enumerate domain groups
querydominfo           # Domain information
netshareenum           # Enumerate shares
netshareenumall        # Enumerate all shares
lsaquery               # LSA query
lookupnames            # Lookup SID/NAME
lookuprids             # Lookup RIDs
queryuser              # Query user information
querygroup             # Query group information
```

### SMB Vulnerability Enumeration

```bash
# Check untuk EternalBlue (MS17-010)
nmap --script smb-vuln-ms17-010 target.com

# Check MS08-067
nmap --script smb-vuln-ms08-067 target.com

# Check untuk SMB vulnerabilities
nmap -p445 --script "smb-vuln-*" target.com

# Manual EternalBlue check
python2 ms17-010.py target.com

# Check untuk SMB exploitation
nmap -p445 --script smb-psexec target.com
```

## SMTP Enumeration

### Basic SMTP Commands

```bash
# Connect ke SMTP server
nc target.com 25
telnet target.com 25

# SMTP commands setelah connect
HELO test.com          # Greeting
EHLO test.com          # Extended greeting
MAIL FROM:<user@test.com>  # Sender
RCPT TO:<user@target.com>   # Recipient
DATA                   # Start message
.                      # End message
QUIT                   # Disconnect

# VRFY - Verify user existence
VRFY user@target.com

# EXPN - Expand mailing list
EXPN mailing-list@target.com
```

### SMTP User Enumeration Tools

```bash
# smtp-user-enum
smtp-user-enum -M VRFY -U users.txt -t target.com
smtp-user-enum -M EXPN -D target.com -U users.txt -t target.com
smtp-user-enum -M RCPT -D target.com -U users.txt -t target.com

# Scan port 25,587,465
smtp-user-enum -p 25 -M VRFY -U users.txt -t target.com
smtp-user-enum -p 587 -M VRFY -U users.txt -t target.com

# Throttle requests
smtp-user-enum -M VRFY -U users.txt -t target.com -w 0.5
```

### Nmap SMTP Scripts

```bash
# SMTP commands enumeration
nmap -p25 --script smtp-commands target.com

# SMTP user enumeration
nmap -p25 --script smtp-enum-users target.com

# SMTP open relay test
nmap -p25 --script smtp-open-relay target.com

# SMTP vulnerabilities
nmap -p25 --script "smtp-vuln-*" target.com
```

### Advanced SMTP Enumeration

```python
#!/usr/bin/env python3
# smtp_enum.py - Custom SMTP enumeration

import socket
import sys
import threading

def test_user(target, user, port=25):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((target, port))

        # Read banner
        banner = s.recv(1024).decode()

        # Send HELO
        s.send(b"HELO test.com\r\n")
        s.recv(1024)

        # Test VRFY
        s.send(f"VRFY {user}\r\n".encode())
        response = s.recv(1024).decode()

        if "250" in response or "252" in response:
            print(f"[+] Valid user: {user}")

        s.close()
    except Exception as e:
        pass

def main():
    target = sys.argv[1]
    users_file = sys.argv[2]

    with open(users_file) as f:
        users = [line.strip() for line in f]

    print(f"[*] Enumerating users on {target}")

    for user in users:
        test_user(target, user)
```

## SNMP Enumeration

### Basic SNMP Commands

```bash
# SNMP walk public community
snmpwalk -c public -v1 target.com
snmpwalk -c public -v2c target.com

# Specific OID
snmpwalk -c public -v2c target.com 1.3.6.1.2.1.1

# SNMPv3
snmpwalk -v3 -l authPriv -u admin -a MD5 -A pass -x DES -X privpass target.com

# SNMP get single OID
snmpget -c public -v1 target.com 1.3.6.1.2.1.1.1.0
```

### SNMP Information Gathering

```bash
# System information
snmpwalk -c public -v2c target.com 1.3.6.1.2.1.1

# Interface information
snmpwalk -c public -v2c target.com 1.3.6.1.2.1.2.2

# Running processes
snmpwalk -c public -v2c target.com 1.3.6.1.2.1.25.1.6

# Software installed
snmpwalk -c public -v2c target.com 1.3.6.1.2.1.25.4.2.1.2

# User accounts (Windows)
snmpwalk -c public -v2c target.com 1.3.6.1.4.1.77.1.2.25

# Windows services
snmpwalk -c public -v2c target.com 1.3.6.1.4.1.77.1.2.3.1

# TCP connections
snmpwalk -c public -v2c target.com 1.3.6.1.2.1.6.13
```

### SNMP Community String Brute Force

```bash
# onesixtyone - Fast SNMP scanner
onesixtyone target.com
onesixtyone -c community.txt target.com

# Common community strings list
cat > community.txt << EOF
public
private
community
manager
admin
cisco
snmp
EOF

# Multiple targets
onesixtyone -c community.txt targets.txt
```

### Nmap SNMP Scripts

```bash
# SNMP system description
nmap -sU -p161 --script snmp-sysdescr target.com

# SNMP processes
nmap -sU -p161 --script snmp-processes target.com

# SNMP Windows users
nmap -sU -p161 --script snmp-win32-users target.com

# SNMP Windows services
nmap -sU -p161 --script snmp-win32-services target.com

# SNMP interfaces
nmap -sU -p161 --script snmp-interfaces target.com

# SNMP brute force
nmap -sU -p161 --script snmp-brute target.com
```

### SNMP Enumeration with Check Script

```bash
#!/bin/bash
# snmp_enum.sh - Comprehensive SNMP enumeration

TARGET=$1
COMMUNITIES=("public" "private" "manager" "admin" "cisco")

echo "[*] SNMP enumeration for $TARGET"

for community in "${COMMUNITIES[@]}"; do
    echo "[-] Trying community: $community"

    # Test if community works
    if snmpget -v2c -c $community $TARGET 1.3.6.1.2.1.1.1.0 >/dev/null 2>&1; then
        echo "[+] Valid community: $community"

        # System info
        echo "[+] System Information:"
        snmpwalk -v2c -c $community $TARGET 1.3.6.1.2.1.1

        # Network interfaces
        echo "[+] Network Interfaces:"
        snmpwalk -v2c -c $community $TARGET 1.3.6.1.2.1.2.2.1

        # Running processes
        echo "[+] Running Processes:"
        snmpwalk -v2c -c $community $TARGET 1.3.6.1.2.1.25.1.6

        # Software (Linux)
        echo "[+] Installed Software:"
        snmpwalk -v2c -c $community $TARGET 1.3.6.1.2.1.25.4.2.1.2 2>/dev/null

        # Windows users
        echo "[+] Windows Users:"
        snmpwalk -v2c -c $community $TARGET 1.3.6.1.4.1.77.1.2.25 2>/dev/null

        break
    fi
done
```

## FTP Enumeration

### Basic FTP Commands

```bash
# Connect ke FTP
ftp target.com

# Anonymous login
Username: anonymous
Password: anonymous@email.com

# FTP commands
ls             # List files
dir            # Detailed list
pwd            # Print working directory
cd             # Change directory
get file.txt   # Download file
put file.txt   # Upload file
mget *.txt     # Download multiple files
mput *.txt     # Upload multiple files
binary         # Binary transfer mode
ascii          # ASCII transfer mode
```

### Automated FTP Enumeration

```bash
# Nmap FTP scripts
nmap -p21 --script ftp-anon target.com
nmap -p21 --script ftp-bounce target.com
nmap -p21 --script ftp-proftpd-backdoor target.com
nmap -p21 --script ftp-libopie target.com
nmap -p21 --script ftp-vsftpd-backdoor target.com

# FTP brute force
nmap -p21 --script ftp-brute target.com
nmap -p21 --script ftp-brute --script-args userdb=users.txt,passdb=pass.txt target.com
```

### FTP Banner Grabbing

```bash
# Banner grab dengan netcat
nc -nv target.com 21
echo "QUIT" | nc target.com 21

# Banner grab dengan telnet
telnet target.com 21

# Banner grab dengan nmap
nmap -sV -p21 target.com
nmap -p21 --script ftp-banner target.com
```

### FTP Passive vs Active Mode

```bash
# Passive mode enumeration
ftp -p target.com

# Active mode enumeration
ftp -A target.com

# Check FTP mode
ftp target.com
ftp> passive
ftp> ascii
```

## Database Enumeration

### MySQL Enumeration

```bash
# Nmap MySQL scripts
nmap -p3306 --script mysql-info target.com
nmap -p3306 --script mysql-variables target.com
nmap -p3306 --script mysql-databases target.com
nmap -p3306 --script mysql-users target.com
nmap -p3306 --script mysql-empty-password target.com
nmap -p3306 --script mysql-enum target.com

# Manual MySQL connection
mysql -h target.com -u root -p

# Commands dalam MySQL
SHOW DATABASES;
SHOW TABLES;
SHOW VARIABLES;
SELECT user FROM mysql.user;
SELECT * FROM mysql.user;
SELECT database();
```

### MSSQL Enumeration

```bash
# Nmap MSSQL scripts
nmap -p1433 --script ms-sql-info target.com
nmap -p1433 --script ms-sql-config target.com
nmap -p1433 --script ms-sql-dump-hashes target.com
nmap -p1433 --script ms-sql-empty-password target.com
nmap -p1433 --script ms-sql-brute target.com

# Manual MSSQL connection
sqlcmd -S target.com -U sa -P password

# Commands dalam SQLCMD
SELECT @@VERSION;
SELECT name FROM sys.databases;
SELECT name FROM sys.tables;
```

### PostgreSQL Enumeration

```bash
# Nmap PostgreSQL scripts
nmap -p5432 --script pgsql-info target.com
nmap -p5432 --script pgsql-databases target.com
nmap -p5432 --script pgsql-users target.com
nmap -p5432 --script pgsql-brute target.com

# Manual PostgreSQL connection
psql -h target.com -U postgres

# Commands dalam psql
\l  -- List databases
\dt -- List tables
\du -- List users
SELECT version();
```

### Oracle Database Enumeration

```bash
# Nmap Oracle scripts
nmap -p1521 --script oracle-enum-users target.com
nmap -p1521 --script oracle-sid-brute target.com

# Manual Oracle connection
sqlplus user/pass@target.com:1521/SID

# Common Oracle SIDs
ORCL
XE
ORCL11G
PROD
DEV
TEST
```

## Active Directory Enumeration

### Domain Controller Enumeration

```bash
# Domain information discovery
nmap -p88,389,445 --script smb-os-discovery target.com

# Kerberos information
nmap -p88 --script krb5-enum-users target.com

# LDAP enumeration
nmap -p389 --script ldap-rootdse target.com

# Domain trust enumeration
nmap -p445 --script smb-enum-domains target.com
```

### BloodHound Data Collection

```bash
# SharpHound - Active Directory data collection
# Dari Windows:
SharpHound.exe -c All
SharpHound.exe -c Session,LoggedOn
SharpHound.exe -c LocalGroup,GPOLocalGroup
SharpHound.exe -c ObjectProps,ACL
SharpHound.exe -c Container,SPNTargets

# Dengan specific domain controller
SharpHound.exe -d target.local -c All

# Collection dengan stealth
SharpHound.exe -c All -s

# Output files:
# 20231210123456_computers.json
# 20231210123456_groups.json
# 20231210123456_users.json
# 20231210123456_domains.json
```

### LDAP Enumeration

```bash
# Anonymous LDAP bind
ldapsearch -h target.com -p 389 -x -s base

# LDAP enumeration
ldapsearch -h target.com -p 389 -x -b "DC=target,DC=com"

# LDAP user enumeration
ldapsearch -h target.com -p 389 -x -b "DC=target,DC=com" "(&(objectClass=user)(objectCategory=person))"

# LDAP with authentication
ldapsearch -h target.com -p 389 -x -D "cn=admin,dc=target,dc=com" -w password -b "DC=target,DC=com"

# LDAP dengan SSL/TLS
ldapsearch -H ldaps://target.com:636 -x -b "DC=target,DC=com"
ldapsearch -H ldap://target.com:389 -x -Z -b "DC=target,DC=com"
```

### Impacket Active Directory Tools

```bash
# GetUserSPNs - Kerberos service principal names
python3 GetUserSPNs.py target.com/user:password

# GetNPUsers - Kerberos ASREPRoast
python3 GetNPUsers.py target.com/ -dc-ip dc_ip -no-pass

# secretsdump.py - Extract secrets
python3 secretsdump.py target.com/admin@dc_ip
python3 secretsdump.py -ntds /tmp/ntds.dit -system /tmp/system.hive LOCAL

# smbclient.py - SMB interaction
python3 smbclient.py target.com/user:password@target -share C$

# wmiexec.py - WMI command execution
python3 wmiexec.py target.com/user:password@target
python3 wmiexec.py -hashes :hash target.com/user@target
```

## Web Application Enumeration

### Directory and File Brute Force

```bash
# Dirb directory enumeration
dirb http://target.com /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
dirb http://target.com -X .php,.asp,.aspx,.jsp

# Gobuster modern enumeration
gobuster dir -u http://target.com -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
gobuster dir -u http://target.com -x php,asp,aspx,jsp,html -t 50

# Ffuf fast web fuzzer
ffuf -w /usr/share/wordlists/dirb/common.txt:FUZZ -u http://target.com/FUZZ
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://target.com/FUZZ -mc 200,204,301,302

# Dirsearch python tool
python3 dirsearch.py -u http://target.com -e php,asp,aspx -x 403,404
```

### Parameter Brute Force

```bash
# Arjun parameter discovery
arjun -u http://target.com/page.php

# ParamSpider parameter extraction
python3 paramspider.py -d target.com

# Ffuf parameter fuzzing
ffuf -w wordlist.txt:FUZZ -u "http://target.com/page?FUZZ=value"
ffuf -w wordlist.txt:FUZZ -u "http://target.com/page?param=FUZZ"
```

### Technology Stack Identification

```bash
# Wappalyzer browser extension
# Visit target website

# WhatWeb command line
whatweb target.com
whatweb -v target.com  # Verbose
whatweb -a 3 target.com  # Aggressive

# BuiltWith online tool
curl https://builtwith.com/target.com

# Netcraft toolbar
curl https://toolbar.netcraft.com/site_report?url=http://target.com
```

### Web Server Header Analysis

```bash
# HTTP headers dengan curl
curl -I http://target.com
curl -v http://target.com  # Verbose

# Headers dengan nmap
nmap -p80 --script http-headers target.com
nmap -p80 --script http-server-header target.com

# Custom header analysis
curl -H "X-Custom-Header: test" http://target.com
```

## Custom Enumeration Scripts

### Multi-Protocol Enumerator

```python
#!/usr/bin/env python3
# multi_enum.py - Multi-protocol enumeration

import socket
import subprocess
import sys
import threading

def enum_smb(target):
    print(f"[*] Enumerating SMB on {target}")
    try:
        result = subprocess.run(['enum4linux-ng', '-A', target], capture_output=True, text=True)
        if result.returncode == 0:
            print(f"[+] SMB enumeration successful for {target}")
            return result.stdout
    except:
        pass

def enum_smtp(target):
    print(f"[*] Enumerating SMTP on {target}")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((target, 25))
        banner = s.recv(1024).decode()
        print(f"[+] SMTP banner: {banner.strip()}")

        # Test VRFY with common users
        users = ['admin', 'administrator', 'root', 'test', 'info']
        for user in users:
            s.send(f"VRFY {user}\r\n".encode())
            response = s.recv(1024).decode()
            if "250" in response:
                print(f"[+] Valid user found: {user}")

        s.close()
    except:
        pass

def enum_ftp(target):
    print(f"[*] Enumerating FTP on {target}")
    try:
        # Test anonymous login
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((target, 21))
        response = s.recv(1024).decode()
        print(f"[+] FTP banner: {response.strip()}")

        s.send(b'USER anonymous\r\n')
        response = s.recv(1024).decode()
        s.send(b'PASS anonymous@email.com\r\n')
        response = s.recv(1024).decode()

        if "230" in response:
            print(f"[+] Anonymous FTP access allowed on {target}")

        s.close()
    except:
        pass

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <target>")
        sys.exit(1)

    target = sys.argv[1]

    # Run enumeration threads
    threads = [
        threading.Thread(target=enum_smb, args=(target,)),
        threading.Thread(target=enum_smtp, args=(target,)),
        threading.Thread(target=enum_ftp, args=(target,))
    ]

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()

if __name__ == "__main__":
    main()
```

## Best Practices for Enumeration

### Documentation

```bash
# Organize enumeration results
mkdir -p enumeration_results/{smb,smtp,snmp,ftp,database,ad,web}

# Save all command outputs
nmap -p445 --script smb-enum-shares target.com > enumeration_results/smb/shares.txt
enum4linux-ng -A target.com > enumeration_results/smb/full_enum.txt

# Create enumeration timeline
echo "$(date): Started SMB enumeration" >> enumeration_timeline.txt
echo "$(date): Started SMTP enumeration" >> enumeration_timeline.txt
```

### Rate Limiting

```bash
# Avoid triggering security measures
enum4linux-ng -A target.com | pv -q -L 50  # Limit to 50 lines per second

# Add delays dalam enumeration scripts
sleep 2  # Wait between commands
```

### Error Handling

```bash
# Check if service is up before enumeration
if ! nc -z target.com 445; then
    echo "SMB is not running on target"
    exit 1
fi

# Graceful error handling
enum4linux-ng -A target.com 2>/dev/null | tee enum_results.txt
```

## Common Issues and Solutions

### Issue: Connection Refused

```bash
# Check if service is actually running
nmap -p PORT target.com

# Try alternative ports
nmap -p- target.com
```

### Issue: Authentication Required

```bash
# Try common credentials
enum4linux-ng -u guest -p "" target.com
enum4linux-ng -u admin -p "password" target.com

# Use credential files
enum4linux-ng -u users.txt -p passwords.txt target.com
```

### Issue: Service Blocks After Too Many Attempts

```bash
# Use delays
sleep 5 between attempts

# Use multiple source IPs
# Rotate connection attempts

# Implement exponential backoff
for i in {1..10}; do
    sleep $((2**i))
    try_command
done
```

Enumeration is critical for understanding the attack surface and identifying exploitation paths. Always be thorough in enumeration - the more you know about the target, the better your exploitation will be.