# Seclists Reference - Wordlists & Payloads untuk Penetration Testing

Seclists adalah koleksi lengkap dari berbagai jenis wordlists, payloads, dan resources yang digunakan untuk penetration testing. Repository ini dikembangkan oleh Daniel Miessler dan menjadi standar industri untuk wordlists.

## 🔗 Repository Resmi

- **GitHub:** [https://github.com/danielmiessler/SecLists](https://github.com/danielmiessler/SecLists)
- **Update Frequency:** Regular updates dengan kontribusi dari community
- **License:** MIT

## Instalasi Seclists

### Kali Linux
```bash
# Sudah terinstall secara default di Kali Linux
ls -la /usr/share/seclists/

# Jika belum ada:
sudo apt update
sudo apt install seclists
```

### Install Manual dari GitHub
```bash
git clone https://github.com/danielmiessler/SecLists.git
cd SecLists
```

### Install di Other OS
```bash
# Ubuntu/Debian
sudo apt install seclists

# RHEL/CentOS
sudo yum install seclists

# macOS (dengan Homebrew)
brew install seclists
```

## 📁 Struktur Direktori Seclists

### 1. Discovery
Lokasi: `/usr/share/seclists/Discovery/`

#### Web-Content
```bash
# Directory dan file enumeration
/usr/share/seclists/Discovery/Web-Content/
├── common.txt              # 473.500+ words - Sangat besar, gunakan hati-hati
├── directory-list-2.3-medium.txt  # 220.561 words - Balance antara ukuran dan coverage
├── directory-list-2.3-small.txt   # 100.800 words - Cepat, untuk quick scan
├── big.txt                 # 2.1M words - Hanya untuk exhaustive scan
├── raft-medium-directories.txt    # 50.000 words
├── raft-small-directories.txt     # 10.000 words
├── RobotsDisallowed         # 1.000+ paths dari robots.txt
├── common-locations.txt     # Paths umum seperti /admin, /backup
└── technologies/           # Wordlists untuk teknologi spesifik
    ├── Apache.txt
    ├── IIS.txt
    ├── Nginx.txt
    └── Tomcat.txt

# Penggunaan:
gobuster dir -u http://target.com -w /usr/share/seclists/Discovery/Web-Content/common.txt
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://target.com/FUZZ
```

#### DNS
```bash
/usr/share/seclists/Discovery/DNS/
├── subdomains-top1million-5000.txt  # Top 5.000 subdomains
├── subdomains-top1million-110000.txt  # Top 110.000 subdomains
├── bruteforce.txt              # Untuk subdomain brute force
├── dns-Jhaddix.txt            # Subdomain wordlist dari Jhaddix
└── combined_subdomains.txt     # Kombinasi berbagai sumber

# Penggunaan:
gobuster vhost -u http://target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://FUZZ.target.com
```

#### Subdomains
```bash
/usr/share/seclists/Discovery/Subdomains/
├── bitdiscovery-subdomains-top1million.txt
├── jhaddix-all.txt
└── common-subdomains.txt
```

#### IOT
```bash
/usr/share/seclists/Discovery/IOT/
├── iot-servers.txt
├── http-ports.txt
└── web-logins.txt
```

### 2. Passwords
Lokasi: `/usr/share/seclists/Passwords/`

#### Common Passwords
```bash
/usr/share/seclists/Passwords/Common-Credentials/
├── 10-million-password-list-top-1000000.txt  # Top 1 juta password
├── 10-million-password-list-top-10000.txt    # Top 10.000 password
├── 500-worst-passwords.txt                   # Password terburuk
├── common-passwords.txt                      # 10.000 password umum
└── rockyou.txt                              # 14 juta+ password (very popular)

# Penggunaan:
hydra -l admin -P /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-10000.txt ssh://target.com
john --wordlist=/usr/share/seclists/Passwords/Common-Credentials/rockyou.txt hash.txt
```

#### Default Credentials
```bash
/usr/share/seclists/Passwords/Default-Credentials/
├── default-passwords.txt                    # Default passwords umum
├── ftp-default-passwords.txt               # FTP defaults
├── http-default-passwords.txt              # HTTP form defaults
├── rdp-default-passwords.txt               # RDP defaults
├── ssh-default-passwords.txt               # SSH defaults
├── telnet-default-passwords.txt            # Telnet defaults
└── xampp-default-passwords.txt             # XAMPP defaults

# Penggunaan:
medusa -h target.com -u admin -P /usr/share/seclists/Passwords/Default-Credentials/http-default-passwords.txt -M http
```

#### Router & Network Device Passwords
```bash
/usr/share/seclists/Passwords/default-passwords/
├── cisco-default-passwords.txt
├── router-default-passwords.txt
├── juniper-default-passwords.txt
└── mikrotik-default-passwords.txt
```

#### Leaked Passwords
```bash
/usr/share/seclists/Passwords/Leaked-Databases/
├── Ashley-Madison.txt
├── Adobe.txt
├── LinkedIn.txt
├── Myspace.txt
└── rockyou-75.txt      # 75% dari rockyou
```

#### Password Masks (Mask Mode)
```bash
/usr/share/seclists/Passwords/Masks/
├── Common-Patterns.txt
├── Number-Patterns.txt
└── Special-Patterns.txt

# Penggunaan dengan Hashcat:
hashcat -m 0 -a 3 hash.txt ?u?l?l?l?l?d?d?d?d  # Uppercase + 4 lowercase + 4 digits
```

### 3. Usernames
Lokasi: `/usr/share/seclists/Usernames/`

#### Common Usernames
```bash
/usr/share/seclists/Usernames/
├── names.txt                    # Common first names
├── usernames.txt                # Common usernames (10.000+)
├── xato-net-10-million-usernames.txt  # 10 juta usernames dari xato
└── top-usernames-shortlist.txt  # Top 1.000 usernames

# Penggunaan:
hydra -L /usr/share/seclists/Usernames/top-usernames-shortlist.txt -P passwords.txt ftp://target.com
```

#### Domain Usernames
```bash
/usr/share/seclists/Usernames/Names/
├── first-names-usa.txt          # US first names
├── last-names-usa.txt           # US last names
├── top-first-names-usa.txt      # Top US first names
└── top-last-names-usa.txt       # Top US last names
```

### 4. Fuzzing
Lokasi: `/usr/share/seclists/Fuzzing/`

#### Web Fuzzing
```bash
/usr/share/seclists/Fuzzing/
├── Big-Unicode.txt              # Unicode fuzzing payload
├── fuzzdb-1.09/
│   ├── attack-payloads/
│   ├── discovery-predictable-responses/
│   └── xss/
├── SQLi.txt                     # SQL injection payloads
├── XSS.txt                      # XSS payloads
├── Command-Injection.txt        # Command injection payloads
└── File-Upload-Names.txt        # File upload test names

# Penggunaan:
ffuf -w /usr/share/seclists/Fuzzing/SQLi.txt -u "http://target.com/page.php?id=FUZZ"
```

#### API Fuzzing
```bash
/usr/share/seclists/Fuzzing/API-Payloads/
├── GraphQL.txt                  # GraphQL fuzzing
├── REST.txt                     # REST API fuzzing
└── SOAP.txt                     # SOAP fuzzing
```

### 5. IOCs (Indicators of Compromise)
Lokasi: `/usr/share/seclists/IOCs/`

#### Malware Domains
```bash
/usr/share/seclists/IOCs/
├── Malicious-URLs.txt           # Malicious URLs
├── Malicious-Domains.txt        # Malicious domains
├── Malware-Hashes.txt           # Malware hashes
└── Suspicious-Emails.txt        # Suspicious email addresses
```

## 🛠️ Best Practices Penggunaan Seclists

### 1. Pilih Wordlist yang Tepat

```bash
# Quick scan (speed prioritized)
gobuster dir -u target.com -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt

# Comprehensive scan (coverage prioritized)
gobuster dir -u target.com -w /usr/share/seclists/Discovery/Web-Content/common.txt

# Targeted scan (technology-specific)
gobuster dir -u target.com -w /usr/share/seclists/Discovery/Web-Content/technologies/Nginx.txt
```

### 2. Combine Multiple Wordlists

```bash
# Combine dengan cat
cat /usr/share/seclists/Discovery/Web-Content/common.txt /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt > combined.txt

# Combine dengan uniq untuk remove duplicates
cat wordlist1.txt wordlist2.txt | sort | uniq > combined_unique.txt

# Combine dengan limit untuk large wordlists
head -n 100000 /usr/share/seclists/Discovery/Web-Content/common.txt > common_100k.txt
```

### 3. Create Custom Wordlists

```bash
# Extract dari web application dengan CeWL
cewl http://target.com -w custom_words.txt

# Extract dan combine dengan Seclists
cat custom_words.txt /usr/share/seclists/Discovery/Web-Content/common.txt > enhanced_wordlist.txt

# Generate pattern-based wordlist
# Generate untuktahun dengan John:
john --stdout --wordlist=/usr/share/seclists/Passwords/Common-Credentials/rockyou.txt --rules > password_with_rules.txt
```

### 4. Tool-Specific Wordlists

```bash
# Untuk Hydra - Format username:password
echo -e "admin:admin\nadmin:password\nroot:root" > hydra_creds.txt

# Unturffuf - Format tanpa extension
sed 's/\.php//' wordlist.php > wordlist_noext.txt

# Untuk Burp Intruder
# Load wordlist langsung dari Seclists
```

## 🔧 Tool Integration

### Gobuster
```bash
# Basic dir busting
gobuster dir -u http://target.com -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt

# Dengan extensions
gobuster dir -u http://target.com -w /usr/share/seclists/Discovery/Web-Content/common.txt -x php,asp,aspx,jsp

# Vhost enumeration
gobuster vhost -u http://target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

### Ffuf
```bash
# Basic fuzzing
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://target.com/FUZZ

# POST parameter fuzzing
ffuf -w /usr/share/seclists/Passwords/Common-Credentials/common-passwords.txt -X POST -d "param=FUZZ" -u http://target.com/login

# Multiple wordlists
ffuf -w /usr/share/seclists/Usernames/top-usernames-shortlist.txt:W1 -w /usr/share/seclists/Passwords/Common-Credentials/common-passwords.txt:W2 -u http://target.com/api -X POST -d '{"user":"W1","pass":"W2"}'
```

### Hydra
```bash
# SSH brute force
hydra -L /usr/share/seclists/Usernames/top-usernames-shortlist.txt -P /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-10000.txt ssh://target.com

# RDP brute force
hydra -L /usr/share/seclists/Usernames/top-usernames-shortlist.txt -P /usr/share/seclists/Passwords/Common-Credentials/common-passwords.txt rdp://target.com

# HTTP POST brute force
hydra -l admin -P /usr/share/seclists/Passwords/Common-Credentials/rockyou.txt http-post-form "/login.php:username=^USER^&password=^PASS^:Invalid"
```

### John the Ripper
```bash
# Basic wordlist attack
john --wordlist=/usr/share/seclists/Passwords/Common-Credentials/rockyou.txt hash.txt

# Dengan rules
john --wordlist=/usr/share/seclists/Passwords/Common-Credentials/rockyou.txt --rules hash.txt

# Mask attack
john --wordlist=/usr/share/seclists/Passwords/Common-Credentials/rockyou.txt --mask='?u?l?l?l?l?d?d' hash.txt
```

### Hashcat
```bash
# Wordlist attack
hashcat -m 0 hash.txt /usr/share/seclists/Passwords/Common-Credentials/rockyou.txt

# Combinator attack
hashcat -m 0 hash.txt /usr/share/seclists/Passwords/Common-Credentials/common-passwords.txt /usr/share/seclists/Passwords/Common-Credentials/rockyou.txt -a 1

# Rule-based attack
hashcat -m 0 hash.txt /usr/share/seclists/Passwords/Common-Credentials/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
```

## 📊 Wordlist Performance

### Size vs Speed Trade-off

| Wordlist | Size | Use Case | Speed |
|----------|------|----------|-------|
| `directory-list-2.3-small.txt` | 100KB | Quick scan | Very Fast |
| `directory-list-2.3-medium.txt` | 2MB | Balanced | Fast |
| `common.txt` | 4MB | Comprehensive | Medium |
| `big.txt` | 30MB | Exhaustive | Slow |

### Tips Optimization

```bash
# Throttling untuk avoid blocking
gobuster dir -u target.com -w wordlist.txt --delay 1s

# Parallel processing
ffuf -w wordlist.txt -u http://target.com/FUZZ -t 50

# Resume interrupted scan
gobuster dir -u target.com -w wordlist.txt --resume
```

## 🚀 Advanced Usage

### Custom Wordlist Generation

```python
#!/usr/bin/env python3
# custom_wordlist.py - Generate custom wordlist

import itertools
import sys

def generate_wordlist(base_words, years, special_chars):
    wordlist = set()

    # Base words
    wordlist.update(base_words)

    # Base + number
    for word in base_words:
        for num in range(0, 100):
            wordlist.add(f"{word}{num}")
            wordlist.add(f"{word}{num:04d}")

    # Base + year
    for word in base_words:
        for year in years:
            wordlist.add(f"{word}{year}")
            wordlist.add(f"{word}{year[-2:]}")

    # Capital variations
    for word in list(wordlist):
        wordlist.add(word.capitalize())
        wordlist.add(word.upper())

    return wordlist

# Usage
base = ["admin", "password", "target", "company"]
years = ["2020", "2021", "2022", "2023", "2024"]
special = ["!", "@", "#"]

wordlist = generate_wordlist(base, years, special)

with open("custom_wordlist.txt", "w") as f:
    for word in sorted(wordlist):
        f.write(f"{word}\n")
```

### Context-Aware Wordlist

```bash
# Extract dari target website
curl -s http://target.com | grep -oE '\b[a-zA-Z0-9_-]{4,20}\b' | sort -u > website_words.txt

# Combine dengan common passwords
cat website_words.txt /usr/share/seclists/Passwords/Common-Credentials/common-passwords.txt > contextual_wordlist.txt
```

## 📝 Maintenance

### Update Seclists
```bash
# Jika install dari GitHub
cd /path/to/SecLists
git pull origin master

# Jika install via package manager
sudo apt update && sudo apt upgrade seclists
```

### Backup Custom Wordlists
```bash
# Create backup directory
mkdir -p ~/custom_wordlists

# Backup custom wordlists
cp custom_wordlist.txt ~/custom_wordlists/
cp combined_wordlist.txt ~/custom_wordlists/
```

## ⚠️ Important Considerations

1. **Legal Use:** Hanya gunakan pada authorized systems
2. **Rate Limiting:** Avoid triggering security measures
3. **Resource Usage:** Large wordlists can consume significant resources
4. **False Positives:** Be prepared to handle false positive results
5. **Customization:** Always consider creating custom wordlists for specific targets

## 📚 Additional Resources

### Alternative Wordlist Collections
- [RockYou.txt](https://wiki.skullsecurity.org/Passwords)
- [Hashcat Rule-based Wordlists](https://hashcat.net/wiki/doku.php?id=rule_based_attack)
- [PacketStorm Wordlists](https://packetstormsecurity.com/Crackers/wordlists/)

### Wordlist Creation Tools
- [CeWL](https://github.com/digininja/CeWL) - Custom wordlist generator
- [Crunch](https://sourceforge.net/projects/crunch-wordlist/) - Wordlist generator
- [Mangler](https://github.com/xntrik/mangler) - Wordlist manipulation tool

Seclists adalah essential tool untuk penetration testing. Understanding struktur dan memilih wordlist yang tepat akan meningkatkan efficiency dan effectiveness dari security testing.