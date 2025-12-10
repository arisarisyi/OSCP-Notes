# Penetration Testing Tools Reference

Daftar lengkap tools yang digunakan untuk penetration testing beserta link GitHub, dokumentasi, dan instalasi.

## ⭐ Legend Prioritas

- **⭐⭐⭐** WAJIB (Harus dikuasai untuk OSCP)
- **⭐⭐** PENTING (Sangat membantu)
- **⭐** REKOMENDASI (Baik untuk diketahui)
- Tanpa bintang: Opsional/Spesifik

## 🎯 Prioritas Tools untuk OSCP

### ⭐⭐⭐ Tools WAJIB (Must Master for OSCP)
1. **Nmap** - Port scanning dan service detection
2. **Nmap Scripts (NSE)** - Advanced scanning capabilities
3. **Burp Suite** - Web proxy and vulnerability scanner
4. **LinPEAS** - Linux privilege escalation
5. **WinPEAS** - Windows privilege escalation
6. **Metasploit Framework** - Exploitation framework

### ⭐⭐ Tools PENTING (Very Helpful)
1. **Subfinder** - Subdomain discovery
2. **Dirb/Gobuster** - Directory/file enumeration
3. **Hydra** - Password brute forcing
4. **Netcat/Socat** - Network utilities
5. **SQLMap** - SQL injection testing
6. **Ffuf** - Web fuzzing
7. **OWASP ZAP** - Web application security
8. **Dirsearch** - Web path scanner
9. **Feroxbuster** - Content discovery
10. **Wfuzz** - Web application fuzzer
11. **enum4linux-ng** - SMB enumeration
12. **SMBMap** - SMB share enumeration
13. **Masscan** - High-speed port scanner
14. **Hashcat** - Password cracking
15. **John the Ripper** - Password cracking
16. **LinEnum.sh** - Linux enumeration
17. **PowerUp** - Windows privilege escalation
18. **Mimikatz** - Windows credential extraction
19. **Linux Exploit Suggester** - Kernel exploit suggestions

## 📂 Kategori Tools

### Information Gathering

#### ⭐⭐⭐ Nmap
- Network mapper and port scanner
- GitHub: https://github.com/nmap/nmap
- Docs: https://nmap.org/book/
- Install: `sudo apt install nmap`

#### ⭐⭐ Subfinder
- Subfinder is a subdomain discovery tool that discovers valid subdomains for websites
- GitHub: https://github.com/projectdiscovery/subfinder
- Docs: https://docs.projectdiscovery.io/tools/subfinder/
- Install: `go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest`

#### ⭐⭐ Dirb/Gobuster
- Directory and file brute forcing
- Dirb: `sudo apt install dirb`
- Gobuster: `go install github.com/OJ/gobuster/v3@latest`
- Gobuster GitHub: https://github.com/OJ/gobuster
- Gobuster Docs: https://github.com/OJ/gobuster/wiki

#### ⭐⭐ Hydra
- Password cracking tool for various protocols
- GitHub: https://github.com/vanhauser-thc/thc-hydra
- Docs: https://github.com/vanhauser-thc/thc-hydra/wiki
- Install: `sudo apt install hydra`

#### ⭐⭐ Netcat/Socat
- Network utilities for reading/writing across network connections
- Netcat: `sudo apt install netcat-traditional`
- Socat: `sudo apt install socat`

#### ⭐ Amass
- In-depth Attack Surface Mapping and Asset Discovery
- GitHub: https://github.com/OWASP/Amass
- Docs: https://github.com/OWASP/Amass/wiki
- Install: `go install -v github.com/OWASP/Amass/v3/...@master`

#### ⭐ Sublist3r
- Fast subdomains enumeration tool
- GitHub: https://github.com/aboul3la/Sublist3r
- Install: `pip3 install sublist3r`

#### ⭐ Nikto
- Web server scanner
- GitHub: https://github.com/sullo/nikto
- Docs: https://github.com/sullo/nikto/wiki
- Install: `sudo apt install nikto`

#### theHarvester
- E-mails, subdomains and names Harvester
- GitHub: https://github.com/laramies/theHarvester
- Docs: https://github.com/laramies/theHarvester/wiki
- Install: `pip install theHarvester`

- [Sherlock](https://github.com/sherlock-project/sherlock) - Hunt down social media accounts by username across social networks
  - Install: `pip3 install sherlock`

- [Recon-ng](https://github.com/lanmaster53/recon-ng) - Web Reconnaissance Framework
  - GitHub: https://github.com/lanmaster53/recon-ng
  - Docs: https://github.com/lanmaster53/recon-ng/wiki
  - Install: `pip install recon-ng`

- [DnsRecon](https://github.com/darkoperator/dnsrecon) - DNS Enumeration Script
  - GitHub: https://github.com/darkoperator/dnsrecon
  - Install: `pip install dnsrecon`

- [Fierce](https://github.com/mschwager/fierce) - A DNS reconnaissance tool for locating non-contiguous IP space
  - GitHub: https://github.com/mschwager/fierce
  - Install: `pip install fierce`

### Scanning & Enumeration

#### ⭐⭐⭐ Nmap Scripts (NSE)
- Nmap Scripting Engine for advanced scanning
- GitHub: https://github.com/nmap/nmap/tree/master/scripts
- Docs: https://nmap.org/nsedoc/
- Categories: auth, brute, default, discovery, exploit, external, intrusive, malware, safe, version, vuln

#### ⭐⭐ enum4linux-ng
- SMB enumeration tool (replaces enum4linux)
- GitHub: https://github.com/CiscoCXSecurity/enum4linux-ng
- Docs: https://github.com/CiscoCXSecurity/enum4linux-ng/wiki
- Install: `git clone https://github.com/CiscoCXSecurity/enum4linux-ng.git`

#### ⭐⭐ SMBMap
- SMB Share Enumerating Tool
- GitHub: https://github.com/ShawnDEvans/smbmap
- Install: `sudo apt install smbmap`

#### ⭐⭐ SNMPWalk
- SNMP enumeration utility
- Install: `sudo apt install snmp`

#### ⭐⭐ Masscan
- High-speed TCP port scanner
- GitHub: https://github.com/robertdavidgraham/masscan
- Docs: https://github.com/robertdavidgraham/masscan/blob/master/README.md
- Install: `sudo apt install masscan`

#### ⭐ Impacket
- Collection of Python classes for network protocols
- GitHub: https://github.com/SecureAuthCorp/impacket
- Docs: https://impacket.readthedocs.io/
- Install: `pip install impacket`

#### ⭐ BloodHound
- Active Directory relationship mapping
- GitHub: https://github.com/BloodHoundAD/BloodHound
- Docs: https://bloodhound.readthedocs.io/
- Install: `sudo apt install bloodhound`

#### ⭐ CrackMapExec
- Network pentesting swiss army knife
- GitHub: https://github.com/byt3bl33d3r/CrackMapExec
- Docs: https://github.com/byt3bl33d3r/CrackMapExec/wiki
- Install: `pip install crackmapexec`

#### ⭐ Responder
- LLMNR, NBT-NS and MDNS poisoner
- GitHub: https://github.com/SpiderLabs/Responder
- Install: `git clone https://github.com/SpiderLabs/Responder.git`

- [BloodHound.py](https://github.com/fox-it/BloodHound.py) - A Python based ingestor for BloodHound
  - GitHub: https://github.com/fox-it/BloodHound.py
  - Install: `pip install bloodhound`

- [Unicornscan](https://github.com/huntergregal/unicornscan) - Asynchronous TCP and UDP port scanner
  - Install: `sudo apt install unicornscan`

### Web Application Testing

#### ⭐⭐⭐ Burp Suite
- Web vulnerability scanner and proxy
- Community Edition: https://portswigger.net/burp/communitydownload
- Docs: https://portswigger.net/burp/documentation
- Extensions:
  - Logger++: https://github.com/portswigger/logger-plus-plus
  - Autorize: https://github.com/PortSwigger/autorize
  - Turbo Intruder: Built-in
  - Repeater: Built-in

#### ⭐⭐ SQLMap
- Automatic SQL injection and database takeover tool
- GitHub: https://github.com/sqlmapproject/sqlmap
- Docs: https://sqlmap.org/
- Install: `pip install sqlmap`

#### ⭐⭐ Ffuf
- Fast web fuzzer written in Go
- GitHub: https://github.com/ffuf/ffuf
- Docs: https://github.com/ffuf/ffuf#usage
- Install: `go install github.com/ffuf/ffuf@latest`

#### ⭐ OWASP ZAP
- Free security tool for finding vulnerabilities in web applications
- GitHub: https://github.com/zaproxy/zaproxy
- Docs: https://www.zaproxy.org/docs/
- Install: `sudo apt install zaproxy`

#### ⭐ Dirsearch
- Web path scanner
- GitHub: https://github.com/maurosoria/dirsearch
- Install: `pip install dirsearch`

#### ⭐ Feroxbuster
- Fast, simple, recursive content discovery tool
- GitHub: https://github.com/epi052/feroxbuster
- Docs: https://github.com/epi052/feroxbuster#usage
- Install: `cargo install feroxbuster`

#### ⭐ Wfuzz
- Web application fuzzer
- GitHub: https://github.com/xmendez/wfuzz
- Docs: https://wfuzz.readthedocs.io/
- Install: `pip install wfuzz`

- [CeWL](https://github.com/digininja/CeWL) - Custom Word List Generator
  - GitHub: https://github.com/digininja/CeWL
  - Install: `git clone https://github.com/digininja/CeWL.git`

- [Medusa](https://github.com/jmk-foofus/medusa) - Parallel, modular, login brute-forcer
  - Install: `sudo apt install medusa`

### Exploitation Frameworks

#### ⭐⭐⭐ Metasploit Framework
- Metasploit penetration testing software
- GitHub: https://github.com/rapid7/metasploit-framework
- Docs: https://docs.metasploit.com/
- Install: `curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && chmod 755 msfinstall && ./msfinstall`

### Password Cracking

#### ⭐⭐ Hashcat
- World's fastest and most advanced password recovery utility
- GitHub: https://github.com/hashcat/hashcat
- Docs: https://hashcat.net/wiki/
- Install: `sudo apt install hashcat`

#### ⭐ John the Ripper
- Advanced password cracking tool
- GitHub: https://github.com/openwall/john
- Docs: https://www.openwall.com/john/doc/
- Install: `sudo apt install john`

- [Hash-Identifier](https://hashid.it/)
  - Tool: hashid
  - Install: `sudo apt install hashid`

### Post-Exploitation

#### ⭐⭐⭐ LinPEAS
- Linux Privilege Escalation Awesome Script
- GitHub: https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS
- Docs: https://linpeas.readthedocs.io/

#### ⭐⭐⭐ WinPEAS
- Windows Privilege Escalation Awesome Script
- GitHub: https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS
- Docs: https://winpeas.readthedocs.io/

#### ⭐⭐ LinEnum.sh
- Scripted Local Linux Enumeration & Privilege Escalation Checks
- GitHub: https://github.com/rebootuser/LinEnum

#### ⭐⭐ PowerUp
- A PowerShell Privilege Escalation Tool
- GitHub: https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc
- Docs: https://powersploit.readthedocs.io/

#### ⭐ Mimikatz
- A little tool to play with Windows security
- GitHub: https://github.com/gentilkiwi/mimikatz
- Docs: https://github.com/gentilkiwi/mimikatz/wiki

#### ⭐ Linux Exploit Suggester
- Linux privilege escalation auditing tool
- GitHub: https://github.com/mzet-/linux-exploit-suggester

- [Windows Exploit Suggester](https://github.com/gellin/windows-exploit-suggester)
  - GitHub: https://github.com/gellin/windows-exploit-suggester

- [BeRoot](https://github.com/AlessandroZ/BeRoot) - Privilege Escalation Project
  - GitHub: https://github.com/AlessandroZ/BeRoot

- [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) - Sysinternals ProcDump
  - Download: https://docs.microsoft.com/en-us/sysinternals/downloads/procdump

- [Psexec](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec) - Sysinternals PsExec
  - Download: https://docs.microsoft.com/en-us/sysinternals/downloads/psexec

### Network Tools

- [Netcat](https://github.com/andrew-d/static-binaries) - Swiss Army knife for networking
  - Install: `sudo apt install netcat-traditional`

- [Socat](http://www.dest-unreach.org/socat/) - Netcat on steroids
  - Install: `sudo apt install socat`

- [Wireshark](https://github.com/wireshark/wireshark) - Network protocol analyzer
  - GitHub: https://github.com/wireshark/wireshark
  - Docs: https://www.wireshark.org/docs/
  - Install: `sudo apt install wireshark`

- [Tcpdump](http://www.tcpdump.org/) - Network packet analyzer
  - Install: `sudo apt install tcpdump`

- [SSH Tunnel](https://github.com/sshuttle/sshuttle) - Transparent proxy server that works as a poor man's VPN
  - GitHub: https://github.com/sshuttle/sshuttle
  - Install: `sudo apt install sshuttle`

- [Chisel](https://github.com/jpillora/chisel) - A fast TCP/UDP tunnel over HTTP
  - GitHub: https://github.com/jpillora/chisel
  - Install: `go install github.com/jpillora/chisel@latest`

- [Proxychains](https://github.com/haad/proxychains) - Proxy chains - redirect connections through SOCKS4/5 or HTTP proxies
  - GitHub: https://github.com/haad/proxychains
  - Install: `sudo apt install proxychains4`

- [DNSChef](https://github.com/iphelix/dnschef) - DNS proxy for penetration testers
  - GitHub: https://github.com/iphelix/dnschef
  - Install: `pip install dnschef`

### Forensics & Analysis

- [Volatility Framework](https://github.com/volatilityfoundation/volatility) - Memory forensics framework
  - GitHub: https://github.com/volatilityfoundation/volatility
  - Docs: https://www.volatilityfoundation.org/documentation/
  - Install: `pip install volatility`

- [Autopsy](https://github.com/sleuthkit/autopsy) - Digital forensics platform
  - GitHub: https://github.com/sleuthkit/autopsy
  - Docs: https://www.sleuthkit.org/autopsy/docs.php
  - Install: `sudo apt install autopsy`

- [Binwalk](https://github.com/ReFirmLabs/binwalk) - Firmware analysis tool
  - GitHub: https://github.com/ReFirmLabs/binwalk
  - Docs: https://github.com/ReFirmLabs/binwalk/wiki
  - Install: `sudo apt install binwalk`

- [ExifTool](https://github.com/exiftool/exiftool) - Read, write and edit meta information
  - GitHub: https://github.com/exiftool/exiftool
  - Docs: https://exiftool.org/
  - Install: `sudo apt install exiftool`

- [Strings](https://github.com/strace/strace) - Find the printable strings in a file
  - Install: `sudo apt install binutils`

### Reverse Engineering

- [Ghidra](https://github.com/NationalSecurityAgency/ghidra) - Software reverse engineering (SRE) framework
  - GitHub: https://github.com/NationalSecurityAgency/ghidra
  - Docs: https://ghidra.re/

- [Radare2](https://github.com/radareorg/radare2) - UNIX-like reverse engineering framework and command-line toolset
  - GitHub: https://github.com/radareorg/radare2
  - Docs: https://rada.re/n/
  - Install: `sudo apt install radare2`

- [IDA Pro](https://www.hex-rays.com/products/ida/index.shtml) - Multi-processor disassembler and debugger
  - Commercial tool, requires license

- [x64dbg](https://github.com/x64dbg/x64dbg) - An open-source x64/x32 debugger for windows
  - GitHub: https://github.com/x64dbg/x64dbg
  - Docs: https://x64dbg.com/

### Mobile Security

- [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) - Mobile Security Framework (MobSF) is an automated, all-in-one mobile application pen-testing, malware analysis and security assessment framework
  - GitHub: https://github.com/MobSF/Mobile-Security-Framework-MobSF
  - Docs: https://mobsf.github.io/Mobile-Security-Framework-MobSF/
  - Install: `pip3 install mobsf`

- [Frida](https://github.com/frida/frida) - Dynamic instrumentation toolkit for developers, reverse-engineers, and security researchers
  - GitHub: https://github.com/frida/frida
  - Docs: https://frida.re/docs/home/
  - Install: `pip install frida-tools`

- [Objection](https://github.com/sensepost/objection) - Runtime mobile exploration toolkit, powered by Frida
  - GitHub: https://github.com/sensepost/objection
  - Docs: https://github.com/sensepost/objection/wiki
  - Install: `pip install objection`

### Wireless Security

- [Aircrack-ng](https://github.com/aircrack-ng/aircrack-ng) - Aircrack-ng is a complete suite of tools to assess WiFi network security
  - GitHub: https://github.com/aircrack-ng/aircrack-ng
  - Docs: https://www.aircrack-ng.org/documentation.html
  - Install: `sudo apt install aircrack-ng`

- [Wifite2](https://github.com/derv82/wifite2) - Rewrite of the popular wireless network auditor, "wifite"
  - GitHub: https://github.com/derv82/wifite2
  - Install: `pip install wifite`

- [Kismet](https://www.kismetwireless.net/) - Wireless network detector, sniffer, and intrusion detection system
  - GitHub: https://github.com/kismetwireless/kismet
  - Docs: https://www.kismetwireless.net/docs/
  - Install: `sudo apt install kismet`

### IoT Security

- [Firmadyne](https://github.com/firmadyne/firmadyne) - Scalable system for emulation and dynamic analysis of Linux-based embedded firmware
  - GitHub: https://github.com/firmadyne/firmadyne
  - Docs: https://github.com/firmadyne/firmadyne/blob/master/manual/manual.md

- [IoTSeeker](https://github.com/forensicxlab/IoTseeker) - Firmware scanning and analysis tool
  - GitHub: https://github.com/forensicxlab/IoTseeker

- [ATT&CK for ICS](https://collaborate.mitre.org/attackics/index.php) - Adversarial Tactics, Techniques, and Common Knowledge for Industrial Control Systems
  - Website: https://collaborate.mitre.org/attackics/index.php

### Cloud Security

- [Pacu](https://github.com/RhinoSecurityLabs/pacu) - AWS exploitation framework, designed for testing the security of Amazon Web Services environments
  - GitHub: https://github.com/RhinoSecurityLabs/pacu
  - Docs: https://rhinosecuritylabs.com/aws/aws-pacu/
  - Install: `pip install pacu`

- [CloudGoat](https://github.com/RhinoSecurityLabs/cloudgoat) - Rhino Security Labs' "Vulnerable by Design" AWS deployment tool
  - GitHub: https://github.com/RhinoSecurityLabs/cloudgoat
  - Docs: https://rhinosecuritylabs.com/cloudgoat/

- [ScoutSuite](https://github.com/nccgroup/ScoutSuite) - Multi-cloud security auditing tool
  - GitHub: https://github.com/nccgroup/ScoutSuite
  - Docs: https://github.com/nccgroup/ScoutSuite/wiki
  - Install: `pip install scoutsuite`

- [Prowler](https://github.com/toniblyx/prowler) - Prowler is a security tool for AWS, Azure, GCP and Kubernetes to do security assessments, audits, incident response, compliance, continuous monitoring, hardening and forensics readiness
  - GitHub: https://github.com/toniblyx/prowler
  - Install: `pip install prowler`

### Documentation & Reporting

- [Pentest-Report-Template](https://github.com/juliocesarfort/public-pentesting-reports)
  - GitHub: https://github.com/juliocesarfort/public-pentesting-reports

- [Pentest-Template](https://github.com/0xZDH/pentest-template)
  - GitHub: https://github.com/0xZDH/pentest-template

- [LazyRecon](https://github.com/nahamsec/lazyrecon) - A tool that performs automated initial enumeration for penetration testers
  - GitHub: https://github.com/nahamsec/lazyrecon

- [Reconftw](https://github.com/six2dez/reconftw)
  - GitHub: https://github.com/six2dez/reconftw
  - Docs: https://github.com/six2dez/reconftw/wiki

## 🐧 Kali Linux Default Tools

Sebagian besar tools sudah tersedia di Kali Linux:

```bash
# Install semua tools penting
sudo apt update
sudo apt install -y nmap nikto hydra john hashcat wireshark tcpdump burpsuite metasploit-framework responder smbmap enum4linux-ng gobuster sqlmap

# Install tools tambahan dari source
git clone https://github.com/danielmiessler/SecLists.git
git clone https://github.com/PowerShellMafia/PowerSploit.git
git clone https://github.com/carlospolop/PEASS-ng.git
```

## 📊 Tool Comparison Matrix

| Category | Free | Commercial | Linux | Windows | macOS | CLI | GUI |
|----------|------|------------|-------|---------|-------|-----|-----|
| Nmap | ✅ | | ✅ | ✅ | ✅ | ✅ | |
| Burp Suite | ✅ (CE) | ✅ (Pro) | ✅ | ✅ | ✅ | | ✅ |
| Metasploit | ✅ | | ✅ | ✅ | ✅ | ✅ | ✅ |
| Cobalt Strike | | ✅ | | ✅ | | ✅ | |
| Nessus | ✅ (Home) | ✅ (Pro) | ✅ | ✅ | | ✅ | ✅ |
| Wireshark | ✅ | | ✅ | ✅ | ✅ | | ✅ |
| IDA Pro | | ✅ | | ✅ | | | ✅ |

## 🛠️ Installation Scripts

### Automated Installation for Ubuntu/Kali

```bash
#!/bin/bash
# install_tools.sh - Install essential penetration testing tools

echo "[*] Installing penetration testing tools..."

# Basic tools
sudo apt update
sudo apt install -y nmap nikto hydra john hashcat wireshark tcpdump netcat-traditional socat git python3 python3-pip

# Web testing
sudo apt install -y burpsuite gobuster sqlmap dirb

# Network testing
sudo apt install -y enum4linux-ng smbmap responder

# Password cracking
sudo apt install -y hashcat john

# Wireless testing
sudo apt install -y aircrack-ng

# Install additional tools
pip3 install theHarvester sublist3r dirsearch ffuf wfuzz
pip3 install impacket bloodhound crackmapexec

# Install Go tools
go install github.com/OJ/gobuster/v3@latest
go install github.com/ffuf/ffuf@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Clone useful repositories
cd /opt
sudo git clone https://github.com/danielmiessler/SecLists.git
sudo git clone https://github.com/PowerShellMafia/PowerSploit.git
sudo git clone https://github.com/carlospolop/PEASS-ng.git
sudo git clone https://github.com/laramies/theHarvester.git
sudo git clone https://github.com/aboul3la/Sublist3r.git

echo "[+] Installation complete!"
```

### Docker Setup

```bash
# Pull security images
docker pull kalilinux/kali-rolling
docker pull owasp/zap2docker-stable
docker pull citizenstig/dvwa
docker pull vulnerables/web-dvwa

# Run OWASP ZAP
docker run -it -p 8080:8080 owasp/zap2docker-stable zap.sh -host 0.0.0.0 -port 8080 -daemon

# Run Kali container
docker run -it kalilinux/kali-rolling /bin/bash
```

## 📝 Tips & Best Practices

1. **Keep Tools Updated**
   ```bash
   # Update Nmap scripts
   nmap --script-updatedb

   # Update Metasploit
   msfupdate

   # Update Seclists
   cd /path/to/SecLists
   git pull origin master
   ```

2. **Create Tool Aliases**
   ```bash
   echo 'alias ports="netstat -tulnp"' >> ~/.bashrc
   echo 'alias scan="nmap -sS -sV -A"' >> ~/.bashrc
   ```

3. **Use Version Control**
   ```bash
   # Track custom scripts
   git init ~/pentest-scripts
   git add .
   git commit -m "Initial commit"
   ```

4. **Documentation**
   - Keep README for custom tools
   - Document custom configurations
   - Store example usage

## ⚠️ Legal Disclaimer

Remember to only use these tools on systems you have explicit permission to test. Unauthorized testing is illegal and unethical.

---

## 📚 Additional Resources

- [Kali Linux Tools Site](https://tools.kali.org/tools-listing)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [Pentester's Framework](https://github.com/trustedsec/pfs)