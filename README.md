# PEN-200 (PWK) — Syllabus Ringkasan

> **Catatan:** File ini merupakan penataan ulang syllabus resmi menjadi format catatan belajar. Konten berisi learning modules, learning units, dan learning objectives sesuai materi sumber.

## Ringkasan Umum

- **Kursus:** Penetration Testing with Kali Linux (PEN-200 / PWK)
- **Versi Syllabus Sumber:** PWK v3.0 (OffSec)
- **Tujuan File:** Menyusun modul dan learning objectives sebagai referensi/catatan belajar OSCP.

## Daftar File Catatan

Berdasarkan syllabus ini, telah dibuat file-file catatan markdown terpisah:

### 📂 Information Gathering
- [01_Information_Gathering.md](01_Information_Gathering.md) - File utama
- [01_01_Reconnaissance.md](01_01_Reconnaissance.md) - Passive & Active Reconnaissance
- [01_02_Scanning.md](01_02_Scanning.md) - Port Scanning & Service Detection
- [01_03_Enumeration_Techniques.md](01_03_Enumeration_Techniques.md) - Service-Specific Enumeration

### 📂 Vulnerability Assessment & Exploitation
- [02_Vulnerability_Assessment.md](02_Vulnerability_Assessment.md) - File utama
- [02_01_Vulnerability_Assessment.md](02_01_Vulnerability_Assessment.md) - Scanning & Assessment
- [02_02_Exploitation_Techniques.md](02_02_Exploitation_Techniques.md) - Exploitation Methods

### 📂 Post-Exploitation
- [03_Post_Exploitation.md](03_Post_Exploitation.md) - File utama
- [03_01_System_Enumeration.md](03_01_System_Enumeration.md) - System Enumeration
- [03_02_Privilege_Escalation.md](03_02_Privilege_Escalation.md) - Privilege Escalation
- [03_03_Persistence_Mechanisms.md](03_03_Persistence_Mechanisms.md) - Persistence Methods
- [03_04_Lateral_Movement.md](03_04_Lateral_Movement.md) - Lateral Movement
- [03_05_Data_Exfiltration.md](03_05_Data_Exfiltration.md) - Data Exfiltration

### 📂 Reference & Resources
- [98_Tools_Reference.md](98_Tools_Reference.md) - Complete Tools List & Documentation
- [99_Seclists_Reference.md](99_Seclists_Reference.md) - Wordlists & Brute Force Guide

---

## Modul Pembelajaran & Learning Objectives

### 1. Penetration Testing with Kali Linux — General Course Introduction

#### Welcome to PWK
- Tujuan belajar:
  - Mengetahui komponen kursus
  - Menyiapkan Attacking Kali VM
  - Terkoneksi dan berinteraksi melalui PWK VPN
  - Memahami cara menyelesaikan Module Exercises

#### How to Approach the Course
- Tujuan belajar:
  - Membentuk model pembelajaran berbasis peningkatan ketidakpastian
  - Memahami komponen pembelajaran dalam PEN-200

#### Summary of PWK Learning Modules
- Tujuan belajar: Gambaran tingkat tinggi atas setiap learning module

### 2. Introduction to Cybersecurity

#### The Practice of Cybersecurity
- Tujuan belajar:
  - Mengenali tantangan di keamanan informasi
  - Memahami hubungan offensive ↔ defensive security
  - Membangun mindset yang berguna untuk security work

#### Threats and Threat Actors
- Tujuan belajar:
  - Memahami interaksi attacker/defender
  - Membedakan risiko, ancaman, kerentanan, dan exploit
  - Mengidentifikasi kelas threat actor dan contoh insiden

#### The CIA Triad
- Tujuan belajar: Pahami pentingnya Confidentiality, Integrity, Availability

#### Security Principles, Controls, and Strategies
- Tujuan belajar:
  - Pentingnya defense-in-depth
  - Pengenalan threat intelligence, access control, kebijakan mitigasi

#### Cybersecurity Laws, Regulations, Standards, and Frameworks
- Tujuan belajar: Memahami pemandu hukum/regulasi dan framework yang relevan

#### Career Opportunities in Cybersecurity
- Tujuan belajar: Mengetahui peran dan jalur karir di bidang keamanan

### 3. Effective Learning Strategies

#### Learning Theory
- Tujuan belajar: Dasar teori pendidikan, mekanisme memori, dual encoding, Curve of Forgetting

#### Unique Challenges to Learning Technical Skills
- Tujuan belajar: Tantangan pembelajaran digital, skenario tak terduga, pembelajaran remote

#### OffSec Methodology
- Tujuan belajar: Pahami Demonstrative Methodology dan pendekatan OffSec

#### Case Study: chmod -x chmod
- Tujuan belajar: Contoh studi kasus untuk memperluas pemahaman dan latihan problem solving

#### Tactics and Common Methods
- Tujuan belajar: Retrieval practice, spaced practice, SQ3R/PQ4R, Feynman Technique, Leitner

#### Advice and Suggestions on Exams
- Tujuan belajar: Manajemen stres ujian, menilai kesiapan, strategi ujian OSCP

#### Practical Steps
- Tujuan belajar: Membuat strategi jangka panjang, alokasi waktu, fokus, dan kolaborasi belajar

### 4. Report Writing for Penetration Testers

#### Understanding Note-Taking
- Tujuan belajar: Struktur dokumentasi, portability catatan, pemilihan tools, pentingnya screenshot

#### Writing Effective Technical Penetration Testing Reports
- Tujuan belajar:
  - Menyusun Executive Summary
  - Membuat technical summary; mendokumentasikan temuan & rekomendasi
  - Menggunakan appendices, resources, dan references

### 5. Information Gathering

#### The Penetration Testing Lifecycle
- Tujuan belajar: Memahami tahapan pentest dan peran information gathering

#### Passive Information Gathering
- Tujuan belajar: OSINT, teknik passive Web/DNS reconnaissance

#### Active Information Gathering
- Tujuan belajar: Konsep port scanning (Nmap/Netcat), enumerasi DNS/SMB/SMTP/SNMP, dan teknik Living off the Land (LoL)

### 6. Vulnerability Scanning

#### Vulnerability Scanning Theory
- Tujuan belajar: Jenis dan pertimbangan vulnerability scan

#### Vulnerability Scanning with Nessus
- Tujuan belajar: Instalasi & konfigurasi Nessus, authenticated scans, memahami plugin & hasil scan

#### Vulnerability Scanning with Nmap
- Tujuan belajar: Menggunakan Nmap Scripting Engine (NSE) untuk lightweight scanning dan custom scripts

### 7. Introduction to Web Applications

#### Web Application Assessment Methodology
- Tujuan belajar: Metodologi pengujian web, OWASP Top 10, kerentanan umum

#### Web Application Assessment Tools
- Tujuan belajar: Teknik enumerasi web, teori proxy, prinsip kerja Burp Suite proxy

#### Web Application Enumeration
- Tujuan belajar: Inspect headers/cookies/source code, API testing principles

#### Common Web Vulnerabilities (konsep)
- **XSS:** tipe XSS, konsep pemanfaatan dasar
- **Directory Traversal:** path traversal & encoding
- **File Inclusion (LFI/RFI):** konsep dan perbedaan
- **File Upload:** deteksi vektor
- **Command Injection:** konsep injeksi perintah OS
- **SQL Injection:** teori SQL, manual SQLi (UNION, Error, Blind), serta aspek automasi dan dampaknya pada DB (konsep)

> **Catatan:** Semua topik web disampaikan sebagai konsep & metodologi; tidak termasuk payload atau instruksi eksploitasi langsung.

### 8. Client-Side Attacks

#### Target Reconnaissance & Client Fingerprinting
- Tujuan belajar: Kumpulkan info untuk serangan sisi-klien, fingerprinting target

#### Exploiting Microsoft Office / Abusing Windows Library Files
- Tujuan belajar: Memahami variasi serangan client-side (konseptual) dan cara library/shortcut dapat disalahgunakan

### 9. Locating Public Exploits

#### Getting Started & Online Exploit Resources
- Tujuan belajar: Risiko menjalankan exploit tak tepercaya, analisis kode exploit, penggunaan search operators

#### Offline Exploit Resources
- Tujuan belajar: Exploit frameworks, SearchSploit, Nmap NSE scripts

#### Exploiting a Target (konseptual)
- Tujuan belajar: Workflow pentest untuk menemukan & mencoba exploit publik secara aman (konsep)

#### Fixing Exploits (konseptual)
- Tujuan belajar: Pengantar teori memory corruption, cross-compiling, modifikasi exploit (tingkat tinggi), troubleshooting web exploit issues

### 10. Antivirus Evasion

#### AV Software Key Components and Operations
- Tujuan belajar: Komponen AV, deteksi known vs unknown threats

#### AV Evasion in Practice
- Tujuan belajar: Best practices untuk testing AV evasion (konsep) dan alat bantu otomatis (konseptual)

### 11. Password Attacks

#### Attacking Network Services Logins
- Tujuan belajar: Pendekatan untuk target SSH, RDP, HTTP POST login forms

#### Password Cracking Fundamentals
- Tujuan belajar: Metodologi cracking dasar, manipulasi wordlists, cracking password manager files, SSH key passphrases

#### Working with Password Hashes
- Tujuan belajar: Mendapatkan & memecah NTLM / Net-NTLMv2 hashes, pass-the-hash/relay konsep

### 12. Windows Privilege Escalation

#### Enumerating Windows
- Tujuan belajar: Privileges & access control, situational awareness, mencari informasi sensitif (termasuk output PowerShell), automated enumeration tools

#### Leveraging Windows Services
- Tujuan belajar: Hijack service binaries/DLLs, unquoted service paths

#### Abusing Other Windows Components
- Tujuan belajar: Scheduled Tasks, jenis exploit privilege escalation, eksekusi sebagai privileged accounts

### 13. Linux Privilege Escalation

#### Enumerating Linux
- Tujuan belajar: Struktur file & permission, manual & otomatis enumeration

#### Exposed Confidential Information
- Tujuan belajar: Inspect history files, user/system trails untuk credential harvesting

#### Insecure File Permissions & System Components
- Tujuan belajar: Abuse insecure cron jobs, SUID binaries/capabilities, sudo misconfigurations, kernel vulnerabilities untuk eskalasi

### 14. Port Redirection, SSH Tunneling & Advanced Tunneling

#### Port Forwarding with \*NIX / Windows Tools
- Tujuan belajar: Konsep port forwarding (socat, ssh, plink, netsh), kapan digunakan

#### SSH Tunneling
- Tujuan belajar: Local / remote / dynamic port forwarding

#### Advanced Tunneling
- Tujuan belajar: HTTP tunneling (Chisel), DNS tunneling (dnscat), tunneling melalui DPI

### 15. The Metasploit Framework

#### Getting Familiar with Metasploit
- Tujuan belajar: Setup, navigasi, auxiliary & exploit modules (konsep)

#### Using Metasploit Payloads & Post-Exploitation
- Tujuan belajar: Pembeda staged vs non-staged payloads, Meterpreter overview, post-exploitation basics, pivoting

#### Automating Metasploit
- Tujuan belajar: Resource scripts & automasi (konsep)

### 16. Active Directory

#### Introduction and Enumeration
- Tujuan belajar: Manual enumeration via Windows utilities, PowerShell/.NET techniques

#### Expanding Enumeration Repertoire
- Tujuan belajar: Enumerate OS permissions, SPNs, object permissions, domain shares

#### Automated Enumeration
- Tujuan belajar: SharpHound data collection, BloodHound analysis

#### Attacking AD Authentication
- Tujuan belajar: NTLM/Kerberos basics, cached creds, password attacks, Kerberos SPN abuse, forging service tickets (konsep)

#### Lateral Movement & Persistence
- Tujuan belajar: WMI/WinRM/WinRS, PsExec, Pass-the-Hash/Overpass-The-Hash, DCOM misuse, golden tickets, shadow copies (konsep)

### 17. Assembling the Pieces (Lab Scenarios)

#### Enumerating the Public Network
- Tujuan belajar: Public network enumeration & informasi untuk tahap selanjutnya

#### Attacking WEBSRV1 / INTERNALSRV1 / INTERNAL NETWORK
- Tujuan belajar (contoh kasus lab):
  - Memanfaatkan kelemahan WordPress plugins (konsep)
  - Crack SSH key passphrases, privilege escalation via sudo/dev artifacts
  - Validasi kredensial domain dari non-domain machine, phishing konsep untuk akses internal, enumerasi hosts/services/sessions

#### Gaining Access to the Domain Controller
- Tujuan belajar: Teknik persiapan client-side, fingerprinting, dan langkah-langkah menuju kontrol domain (konseptual)

### 18. Trying Harder: The Labs (Challenge Labs)

#### PWK Challenge Lab Overview
- Tujuan belajar: Mengenal tipe Challenge Labs dan cara memperlakukannya sebagai mock OSCP

#### Challenge Lab Details
- Tujuan belajar: Konsep dependency antar host, decoy machines, pengaruh router/NAT, perlakuan kredensial & serangan password

---

## 📝 Cara Menggunakan Catatan Ini

1. **Ikuti alur modul sesuai syllabus** - Mulai dari Module 1 hingga 18
2. **Buka file yang relevan** - Setiap topik memiliki file markdown terpisah
3. **Praktikkan setiap teknik** - Gunakan lab environment atau VM yang legal
4. **Buat catatan tambahan** - Tambahkan penemuan pribadi di masing-masing file

## ⚠️ Disclaimer

> **Penting:** Catatan ini dibuat untuk tujuan pembelajaran dan persiapan sertifikasi OSCP. Gunakan semua teknik yang dipelajari hanya pada sistem yang memiliki izin eksplisit. Penulis tidak bertanggung jawab atas penyalahgunaan informasi dalam dokumen ini.

---

## 📚 Referensi Tambahan

- [Official OffSec Documentation](https://help.offsec.com/)
- [OSCP Exam Guide](https://help.offsec.com/hc/en-us/articles/360040165632-OSCP-Exam-Guide)
- [Kali Linux Tools](https://www.kali.org/tools-listing/)