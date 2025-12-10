# 96. VulnHub Machine Recommendations untuk OSCP Preparation

VulnHub menyediakan koleksi vulnerable machines gratis untuk practice penetration testing. Berikut adalah rekomendasi machines berdasarkan difficulty dan skills yang akan dikembangkan untuk OSCP preparation.

## 🎯 Learning Path Structure

### Progression Path
1. **Very Easy** → Basic enumeration & exploitation
2. **Easy** → Multiple techniques, simple priv esc
3. **Medium** → Complex enumeration, custom exploits
4. **Hard** → Advanced techniques, multiple machines
5. **Insane** → Real-world scenarios, time pressure

## ⭐ Very Easy Machines (Beginner Friendly)

### 1. SickOs 1.1
- **Author: D4rkstat
- **Download:** [SickOs 1.1](https://www.vulnhub.com/entry/sickos-11,132/)
- **Skills:**
  - Basic port scanning (Nmap)
  - Service enumeration
  - Web directory enumeration (Dirb)
  - Simple web exploitation
  - Basic privilege escalation
- **Tools yang dipelajari:** Nmap, Dirb, Netcat, SearchSploit
- **OSCP Relevance:** ⭐⭐⭐ Dasar web exploitation

### 2. Pentester Lab: Basic
- **Author:** Pentester Lab
- **Download:** [Pentester Lab: Basic](https://www.vulnhub.com/entry/pentester-lab-basic,114/)
- **Skills:**
  - File upload vulnerability
  - PHP reverse shell
  - Basic Linux commands
  - Simple privilege escalation
- **Tools yang dipelajari:** Burp Suite, Netcat, PHP
- **OSCP Relevance:** ⭐⭐⭐ File upload techniques

### 3. FristiLeaks 1.3
- **Author:** Armin Rex
- **Download:** [FristiLeaks 1.3](https://www.vulnhub.com/entry/fristileaks-13,133/)
- **Skills:**
  - Web enumeration
  - Steganography
  - Base64 decoding
  - Custom exploitation
- **Tools yang dipelajari:** Gobuster, Steghide, Base64
- **OSCP Relevance:** ⭐⭐ Steganography basics

## ⭐⭐ Easy Machines

### 4. Kioptrix Level 1
- **Author:** Kioptrix
- **Download:** [Kioptrix Level 1](https://www.vulnhub.com/entry/kioptrix-level-1-1,22/)
- **Skills:**
  - Service version enumeration
  - Samba exploitation
  - Public exploit usage
  - Password cracking
- **Tools yang dipelajari:** Nmap, SearchSploit, Hydra, John
- **OSCP Relevance:** ⭐⭐⭐ Samba & password attacks

### 5. Billu B0x
- **Author:** Indian Cyber Hunter
- **Download:** [Billu B0x](https://www.vulnhub.com/entry/billu-b0x-1,51/)
- **Skills:**
  - Web application testing
  - LFI (Local File Inclusion)
  - Password cracking
  - Cron job exploitation
- **Tools yang dipelajari:** Burp Suite, Lfimap, John
- **OSCP Relevance:** ⭐⭐⭐ Web apps & cron jobs

### 6. VulnOS 2
- **Author:**世尊
- **Download:** [VulnOS 2](https://www.vulnhub.com/entry/vulnos-2,149/)
- **Skills:**
  - Port knocking
  - WordPress enumeration
  - WP plugin exploitation
  - Privilege escalation
- **Tools yang dipelajari:** Nmap, Wpscan, Knock
- **OSCP Relevance:** ⭐⭐ WordPress exploitation

## ⭐⭐⭐ Medium Machines

### 7. ST-2: Bomberman
- **Author:** strukt
- **Download:** [ST-2: Bomberman](https://www.vulnhub.com/entry/st-2-bomberman,293/)
- **Skills:**
  - Advanced enumeration
  - SQL injection
  - Buffer overflow
  - Custom exploits
- **Tools yang dipelajari:** SQLMap, GDB, Immunity Debugger
- **OSCP Relevance:** ⭐⭐⭐ SQLi & basic buffer overflow

### 8. Mr-Robot
- **Author:** @leonjza
- **Download:** [Mr-Robot](https://www.vulnhub.com/entry/mr-robot-1,151/)
- **Skills:**
  - WordPress exploitation
  - Password cracking (hashcat)
  - Privilege escalation
  - Steganography
- **Tools yang dipelajari:** Wpscan, Hashcat, Steghide
- **OSCP Relevance:** ⭐⭐⭐ Complete OSCP-like flow

### 9. DC-1
- **Author:** DCAU
- **Download:** [DC-1](https://www.vulnhub.com/entry/dc-1,292/)
- **Skills:**
  - Drupal enumeration
  - Drupal exploitation
  - SUID binary abuse
  - Shell escaping
- **Tools yang dipelajari:** Nmap, Drupal exploits, SUID enumeration
- **OSCP Relevance:** ⭐⭐⭐ Drupal & SUID abuse

### 10. Symphony
- **Author:** c0rruptedb1t
- **Download:** [Symphony](https://www.vulnhub.com/entry/symfony-1,231/)
- **Skills:**
  - PHP framework exploitation
  - SQL injection
  - Custom exploitation
  - Privilege escalation
- **Tools yang dipelajari:** Burp Suite, SQLMap, PHP
- **OSCP Relevance:** ⭐⭐ PHP frameworks & SQLi

## ⭐⭐⭐⭐ Hard Machines

### 11. Sunst0r
- **Author:** Sunst0r
- **Download:** [Sunst0r](https://www.vulnhub.com/entry/sunstorm-1,252/)
- **Skills:**
  - Advanced web exploitation
  - Node.js vulnerabilities
  - Redis exploitation
  - Container escape
- **Tools yang dipelajari:** Redis-cli, Docker enumeration
- **OSCP Relevance:** ⭐⭐ Node.js & Redis

### 12. Tr0ll 1
- **Author:** tryhackme
- **Download:** [Tr0ll 1](https://www.vulnhub.com/entry/tr0ll-1,100/)
- **Skills:**
  - Manual exploitation
  - Password cracking
  - Service exploitation
  - Persistence
- **Tools yang dipelajari:** John, Hydra, Service enumeration
- **OSCP Relevance:** ⭐⭐ Persistence techniques

### 13. Inferno
- **Author:** b33f
- **Download:** [Inferno](https://www.vulnhub.com/entry/inferno-1,269/)
- **Skills:**
  - Web application hacking
  - CSRF exploitation
  - Database enumeration
  - Advanced privilege escalation
- **Tools yang dipelajari:** Burp Suite, SQLMap, LinPEAS
- **OSCP Relevance:** ⭐⭐ CSRF & advanced priv esc

### 14. DC-5
- **Author:** DCAU
- **Download:** [DC-5](https://www.vulnhub.com/entry/dc-5,314/)
- **Skills:**
  - File inclusion
  - LFI to RCE
  - Cron job abuse
  - Custom scripts
- **Tools yang dipelajari:** LFI techniques, Cron enumeration
- **OSCP Relevance:** ⭐⭐⭐ LFI to RCE techniques

## ⭐⭐⭐⭐⭐ Insane Machines

### 15. Reckless
- **Author:** dhankani
- **Download:** [Reckless](https://www.vulnhub.com/entry/reckless-1,268/)
- **Skills:**
  - Active Directory
  - Kerberos exploitation
  - Pass-the-Ticket
  - Multiple attack vectors
- **Tools yang dipelajari:** Impacket, BloodHound, Rubeus
- **OSCP Relevance:** ⭐⭐⭐⭐ AD concepts (bonus)

### 16. Hackable III
- **Author:** g0tmi1k
- **Download:** [Hackable III](https://www.vulnhub.com/entry/hackable-iii,373/)
- **Skills:**
  - Multiple vulnerabilities
  - Time pressure
  - Documentation skills
  - Report writing
- **Tools yang dipelajari:** All previous tools
- **OSCP Relevance:** ⭐⭐⭐⭐ Exam simulation

### 17. Breach 1.0
- **Author:** 0xCyberY
- **Download:** [Breach 1.0](https://www.vulnhub.com/entry/breach-10,152/)
- **Skills:**
  - Multiple machines
  - Pivoting
  - Lateral movement
  - Advanced exploitation
- **Tools yang dipelajari:** SSH tunneling, Proxychains
- **OSCP Relevance:** ⭐⭐⭐⭐ Multi-host environment

### 18. Infosec Prep: OSCP-like
- **Author:** InfoSec Institute
- **Download:** [Infosec Prep: OSCP-like](https://www.vulnhub.com/entry/infosec-prep-oscp-like,219/)
- **Skills:**
  - OSCP-like scenarios
  - Time management
  - Multiple services
  - Documentation
- **Tools yang dipelajari:** Complete toolset
- **OSCP Relevance:** ⭐⭐⭐⭐⭐ Closest to real exam

## 📝 Study Plan Template

### Week 1-2: Foundation (Very Easy)
```bash
# Schedule
Day 1-2: SickOs 1.1 + write-up review
Day 3-4: Pentester Lab: Basic + methodology
Day 5-6: FristiLeaks 1.3 + steganography practice
Day 7: Review & note-taking
```

### Week 3-4: Core Skills (Easy)
```bash
# Schedule
Day 1-3: Kioptrix Level 1 + Samba deep dive
Day 4-6: Billu B0x + LFI techniques
Day 7: VulnOS 2 + WordPress security
```

### Week 5-8: Intermediate (Medium)
```bash
# Schedule
Week 5: DC-1 + Drupal exploitation
Week 6: Mr-Robot + hashcat practice
Week 7: ST-2 + SQL injection mastery
Week 8: Symphony + PHP framework research
```

### Week 9-12: Advanced (Hard/Insane)
```bash
# Schedule
Week 9: DC-5 + LFI to RCE techniques
Week 10: Inferno + CSRF practice
Week 11: Tr0ll 1 + persistence methods
Week 12: Hackable III + exam simulation
```

## 🔧 Skills Development Checklist

### Enumeration Skills
- [ ] Port scanning dengan Nmap
- [ ] Service version detection
- [ ] Web application enumeration
- [ ] Directory/file brute force
- [ ] SNMP/SMB/SMTP enumeration
- [ ] DNS reconnaissance

### Exploitation Skills
- [ ] Public exploit usage
- [ ] Custom exploit development
- [ ] Web application vulnerabilities
- [ ] Buffer overflow basics
- [ ] SQL injection
- [ ] File inclusion attacks

### Post-Exploitation Skills
- [ ] System enumeration (Linux/Windows)
- [ ] Privilege escalation techniques
- [ ] Persistence mechanisms
- [ ] Data exfiltration
- [ ] Lateral movement basics

### Methodology Skills
- [ ] Documentation practice
- [ ] Time management
- [ ] Report writing
- [ ] Tool selection
- [ ] Attack path planning

## 📊 Progress Tracking

### Machine Completion Log
```markdown
| Machine | Completed | Date | Time | Root Obtained | Notes |
|---------|-----------|------|------|---------------|-------|
| SickOs 1.1 | ✓ | 2024-01-01 | 2h | ✓ | Basic web exploitation |
| Kioptrix | ✓ | 2024-01-03 | 4h | ✓ | Sambaexploit |
| DC-1 | | | | | In progress |
```

### Skills Assessment
```markdown
| Skill Category | Current Level | Target | Practice Needed |
|----------------|---------------|--------|-----------------|
| Enumeration | Intermediate | Advanced | DNS/SMTP |
| Web Exploitation | Basic | Advanced | SQLi/XSS |
| Priv Esc | Basic | Advanced | Linux/Windows |
| Buffer Overflow | None | Basic | Basic concepts |
```

## 🎯 Exam Day Simulation

### 24-Hour Challenge
1. **Setup:** Pick 3 medium machines
2. **Time:** 8 hours total
3. **Rules:**
   - No automated exploits
   - Document every step
   - Get root on all machines
   - Write brief report

### 5-Hour Challenge
1. **Setup:** Pick 1 hard machine
2. **Time:** 5 hours max
3. **Rules:**
   - Simulate exam conditions
   - Focus on methodology
   - Practice time management

## 📚 Additional Resources

### Write-up Sources
- [VulnHub Write-ups](https://www.vulnhub.com/write-up-directory/)
- [Exploit-DB Write-ups](https://www.exploit-db.com/)
- [GitHub Repositories](https://github.com/topics/vulnhub-writeups)

### Video Walkthroughs
- [IppSec YouTube Channel](https://www.youtube.com/c/ippsec)
- [The Cyber Mentor YouTube](https://www.youtube.com/c/TheCyberMentor)
- [John Hammond YouTube](https://www.youtube.com/c/JohnHammond010)

### Practice Platforms
- [Hack The Box](https://www.hackthebox.eu/) - Similar difficulty
- [TryHackMe](https://tryhackme.com/) - Guided learning
- [Proving Grounds](https://www.ine.com/practice) - OffSec official

## ⚡ Tips for Success

### Before Starting
1. **Read instructions carefully**
2. **Set up proper environment**
3. **Have tools ready**
4. **Understand the objective**

### During Practice
1. **Take screenshots**
2. **Document commands**
3. **Note learnings**
4. **Time yourself**

### After Completion
1. **Write your own write-up**
2. **Compare with others**
3. **Identify gaps**
4. **Practice similar machines**

## 🏆 OSCP Readiness Indicators

You're ready for OSCP when you can:
- [ ] Complete medium machines in 3-4 hours
- [ ] Enumerate all services systematically
- [ ] Find vulnerabilities without hints
- [ ] Exploit without pre-written scripts
- [ ] Get root consistently
- [ ] Document all steps clearly
- [ ] Manage time effectively
- [ ] Stay calm under pressure

## 📞 Community Support

### Forums/Discord
- [VulnHub Discord](https://discord.gg/vulnhub)
- [r/oscp](https://www.reddit.com/r/oscp/)
- [HackTheBox Forums](https://forum.hackthebox.eu/)

### Study Groups
- Find local OSCP study groups
- Join online communities
- Participate in CTFs
- Share knowledge

---

## 💭 Final Thoughts

VulnHub machines are excellent for building foundational skills and methodology. Remember:

1. **Focus on the process, not just the result**
2. **Document everything for learning**
3. **Don't rush through machines**
4. **Understand why exploits work**
5. **Build your methodology**
6. **Practice time management**

Consistent practice with these machines will build the skills and confidence needed for the OSCP exam. Start with easy machines and gradually increase difficulty as you become more comfortable with the tools and techniques.

**Good luck with your OSCP preparation!** 🚀