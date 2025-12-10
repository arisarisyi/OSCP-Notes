# OSINT Web Resources for Penetration Testing

Daftar lengkap web resources dan online tools yang penting untuk Open Source Intelligence (OSINT) dan penetration testing.

## ⭐ Legend Prioritas

- **⭐⭐⭐** WAJIB (Harus diketahui dan digunakan rutin)
- **⭐⭐** PENTING (Sangat berguna untuk OSINT)
- **⭐** REKOMENDASI (Baik untuk diketahui)

## 🔍 Search Engines & Asset Discovery

### ⭐⭐⭐ Shodan
- **URL:** https://shodan.io/
- **Deskripsi:** Search engine untuk Internet-connected devices
- **Kegunaan:**
  - Cari exposed devices (cameras, IoT, servers)
  - Find specific services (RDP, SSH, webcams)
  - Enumerate subdomains dan IP ranges
  - Historical data tracking
- **Query Examples:**
  ```
  port:445 "domain controller"
  port:22 "SSH-2.0-OpenSSH"
  "default password" camera
  product:"Apache httpd"
  ```
- **Pricing:** Free dengan credits, berbayar untuk unlimited

### ⭐⭐⭐ Censys
- **URL:** https://censys.io/
- **Deskripsi:** Search engine untuk Internet-connected devices
- **Kegunaan:**
  - Discover certificates and domains
  - Find exposed services
  - Certificate transparency logs
  - Historical certificates data
- **Query Examples:**
  ```
  services.service_name: ssh
  parsed.names: target.com
  services.tls.certificate.parsed.names: target.com
  ```

### ⭐⭐⭐ Google Dorking
- **URL:** https://www.google.com/
- **Deskripsi:** Advanced search operators untuk menemukan sensitive information
- **Kegunaan:**
  - Find exposed documents
  - Discover login pages
  - Find configuration files
  - Locate sensitive information
- **Advanced Operators:**
  ```
  site:domain.com
  filetype:pdf | filetype:doc | filetype:xls
  inurl:admin | inurl:login
  intitle:"index of"
  "password" OR "secret" OR "confidential"
  ```

### ⭐⭐ Bing
- **URL:** https://www.bing.com/
- **Deskripsi:** Microsoft search engine dengan advanced features
- **Kegunaan:**
  - Different search results dari Google
  - IP-based searching
  - More lenient indexing
- **Advanced Search:**
  ```
  site:domain.com filetype:pdf
  ip:192.168.1.1
  ```

### ⭐ DuckDuckGo
- **URL:** https://duckduckgo.com/
- **Deskripsi:** Privacy-focused search engine
- **Kegunaan:**
  - No tracking or personalization
  - Bang commands for direct site search
  - Clean results without filter bubbles
- **Bang Commands:**
  ```
  !g keyword  - Search on Google
  !gh username - Search GitHub
  !w keyword  - Search Wikipedia
  ```

## 🔐 Domain & DNS Intelligence

### ⭐⭐⭐ DNSDumpster
- **URL:** https://dnsdumpster.com/
- **Deskripsi:** Online DNS research tool
- **Kegunaan:**
  - DNS records lookup
  - Subdomain discovery
  - DNS map visualization
  - IP address resolution
- **Features:**
  - A, MX, NS, TXT records
  - Subdomain enumeration
  - IP address sharing

### ⭐⭐⭐ VirusTotal
- **URL:** https://www.virustotal.com/
- **Deskripsi:** Malware and URL analysis service
- **Kegunaan:**
  - URL scanning
  - Domain reputation
  - Subdomain discovery
  - IP information
  - Historical passive DNS data
- **Passive DNS:** Reveal all historical DNS records

### ⭐⭐ SecurityTrails
- **URL:** https://securitytrails.com/
- **Deskripsi:** Attack surface monitoring platform
- **Kegunaan:**
  - Subdomain discovery
  - Historical DNS data
  - IP address information
  - Domain WHOIS
  - Associated domains
- **Pricing:** Free dengan limitations, berbayar untuk full access

### ⭐⭐ Sublist3r API
- **URL:** https://sublist3r.readthedocs.io/
- **Deskripsi:** Subdomain enumeration service
- **Kegunaan:**
  - API untuk programmatic access
  - Multiple search engines
  - Real-time subdomain discovery

### ⭐ DNSRecon
- **URL:** https://github.com/darkoperator/dnsrecon
- **Deskripsi:** DNS enumeration script
- **Kegunaan:**
  - Zone transfer attempts
  - SRV record enumeration
  - Reverse lookups
  - Cache snooping

### ⭐ Amass Intelligence
- **URL:** https://github.com/OWASP/Amass
- **Deskripsi:** In-depth attack surface mapping
- **Kegunaan:**
  - Passive/active reconnaissance
  - Certificate transparency logs
  - Search engines integration
  - DNS enumeration

## 📧 Email & Domain Intelligence

### ⭐ Hunter.io
- **URL:** https://hunter.io/
- **Deskripsi:** Email finder and verifier
- **Kegunaan:**
  - Find email addresses by domain
  - Email verification
  - Pattern recognition
  - Professional network discovery
- **Pricing:** Free quota per month, berbayar untuk unlimited

### ⭐⭐ Mailtester
- **URL:** https://mailtester.com/
- **Deskripsi:** Email server testing
- **Keguaan:**
  - MX record lookup
  - SMTP testing
  - Email verification
  - SPF/DKIM records

### ⭐⭐ Email Hippo
- **URL:** https://www.emailhippo.com/
- **Deskripsi:** Email verification service
- **Kegunaan:**
  - Email validation
  - Disposable email detection
  - Free/SMTP checking

### ⭐ SpoofCheck
- **URL:** https://www.returnpath.net/resources/sender-check/
- **Deskripsi:** Email spoofing detection
- **Kegunaan:**
  - SPF record verification
  - DMARC record check
  - DNS configuration validation

## 🌐 Social Media & Username Enumeration

### ⭐⭐⭐ Sherlock
- **URL:** https://github.com/sherlock-project/sherlock
- **Deskripsi:** Username search across social networks
- **Kegunaan:**
  - Find social media accounts
  - Username consistency check
  - OSINT data gathering
- **Install:** `pip install sherlock`

### ⭐⭐ WhatsMyName
- **URL:** https://whatsmyname.app/
- **Deskripsi:** Web-based username search
- **Kegunaan:**
  - Check username availability
  - Find existing accounts
  - Investigate digital footprint

### ⭐ Social Analyzer
- **URL:** https://github.com/x-hw/social-analyzer
- **Deskripsi:** OSINT tool for social media
- **Kegunaan:**
  - Instagram, Twitter, TikTok analysis
  - Profile information gathering
  - Activity monitoring

### ⭐⭐ Maigret
- **URL:** https://github.com/soxoj/maigret
- **Deskripsi:** Find username across many social networks
- **Kegunaan:**
  - Web scraping based search
  - JSON/API based search
  - Customizable platforms

## 🏢 Company & Business Intelligence

### ⭐⭐⭐ LinkedIn
- **URL:** https://www.linkedin.com/
- **Deskripsi:** Professional networking platform
- **Kegunaan:**
  - Employee enumeration
  - Email format discovery
  - Organizational structure
  - Department information

### ⭐⭐ Crunchbase
- **URL:** https://www.crunchbase.com/
- **Deskripsi:** Business platform for company information
- **Kegunaan:**
  - Company information
  - Employee count
  - Technology stack
  - Acquisitions

### ⭐⭐ Glassdoor
- **URL:** https://www.glassdoor.com/
- **Deskripsi:** Company reviews and information
- **Kegunaan:**
  - Technology stack discovery
  - Internal applications
  - Company size
  - Security practices

### ⭐⭐ SimilarTech
- **URL:** https://www.similartech.com/
- **Deskripsi:** Technology profiler and competitive intelligence
- **Kegunaan:**
  - Technology stack identification
  - Website technology discovery
  - Vendor information

## 🔍 IP & Network Intelligence

### ⭐⭐⭐ AbuseIPDB
- **URL:** https://www.abuseipdb.com/
- **Deskripsi:** IP address abuse database
- **Kegunaan:**
  - IP reputation checking
  - Abuse reports
  - Country information
  - Tor exit node identification

### ⭐⭐ IP2Location
- **URL:** https://www.ip2location.io/
- **Deskripsi:** IP geolocation service
- **Kegunaan:**
  - IP geolocation
  - ISP information
  - Proxy/VPN detection

### ⭐⭐ uTrace
- **URL:** https://utracer.com/
- **Deskripsi:** IP tracing tool
- **Kegunaan:**
  - IP geolocation
  - Route tracing
  - ISP information

### ⭐ Spamhaus
- **URL:** https://www.spamhaus.org/
- **Deskripsi:** Spam and cybercrime information
- **Kegunaan:**
  - Blocklist checking
  - IP reputation
  - Botnet identification

## 🌍 Geolocation & Mapping

### ⭐⭐⭐ Google Earth / Maps
- **URL:** https://earth.google.com/
- **Deskripsi:** Satellite imagery and mapping
- **Kegunaan:**
  - Physical security assessment
  - Location verification
  - Building layout analysis
  - Entry point identification

### ⭐⭐ OpenStreetMap
- **URL:** https://www.openstreetmap.org/
- **Deskripsi:** Collaborative mapping project
- **Kegunaan:**
  - Street level details
  - Building information
  - Infrastructure mapping

### ⭐⭐ Google Street View
- **URL:** https://www.google.com/streetview/
- **Deskripsi:** Street-level imagery
- **Kegunaan:**
  - Physical security assessment
  - Entry points
  - Security measures

## 🔒 SSL/TLS Certificate Intelligence

### ⭐⭐⭐ crt.sh
- **URL:** https://crt.sh/
- **Deskripsi:** Certificate transparency log search
- **Kegunaan:**
  - Certificate discovery
  - Subdomain enumeration
  - Historical certificates
  - Certificate transparency monitoring

### ⭐⭐⭐ Certificate Search
- **URL:** https://censys.io/certificates
- **Deskripsi:** Certificate search engine
- **Kegunaan:**
  - Wildcard certificates
  - Subject Alternative Names (SAN)
  - Issuer information

### ⭐⭐ SSL Labs
- **URL:** https://www.ssllabs.com/ssltest/
- **Deskripsi:** SSL/TLS certificate testing
- **Kegunaan:**
  - Certificate analysis
  - Configuration testing
  - Vulnerability detection

## 📄 Document & File Discovery

### ⭐⭐⭐ Google Custom Search
- **URL:** https://cse.google.com/
- **Deskripsi:** Custom search engine creation
- **Kegunaan:**
  - Targeted document search
  - Custom search parameters
  - Automation capabilities

### ⭐⭐ Wayback Machine
- **URL:** https://web.archive.org/
- **Deskripsi:** Internet archive and web page history
- **Kegunaan:**
  - Historical website versions
  - Changed page detection
  - Deleted content recovery
  - Link discovery

### ⭐⭐ DocumentCloud
- **URL:** https://www.documentcloud.org/
- **Deskripsi:** Document repository for journalists
- **Keguaan:**
  - Sensitive document search
  - Company disclosures
  - Government documents

### ⭐⭐ PDF Drive
- **URL:** https://www.pdfdrive.com/
- **Deskripsi**: Search engine for PDF documents
- **Kegunaan:**
  - Document search
  - Manual discovery
  - Configuration guides

## 🚨 Vulnerability & Exploit Intelligence

### ⭐⭐⭐ Exploit-DB
- **URL:** https://www.exploit-db.com/
- **Deskripsi:** Exploit archive and vulnerability database
- **Kegunaan:**
  - Exploit search
  - Vulnerability research
  - CVE mapping
  - Exploit code

### ⭐⭐ Packet Storm
- **URL:** https://packetstormsecurity.org/
- **Deskripsi:** Security information and resources
- **Keguaan:**
  - Exploit archives
  - Security advisories
  - Tools and exploits

### ⭐⭐⭐ MITRE ATT&CK
- **URL:** https://attack.mitre.org/
- **Deskripsi:** Adversary tactics, techniques, and procedures
- **Kegunaan:**
  - TTP analysis
  - Attribution research
  - Threat intelligence
  - Mitigation strategies

### ⭐⭐ CVE Details
- **URL:** https://www.cvedetails.com/
- **Deskripsi**: CVE vulnerability database
- **Keguaan:**
  - Vulnerability lookup
  - CVSS scores
  - Affected products
  - Exploit availability

## 🤖 Automation & API Resources

### ⭐⭐ Shodan CLI
- **URL:** https://github.com/achillean/shodan-python
- **Deskripsi:** Python library and CLI for Shodan
- **Install:** `pip install shodan`
- **Commands:**
  ```python
  shodan host 192.168.1.1
  shodan count "port:445 country:US"
  shodan download --limit 1000 port:22
  ```

### ⭐⭐ Censys Python
- **URL:** https://github.com/censys/censys-python
- **Deskripsi**: Python library for Censys API
- **Install:** `pip install censys`

### ⭐⭐ SecurityTrails API
- **URL:** https://securitytrails.com/docs/api
- **Deskripsi**: REST API for OSINT
- **Features:**
  - Subdomain enumeration
  - DNS history
  - Associated domains

### ⭐⭐ RiskIQ API
- **URL:** https://api.riskiq.net/
- **Deskripsi**: Risk intelligence API
- **Features:**
  - Domain intelligence
  - Passive DNS
  - Malware analysis

## 📱 Mobile & App Intelligence

### ⭐⭐⭐ App Store (Apple)
- **URL:** https://apps.apple.com/
- **Deskripsi**: Apple's app store
- **Kegunaan:**
  - Company applications
  - Employee-developed apps
  - Mobile security assessment

### ⭐⭐⭐ Google Play Store
- **URL:** https://play.google.com/
- **Deskripsi**: Android app store
- **Kegunaan:**
  - Company applications
  - API endpoints discovery
  - Application testing

### ⭐⭐ AppBrain
- **URL:** https://www.appbrain.com/
- **Deskripsi**: Android app store statistics
- **Kegunaan:**
  - Developer information
  - Application statistics
  - SDK information

## 🚨 Dark Web Resources

### ⭐ Ahmia
- **URL:** https://ahmia.fi/
- **Deskripsi**: Tor search engine
- **Kegunaan:**
  - Dark web search
  - Onion site discovery
  - Hidden services

### ⭐ OnionScan
- **URL:** https://onionscan.org/
- **Deskripsi**: Dark web scanner
- **Kegunaan:**
  - Onion site analysis
  - Service fingerprinting
  - Configuration analysis

### ⭐ CheckPhish
- **URL:** https://checkphish.ai/
- **Deskripsi**: Phishing site detection
- **Keguaan:**
  - Phishing site verification
  - Brand monitoring
  - Campaign tracking

## 🔌 Browser Extensions & Add-ons

### ⭐⭐⭐ Wappalyzer

- **Download:** [Chrome Extension](https://chrome.google.com/webstore/detail/wappalyzer/gppongmhjkpfnbhagpmjfkannfbfcag) | [Firefox Add-on](https://addons.mozilla.org/en-US/firefox/addon/wappalyzer/)
- **Kegunaan:**
  - Identifikasi teknologi web (framework, CMS, server, analytics)
  - Deteksi JavaScript libraries
  - Identify web server information
  - Technology stack analysis
- **Features:**
  - Technology fingerprinting
  - Version detection
  - IP address lookup
  - SSL certificate info

### ⭐⭐⭐ FoxyProxy

- **Download:** [Chrome Extension](https://chrome.google.com/webstore/detail/foxyproxy-standard/gcknhkkoolaabfmlnbnogjdfpbklook) | [Firefox Add-on](https://addons.mozilla.org/en-US/firefox/addon/foxyproxy-standard/)
- **Kegunaan:**
  - Proxy management untuk routing traffic
  - Multiple proxy configuration
  - SSH tunneling support
  - Domain-based proxy routing
- **Features:**
  - Multiple proxy profiles
  - Automatic proxy switching
  - SOCKS5/HTTP proxy support
  - PAC file support

### ⭐⭐⭐ Cookie Editor

- **Download:** [Chrome Extension](https://chrome.google.com/webstore/detail/editthiscookie/fngmhnnpilocpplnbkdgkkohbibnhfgh) | [Firefox Add-on](https://addons.mozilla.org/en-US/firefox/addon/editthiscookie/)
- **Kegunaan:**
  - Edit, delete, dan export cookies
  - Session hijacking
  - Authentication bypass testing
  - Cookie manipulation
- **Features:**
  - Search and filter cookies
  - Import/export cookies
  - Edit cookie values
  - Session management

### ⭐⭐⭐ HTTP Header Live

- **Download:** [Chrome Extension](https://chrome.google.com/webstore/detail/http-header-live/ineipidpohbgdaaejeojmbaomdjceac) | [Firefox Add-on](https://addons.mozilla.org/en-US/firefox/addon/http-header-live/)
- **Keguaan:**
  - Monitor HTTP headers in real-time
  - Debug web applications
  - Security header analysis
  - API request/response inspection
- **Fetures:**
  - Real-time header monitoring
  - Request/ body display
  - HTTP status codes
  - Timeline view

### ⭐⭐ XPath Helper

- **Download:** [Chrome Extension](https://chrome.google.com/webstore/detail/xpath-helper/hgimnlojpcncblnfcdpfngimdmnjibln) | [Firefox Alternative](https://addons.mozilla.org/en-US/firefox/addon/fire-path/)
- **Keguaan:**
  - XPath expression testing
  - Web scraping assistance
  - XML/HTML path extraction
  - Debug web applications
- **Features:**
  - Real-time XPath evaluation
  - Auto-complete suggestions
  - Result highlighting
  - Multiple expressions

### ⭐⭐ Tampermonkey/Greasemonkey

- **Download:**
  - Tampermonkey: [Chrome](https://chrome.google.com/webstore/tampermonkey/dhdgffkkebhmkfjojpclmlgfepdokom/) | [Firefox](https://addons.mozilla.org/en-US/firefox/addon/tampermonkey/)
  - Greasemonkey: [Firefox](https://addons.mozilla.org/en-US/firefox/addon/greasemonkey/)
- **Kegunaan:**
  - Run custom JavaScript on websites
  - Modify web pages
  - Automate repetitive tasks
  - Add functionality to sites
- **Features:**
  - Script management
  - Auto-update scripts
  - Script debugging
  - Resource injection

### ⭐⭐ Web Developer Tools (Built-in)

- **Chrome:** Press F12 → Developer Tools
- **Firefox:** Press F12 → Developer Tools
- **Kegunaan:**
  - Element inspection
  - Console debugging
  - Network monitoring
  - Performance analysis
- **Key Features:**
  - Inspect Element
  - Console
  - Network tab
  - Sources
  - Performance
  - Security

### ⭐⭐ EditThisCookie (Alternative)
- **Firefox:** [Cookie Quick Manager](https://addons.mozilla.org/en-US/firefox/addon/cookie-quick-manager/)
- **Chrome:** [Cookie Editor](https://chrome.google.com/webstore/detail/cookie-editor/mlomjdfmfegflcgfplmphehkomifcgfaj)
- **Advanced Features:**
  - Bulk cookie editing
  - Cookie creation
  - Domain filtering
  - Session persistence

### ⭐ Session Hijacker

- **Download:** [Chrome Extension](https://chrome.google.com/webstore/detail/session-hijacker/fidgomonjdlmmpcdgjodfhjocbpfjdpf)
- **Kegunaan:**
  - Session token extraction
  - Authorization header capture
  - Session hijacking demonstration
  - Security testing
- **Features:**
  - Token extraction
  - Domain filtering
  - Multiple tabs support

### ⭐⭐ HackBar

- **Download:** [Firefox Add-on](https://addons.mozilla.org/en-US/firefox/addon/hackbar/)
- **Alternative for Chrome:** [Burp Suite Extension](https://portswigger.net/burp/docs/communitydownload)
- **Keguaan:**
  - SQL injection testing
  - XSS payload testing
  - Parameter fuzzing
  - Custom payload creation
- **Features:**
  - Payload library
  - History tracking
  - Encoding/decoding
  - Custom parameters

### ⭐⭐ User-Agent Switcher

- **Download:** [Chrome Extension](https://chrome.google.com/webstore/user-agent-switcher-for-c/djflflibiepbjdhfpcgabjoeikadcmjil/) | [Firefox Add-on](https://addons.mozilla.org/en-US/firefox/addon/user-agent-string-switcher/)
- **Kegunaan:**
  - Browser fingerprinting evasion
  - Mobile device emulation
  - Bypass browser restrictions
  - Compatibility testing
- **Features:**
  - Pre-defined user agents
  - Custom user agents
  - Random rotation
  - Device filtering

### ⭐⭐ JSON Formatter

- **Download:** [Chrome Extension](https://chrome.google.com/webstore/json-formatter/bcjindjcajdmjjgmidgodglfglekapipfj) | [Firefox Add-on](https://addons.mozilla.org/en-US/firefox/addon/jsonview/)
- **Kegunaan:**
  - Format JSON responses
  - Syntax highlighting
  - Collapsible tree view
  - JSON validation
- **Features:**
  - Syntax validation
  - Color formatting
  - Collapsible nodes
  - Raw/minified view

### ⭐⭐ Markdown Preview

- **Download:**
  - Chrome: [Markdown Preview Plus](https://chrome.google.com/webstore/markdown-preview-plus/elifmaoikdlpiljhejogfnlghiknckcaje)
  - Firefox: [Markdown Viewer](https://addons.mozilla.org/en-US/firefox/addon/markdown-viewer/)
- **Kegunaan:**
  - Markdown editing
  - Real-time preview
  - Documentation creation
  - README editing
- **Features:**
  - Live preview
  - Syntax highlighting
  - Export options
  - Custom CSS support

### ⭐⭐ Speed Test

- **Download:** [Chrome Extension](https://chrome.google.com/webstore/speed-test-by-cloudflare/plojekkgcpbnjoclpbamhijodbapdpmgj/)
- **Kegunaan:**
  - Network speed testing
  - Latency testing
  - Bandwidth verification
  - Connection diagnostics
- **Features:**
  - Global coverage
  - Historical data
  - Comparison tools
  - Advanced metrics

### ⭐⭐ DNSSEC Analyzer

- **Download:** [Firefox Add-on](https://addons.mozilla.org/en-US/firefox/addon/dnssec-analyzer/)
- **Kegunaan:**
  - DNSSEC validation
  - DNS chain of trust analysis
  - Security verification
  - Certificate checking
- **Features:**
  - Chain validation
  - Trust anchor checking
  - Security status
  - Detailed reporting

## 📝 Tips & Best Practices

### General OSINT Workflow

1. **Start Broad** - Use search engines untuk initial discovery
2. **Domain Focus** - Focus on target domain dan subdomains
3. **Technical Enumeration** - Use specialized tools
4. **Passive Only** - Avoid direct interaction initially
5. **Document Everything** - Keep detailed notes
6. **Cross-Reference** - Verify findings with multiple sources
7. **Time Intelligence** - Periodic re-checks for new information

### Common Queries for Pentesting

#### Google Dorks
```
site:target.com inurl:admin
site:target.com filetype:pdf "confidential"
site:target.com "password" OR "secret"
site:target.com ext:php "index of"
inurl:"wp-content" site:target.com
intitle:"index of" site:target.com backup
```

#### Shodan Queries
```
org:"Target Organization"
ssl:target.com
port:445 "domain controller"
port:22 "SSH-2.0-OpenSSH"
http.title:"login page" hostname:target
```

#### DNS Enumeration
```
*.target.com
*.internal.target.com
dev.target.com
staging.target.com
```

### Automation Script Template

```python
#!/usr/bin/env python3
# osint_automation.py

import requests
import json
import time

def search_shodan(query, api_key):
    """Search Shodan with given query"""
    url = "https://api.shodan.io/shodan/host/search"
    params = {"key": api_key, "query": query}
    response = requests.get(url, params=params)
    return response.json()

def get_subdomains(domain, api_key):
    """Get subdomains from various sources"""
    subdomains = []

    # Use multiple APIs
    sources = [
        f"https://crt.sh/?q=%.{domain}",
        f"https://dnsdumpster.com/"
    ]

    return subdomains

def main():
    target_domain = "target.com"
    shodan_api_key = "YOUR_API_KEY"

    # Search for targets
    query = f"ssl:{target_domain}"
    results = search_shodan(query, shodan_api_key)

    # Process results
    for host in results['matches']:
        print(f"Host: {host['ip_str']}")
        print(f"Port: {host['port']}")
        print(f"Org: {host.get('org', 'Unknown')}")
        print("-" * 50)

if __name__ == "__main__":
    main()
```

### Legal Considerations

⚠️ **IMPORTANT:** Always ensure you have:
- **Authorization** for target assessment
- **Compliance** with local laws
- **Ethical approach** to information gathering
- **Documentation** of all activities
- **Scope definition** that respects privacy

### OSINT Resources for Learning

1. **OSINT Framework:** https://osintframework.com/
2. **OSINT Curious Project:** https://osintcurious.com/
3. **Bellingcat Guides:** https://www.bellingcat.com/resources/
4. **OSINT Techniques Blog:** https://medium.com/@osinttechniques

---

## 🔗 Quick Reference

### Essential Tools Bookmark Folder:
- Search Engines: Shodan, Censys, Google
- DNS: DNSDumpster, VirusTotal
- Social: Sherlock, LinkedIn
- Docs: Wayback Machine, Exploit-DB
- Automation: Shodan CLI, Censys Python

### Daily Checklist:
- [ ] Monitor certificate transparency logs
- [ ] Search for new subdomains
- [ ] Check for exposed services
- [ ] Review security bulletins
- [ ] Document findings

---

**Remember:** OSINT is the foundation of any security assessment. The more information you gather passively, the better prepared you'll be for active testing. Always combine multiple sources and verify findings for accuracy.