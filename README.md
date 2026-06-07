# Bug Bounty Recon Toolkit

Automated recon toolkit for authorized bug bounty testing on Indonesian platforms.

## ⚠️ Legal Disclaimer

**Only use against targets you are AUTHORIZED to test.**

Unauthorized testing is illegal under:
- Indonesian UU ITE (UU No. 11/2008)
- Computer Misuse Act (various jurisdictions)

Always register on the bug bounty platform and read the program's scope/policy BEFORE testing.

## 🚀 Quick Start

```bash
cd /root/bugbounty-toolkit
source venv/bin/activate

# Interactive menu
python3 bounty.py

# Or use individual tools directly
python3 subdomains.py tokopedia.com
python3 recon.py api.gojek.com
python3 vulnscan.py "https://target.com/page?id=1"
```

## 🛠️ Tools

### 1. Subdomain Enumeration (`subdomains.py`)
```bash
python3 subdomains.py <domain> [wordlist] [--threads N]
```
- DNS bruteforce with 310+ common subdomains
- Async, multi-threaded
- Results saved to `./output/`

### 2. Quick Recon (`recon.py`)
```bash
python3 recon.py <target>
```
- Port scanning (30+ common ports)
- Technology fingerprinting (50+ signatures)
- Security header analysis
- SSL certificate check
- Common sensitive paths

### 3. Vulnerability Scanner (`vulnscan.py`)
```bash
python3 vulnscan.py <target>
```
- **SQLi** — Error-based + Time-based detection
- **XSS** — Reflected XSS + SSTI detection
- **Open Redirect** — Parameter-based redirect testing
- **CORS** — Misconfiguration detection
- **Sensitive Files** — .env, .git, backups, configs

### 4. Main CLI (`bounty.py`)
```bash
python3 bounty.py
```
- Interactive menu for all tools
- Indonesian target reference list
- Full scan mode (all tools combined)

## 🎯 Indonesian Bug Bounty Targets

| Company | Platform | Scope | Payout |
|---------|----------|-------|--------|
| Tokopedia | bounty.tokopedia.net (CLOSED) | *.tokopedia.com | N/A |
| Gojek/GoTo | HackerOne | *.gojek.com, GoPay | $100-5,000+ |
| Traveloka | Bugcrowd | *.traveloka.com | $50-1,500+ |
| Bukalapak | HackerOne | *.bukalapak.com | $50-1,000+ |
| Shopee ID | Email (security@shopee.com) | *.shopee.co.id | varies |
| Grab | HackerOne | *.grab.com, *.grabtaxi.com | $100-5,000+ |
| Tokocrypto | HackerOne | *.tokocrypto.com | varies |

## 📁 Output

All results saved to `./output/` as JSON:
- `subdomains_<domain>_<timestamp>.json`
- `vulns_<timestamp>.json`

## 🔧 Dependencies

- Python 3.8+
- aiohttp, dnspython, rich, colorama, pyyaml

## 💡 Tips

1. **Start with subdomains** — find hidden dev/staging environments
2. **Check sensitive files first** — .env, .git, backups = instant bounty
3. **Test parameters** — append `?id=1` to URLs, then test SQLi/XSS
4. **Register on platforms first** — HackerOne, Bugcrowd, Intigriti
5. **Read program scope** — only test what's in scope
6. **Be polite** — rate limiting built-in, don't DDoS
7. **Document everything** — screenshots, HTTP requests, payloads used
8. **Report responsibly** — follow platform disclosure guidelines

## 📊 Bounty Hunting Workflow

```
1. Register on HackerOne/Bugcrowd
2. Pick target from Indonesian programs list
3. Run subdomain enumeration
4. Run quick recon on interesting subdomains
5. Check sensitive files (.env, .git, backups)
6. Test parameters for SQLi/XSS
7. Document findings with evidence
8. Submit report via platform
9. Wait for triage (usually 1-7 days)
10. Get paid 💰
```

## 🏆 Findings (June 2026)

### Tokopedia
- **Staging environment accessible via direct IP bypass**
- Hardcoded OAuth/Facebook/Google API keys in client-side JS
- Internal endpoints leaked (accounts, pay, chat, seller, SSE)
- Consul feature flag templates rendered client-side
- Status: Reported to security@bytedance.com

### Grab
- **S3 bucket `bpa-public-resources` fully public on cdn.grab-bat.net**
- 1000+ files including merchant data, legal docs, OTP source code
- Internal project folders (batman-avatar-log, bpia-6685)
- Country-specific marketing materials (ID, MY, TH, VN, SG)
- Status: Reported via HackerOne (Report #4780199)

### Shopee
- **UAT environment (uat.shopee.co.id) publicly accessible**
- Shopee CCMS App Key & Secret hardcoded
- Google Maps API keys (Live + NonLive) exposed
- Git SHA and branch name leaked
- CORS wildcard (Access-Control-Allow-Origin: *)
- CSP reveals internal UAT domains (AirPay, Korea, China)
- Status: Reported to security@shopee.com
