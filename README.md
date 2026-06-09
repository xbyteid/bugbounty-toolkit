# 🛡️ Bug Bounty Toolkit v10.1 — Full Arsenal Edition

69+ tools for finding critical vulnerabilities in bug bounty programs.

31 custom Python scripts + 17 Go/binary tools + 9 cloned repos + 6 system tools + stealth browser automation.

## 🚀 Quick Start

```bash
python3 bounty.py          # Interactive menu
python3 bounty.py full URL  # Full scan everything
```

## 📡 Recon Tools

| Tool | Command | Description |
|------|---------|-------------|
| Subdomains | `bounty.py subdomains domain.com` | Enumerate subdomains (52K wordlist) |
| CRT.sh | `bounty.py crtsh domain.com` | Certificate Transparency discovery |
| Recon | `bounty.py recon domain.com` | Port scan + tech fingerprint |
| Tech Detect | `bounty.py tech URL` | Technology & CMS fingerprinting |
| Favicon Hash | `bounty.py favicon URL` | Shodan/Censys favicon hash |
| Scope Scanner | `bounty.py scope URL` | H1 scope validation |

## 🐛 Scanners

| Tool | Command | Description |
|------|---------|-------------|
| Vuln Scan | `bounty.py vulnscan URL` | SQLi, XSS, SSTI, Open Redirect |
| GraphQL | `bounty.py graphql URL` | Introspection + IDOR testing |
| S3 | `bounty.py s3 -b bucket` | S3 bucket misconfiguration |
| Access Control | `bounty.py acl URL` | IDOR, priv esc, mass assignment |
| Race Condition | `bounty.py race URL` | Concurrent request testing |
| SSRF | `bounty.py ssrf URL` | Server-Side Request Forgery |

## 🔑 Secret Finders

| Tool | Command | Description |
|------|---------|-------------|
| JS Secrets | `bounty.py secrets URL` | API keys, tokens, creds in JS |
| GitHub Secrets | `bounty.py ghsecrets repo` | Scan GitHub repos for leaked keys |
| TruffleHog | `trufflehog git https://github.com/x/y` | Deep secret scanning (Go) |
| Gitleaks | `gitleaks detect --source .` | Git secret scanner |

## 🔥 Critical Bug Finders

| Tool | Command | Description |
|------|---------|-------------|
| CORS | `bounty.py cors URL` | CORS misconfiguration scanner |
| Redirect | `bounty.py redirect URL` | Open redirect for OAuth hijack |
| CRLF | `bounty.py crlf URL` | CRLF injection scanner |
| Fuzzer | `bounty.py fuzz URL` | Hidden endpoints + IDOR params |
| Param Miner | `bounty.py paramminer URL` | Hidden parameter discovery |

## 💀 Advanced Tools

| Tool | Command | Description |
|------|---------|-------------|
| JWT Analyzer | `bounty.py jwt TOKEN` | Decode, analyze, forge JWT tokens |
| OAuth Tester | `bounty.py oauth URL` | OAuth flow testing |
| Session Analyzer | `bounty.py session URL` | Session management testing |
| Email Security | `bounty.py email domain` | SPF/DKIM/DMARC checker |
| WAF Detect | `bounty.py waf URL` | WAF fingerprint + bypass tips |
| Sensitive Files | `bounty.py sensitive URL` | .env, .git, backups, configs |

## 🆕 New in v10.0–v10.1

| Tool | Type | Description |
|------|------|-------------|
| Holehe | Python (pip) | Email OSINT — check registrations across 120+ sites |
| Scrapling | Python (pip) | Undetectable web scraper with anti-bot bypass |
| Porch-Pirate | Python (pip) | Postman collection OSINT — dump secrets from public workspaces |
| cloud_enum | Python | Multi-cloud enumeration (AWS S3, Azure Blobs, GCP) |
| CloakQuest3r | Python | Uncover real IP behind Cloudflare & other CDNs |
| Nomore403 | Go | Automated 403/40X bypass techniques (path mutation, header injection) |
| SqliSniper | Python | Time-based blind SQLi fuzzer for HTTP headers |
| cvemap | Go | CVE search & filter with powerful queries (ProjectDiscovery) |

## 🛠️ External Go/Binary Tools

| Tool | Version | Description |
|------|---------|-------------|
| nuclei | v3.8.0 | Vulnerability scanner (template-based) |
| subfinder | v2.14.0 | Subdomain enumeration |
| httpx | v1.6+ | HTTP probing |
| naabu | latest | Port scanner |
| katana | latest | Web crawler |
| ffuf | v2.1.0 | Web fuzzer |
| dalfox | v2.13.0 | XSS scanner |
| gitleaks | v8.30.1 | Git secret scanner |
| trufflehog | v3.88.24 | Deep secret scanning |
| rustscan | v2.3.0 | Fast port scanner |
| feroxbuster | v2.11.0 | Content discovery |
| gobuster | v3.8.2 | Directory/DNS brute-force |
| anew | latest | Append unique lines |
| notify | latest | Push notifications (Telegram/Discord) |
| cent | latest | Nuclei template aggregator |
| uro | v1.0.2 | URL deduplication |
| gau | v2.2.4 | URL fetcher (Wayback/CommonCrawl) |
| dnsx | latest | DNS toolkit |
| uncover | v1.2.1 | Attack surface discovery |
| cvemap | latest | CVE search & filter |
| nomore403 | latest | 403/40X bypass |

## 🔧 System Tools

| Tool | Version | Description |
|------|---------|-------------|
| nmap | 7.94 | Network scanner |
| nikto | latest | Web server scanner |
| hydra | v9.5 | Password brute-force |
| sqlmap | latest | SQL injection |
| jwt_tool | latest | JWT cracking/analysis |
| arjun | v2.2.7 | Hidden parameter discovery |

## 🌐 Browser Automation

| Tool | Description |
|------|-------------|
| Playwright | Stealth browser automation |
| playwright-stealth | Anti-detection patches |
| Selenium | Browser automation |
| tf-playwright-stealth | Additional stealth |

## 💣 Full Scan

```bash
python3 bounty.py full https://target.com
```

Runs ALL scanning phases. Takes 15-45 minutes per target.

## 📦 Output

All results saved to `./output/` as JSON files.

## ⚠️ Disclaimer

For authorized security testing only. Always get permission before scanning.

## 📝 License

MIT
