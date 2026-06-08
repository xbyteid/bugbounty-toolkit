# 🛡️ Bug Bounty Toolkit v4.0 — ULTRA OP Edition

24 tools for finding critical vulnerabilities in bug bounty programs.

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
| Tech Detect | `bounty.py tech URL` | 🆕 Technology & CMS fingerprinting |
| Favicon Hash | `bounty.py favicon URL` | 🆕 Shodan/Censys favicon hash |

## 🐛 Scanners

| Tool | Command | Description |
|------|---------|-------------|
| Vuln Scan | `bounty.py vulnscan URL` | SQLi, XSS, SSTI, Open Redirect |
| GraphQL | `bounty.py graphql URL` | Introspection + IDOR testing |
| S3 | `bounty.py s3 -b bucket` | S3 bucket misconfiguration |

## 🔑 Secret Finders

| Tool | Command | Description |
|------|---------|-------------|
| JS Secrets | `bounty.py secrets URL` | API keys, tokens, creds in JS |
| Takeover | `bounty.py takeover domain` | Dangling CNAME subdomain takeover |

## 🔥 Critical Bug Finders

| Tool | Command | Description |
|------|---------|-------------|
| CORS | `bounty.py cors URL` | CORS misconfiguration scanner |
| Redirect | `bounty.py redirect URL` | Open redirect for OAuth hijack |
| SSRF | `bounty.py ssrf URL` | Server-Side Request Forgery |
| CRLF | `bounty.py crlf URL` | 🆕 CRLF injection scanner |
| Fuzzer | `bounty.py fuzz URL` | Hidden endpoints + IDOR params |

## 💀 SUPER OP Tools

| Tool | Command | Description |
|------|---------|-------------|
| JWT Analyzer | `bounty.py jwt TOKEN` | Decode, analyze, forge JWT tokens |
| Access Control | `bounty.py acl URL` | IDOR, priv esc, mass assignment |
| Race Condition | `bounty.py race URL` | Concurrent request testing |
| Sensitive Files | `bounty.py sensitive URL` | .env, .git, backups, configs |
| Param Miner | `bounty.py paramminer URL` | 🆕 Hidden parameter discovery |

## 🆕 NEW v4.0 Tools

| Tool | Command | Description |
|------|---------|-------------|
| WAF Detect | `bounty.py waf URL` | WAF fingerprint + bypass tips |
| Email Security | `bounty.py email domain` | SPF/DKIM/DMARC checker |
| CRLF Scanner | `bounty.py crlf URL` | CRLF injection testing |
| Param Miner | `bounty.py paramminer URL` | Hidden param discovery (wordlist) |
| Tech Detect | `bounty.py tech URL` | 100+ tech/CMS fingerprinting |
| Favicon Hash | `bounty.py favicon URL` | Shodan/Censys infra discovery |

## 💣 Full Scan

```bash
python3 bounty.py full https://target.com
```

Runs ALL 21 scanning phases. Takes 15-45 minutes per target.

## 📦 Output

All results saved to `./output/` as JSON files.

## ⚠️ Disclaimer

For authorized security testing only. Always get permission before scanning.

## 📝 License

MIT
