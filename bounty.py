#!/usr/bin/env python3
"""
Bug Bounty Toolkit v3.0 — SUPER OP Edition
18 tools for finding critical vulnerabilities

Tools:
  RECON:     subdomains, crtsh, recon, full_recon
  SCANNERS:  vulnscan, graphql, s3, cors, ssrf, redirect, fuzz
  SECRETS:   secrets, takeover
  CRITICAL:  jwt, acl, race, sensitive
  ULTIMATE:  full (everything)
"""

import os
import sys
import json
import time
import requests
from datetime import datetime

requests.packages.urllib3.disable_warnings()

BANNER = """
╔══════════════════════════════════════════════════════════════╗
║           🛡️  BUG BOUNTY TOOLKIT v3.0 — SUPER OP  🛡️       ║
║              github.com/xbyteid                             ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║  📡 RECON:                                                   ║
║     1.  🔍 Subdomain Enumeration                             ║
║     2.  📜 Certificate Transparency (crt.sh)                 ║
║     3.  🔌 Port Scan + Tech Fingerprint                      ║
║     4.  🔎 Full Recon (all above combined)                   ║
║                                                              ║
║  🐛 SCANNERS:                                                ║
║     5.  🐛 Vulnerability Scanner                             ║
║     6.  🔗 GraphQL Scanner                                   ║
║     7.  📦 S3 Bucket Scanner                                 ║
║                                                              ║
║  🔑 SECRETS:                                                 ║
║     8.  🔑 JS Secret Scanner (API keys, tokens, creds)       ║
║     9.  🏴‍☠️ Subdomain Takeover Checker                       ║
║                                                              ║
║  🔥 CRITICAL BUG FINDERS:                                   ║
║    10.  🔀 CORS Misconfiguration Scanner                     ║
║    11.  ↗️  Open Redirect Scanner (OAuth hijack)              ║
║    12.  🌐 SSRF Scanner                                      ║
║    13.  🔍 Parameter & Endpoint Fuzzer                       ║
║                                                              ║
║  💀 SUPER OP TOOLS (NEW!):                                   ║
║    14.  🔐 JWT Analyzer & Forger                             ║
║    15.  🔓 Broken Access Control (IDOR + Priv Esc)           ║
║    16.  🏁 Race Condition Tester                             ║
║    17.  📁 Sensitive File Scanner (.env, .git, backups)      ║
║                                                              ║
║    18.  💣 FULL SCAN (everything combined)                   ║
║                                                              ║
║     0. Exit                                                  ║
╚══════════════════════════════════════════════════════════════╝
"""

def run_tool(script, args=""):
    cmd = f"{sys.executable} {os.path.join(os.path.dirname(__file__), script)} {args}"
    os.system(cmd)

def full_scan(url):
    from urllib.parse import urlparse
    parsed = urlparse(url)
    domain = parsed.netloc
    
    print(f"\n{'='*60}")
    print(f"💣 FULL SUPER OP SCAN — {domain}")
    print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}\n")
    
    scripts_dir = os.path.dirname(__file__)
    py = sys.executable
    
    phases = [
        ("📡 PHASE 1: SUBDOMAIN ENUM", f"{py} {scripts_dir}/subdomains.py {domain}"),
        ("📡 PHASE 2: CERTIFICATE TRANSPARENCY", f"{py} {scripts_dir}/crtsh.py {domain}"),
        ("📡 PHASE 3: PORT SCAN + FINGERPRINT", f"{py} {scripts_dir}/recon.py {domain}"),
        ("🔑 PHASE 4: JS SECRET SCANNER", f"{py} {scripts_dir}/js_secret_scanner.py {url}"),
        ("🏴‍☠️ PHASE 5: SUBDOMAIN TAKEOVER", f"{py} {scripts_dir}/subdomain_takeover.py {domain}"),
        ("📁 PHASE 6: SENSITIVE FILES", f"{py} {scripts_dir}/sensitive_scanner.py {url}"),
        ("🔀 PHASE 7: CORS SCANNING", f"{py} {scripts_dir}/cors_scanner.py {url}"),
        ("↗️  PHASE 8: OPEN REDIRECT", f"{py} {scripts_dir}/open_redirect.py {url}"),
        ("🌐 PHASE 9: SSRF SCANNING", f"{py} {scripts_dir}/ssrf_scanner.py {url}"),
        ("🔓 PHASE 10: ACCESS CONTROL (IDOR)", f"{py} {scripts_dir}/access_control.py {url}"),
        ("🔐 PHASE 11: JWT ANALYSIS", f"{py} {scripts_dir}/jwt_analyzer.py {url}"),
        ("🏁 PHASE 12: RACE CONDITIONS", f"{py} {scripts_dir}/race_condition.py {url}"),
        ("🔍 PHASE 13: PARAMETER FUZZING", f"{py} {scripts_dir}/param_fuzzer.py {url}"),
        ("🐛 PHASE 14: VULNERABILITY SCAN", f"{py} {scripts_dir}/vulnscan.py {url}"),
        ("🔗 PHASE 15: GRAPHQL SCAN", f"{py} {scripts_dir}/graphql_scan.py {url}"),
    ]
    
    for name, cmd in phases:
        print(f"\n{'='*60}")
        print(name)
        print('='*60)
        os.system(cmd)
    
    print(f"\n{'='*60}")
    print(f"✅ FULL SUPER OP SCAN COMPLETE")
    print(f"Finished: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Results in ./output/")
    print(f"{'='*60}\n")

def main():
    print(BANNER)
    
    while True:
        try:
            choice = input("\n🎯 Select tool (0-18): ").strip()
            
            if choice == "0":
                print("👋 Bye!")
                break
            elif choice == "1":
                d = input("Domain: ").strip()
                b = input("Big wordlist? (y/N): ").strip().lower()
                run_tool("subdomains.py", f"{d} {'--big' if b=='y' else ''}")
            elif choice == "2":
                run_tool("crtsh.py", input("Domain: ").strip())
            elif choice == "3":
                run_tool("recon.py", input("Target: ").strip())
            elif choice == "4":
                d = input("Domain: ").strip()
                run_tool("subdomains.py", d)
                run_tool("crtsh.py", d)
                run_tool("recon.py", d)
            elif choice == "5":
                run_tool("vulnscan.py", input("URL: ").strip())
            elif choice == "6":
                run_tool("graphql_scan.py", input("URL: ").strip())
            elif choice == "7":
                run_tool("s3scanner.py", f"-b {input('Bucket: ').strip()}")
            elif choice == "8":
                run_tool("js_secret_scanner.py", input("URL: ").strip())
            elif choice == "9":
                run_tool("subdomain_takeover.py", input("Domain: ").strip())
            elif choice == "10":
                run_tool("cors_scanner.py", input("URL: ").strip())
            elif choice == "11":
                run_tool("open_redirect.py", input("URL: ").strip())
            elif choice == "12":
                run_tool("ssrf_scanner.py", input("URL: ").strip())
            elif choice == "13":
                u = input("URL: ").strip()
                d = input("Deep? (y/N): ").strip().lower()
                run_tool("param_fuzzer.py", f"{u} {'--deep' if d=='y' else ''}")
            elif choice == "14":
                run_tool("jwt_analyzer.py", input("JWT Token or URL: ").strip())
            elif choice == "15":
                u = input("URL: ").strip()
                d = input("Deep? (y/N): ").strip().lower()
                run_tool("access_control.py", f"{u} {'--deep' if d=='y' else ''}")
            elif choice == "16":
                run_tool("race_condition.py", input("URL: ").strip())
            elif choice == "17":
                run_tool("sensitive_scanner.py", input("URL: ").strip())
            elif choice == "18":
                full_scan(input("URL: ").strip())
            else:
                print("❌ Invalid choice")
        except KeyboardInterrupt:
            print("\n👋 Bye!")
            break
        except Exception as e:
            print(f"❌ Error: {e}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        tool = sys.argv[1]
        args = " ".join(sys.argv[2:])
        
        script_map = {
            "subdomains": "subdomains.py", "crtsh": "crtsh.py",
            "recon": "recon.py", "vulnscan": "vulnscan.py",
            "graphql": "graphql_scan.py", "s3": "s3scanner.py",
            "secrets": "js_secret_scanner.py", "takeover": "subdomain_takeover.py",
            "cors": "cors_scanner.py", "redirect": "open_redirect.py",
            "ssrf": "ssrf_scanner.py", "fuzz": "param_fuzzer.py",
            "jwt": "jwt_analyzer.py", "acl": "access_control.py",
            "race": "race_condition.py", "sensitive": "sensitive_scanner.py",
            "full": None,
        }
        
        if tool == "full":
            full_scan(args)
        elif tool in script_map:
            run_tool(script_map[tool], args)
        else:
            print(f"Unknown tool: {tool}")
            print(f"Available: {', '.join(script_map.keys())}")
    else:
        main()
