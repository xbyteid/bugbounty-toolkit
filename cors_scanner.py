#!/usr/bin/env python3
"""
CORS Misconfiguration Scanner — Find exploitable CORS issues
Usage: python3 cors_scanner.py <url>
"""

import sys
import json
import requests
from urllib.parse import urlparse

requests.packages.urllib3.disable_warnings()

EVIL_ORIGINS = [
    "https://evil.com",
    "https://attacker.com",
    "null",
    "https://TARGET.com.evil.com",  # Subdomain bypass
    "https://TARGET.com%60.evil.com",  # Backtick bypass
    "https://TARGET.com@evil.com",  # @ bypass
    "https://evil.com#TARGET.com",  # Fragment bypass
    "https://TARGET.comevil.com",  # Prefix bypass
    "https://subdomain.TARGET.com",  # Subdomain trust
    "https://TARGET.com\.evil.com",  # Backslash bypass
    "https://TARGET.com:.evil.com",  # Colon bypass
]

def check_cors(url, origin):
    """Check if server reflects origin in CORS headers"""
    try:
        headers = {"Origin": origin}
        r = requests.get(url, headers=headers, timeout=10, verify=False, allow_redirects=True,
                        headers2={"User-Agent": "Mozilla/5.0"})
        
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        acac = r.headers.get("Access-Control-Allow-Credentials", "")
        acam = r.headers.get("Access-Control-Allow-Methods", "")
        acah = r.headers.get("Access-Control-Allow-Headers", "")
        aceh = r.headers.get("Access-Control-Expose-Headers", "")
        
        return {
            "origin_sent": origin,
            "acao": acao,
            "acac": acac,
            "acam": acam,
            "acah": acah,
            "aceh": aceh,
            "status": r.status_code,
            "vulnerable": False,
            "severity": "none",
            "description": ""
        }
    except Exception as e:
        return {"origin_sent": origin, "error": str(e)}

def analyze_cors(result, target_domain):
    """Analyze CORS configuration for vulnerabilities"""
    acao = result.get("acao", "")
    acac = result.get("acac", "").lower()
    origin = result.get("origin_sent", "")
    
    if not acao:
        result["vulnerable"] = False
        result["severity"] = "none"
        result["description"] = "No CORS headers"
        return result
    
    # Wildcard with credentials — CRITICAL
    if acao == "*" and acac == "true":
        result["vulnerable"] = True
        result["severity"] = "critical"
        result["description"] = "Wildcard origin WITH credentials — full cross-origin data theft"
        return result
    
    # Null origin reflection — HIGH
    if origin == "null" and acao == "null":
        result["vulnerable"] = True
        result["severity"] = "high"
        result["description"] = "null origin reflected with credentials — exploitable via sandboxed iframe"
        return result
    
    # Wildcard without credentials — LOW (usually safe)
    if acao == "*":
        result["vulnerable"] = False
        result["severity"] = "info"
        result["description"] = "Wildcard origin (no credentials) — generally safe"
        return result
    
    # Origin reflected — check if exploitable
    if origin.lower() == acao.lower():
        # Check for domain validation flaws
        parsed_target = urlparse(f"https://{target_domain}")
        target_host = parsed_target.netloc
        
        evil_parsed = urlparse(origin)
        evil_host = evil_parsed.netloc
        
        # Subdomain bypass: evil.TARGET.com
        if target_host in evil_host and evil_host != target_host:
            result["vulnerable"] = True
            result["severity"] = "high"
            result["description"] = f"Subdomain bypass: {origin} accepted — attacker needs XSS on any subdomain"
            return result
        
        # Exact evil origin reflected
        if "evil.com" in origin or "attacker.com" in origin:
            result["vulnerable"] = True
            result["severity"] = "critical" if acac == "true" else "high"
            result["description"] = f"Arbitrary origin reflected: {origin} (credentials: {acac})"
            return result
        
        # null reflected
        if origin == "null":
            result["vulnerable"] = True
            result["severity"] = "high"
            result["description"] = "null origin reflected — exploitable via sandboxed iframe"
            return result
        
        # Prefix matching bypass
        if f"{target_host}." in evil_host or f"{target_host}@" in evil_host:
            result["vulnerable"] = True
            result["severity"] = "critical" if acac == "true" else "high"
            result["description"] = f"Prefix/domain bypass: {origin} accepted"
            return result
        
        # Special chars bypass
        if any(c in origin for c in ["\\", "%60", "@", "#", ":"]):
            result["vulnerable"] = True
            result["severity"] = "high"
            result["description"] = f"Special character bypass: {origin}"
            return result
        
        # Reflected without special bypass — still risky with credentials
        if acac == "true":
            result["vulnerable"] = True
            result["severity"] = "medium"
            result["description"] = f"Origin reflected with credentials: {origin}"
            return result
        else:
            result["vulnerable"] = False
            result["severity"] = "low"
            result["description"] = f"Origin reflected without credentials"
            return result
    
    result["vulnerable"] = False
    result["severity"] = "none"
    result["description"] = f"Origin not reflected (got: {acao})"
    return result

def scan_url(url):
    """Full CORS scan on a URL"""
    target_domain = urlparse(url).netloc
    
    print(f"\n{'='*60}")
    print(f"🔀 CORS Misconfiguration Scanner")
    print(f"Target: {url}")
    print(f"{'='*60}\n")
    
    # First check if site has any CORS headers
    print("📡 Checking baseline CORS headers...")
    try:
        r = requests.get(url, timeout=10, verify=False, headers={"User-Agent": "Mozilla/5.0"})
        baseline_cors = {
            "Access-Control-Allow-Origin": r.headers.get("Access-Control-Allow-Origin", ""),
            "Access-Control-Allow-Credentials": r.headers.get("Access-Control-Allow-Credentials", ""),
            "Access-Control-Allow-Methods": r.headers.get("Access-Control-Allow-Methods", ""),
            "Access-Control-Allow-Headers": r.headers.get("Access-Control-Allow-Headers", ""),
        }
        
        if any(v for v in baseline_cors.values()):
            print("  CORS headers found:")
            for k, v in baseline_cors.items():
                if v:
                    print(f"    {k}: {v}")
        else:
            print("  No CORS headers on base URL (testing anyway...)")
    except Exception as e:
        print(f"  ❌ Error: {e}")
        return []
    
    # Test each evil origin
    results = []
    vulnerable = []
    
    evil_origins = [o.replace("TARGET", target_domain.replace("www.", "")) for o in EVIL_ORIGINS]
    
    # Add more variants
    evil_origins.extend([
        f"https://{target_domain}",  # Self-origin (baseline)
        f"https://www.{target_domain}",
        f"http://{target_domain}",
        f"https://{target_domain}:443",
        f"https://{target_domain}.evil.com",
        f"https://evil{target_domain}",
        f"https://{target_domain}%09.evil.com",  # Tab bypass
        f"https://{target_domain}%23.evil.com",  # Hash bypass
    ])
    
    print(f"\n🔎 Testing {len(evil_origins)} origin variants...\n")
    
    for origin in evil_origins:
        result = check_cors(url, origin)
        result = analyze_cors(result, target_domain)
        results.append(result)
        
        if result.get("vulnerable"):
            vulnerable.append(result)
            sev = result["severity"].upper()
            icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(sev, "⚪")
            print(f"  {icon} [{sev}] Origin: {origin}")
            print(f"     ACAO: {result.get('acao')}")
            print(f"     Credentials: {result.get('acac', 'N/A')}")
            print(f"     {result['description']}")
            print()
    
    # Summary
    print(f"\n{'='*60}")
    print(f"📊 CORS SCAN RESULTS")
    print(f"{'='*60}")
    print(f"Origins tested: {len(evil_origins)}")
    print(f"Vulnerable: {len(vulnerable)}")
    
    if vulnerable:
        critical = [v for v in vulnerable if v["severity"] == "critical"]
        high = [v for v in vulnerable if v["severity"] == "high"]
        medium = [v for v in vulnerable if v["severity"] == "medium"]
        
        if critical:
            print(f"\n🔴 CRITICAL ({len(critical)}):")
            for v in critical:
                print(f"  {v['description']}")
        if high:
            print(f"\n🟠 HIGH ({len(high)}):")
            for v in high:
                print(f"  {v['description']}")
        if medium:
            print(f"\n🟡 MEDIUM ({len(medium)}):")
            for v in medium:
                print(f"  {v['description']}")
    else:
        print("\n✅ No CORS misconfigurations found!")
    
    # Save
    import os
    os.makedirs("output", exist_ok=True)
    domain = target_domain.replace(".", "_")
    outfile = f"output/cors_{domain}.json"
    with open(outfile, "w") as f:
        json.dump(vulnerable, f, indent=2)
    print(f"\n💾 Saved to {outfile}")
    
    return vulnerable

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 cors_scanner.py <url>")
        print("Example: python3 cors_scanner.py https://api.example.com")
        sys.exit(1)
    
    scan_url(sys.argv[1])
