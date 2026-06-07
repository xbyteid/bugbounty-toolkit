#!/usr/bin/env python3
"""
JS Secret Scanner — Extract API keys, tokens, secrets from JavaScript bundles
Usage: python3 js_secret_scanner.py <url_or_file>
"""

import re
import sys
import json
import hashlib
import requests
from urllib.parse import urlparse

requests.packages.urllib3.disable_warnings()

# High-confidence secret patterns
PATTERNS = {
    "AWS Access Key": r"(?<![A-Z0-9])(AKIA[0-9A-Z]{16})(?![A-Z0-9])",
    "AWS Secret Key": r"(?i)aws_secret_access_key[^=]*=\s*['\"]?([A-Za-z0-9/+=]{40})",
    "Google API Key": r"AIza[0-9A-Za-z_\-]{35}",
    "Google OAuth ID": r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
    "Firebase Key": r"(?i)firebase[^'\"]*['\"]([^'\"]*AIza[0-9A-Za-z_\-]{35}[^'\"]*)['\"]",
    "GitHub Token": r"(gh[ps]_[A-Za-z0-9_]{36,255}|github_pat_[A-Za-z0-9_]{22,255})",
    "GitHub OAuth": r"(?i)github[^'\"]*['\"]([0-9a-f]{20})['\"]",
    "Slack Token": r"xox[bpsorta]-[0-9A-Za-z\-]{10,255}",
    "Slack Webhook": r"hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+",
    "Stripe Key": r"(sk|pk|rk)_(test|live)_[0-9a-zA-Z]{10,99}",
    "Twilio": r"(?i)twilio[^'\"]*['\"]([0-9a-f]{32})['\"]",
    "SendGrid": r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}",
    "Mailgun": r"key-[0-9a-zA-Z]{32}",
    "Algolia": r"(?i)algolia[^'\"]*['\"]([0-9a-f]{32})['\"]",
    "Heroku API": r"(?i)heroku[^'\"]*['\"]([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['\"]",
    "JWT Token": r"eyJ[A-Za-z0-9_\-]*\.eyJ[A-Za-z0-9_\-]*\.[A-Za-z0-9_\-]+",
    "Private Key": r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
    "Generic API Key": r"(?i)(api[_-]?key|apikey|api[_-]?secret|client[_-]?secret|app[_-]?secret|secret[_-]?key|access[_-]?key|auth[_-]?token|bearer)\s*[:=]\s*['\"]([A-Za-z0-9_\-\.]{16,128})['\"]",
    "Generic Token": r"(?i)(token|secret|password|passwd|pwd)\s*[:=]\s*['\"]([A-Za-z0-9_\-\.]{16,256})['\"]",
    "S3 Bucket": r"[a-z0-9][a-z0-9\-\.]{1,61}[a-z0-9]\.s3[.\-][a-z0-9\-]+\.amazonaws\.com",
    "Azure Storage": r"(?i)(AccountKey|SharedKey)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{86,88})['\"]?",
    "Database URL": r"(?i)(mysql|postgres|mongodb|redis|amqp|mssql)://[^\s'\"<>]{10,200}",
    "Internal IP": r"(?<![0-9])(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})(?![0-9])",
    "Email Address": r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
    "Auth0 Client ID": r"(?i)auth0[^'\"]*clientId['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{16,64})['\"]?",
    "Auth0 Domain": r"[a-zA-Z0-9\-]+\.us\.auth0\.com",
    "Sentry DSN": r"https://[0-9a-f]+@[a-z0-9\-]+\.sentry\.io/[0-9]+",
    "Firebase Config": r"(?i)firebase[^{]*\{[^}]*apiKey[^}]*\}",
    "WebSocket URL": r"wss?://[a-zA-Z0-9\-\.]+[a-zA-Z0-9/\.\-_]*",
    "Internal URL": r"https?://(?:internal|admin|staging|dev|test|debug|beta|sandbox|qa|uat)[\-\.][a-zA-Z0-9\-\.]+\.[a-z]{2,}",
    "Cloudflare API": r"(?i)cloudflare[^'\"]*['\"]([0-9a-f]{37})['\"]",
    "Datadog API": r"(?i)datadog[^'\"]*['\"]([0-9a-f]{32})['\"]",
    "New Relic Key": r"(?i)newrelic[^'\"]*['\"]([A-Za-z0-9]{32,64})['\"]",
    "Shopify Token": r"(shpat|shpca|shppa|shpss)_[a-fA-F0-9]{32}",
    "Square Token": r"(sq0[a-z]{3}-[0-9A-Za-z\-_]{22,43})",
    "Twitch Token": r"(?i)twitch[^'\"]*['\"]([A-Za-z0-9]{30})['\"]",
    "Discord Webhook": r"discord(app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_\-]+",
    "Telegram Bot Token": r"[0-9]{8,10}:[A-Za-z0-9_\-]{35}",
    "Mapbox Token": r"pk\.[0-9a-zA-Z]{60,}",
    "Amplitude Key": r"(?i)amplitude[^'\"]*['\"]([0-9a-f]{32})['\"]",
    "Segment Key": r"(?i)segment[^'\"]*['\"]([A-Za-z0-9]{32})['\"]",
    "Intercom App ID": r"(?i)intercom[^'\"]*['\"]([A-Za-z0-9]{6,10})['\"]",
    "Mixpanel Token": r"(?i)mixpanel[^'\"]*['\"]([0-9a-f]{32})['\"]",
    "ReCaptcha Key": r"(?i)(recaptcha|captcha)[^'\"]*['\"]6L[A-Za-z0-9_\-]{38}['\"]",
    "HCaptcha Key": r"(?i)hcaptcha[^'\"]*['\"]([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['\"]",
    "Basic Auth URL": r"https?://[^:]+:[^@]+@[a-zA-Z0-9\-\.]+",
    "Swagger/OpenAPI": r"(?i)(swagger|openapi)[^'\"]*\.(json|yaml|yml)",
    "GraphQL Endpoint": r"(?i)(graphql|graphiql|gql)[^'\"]*endpoint[^'\"]*['\"]([^'\"]+)['\"]",
    "Debug Endpoint": r"(?i)(debug|trace|profiler|phpinfo|server-status|server-info|elmah|actuator)[^'\"]*",
    "Webhook URL": r"(?i)webhook[^'\"]*(https?://[^\s'\"]+)",
}

# False positive filters
FALSE_POSITIVES = {
    "example", "test", "dummy", "sample", "placeholder", "xxx", "your_",
    "insert_", "replace_", "changeme", "password123", "abcdef", "000000",
    "111111", "aaaaaa", "TODO", "CHANGEME", "REPLACE"
}

def is_false_positive(value):
    v = value.lower()
    return any(fp.lower() in v for fp in FALSE_POSITIVES)

def scan_text(text, source=""):
    findings = []
    seen = set()
    
    for name, pattern in PATTERNS.items():
        matches = re.findall(pattern, text)
        for match in matches:
            if isinstance(match, tuple):
                match = match[-1]  # Get last group
            
            # Skip false positives
            if is_false_positive(match):
                continue
            
            # Dedupe
            h = hashlib.md5(match.encode()).hexdigest()
            if h in seen:
                continue
            seen.add(h)
            
            # Get context (line containing match)
            for line in text.split('\n'):
                if match in line:
                    context = line.strip()[:200]
                    break
            else:
                context = ""
            
            findings.append({
                "type": name,
                "value": match[:80] + ("..." if len(match) > 80 else ""),
                "context": context,
                "source": source
            })
    
    return findings

def fetch_js(url):
    """Fetch JS content from URL"""
    try:
        r = requests.get(url, timeout=15, verify=False, headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })
        return r.text
    except:
        return ""

def find_js_urls(html, base_url):
    """Extract JS URLs from HTML"""
    urls = []
    # Script src tags
    for match in re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html):
        if match.startswith("//"):
            match = "https:" + match
        elif match.startswith("/"):
            from urllib.parse import urljoin
            match = urljoin(base_url, match)
        elif not match.startswith("http"):
            from urllib.parse import urljoin
            match = urljoin(base_url, match)
        urls.append(match)
    return urls

def scan_url(url):
    """Scan a URL and its JS bundles"""
    all_findings = []
    
    print(f"\n{'='*60}")
    print(f"🔍 JS Secret Scanner")
    print(f"Target: {url}")
    print(f"{'='*60}\n")
    
    # Fetch main page
    print("📡 Fetching main page...")
    try:
        r = requests.get(url, timeout=15, verify=False, headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })
        html = r.text
    except Exception as e:
        print(f"❌ Failed to fetch: {e}")
        return []
    
    # Scan HTML itself
    print("🔎 Scanning HTML for secrets...")
    findings = scan_text(html, url)
    all_findings.extend(findings)
    
    # Find JS bundles
    js_urls = find_js_urls(html, url)
    print(f"📜 Found {len(js_urls)} JavaScript bundles\n")
    
    # Scan each JS bundle
    for i, js_url in enumerate(js_urls, 1):
        print(f"  [{i}/{len(js_urls)}] Scanning: {js_url[:80]}...")
        js_content = fetch_js(js_url)
        if js_content:
            findings = scan_text(js_content, js_url)
            all_findings.extend(findings)
            if findings:
                print(f"    ⚠️  Found {len(findings)} secrets!")
    
    # Also check common JS paths
    common_paths = [
        "/static/js/main.js", "/static/js/app.js", "/static/js/bundle.js",
        "/assets/js/app.js", "/js/app.js", "/dist/js/app.js",
        "/static/js/main.chunk.js", "/build/static/js/main.js",
        "/webpack-runtime.js", "/manifest.json", "/config.js",
        "/env.js", "/.env", "/.env.local", "/.env.production",
        "/firebase-messaging-sw.js", "/firebase-app.js",
        "/swagger.json", "/api-docs", "/openapi.json",
    ]
    
    from urllib.parse import urljoin
    base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
    
    print("\n🔎 Checking common paths...")
    for path in common_paths:
        test_url = urljoin(base, path)
        try:
            r = requests.get(test_url, timeout=5, verify=False, headers={
                "User-Agent": "Mozilla/5.0"
            })
            if r.status_code == 200 and len(r.text) > 50:
                findings = scan_text(r.text, test_url)
                all_findings.extend(findings)
                if findings:
                    print(f"  ⚠️  {path}: {len(findings)} secrets!")
        except:
            pass
    
    # Dedupe final results
    seen = set()
    unique = []
    for f in all_findings:
        key = f"{f['type']}:{f['value']}"
        if key not in seen:
            seen.add(key)
            unique.append(f)
    
    # Print results
    print(f"\n{'='*60}")
    print(f"📊 RESULTS: {len(unique)} unique secrets found")
    print(f"{'='*60}\n")
    
    if not unique:
        print("✅ No secrets found!")
        return unique
    
    # Group by severity
    critical = []
    high = []
    medium = []
    low = []
    
    critical_types = ["AWS Access Key", "AWS Secret Key", "Private Key", "Database URL",
                      "Stripe Key", "Azure Storage", "Cloudflare API"]
    high_types = ["Google API Key", "GitHub Token", "Slack Token", "JWT Token",
                  "Generic API Key", "Auth0 Client ID", "Shopify Token"]
    medium_types = ["Firebase Key", "Sentry DSN", "Internal URL", "Internal IP",
                    "WebSocket URL", "Auth0 Domain", "S3 Bucket"]
    
    for f in unique:
        if f["type"] in critical_types:
            critical.append(f)
        elif f["type"] in high_types:
            high.append(f)
        elif f["type"] in medium_types:
            medium.append(f)
        else:
            low.append(f)
    
    if critical:
        print("🔴 CRITICAL:")
        for f in critical:
            print(f"  [{f['type']}] {f['value']}")
            if f['context']:
                print(f"    Context: {f['context'][:100]}")
            print()
    
    if high:
        print("🟠 HIGH:")
        for f in high:
            print(f"  [{f['type']}] {f['value']}")
            if f['context']:
                print(f"    Context: {f['context'][:100]}")
            print()
    
    if medium:
        print("🟡 MEDIUM:")
        for f in medium:
            print(f"  [{f['type']}] {f['value']}")
            if f['context']:
                print(f"    Context: {f['context'][:100]}")
            print()
    
    if low:
        print("🟢 LOW/INFO:")
        for f in low:
            print(f"  [{f['type']}] {f['value'][:60]}")
    
    # Save results
    import os
    os.makedirs("output", exist_ok=True)
    domain = urlparse(url).netloc.replace(".", "_")
    outfile = f"output/secrets_{domain}.json"
    with open(outfile, "w") as f:
        json.dump(unique, f, indent=2)
    print(f"\n💾 Saved to {outfile}")
    
    return unique

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 js_secret_scanner.py <url_or_file>")
        print("Example: python3 js_secret_scanner.py https://example.com")
        sys.exit(1)
    
    target = sys.argv[1]
    
    if target.startswith("http"):
        scan_url(target)
    else:
        # Scan local file
        with open(target) as f:
            text = f.read()
        findings = scan_text(text, target)
        print(f"\nFound {len(findings)} secrets")
        for f in findings:
            print(f"  [{f['type']}] {f['value']}")
