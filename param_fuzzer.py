#!/usr/bin/env python3
"""
Parameter Fuzzer — Discover hidden API endpoints and parameters
Usage: python3 param_fuzzer.py <url>
"""

import sys
import json
import re
import requests
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, urljoin

requests.packages.urllib3.disable_warnings()

# Common API endpoint patterns
API_PATHS = [
    "/api/v1", "/api/v2", "/api/v3", "/api/internal", "/api/admin",
    "/api/debug", "/api/config", "/api/users", "/api/user",
    "/api/auth", "/api/login", "/api/token", "/api/refresh",
    "/api/keys", "/api/secrets", "/api/webhooks", "/api/webhook",
    "/api/health", "/api/status", "/api/info", "/api/version",
    "/api/metrics", "/api/logs", "/api/events", "/api/search",
    "/api/settings", "/api/profile", "/api/account", "/api/accounts",
    "/api/billing", "/api/payments", "/api/orders", "/api/subscriptions",
    "/api/uploads", "/api/files", "/api/documents", "/api/reports",
    "/api/notifications", "/api/messages", "/api/email", "/api/sms",
    "/api/analytics", "/api/dashboard", "/api/admin/users",
    "/api/admin/config", "/api/admin/logs", "/api/admin/stats",
    "/api/internal/debug", "/api/internal/config", "/api/internal/health",
    "/api/swagger", "/api/docs", "/api/openapi", "/api/graphql",
    "/v1/models", "/v1/messages", "/v1/complete", "/v1/chat",
    "/v1/embeddings", "/v1/images", "/v1/audio", "/v1/files",
    "/v1/fine_tuning", "/v1/assistants", "/v1/threads",
    "/graphql", "/graphiql", "/gql", "/playground",
    "/.well-known/openid-configuration", "/.well-known/jwks.json",
    "/.well-known/security.txt", "/.well-known/assetlinks.json",
    "/oauth/authorize", "/oauth/token", "/oauth/revoke",
    "/auth/login", "/auth/logout", "/auth/callback", "/auth/token",
    "/auth/register", "/auth/forgot", "/auth/reset",
    "/admin", "/admin/login", "/admin/dashboard", "/admin/api",
    "/debug", "/debug/vars", "/debug/pprof", "/debug/requests",
    "/trace", "/metrics", "/prometheus", "/grafana",
    "/swagger", "/swagger.json", "/swagger-ui", "/swagger-ui.html",
    "/api-docs", "/api-docs.json", "/openapi.json", "/openapi.yaml",
    "/internal", "/private", "/secret", "/hidden",
    "/test", "/staging", "/dev", "/canary", "/beta",
    "/health", "/healthz", "/ready", "/readyz", "/livez",
    "/env", "/config", "/configuration", "/settings",
    "/version", "/info", "/about", "/status",
    "/actuator", "/actuator/health", "/actuator/env", "/actuator/info",
    "/actuator/beans", "/actuator/configprops", "/actuator/mappings",
    "/console", "/shell", "/terminal", "/exec",
    "/phpinfo", "/server-status", "/server-info", "/elmah",
    "/wp-admin", "/wp-login.php", "/wp-json", "/wp-json/wp/v2/users",
    "/xmlrpc.php", "/readme.html", "/license.txt",
    "/.git/HEAD", "/.git/config", "/.env", "/.env.local",
    "/.env.production", "/.env.staging", "/.env.development",
    "/backup", "/dump", "/export", "/import",
    "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
    "/favicon.ico", "/humans.txt", "/security.txt",
    "/feed", "/rss", "/atom.xml", "/sitemap",
    "/cdn-cgi/trace", "/cgi-bin/", "/fcgi-bin/",
]

# Common parameters to fuzz
COMMON_PARAMS = [
    "id", "uid", "user_id", "user", "username", "email",
    "account", "account_id", "profile", "profile_id",
    "token", "access_token", "api_key", "apikey", "key", "secret",
    "session", "session_id", "sid", "auth", "auth_token",
    "page", "limit", "offset", "size", "count", "sort", "order", "filter",
    "q", "query", "search", "term", "keyword",
    "format", "type", "action", "method", "callback",
    "file", "path", "dir", "folder", "name", "filename",
    "url", "uri", "redirect", "return", "next", "goto",
    "host", "server", "endpoint", "target", "dest",
    "debug", "test", "admin", "mode", "env",
    "version", "v", "api_version", "lang", "locale",
    "data", "json", "xml", "raw", "body",
    "cmd", "command", "exec", "run", "eval",
    "include", "require", "load", "import",
    "template", "view", "layout", "partial",
    "config", "setting", "option", "param",
]

# High-impact param combos
IDOR_PARAMS = [
    {"id": "1"}, {"id": "2"}, {"user_id": "1"}, {"account_id": "1"},
    {"profile_id": "1"}, {"order_id": "1"}, {"invoice_id": "1"},
    {"file_id": "1"}, {"doc_id": "1"}, {"report_id": "1"},
    {"uid": "1"}, {"user": "admin"}, {"email": "admin@example.com"},
]

def check_path(base_url, path):
    """Check if a path exists and analyze response"""
    url = urljoin(base_url, path)
    try:
        r = requests.get(url, timeout=8, verify=False, allow_redirects=False,
                        headers={"User-Agent": "Mozilla/5.0"})
        
        interesting = False
        reason = []
        
        # Interesting status codes
        if r.status_code == 200 and len(r.text) > 0:
            # Check for interesting content
            body = r.text.lower()
            if any(kw in body for kw in ["api", "token", "key", "secret", "password",
                                          "admin", "debug", "config", "internal",
                                          "user", "email", "database", "error",
                                          "swagger", "openapi", "graphql"]):
                interesting = True
                reason.append("Interesting content")
        
        if r.status_code in [401, 403]:
            interesting = True
            reason.append(f"Exists but protected ({r.status_code})")
        
        if r.status_code == 405:
            interesting = True
            reason.append("Method not allowed (path exists)")
        
        if r.status_code in [301, 302]:
            location = r.headers.get("Location", "")
            if any(kw in location.lower() for kw in ["login", "auth", "admin", "internal"]):
                interesting = True
                reason.append(f"Redirects to: {location[:80]}")
        
        # Check for interesting headers
        interesting_headers = {}
        for h in ["x-request-id", "x-runtime", "x-debug", "x-trace",
                   "server", "x-powered-by", "x-aspnet-version",
                   "x-ratelimit-limit", "x-ratelimit-remaining"]:
            if h in r.headers:
                interesting_headers[h] = r.headers[h]
        
        if interesting_headers:
            interesting = True
            reason.append(f"Headers: {list(interesting_headers.keys())}")
        
        return {
            "path": path,
            "url": url,
            "status": r.status_code,
            "size": len(r.text),
            "interesting": interesting,
            "reason": ", ".join(reason),
            "headers": interesting_headers,
            "body_preview": r.text[:200] if interesting else ""
        }
    except Exception as e:
        return {"path": path, "url": url, "error": str(e), "interesting": False}

def check_params(base_url, params_to_test):
    """Check URL parameters for IDOR and injection"""
    results = []
    
    for params in params_to_test:
        try:
            r = requests.get(base_url, params=params, timeout=8, verify=False,
                           headers={"User-Agent": "Mozilla/5.0"})
            
            if r.status_code == 200 and len(r.text) > 100:
                results.append({
                    "params": params,
                    "status": r.status_code,
                    "size": len(r.text),
                    "url": r.url
                })
        except:
            pass
    
    return results

def scan_url(url, deep=False):
    """Full parameter and endpoint fuzzing"""
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    
    print(f"\n{'='*60}")
    print(f"🔍 Parameter & Endpoint Fuzzer")
    print(f"Target: {url}")
    print(f"Base: {base}")
    print(f"{'='*60}\n")
    
    # Phase 1: Endpoint discovery
    print("📡 Phase 1: Discovering endpoints...\n")
    
    paths = API_PATHS if deep else API_PATHS[:50]
    findings = []
    
    with ThreadPoolExecutor(max_workers=15) as executor:
        futures = {executor.submit(check_path, base, p): p for p in paths}
        
        for i, future in enumerate(futures, 1):
            result = future.result()
            
            if result.get("interesting"):
                findings.append(result)
                status = result.get("status", "?")
                print(f"  🔵 [{status}] {result['path']}")
                print(f"     {result.get('reason', '')}")
            
            if i % 50 == 0:
                print(f"  ⏳ [{i}/{len(paths)}] scanning...")
    
    # Phase 2: Parameter fuzzing on base URL
    print(f"\n📡 Phase 2: Testing parameters on base URL...\n")
    
    param_findings = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = []
        for param in COMMON_PARAMS[:30]:
            for value in ["1", "admin", "test", "true", "debug"]:
                params = {param: value}
                futures.append(executor.submit(check_params, url, [params]))
        
        for future in futures:
            results = future.result()
            if results:
                for r in results:
                    param_findings.append(r)
                    print(f"  🟡 {r['params']} → {r['status']} ({r['size']} bytes)")
    
    # Phase 3: IDOR check
    print(f"\n📡 Phase 3: IDOR parameter check...\n")
    
    idor_findings = []
    for params in IDOR_PARAMS:
        try:
            r = requests.get(url, params=params, timeout=8, verify=False,
                           headers={"User-Agent": "Mozilla/5.0"})
            if r.status_code == 200 and len(r.text) > 100:
                idor_findings.append({
                    "params": params,
                    "status": r.status_code,
                    "size": len(r.text)
                })
                print(f"  🟠 IDOR test: {params} → {r.status_code} ({len(r.text)} bytes)")
        except:
            pass
    
    # Summary
    print(f"\n{'='*60}")
    print(f"📊 FUZZING RESULTS")
    print(f"{'='*60}")
    print(f"Endpoints found: {len(findings)}")
    print(f"Parameter responses: {len(param_findings)}")
    print(f"IDOR candidates: {len(idor_findings)}")
    
    if findings:
        print(f"\n🔵 INTERESTING ENDPOINTS:")
        for f in findings:
            print(f"  [{f.get('status', '?')}] {f['path']}")
            print(f"    {f.get('reason', '')}")
            if f.get('body_preview'):
                print(f"    Preview: {f['body_preview'][:100]}")
    
    # Save
    import os
    os.makedirs("output", exist_ok=True)
    domain = parsed.netloc.replace(".", "_")
    outfile = f"output/fuzz_{domain}.json"
    all_results = {
        "endpoints": findings,
        "params": param_findings[:20],
        "idor": idor_findings
    }
    with open(outfile, "w") as f:
        json.dump(all_results, f, indent=2)
    print(f"\n💾 Saved to {outfile}")
    
    return all_results

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 param_fuzzer.py <url> [--deep]")
        print("Example: python3 param_fuzzer.py https://api.example.com --deep")
        sys.exit(1)
    
    url = sys.argv[1]
    deep = "--deep" in sys.argv
    scan_url(url, deep)
