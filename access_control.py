#!/usr/bin/env python3
"""
Broken Access Control Tester — IDOR, privilege escalation, mass assignment
Usage: python3 access_control.py <url>
"""

import sys
import json
import re
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urljoin
from concurrent.futures import ThreadPoolExecutor

requests.packages.urllib3.disable_warnings()

# Common ID parameter names
ID_PARAMS = [
    "id", "uid", "user_id", "user", "userId", "user_id", "account_id", "accountId",
    "profile_id", "profileId", "order_id", "orderId", "invoice_id", "invoiceId",
    "file_id", "fileId", "doc_id", "docId", "report_id", "reportId",
    "item_id", "itemId", "product_id", "productId", "payment_id", "paymentId",
    "transaction_id", "transactionId", "ticket_id", "ticketId",
    "message_id", "messageId", "comment_id", "commentId", "post_id", "postId",
    "session_id", "sessionId", "token", "access_token", "api_key",
    "customer_id", "customerId", "merchant_id", "merchantId",
    "transfer_id", "transferId", "withdrawal_id", "withdrawalId",
]

# Admin/privilege endpoints
PRIVILEGE_PATHS = [
    "/admin", "/admin/", "/admin/dashboard", "/admin/users", "/admin/config",
    "/api/admin", "/api/v1/admin", "/api/internal", "/api/debug",
    "/dashboard", "/panel", "/console", "/manage", "/management",
    "/internal", "/staff", "/moderator", "/superadmin",
    "/api/users/me", "/api/user/profile", "/api/account",
    "/api/users/1", "/api/users/2", "/api/users/0",
    "/api/v1/users/1", "/api/v1/users/me",
    "/api/orders", "/api/payments", "/api/transactions",
    "/api/settings", "/api/config", "/api/health",
    "/graphql", "/graphiql",
]

# Mass assignment fields to test
MASS_ASSIGNMENT_FIELDS = [
    {"role": "admin"}, {"is_admin": True}, {"admin": True},
    {"isAdmin": True}, {"privilege": "admin"}, {"level": "admin"},
    {"access_level": "admin"}, {"permissions": "admin"},
    {"role": "superadmin"}, {"verified": True}, {"active": True},
    {"approved": True}, {"premium": True}, {"paid": True},
    {"credit": 999999}, {"balance": 999999}, {"points": 999999},
    {"discount": 100}, {"price": 0}, {"amount": 0},
    {"status": "approved"}, {"flag": True}, {"enabled": True},
]

def test_idor(url, param, ids_to_test):
    """Test for IDOR by swapping IDs"""
    results = []
    parsed = urlparse(url)
    base_params = parse_qs(parsed.query)
    
    for test_id in ids_to_test:
        params = base_params.copy()
        params[param] = [str(test_id)]
        
        # Rebuild URL
        new_query = urlencode(params, doseq=True)
        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
        
        try:
            r = requests.get(test_url, timeout=8, verify=False,
                           headers={"User-Agent": "Mozilla/5.0"})
            
            if r.status_code == 200 and len(r.text) > 50:
                # Check if response is different from original (different user's data)
                results.append({
                    "param": param,
                    "id": test_id,
                    "status": r.status_code,
                    "size": len(r.text),
                    "url": test_url
                })
        except:
            pass
    
    return results

def test_path_access(base_url, paths):
    """Test if protected paths are accessible"""
    results = []
    base = base_url.rstrip('/')
    
    for path in paths:
        url = base + path
        try:
            r = requests.get(url, timeout=8, verify=False,
                           headers={"User-Agent": "Mozilla/5.0"})
            
            if r.status_code in [200, 201, 204]:
                # Check if it's not just a redirect to login
                body = r.text.lower()
                if not any(x in body for x in ["sign in", "log in", "login", "redirect"]):
                    results.append({
                        "path": path,
                        "status": r.status_code,
                        "size": len(r.text),
                        "url": url,
                        "body_preview": r.text[:200]
                    })
            elif r.status_code in [401, 403]:
                results.append({
                    "path": path,
                    "status": r.status_code,
                    "url": url,
                    "note": "Exists but protected"
                })
        except:
            pass
    
    return results

def test_mass_assignment(url, data_template=None):
    """Test for mass assignment vulnerabilities"""
    results = []
    
    if not data_template:
        data_template = {"name": "test", "email": "test@test.com"}
    
    for field in MASS_ASSIGNMENT_FIELDS:
        data = data_template.copy()
        data.update(field)
        
        try:
            # Try POST
            r = requests.post(url, json=data, timeout=8, verify=False,
                            headers={"User-Agent": "Mozilla/5.0",
                                    "Content-Type": "application/json"})
            
            if r.status_code in [200, 201]:
                body = r.text.lower()
                # Check if our injected field was accepted
                for key in field:
                    if key.lower() in body:
                        results.append({
                            "field": field,
                            "status": r.status_code,
                            "response_contains_field": True,
                            "body_preview": r.text[:300]
                        })
                        break
        except:
            pass
    
    return results

def test_method_override(url):
    """Test HTTP method override for bypassing restrictions"""
    results = []
    methods_to_test = ["PUT", "PATCH", "DELETE", "OPTIONS"]
    headers_to_test = [
        {"X-HTTP-Method-Override": "PUT"},
        {"X-HTTP-Method": "PUT"},
        {"X-Method-Override": "PUT"},
        {"_method": "PUT"},
    ]
    
    for method in methods_to_test:
        try:
            if method == "OPTIONS":
                r = requests.options(url, timeout=8, verify=False,
                                   headers={"User-Agent": "Mozilla/5.0"})
            elif method == "PUT":
                r = requests.put(url, timeout=8, verify=False,
                               headers={"User-Agent": "Mozilla/5.0"})
            elif method == "PATCH":
                r = requests.patch(url, timeout=8, verify=False,
                                 headers={"User-Agent": "Mozilla/5.0"})
            elif method == "DELETE":
                r = requests.delete(url, timeout=8, verify=False,
                                  headers={"User-Agent": "Mozilla/5.0"})
            
            if r.status_code in [200, 201, 204]:
                results.append({
                    "method": method,
                    "status": r.status_code,
                    "size": len(r.text),
                    "note": f"Method {method} accepted"
                })
            
            if method == "OPTIONS":
                allow = r.headers.get("Allow", "")
                cors = r.headers.get("Access-Control-Allow-Methods", "")
                if allow or cors:
                    results.append({
                        "method": "OPTIONS",
                        "allow": allow,
                        "cors_methods": cors,
                        "note": "Allowed methods exposed"
                    })
        except:
            pass
    
    # Test method override headers
    for override_header in headers_to_test:
        try:
            r = requests.post(url, headers={
                "User-Agent": "Mozilla/5.0",
                "Content-Type": "application/json",
                **override_header
            }, json={}, timeout=8, verify=False)
            
            if r.status_code in [200, 201, 204]:
                results.append({
                    "method": "Override",
                    "header": override_header,
                    "status": r.status_code,
                    "note": "Method override accepted"
                })
        except:
            pass
    
    return results

def test_rate_limiting(url, num_requests=20):
    """Test if rate limiting is enforced"""
    results = []
    statuses = []
    
    for i in range(num_requests):
        try:
            r = requests.get(url, timeout=5, verify=False,
                           headers={"User-Agent": "Mozilla/5.0"})
            statuses.append(r.status_code)
        except:
            statuses.append(0)
    
    rate_limited = any(s == 429 for s in statuses)
    success_count = statuses.count(200)
    
    results.append({
        "total_requests": num_requests,
        "success_count": success_count,
        "rate_limited": rate_limited,
        "status_codes": dict((s, statuses.count(s)) for s in set(statuses)),
        "note": "No rate limiting!" if not rate_limited and success_count == num_requests else "Rate limiting active"
    })
    
    return results

def test_cors_misconfig(url):
    """Quick CORS misconfiguration check"""
    results = []
    origins = [
        "https://evil.com", "null", "https://attacker.com",
        f"https://{urlparse(url).netloc}.evil.com"
    ]
    
    for origin in origins:
        try:
            r = requests.get(url, headers={
                "Origin": origin,
                "User-Agent": "Mozilla/5.0"
            }, timeout=8, verify=False)
            
            acao = r.headers.get("Access-Control-Allow-Origin", "")
            acac = r.headers.get("Access-Control-Allow-Credentials", "")
            
            if acao:
                if acao == "*" and acac.lower() == "true":
                    results.append({
                        "severity": "CRITICAL",
                        "origin": origin,
                        "acao": acao,
                        "acac": acac,
                        "note": "Wildcard with credentials!"
                    })
                elif acao == origin and origin in ["https://evil.com", "https://attacker.com"]:
                    results.append({
                        "severity": "HIGH",
                        "origin": origin,
                        "acao": acao,
                        "acac": acac,
                        "note": "Arbitrary origin reflected!"
                    })
                elif acao == "null":
                    results.append({
                        "severity": "HIGH",
                        "origin": origin,
                        "acao": acao,
                        "acac": acac,
                        "note": "null origin accepted!"
                    })
        except:
            pass
    
    return results

def test_host_header(url):
    """Test for Host header injection"""
    results = []
    hosts_to_test = [
        "evil.com", "attacker.com", "localhost",
        f"{urlparse(url).netloc}.evil.com",
        "127.0.0.1", "0.0.0.0",
    ]
    
    for host in hosts_to_test:
        try:
            r = requests.get(url, headers={
                "Host": host,
                "User-Agent": "Mozilla/5.0"
            }, timeout=8, verify=False, allow_redirects=False)
            
            location = r.headers.get("Location", "")
            if host in location:
                results.append({
                    "severity": "HIGH",
                    "host": host,
                    "redirect": location,
                    "note": "Host header injection in redirect!"
                })
            
            # Check if response differs
            if r.status_code in [200, 301, 302]:
                results.append({
                    "severity": "INFO",
                    "host": host,
                    "status": r.status_code,
                    "location": location,
                    "note": f"Host '{host}' accepted"
                })
        except:
            pass
    
    return results

def scan_url(url, deep=False):
    """Full access control scan"""
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    
    print(f"\n{'='*60}")
    print(f"🔓 Broken Access Control Tester")
    print(f"Target: {url}")
    print(f"{'='*60}\n")
    
    all_findings = {}
    
    # Phase 1: Path access
    print("📡 Phase 1: Testing protected paths...")
    path_results = test_path_access(base, PRIVILEGE_PATHS)
    accessible = [r for r in path_results if r["status"] in [200, 201, 204]]
    protected = [r for r in path_results if r["status"] in [401, 403]]
    all_findings["paths"] = path_results
    
    if accessible:
        print(f"  🔴 {len(accessible)} paths accessible without auth!")
        for r in accessible:
            print(f"     [{r['status']}] {r['path']}")
    else:
        print(f"  ✅ All paths protected ({len(protected)} confirmed)")
    
    # Phase 2: IDOR on URL params
    print("\n📡 Phase 2: Testing IDOR on URL parameters...")
    existing_params = parse_qs(parsed.query)
    idor_results = []
    
    for param in existing_params:
        if any(x in param.lower() for x in ["id", "uid", "user", "account", "order"]):
            test_ids = ["1", "2", "0", "999", "admin", "test"]
            results = test_idor(url, param, test_ids)
            idor_results.extend(results)
            if results:
                print(f"  🟠 IDOR candidate: {param} responded to {len(results)} different IDs")
    
    # Also test common params
    if not existing_params:
        for param in ["id", "user_id", "uid", "account_id"][:3]:
            test_ids = ["1", "2", "0"]
            results = test_idor(url, param, test_ids)
            idor_results.extend(results)
    
    all_findings["idor"] = idor_results
    
    # Phase 3: CORS
    print("\n📡 Phase 3: Testing CORS misconfiguration...")
    cors_results = test_cors_misconfig(url)
    all_findings["cors"] = cors_results
    
    if cors_results:
        for r in cors_results:
            sev = r["severity"]
            icon = {"CRITICAL": "🔴", "HIGH": "🟠"}.get(sev, "🟡")
            print(f"  {icon} [{sev}] {r['note']}")
    else:
        print("  ✅ No CORS issues")
    
    # Phase 4: Host header
    print("\n📡 Phase 4: Testing Host header injection...")
    host_results = test_host_header(url)
    all_findings["host_header"] = host_results
    
    high_host = [r for r in host_results if r.get("severity") in ["HIGH", "CRITICAL"]]
    if high_host:
        for r in high_host:
            print(f"  🔴 Host injection: {r['note']}")
    else:
        print("  ✅ No host header injection")
    
    # Phase 5: Method override
    print("\n📡 Phase 5: Testing HTTP method override...")
    method_results = test_method_override(url)
    all_findings["methods"] = method_results
    
    accepted = [r for r in method_results if r.get("status") in [200, 201, 204]]
    if accepted:
        for r in accepted:
            print(f"  🟡 {r.get('note', r.get('method', ''))}")
    
    # Phase 6: Rate limiting
    print("\n📡 Phase 6: Testing rate limiting...")
    rate_results = test_rate_limiting(url, 20)
    all_findings["rate_limit"] = rate_results
    
    if rate_results and not rate_results[0]["rate_limited"]:
        print(f"  🔴 NO RATE LIMITING! {rate_results[0]['success_count']}/20 requests succeeded")
    else:
        print("  ✅ Rate limiting active")
    
    # Phase 7: Mass assignment (if deep)
    if deep:
        print("\n📡 Phase 7: Testing mass assignment...")
        mass_results = test_mass_assignment(url)
        all_findings["mass_assignment"] = mass_results
        
        if mass_results:
            for r in mass_results:
                print(f"  🔴 Mass assignment: {r['field']} accepted!")
        else:
            print("  ✅ No mass assignment found")
    
    # Summary
    critical = len([r for r in cors_results if r.get("severity") == "CRITICAL"])
    critical += len([r for r in high_host if r.get("severity") == "CRITICAL"])
    high = len(accessible) + len([r for r in cors_results if r.get("severity") == "HIGH"])
    high += len(high_host)
    
    print(f"\n{'='*60}")
    print(f"📊 ACCESS CONTROL RESULTS")
    print(f"{'='*60}")
    print(f"Critical: {critical}")
    print(f"High: {high}")
    print(f"Medium: {len(idor_results) + len(accepted)}")
    print(f"Info: {len(rate_results)}")
    
    # Save
    import os
    os.makedirs("output", exist_ok=True)
    domain = parsed.netloc.replace(".", "_")
    outfile = f"output/acl_{domain}.json"
    with open(outfile, "w") as f:
        json.dump(all_findings, f, indent=2)
    print(f"\n💾 Saved to {outfile}")
    
    return all_findings

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 access_control.py <url> [--deep]")
        sys.exit(1)
    
    url = sys.argv[1]
    deep = "--deep" in sys.argv
    scan_url(url, deep)
