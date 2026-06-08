#!/usr/bin/env python3
"""Hidden Parameter Discovery (Param Miner)
Discovers hidden parameters by sending requests with different parameter names
and comparing response differences (length, status, time).
"""

import argparse
import json
import time
import requests
import urllib3
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
urllib3.disable_warnings()

# Common hidden parameter names
PARAM_WORDLIST = [
    "id", "user", "uid", "username", "email", "account", "profile", "name",
    "token", "key", "api_key", "apikey", "secret", "access_token", "auth",
    "debug", "test", "admin", "root", "config", "env", "mode", "type",
    "callback", "redirect", "url", "next", "return", "dest", "redirect_uri",
    "page", "limit", "offset", "sort", "order", "filter", "search", "q",
    "format", "output", "view", "template", "layout", "theme", "lang", "locale",
    "file", "path", "dir", "folder", "include", "require", "load", "import",
    "cmd", "exec", "command", "run", "shell", "system", "ping", "host",
    "ip", "addr", "address", "host", "hostname", "port", "proxy",
    "data", "input", "body", "content", "payload", "params", "args",
    "action", "method", "func", "function", "handler", "controller",
    "version", "v", "api", "v1", "v2", "v3", "internal", "private",
    "session", "sid", "sess", "cookie", "jwt", "bearer", "hash",
    "log", "level", "verbose", "trace", "debug", "dev", "development",
    "staging", "stage", "stg", "prod", "production", "pre", "post",
    "test", "testing", "sandbox", "demo", "mock", "fake", "dummy",
    "flag", "feature", "toggle", "enable", "disable", "on", "off",
    "role", "perm", "permission", "access", "scope", "privilege",
    "db", "database", "table", "collection", "query", "sql", "where",
    "ref", "reference", "link", "href", "src", "source", "origin",
    "from", "to", "target", "receiver", "sender", "recipient",
    "amount", "value", "price", "cost", "total", "sum", "balance",
    "status", "state", "stage", "step", "phase", "level", "grade",
    "width", "height", "size", "length", "count", "number", "num",
    "start", "end", "begin", "finish", "stop", "pause", "resume",
    "date", "time", "timestamp", "ts", "since", "until", "before", "after",
    "order_id", "transaction_id", "payment_id", "invoice_id", "item_id",
    "product_id", "item", "product", "sku", "code", "coupon",
    "file_name", "file_path", "upload", "download", "attachment",
    "image", "img", "photo", "avatar", "icon", "logo", "banner",
    "message", "msg", "text", "title", "subject", "body", "description",
    "comment", "note", "review", "feedback", "rating", "score",
    "group", "team", "org", "organization", "company", "department",
    "delete", "remove", "destroy", "purge", "wipe", "clear", "reset",
    "create", "add", "insert", "new", "submit", "save", "update", "edit", "modify",
    "get", "fetch", "read", "load", "list", "show", "view", "display",
    "assign", "unassign", "approve", "reject", "verify", "confirm",
    "lock", "unlock", "freeze", "unfreeze", "activate", "deactivate",
    "grant", "revoke", "deny", "allow", "block", "unblock",
    "export", "import", "backup", "restore", "sync", "refresh",
    "send", "receive", "notify", "alert", "remind", "schedule",
    "open", "close", "connect", "disconnect", "register", "unregister",
    "subscribe", "unsubscribe", "follow", "unfollow", "join", "leave",
    "encrypt", "decrypt", "sign", "verify", "hash", "encode", "decode",
    "compress", "decompress", "zip", "unzip", "pack", "unpack",
    "merge", "split", "clone", "copy", "move", "rename",
    "retry", "abort", "cancel", "skip", "ignore", "force", "override",
    "all", "none", "first", "last", "prev", "previous", "current", "next",
    "self", "me", "my", "mine", "own", "this", "that", "other",
    "is_", "has_", "can_", "do_", "should_", "will_", "was_",
    "enable_debug", "is_admin", "is_internal", "is_private", "is_public",
    "no_auth", "skip_auth", "bypass", "ignore_auth", "force_auth",
    "raw", "pretty", "compact", "full", "brief", "summary", "detail",
    "include_deleted", "include_archived", "with_trashed", "show_all",
    "_method", "_token", "_format", "_page", "_limit", "_sort", "_order",
    "__proto__", "constructor", "prototype", "toString", "valueOf",
]


def test_param(url, param_name, method="GET", baseline=None, timeout=10):
    """Test a single parameter and compare to baseline."""
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    
    if baseline is None:
        try:
            baseline = requests.get(url, headers=headers, timeout=timeout, verify=False)
        except:
            return None
    
    parsed = urllib.parse.urlparse(url)
    
    try:
        if method == "GET":
            # Add param to URL
            params = urllib.parse.parse_qs(parsed.query)
            params[param_name] = ["test"]
            new_query = urllib.parse.urlencode(params, doseq=True)
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
            
            start = time.time()
            r = requests.get(test_url, headers=headers, timeout=timeout, verify=False)
            elapsed = time.time() - start
        else:
            # POST with param in body
            start = time.time()
            r = requests.post(url, headers=headers, data={param_name: "test"}, timeout=timeout, verify=False)
            elapsed = time.time() - start
        
        # Compare to baseline
        len_diff = abs(len(r.text) - len(baseline.text))
        status_diff = r.status_code != baseline.status_code
        time_diff = abs(elapsed - getattr(baseline, '_elapsed', 0))
        
        # Score the finding
        score = 0
        reasons = []
        
        if status_diff:
            score += 3
            reasons.append(f"Status: {baseline.status_code} → {r.status_code}")
        
        if len_diff > 50:
            score += 2
            reasons.append(f"Length diff: +{len_diff} bytes")
        elif len_diff > 10:
            score += 1
            reasons.append(f"Length diff: +{len_diff} bytes")
        
        if time_diff > 1.0:
            score += 1
            reasons.append(f"Time diff: +{time_diff:.1f}s")
        
        # Check for error messages that reveal parameter is processed
        error_patterns = ["invalid", "required", "missing", "expected", "must be", "should be",
                         "cannot be", "not allowed", "forbidden", "unauthorized", "error"]
        for pat in error_patterns:
            if pat in r.text.lower() and pat not in baseline.text.lower():
                score += 2
                reasons.append(f"New error message contains '{pat}'")
                break
        
        if score >= 2:
            return {
                "param": param_name,
                "method": method,
                "score": score,
                "reasons": reasons,
                "baseline": {"status": baseline.status_code, "length": len(baseline.text)},
                "response": {"status": r.status_code, "length": len(r.text)},
            }
    except:
        pass
    
    return None


def main():
    parser = argparse.ArgumentParser(description="Hidden Parameter Discovery (Param Miner)")
    parser.add_argument("url", help="Target URL")
    parser.add_argument("--method", default="GET", choices=["GET", "POST"], help="HTTP method")
    parser.add_argument("--threads", type=int, default=20, help="Concurrent threads")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout")
    parser.add_argument("--wordlist", help="Custom wordlist file (one param per line)")
    parser.add_argument("--deep", action="store_true", help="Use extended wordlist")
    args = parser.parse_args()
    
    url = args.url.rstrip("/")
    if not url.startswith("http"):
        url = "https://" + url
    
    # Load wordlist
    params = PARAM_WORDLIST
    if args.wordlist:
        with open(args.wordlist) as f:
            params = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    elif args.deep:
        # Add more params for deep scan
        params += [f"_{p}" for p in PARAM_WORDLIST[:50]]
        params += [f"{p}_" for p in PARAM_WORDLIST[:50]]
    
    print(f"\033[95m[+]\033[0m Parameter Discovery — {url}")
    print(f"\033[94m[*]\033[0m Method: {args.method} | Params: {len(params)} | Threads: {args.threads}")
    print("=" * 60)
    
    # Get baseline
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    try:
        baseline = requests.get(url, headers=headers, timeout=args.timeout, verify=False)
        baseline._elapsed = baseline.elapsed.total_seconds()
        print(f"\033[94m[*]\033[0m Baseline: {baseline.status_code} | {len(baseline.text)} bytes")
    except Exception as e:
        print(f"\033[91m[-]\033[0m Cannot connect: {e}")
        return
    
    # Test params in parallel
    findings = []
    tested = 0
    
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {}
        for p in params:
            f = executor.submit(test_param, url, p, args.method, baseline, args.timeout)
            futures[f] = p
        
        for future in as_completed(futures):
            tested += 1
            if tested % 50 == 0:
                print(f"\033[94m[*]\033[0m Tested {tested}/{len(params)}...", end="\r")
            
            result = future.result()
            if result:
                findings.append(result)
                print(f"\033[92m[+]\033[0m Found: {result['param']} (score: {result['score']})")
    
    print(f"\n{'=' * 60}")
    
    if not findings:
        print(f"\033[92m[✓]\033[0m No hidden parameters found ({tested} tested)")
    else:
        # Sort by score
        findings.sort(key=lambda x: x["score"], reverse=True)
        print(f"\n\033[91m[!] Found {len(findings)} potential hidden parameters:\033[0m\n")
        for f in findings:
            sev = "HIGH" if f["score"] >= 4 else "MEDIUM" if f["score"] >= 2 else "LOW"
            color = "\033[91m" if sev == "HIGH" else "\033[93m" if sev == "MEDIUM" else "\033[94m"
            print(f"  {color}[{sev}]\033[0m {f['param']} ({f['method']})")
            for r in f["reasons"]:
                print(f"    • {r}")
            print()
    
    out = {"url": url, "method": args.method, "findings": findings, "total_tested": tested}
    with open("output/param_mine.json", "w") as f:
        json.dump(out, f, indent=2)
    print(f"[*] Results saved to output/param_mine.json")


if __name__ == "__main__":
    main()
