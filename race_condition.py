#!/usr/bin/env python3
"""
Race Condition Tester — Send concurrent requests to find race conditions
Usage: python3 race_condition.py <url> [--method POST] [--data '{"key":"value"}'] [--threads 50]
"""

import sys
import json
import time
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

requests.packages.urllib3.disable_warnings()

def send_request(url, method="GET", data=None, headers=None, cookies=None):
    """Send a single request and return result"""
    default_headers = {"User-Agent": "Mozilla/5.0"}
    if headers:
        default_headers.update(headers)
    
    try:
        start = time.time()
        if method == "POST":
            r = requests.post(url, json=data, headers=default_headers, cookies=cookies,
                            timeout=15, verify=False)
        elif method == "PUT":
            r = requests.put(url, json=data, headers=default_headers, cookies=cookies,
                           timeout=15, verify=False)
        elif method == "PATCH":
            r = requests.patch(url, json=data, headers=default_headers, cookies=cookies,
                             timeout=15, verify=False)
        else:
            r = requests.get(url, headers=default_headers, cookies=cookies,
                           timeout=15, verify=False)
        
        elapsed = time.time() - start
        return {
            "status": r.status_code,
            "size": len(r.text),
            "time": elapsed,
            "body": r.text[:500],
            "headers": dict(r.headers)
        }
    except Exception as e:
        return {"error": str(e)}

def race_requests(url, num_requests=50, method="GET", data=None, headers=None, cookies=None):
    """Send concurrent requests to detect race conditions"""
    results = []
    
    with ThreadPoolExecutor(max_workers=num_requests) as executor:
        futures = []
        for _ in range(num_requests):
            futures.append(executor.submit(send_request, url, method, data, headers, cookies))
        
        for future in as_completed(futures):
            results.append(future.result())
    
    return results

def analyze_results(results):
    """Analyze race condition results for anomalies"""
    analysis = {
        "total": len(results),
        "success": 0,
        "errors": 0,
        "status_codes": {},
        "unique_bodies": set(),
        "anomalies": [],
        "timing": {"min": float('inf'), "max": 0, "avg": 0}
    }
    
    times = []
    bodies = []
    
    for r in results:
        if "error" in r:
            analysis["errors"] += 1
            continue
        
        analysis["success"] += 1
        status = r["status"]
        analysis["status_codes"][status] = analysis["status_codes"].get(status, 0) + 1
        
        body_hash = hash(r["body"][:100])
        analysis["unique_bodies"].add(body_hash)
        bodies.append((body_hash, r["body"][:200]))
        
        if r["time"]:
            times.append(r["time"])
    
    if times:
        analysis["timing"]["min"] = min(times)
        analysis["timing"]["max"] = max(times)
        analysis["timing"]["avg"] = sum(times) / len(times)
    
    # Detect anomalies
    # 1. Multiple 200s when normally only 1 should succeed
    ok_count = analysis["status_codes"].get(200, 0)
    if ok_count > 1:
        analysis["anomalies"].append({
            "type": "Multiple Success",
            "severity": "HIGH",
            "description": f"{ok_count} requests returned 200 — possible race condition!",
            "detail": "If this is a one-time action (redeem, transfer, claim), multiple successes = exploit"
        })
    
    # 2. Inconsistent responses
    if len(analysis["unique_bodies"]) > 3:
        analysis["anomalies"].append({
            "type": "Response Variance",
            "severity": "MEDIUM",
            "description": f"{len(analysis['unique_bodies'])} different response bodies detected",
            "detail": "Server behavior inconsistent under concurrent load"
        })
    
    # 3. Mixed status codes
    if len(analysis["status_codes"]) > 2:
        analysis["anomalies"].append({
            "type": "Mixed Status Codes",
            "severity": "MEDIUM",
            "description": f"Multiple status codes: {analysis['status_codes']}",
            "detail": "Server responds differently under concurrent load"
        })
    
    # 4. High timing variance
    if times and (max(times) - min(times)) > 2:
        analysis["anomalies"].append({
            "type": "Timing Variance",
            "severity": "LOW",
            "description": f"Response time varies: {min(times):.2f}s - {max(times):.2f}s",
            "detail": "Large timing gap may indicate lock contention"
        })
    
    # 5. 500 errors under load
    err_count = analysis["status_codes"].get(500, 0)
    if err_count > 0:
        analysis["anomalies"].append({
            "type": "Server Errors",
            "severity": "MEDIUM",
            "description": f"{err_count} internal server errors under load",
            "detail": "Server may crash or behave unexpectedly under concurrent requests"
        })
    
    # 6. 429 rate limiting
    rate_count = analysis["status_codes"].get(429, 0)
    if rate_count == 0 and ok_count == len(results):
        analysis["anomalies"].append({
            "type": "No Rate Limiting",
            "severity": "MEDIUM",
            "description": "No rate limiting detected on concurrent requests",
            "detail": "Race condition exploitation may be possible without throttling"
        })
    
    return analysis

def test_race_scenarios(url, headers=None, cookies=None):
    """Test common race condition scenarios"""
    print(f"\n{'='*60}")
    print(f"🏁 Race Condition Tester")
    print(f"Target: {url}")
    print(f"{'='*60}\n")
    
    scenarios = []
    
    # Scenario 1: Basic GET race
    print("📡 Scenario 1: Concurrent GET requests (50 threads)...")
    results = race_requests(url, 50, "GET", headers=headers, cookies=cookies)
    analysis = analyze_results(results)
    scenarios.append({"name": "GET Race", "analysis": analysis})
    
    print(f"  Results: {analysis['success']}/{analysis['total']} success")
    print(f"  Status codes: {analysis['status_codes']}")
    print(f"  Unique responses: {len(analysis['unique_bodies'])}")
    print(f"  Timing: {analysis['timing']['min']:.2f}s - {analysis['timing']['max']:.2f}s")
    
    for a in analysis["anomalies"]:
        sev_icon = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢"}
        print(f"  {sev_icon.get(a['severity'], '⚪')} [{a['severity']}] {a['type']}: {a['description']}")
    
    # Scenario 2: POST race (common for double-spend, double-claim)
    print("\n📡 Scenario 2: Concurrent POST requests (50 threads)...")
    post_data = {"test": "race_condition"}
    results = race_requests(url, 50, "POST", data=post_data, headers=headers, cookies=cookies)
    analysis = analyze_results(results)
    scenarios.append({"name": "POST Race", "analysis": analysis})
    
    print(f"  Results: {analysis['success']}/{analysis['total']} success")
    print(f"  Status codes: {analysis['status_codes']}")
    
    for a in analysis["anomalies"]:
        sev_icon = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢"}
        print(f"  {sev_icon.get(a['severity'], '⚪')} [{a['severity']}] {a['type']}: {a['description']}")
    
    # Scenario 3: Burst (all at once vs staggered)
    print("\n📡 Scenario 3: Burst comparison (instant vs staggered)...")
    
    # Instant burst
    start = time.time()
    results_instant = race_requests(url, 30, "GET", headers=headers, cookies=cookies)
    instant_time = time.time() - start
    
    # Staggered
    start = time.time()
    results_staggered = []
    for i in range(30):
        r = send_request(url, "GET", headers=headers, cookies=cookies)
        results_staggered.append(r)
        time.sleep(0.05)
    staggered_time = time.time() - start
    
    instant_ok = len([r for r in results_instant if r.get("status") == 200])
    staggered_ok = len([r for r in results_staggered if r.get("status") == 200])
    
    print(f"  Instant burst: {instant_ok}/30 OK in {instant_time:.2f}s")
    print(f"  Staggered: {staggered_ok}/30 OK in {staggered_time:.2f}s")
    
    if instant_ok != staggered_ok:
        print(f"  🔴 DIFFERENT BEHAVIOR! Server responds differently under burst load")
        scenarios.append({
            "name": "Burst vs Staggered",
            "anomaly": f"Burst={instant_ok}, Staggered={staggered_ok}"
        })
    
    # Summary
    print(f"\n{'='*60}")
    print(f"📊 RACE CONDITION RESULTS")
    print(f"{'='*60}")
    
    all_anomalies = []
    for s in scenarios:
        for a in s.get("analysis", {}).get("anomalies", []):
            all_anomalies.append(a)
    
    high = len([a for a in all_anomalies if a["severity"] == "HIGH"])
    medium = len([a for a in all_anomalies if a["severity"] == "MEDIUM"])
    low = len([a for a in all_anomalies if a["severity"] == "LOW"])
    
    print(f"🔴 High: {high}")
    print(f"🟡 Medium: {medium}")
    print(f"🟢 Low: {low}")
    
    if high > 0:
        print("\n⚠️  RACE CONDITION LIKELY! Test with real actions:")
        print("  - Double-spend / double-claim")
        print("  - Coupon/voucher reuse")
        print("  - Transfer duplication")
        print("  - Vote manipulation")
    
    # Save
    import os
    os.makedirs("output", exist_ok=True)
    domain = urlparse(url).netloc.replace(".", "_")
    outfile = f"output/race_{domain}.json"
    with open(outfile, "w") as f:
        json.dump({"scenarios": scenarios}, f, indent=2, default=str)
    print(f"\n💾 Saved to {outfile}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 race_condition.py <url>")
        print("Example: python3 race_condition.py https://example.com/api/redeem")
        sys.exit(1)
    
    test_race_scenarios(sys.argv[1])
