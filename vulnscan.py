#!/usr/bin/env python3
"""
Bug Bounty Recon Toolkit - Web Vulnerability Scanner
Tests for SQLi, XSS, Open Redirect, SSRF patterns
For AUTHORIZED bug bounty testing only.

⚠️  LEGAL DISCLAIMER: Only use against targets you are authorized to test.
    Unauthorized testing is illegal under Indonesian UU ITE (UU No. 11/2008).
"""

import asyncio
import aiohttp
import json
import os
import re
import sys
import time
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urlencode, urljoin, quote
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()

# SQLi payloads (detection only, not exploitation)
SQLI_PAYLOADS = [
    # Error-based detection
    ("'", "syntax|mysql|sql|error|warning|query|oracle|postgresql|sqlite|mssql"),
    ("\"'", "syntax|mysql|sql|error|warning|query|oracle|postgresql|sqlite|mssql"),
    ("1' OR '1'='1", "syntax|mysql|sql|error|warning|query"),
    ("1\" OR \"1\"=\"1", "syntax|mysql|sql|error|warning|query"),
    ("' OR 1=1--", "syntax|mysql|sql|error|warning|query"),
    ("' UNION SELECT NULL--", "syntax|mysql|sql|error|warning|query|union|select"),
    ("1; SELECT 1--", "syntax|mysql|sql|error|warning|query"),
    # Time-based detection
    ("' OR SLEEP(5)--", None),  # Check if response takes >5s
    ("'; WAITFOR DELAY '0:0:5'--", None),
    # Boolean-based detection
    ("' AND '1'='1", None),  # Should return same as normal
    ("' AND '1'='2", None),  # Should return different
]

# XSS payloads (reflected detection)
XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "'-alert(1)-'",
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '"><img src=x onerror=alert(1)>',
    "javascript:alert(1)",
    '{{7*7}}',  # SSTI detection
    '${7*7}',   # SSTI detection
    '<%= 7*7 %>',  # ERB SSTI
]

# Open Redirect payloads
REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "/\\evil.com",
    "///evil.com",
    "////evil.com",
    "https://evil.com%00.legitimate.com",
    "javascript:alert(1)",
]

# Common sensitive paths
SENSITIVE_PATHS = [
    "/.env",
    "/.git/HEAD",
    "/.git/config",
    "/.svn/entries",
    "/.DS_Store",
    "/backup.sql",
    "/database.sql",
    "/dump.sql",
    "/db.sql",
    "/config.php",
    "/config.yml",
    "/config.json",
    "/settings.py",
    "/wp-config.php",
    "/application.properties",
    "/application.yml",
    "/.htaccess",
    "/.htpasswd",
    "/server-status",
    "/server-info",
    "/phpinfo.php",
    "/info.php",
    "/test.php",
    "/debug",
    "/trace",
    "/actuator",
    "/actuator/env",
    "/actuator/health",
    "/swagger-ui.html",
    "/swagger/v1/swagger.json",
    "/api-docs",
    "/graphql",
    "/graphiql",
    "/.well-known/security.txt",
    "/crossdomain.xml",
    "/clientaccesspolicy.xml",
    "/elmah.axd",
    "/trace.axd",
    "/web.config",
    "/WEB-INF/web.xml",
]


async def make_request(session, url, method="GET", data=None, timeout=10):
    """Make HTTP request and return response details."""
    start = time.time()
    try:
        if method == "GET":
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=timeout),
                allow_redirects=False,
                ssl=False,
            ) as resp:
                elapsed = time.time() - start
                body = await resp.text(errors='ignore')
                return {
                    "status": resp.status,
                    "headers": dict(resp.headers),
                    "body": body,
                    "time": elapsed,
                    "url": str(resp.url),
                    "redirect": resp.headers.get("Location", ""),
                }
        elif method == "POST":
            async with session.post(
                url,
                data=data,
                timeout=aiohttp.ClientTimeout(total=timeout),
                allow_redirects=False,
                ssl=False,
            ) as resp:
                elapsed = time.time() - start
                body = await resp.text(errors='ignore')
                return {
                    "status": resp.status,
                    "headers": dict(resp.headers),
                    "body": body,
                    "time": elapsed,
                    "url": str(resp.url),
                    "redirect": resp.headers.get("Location", ""),
                }
    except asyncio.TimeoutError:
        return {"status": 0, "time": time.time() - start, "error": "timeout"}
    except Exception as e:
        return {"status": 0, "time": time.time() - start, "error": str(e)}


async def test_sqli(session, url, param, method="GET"):
    """Test a parameter for SQL injection."""
    findings = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    if param not in params:
        return findings

    # Get baseline response
    baseline = await make_request(session, url)
    if "error" in baseline:
        return findings

    for payload, error_pattern in SQLI_PAYLOADS:
        test_params = params.copy()
        test_params[param] = [payload]

        if method == "GET":
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"
            result = await make_request(session, test_url)
        else:
            result = await make_request(session, url, method="POST", data=test_params)

        if "error" in result:
            continue

        # Error-based detection
        if error_pattern:
            if re.search(error_pattern, result.get("body", ""), re.IGNORECASE):
                findings.append({
                    "type": "SQLi",
                    "subtype": "Error-based",
                    "param": param,
                    "payload": payload,
                    "evidence": "SQL error pattern found in response",
                    "severity": "HIGH",
                    "url": url,
                })

        # Time-based detection
        if "SLEEP" in payload or "WAITFOR" in payload:
            if result.get("time", 0) > 4.5:
                findings.append({
                    "type": "SQLi",
                    "subtype": "Time-based",
                    "param": param,
                    "payload": payload,
                    "evidence": f"Response took {result['time']:.1f}s (expected ~5s)",
                    "severity": "CRITICAL",
                    "url": url,
                })

    return findings


async def test_xss(session, url, param, method="GET"):
    """Test a parameter for reflected XSS."""
    findings = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    if param not in params:
        return findings

    for payload in XSS_PAYLOADS:
        test_params = params.copy()
        test_params[param] = [payload]

        if method == "GET":
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"
            result = await make_request(session, test_url)
        else:
            result = await make_request(session, url, method="POST", data=test_params)

        if "error" in result:
            continue

        body = result.get("body", "")

        # Check if payload is reflected without encoding
        if payload in body:
            # Verify it's not just in a comment or encoded
            if f"<!--{payload}" not in body:
                severity = "HIGH" if "<script>" in payload or "onerror" in payload else "MEDIUM"
                findings.append({
                    "type": "XSS",
                    "subtype": "Reflected",
                    "param": param,
                    "payload": payload,
                    "evidence": "Payload reflected in response without encoding",
                    "severity": severity,
                    "url": url,
                })

        # SSTI detection
        if payload in ["{{7*7}}", "${7*7}"]:
            if "49" in body:
                findings.append({
                    "type": "SSTI",
                    "subtype": "Server-Side Template Injection",
                    "param": param,
                    "payload": payload,
                    "evidence": "Template expression evaluated (7*7=49)",
                    "severity": "CRITICAL",
                    "url": url,
                })

    return findings


async def test_open_redirect(session, url, param):
    """Test for open redirect vulnerability."""
    findings = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    if param not in params:
        return findings

    for payload in REDIRECT_PAYLOADS:
        test_params = params.copy()
        test_params[param] = [payload]
        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"

        result = await make_request(session, test_url)
        if "error" in result:
            continue

        redirect = result.get("redirect", "")
        if redirect and ("evil.com" in redirect or "javascript:" in redirect):
            findings.append({
                "type": "Open Redirect",
                "param": param,
                "payload": payload,
                "evidence": f"Redirects to: {redirect}",
                "severity": "MEDIUM",
                "url": url,
            })

    return findings


async def scan_sensitive_paths(session, base_url):
    """Check for sensitive files/directories."""
    findings = []
    base = base_url.rstrip("/")

    for path in SENSITIVE_PATHS:
        url = f"{base}{path}"
        result = await make_request(session, url, timeout=5)

        if "error" in result:
            continue

        if result["status"] == 200:
            # Verify it's not a generic error page
            body = result.get("body", "")
            if len(body) > 50 and "404" not in body[:200].lower():
                severity = "CRITICAL" if path in ["/.env", "/.git/HEAD", "/.git/config", "/backup.sql", "/database.sql", "/dump.sql"] else "HIGH"
                findings.append({
                    "type": "Sensitive File",
                    "path": path,
                    "status": result["status"],
                    "size": len(body),
                    "severity": severity,
                    "url": url,
                })

    return findings


async def test_cors(session, url):
    """Test for CORS misconfiguration."""
    findings = []
    try:
        headers = {"Origin": "https://evil.com"}
        async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=10), ssl=False) as resp:
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "")

            if acao == "*":
                findings.append({
                    "type": "CORS",
                    "subtype": "Wildcard Origin",
                    "evidence": "Access-Control-Allow-Origin: *",
                    "severity": "LOW",
                    "url": url,
                })
            elif acao == "https://evil.com" and acac.lower() == "true":
                findings.append({
                    "type": "CORS",
                    "subtype": "Origin Reflection with Credentials",
                    "evidence": f"Reflected origin with credentials",
                    "severity": "HIGH",
                    "url": url,
                })
            elif acao == "https://evil.com":
                findings.append({
                    "type": "CORS",
                    "subtype": "Origin Reflection",
                    "evidence": "Origin reflected in ACAO header",
                    "severity": "MEDIUM",
                    "url": url,
                })
    except:
        pass

    return findings


def display_findings(findings):
    """Display vulnerability findings."""
    if not findings:
        console.print("\n[green]✅ No vulnerabilities found[/]")
        return

    table = Table(
        title="🚨 Vulnerabilities Found",
        box=box.ROUNDED,
        show_lines=True,
    )
    table.add_column("Type", style="bold")
    table.add_column("Severity", style="bold")
    table.add_column("Detail")
    table.add_column("URL/Param", style="cyan")

    severity_colors = {
        "CRITICAL": "[bold red]🔴 CRITICAL[/]",
        "HIGH": "[red]🟠 HIGH[/]",
        "MEDIUM": "[yellow]🟡 MEDIUM[/]",
        "LOW": "[green]🟢 LOW[/]",
    }

    for f in findings:
        ftype = f.get("type", "Unknown")
        subtype = f.get("subtype", "")
        if subtype:
            ftype = f"{ftype} ({subtype})"

        severity = severity_colors.get(f.get("severity", "LOW"), f.get("severity", "LOW"))

        detail = f.get("evidence", f.get("payload", ""))
        url = f.get("url", "")
        param = f.get("param", f.get("path", ""))
        if param:
            url = f"{url} [{param}]"

        table.add_row(ftype, severity, detail[:80], url[:60])

    console.print(table)


def save_findings(findings, output_dir="./output"):
    """Save findings to JSON."""
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{output_dir}/vulns_{timestamp}.json"

    data = {
        "timestamp": datetime.now().isoformat(),
        "total_findings": len(findings),
        "findings": findings,
    }

    with open(filename, 'w') as f:
        json.dump(data, f, indent=2)

    console.print(f"[dim]💾 Saved to {filename}[/]")
    return filename


async def scan_target(target):
    """Run full vulnerability scan on a target."""
    if not target.startswith("http"):
        target = f"https://{target}"

    parsed = urlparse(target)
    domain = parsed.hostname

    console.print(Panel.fit(
        f"[bold]🎯 Vulnerability Scan: {domain}[/]\n"
        f"URL: {target}",
        title="⚠️ Authorized Testing Only",
    ))

    all_findings = []
    connector = aiohttp.TCPConnector(limit=10)

    async with aiohttp.ClientSession(connector=connector) as session:
        # 1. Sensitive paths scan
        console.print("\n[bold cyan]📁 Scanning sensitive paths...[/]")
        path_findings = await scan_sensitive_paths(session, target)
        all_findings.extend(path_findings)
        console.print(f"  Found: {len(path_findings)} sensitive paths")

        # 2. CORS check
        console.print("\n[bold cyan]🌐 Checking CORS...[/]")
        cors_findings = await test_cors(session, target)
        all_findings.extend(cors_findings)
        console.print(f"  Found: {len(cors_findings)} CORS issues")

        # 3. Parameter-based testing (if URL has params)
        params = parse_qs(parsed.query)
        if params:
            console.print(f"\n[bold cyan]💉 Testing {len(params)} parameters...[/]")

            for param in params:
                console.print(f"  Testing: [cyan]{param}[/]")

                sqli = await test_sqli(session, target, param)
                all_findings.extend(sqli)

                xss = await test_xss(session, target, param)
                all_findings.extend(xss)

                redirect = await test_open_redirect(session, target, param)
                all_findings.extend(redirect)
        else:
            console.print("\n[dim]No URL parameters to test (add ?param=test to URL)[/]")

    # Display results
    display_findings(all_findings)

    if all_findings:
        save_findings(all_findings)

    console.print(f"\n[bold green]✅ Scan complete for {domain}[/]")
    console.print(f"[dim]Total findings: {len(all_findings)}[/]")

    return all_findings


async def main():
    if len(sys.argv) < 2:
        console.print(Panel.fit(
            "[bold]Bug Bounty Vulnerability Scanner[/]\n\n"
            "Usage: python3 vulnscan.py <target> [target2] ...\n\n"
            "Examples:\n"
            "  python3 vulnscan.py https://target.com/page?id=1\n"
            "  python3 vulnscan.py target.com\n\n"
            "[yellow]⚠️  Only use against authorized targets[/]",
            title="⚠️ Vuln Scanner",
        ))
        return

    targets = sys.argv[1:]
    all_findings = []

    for target in targets:
        findings = await scan_target(target)
        all_findings.extend(findings)
        console.print("\n" + "─" * 60 + "\n")

    # Summary
    if all_findings:
        console.print(f"\n[bold red]🚨 Total: {len(all_findings)} vulnerabilities across all targets[/]")
    else:
        console.print(f"\n[bold green]✅ No vulnerabilities found across all targets[/]")


if __name__ == "__main__":
    asyncio.run(main())
