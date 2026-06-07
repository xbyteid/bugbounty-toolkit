#!/usr/bin/env python3
"""
Bug Bounty Recon Toolkit - Quick Recon
Fast port scan + tech detection + header analysis
For AUTHORIZED bug bounty testing only.
"""

import asyncio
import aiohttp
import json
import os
import socket
import ssl
import sys
import time
from datetime import datetime
from urllib.parse import urlparse
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()

# Common ports to scan
COMMON_PORTS = [
    21, 22, 25, 53, 80, 110, 143, 443, 445, 587, 993, 995,
    1433, 1521, 3000, 3306, 3389, 4443, 5000, 5432, 5900, 6379,
    7001, 8000, 8080, 8443, 8888, 9000, 9090, 9200, 9300, 27017,
]

# Technology signatures from headers/body
TECH_SIGNATURES = {
    "server": {
        "nginx": "Nginx",
        "apache": "Apache",
        "cloudflare": "Cloudflare",
        "gws": "Google Web Server",
        "AmazonS3": "Amazon S3",
        "Vercel": "Vercel",
        "Netlify": "Netlify",
        "GitHub": "GitHub Pages",
        "Fly.io": "Fly.io",
        "Caddy": "Caddy",
        "LiteSpeed": "LiteSpeed",
        "IIS": "Microsoft IIS",
        "openresty": "OpenResty",
    },
    "x-powered-by": {
        "Express": "Node.js/Express",
        "PHP": "PHP",
        "ASP.NET": "ASP.NET",
        "Next.js": "Next.js",
        "NestJS": "NestJS",
        "Laravel": "Laravel",
        "Django": "Django",
        "Flask": "Flask",
        "Ruby on Rails": "Ruby on Rails",
    },
    "x-aspnet-version": {
        "": "ASP.NET",
    },
    "x-runtime": {
        "Ruby": "Ruby on Rails",
    },
}


async def check_port(host, port, timeout=3):
    """Check if a port is open."""
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        return port
    except:
        return None


async def scan_ports(host, ports=None, threads=100):
    """Scan ports on a host."""
    if ports is None:
        ports = COMMON_PORTS

    console.print(f"\n[bold cyan]🔌 Port Scanning: {host}[/]")
    console.print(f"[dim]Ports: {len(ports)} | Threads: {threads}[/]\n")

    semaphore = asyncio.Semaphore(threads)
    open_ports = []

    async def limited_check(port):
        async with semaphore:
            return await check_port(host, port)

    tasks = [limited_check(p) for p in ports]
    results = await asyncio.gather(*tasks)
    open_ports = sorted([p for p in results if p is not None])

    return open_ports


async def fingerprint_url(session, url, timeout=10):
    """Fingerprint a URL for technologies."""
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout),
                               allow_redirects=True, ssl=False) as resp:
            headers = dict(resp.headers)
            body = await resp.text(errors='ignore')
            body_lower = body.lower()

            techs = set()

            # Check headers
            for header, signatures in TECH_SIGNATURES.items():
                value = headers.get(header, "")
                if value:
                    for sig, tech in signatures.items():
                        if sig.lower() in value.lower():
                            techs.add(tech)

            # Check body for common frameworks
            body_sigs = {
                "wp-content": "WordPress",
                "wp-includes": "WordPress",
                "joomla": "Joomla",
                "drupal": "Drupal",
                "shopify": "Shopify",
                "react": "React",
                "vue": "Vue.js",
                "angular": "Angular",
                "next": "Next.js",
                "nuxt": "Nuxt.js",
                "gatsby": "Gatsby",
                "laravel": "Laravel",
                "django": "Django",
                "flask": "Flask",
                "express": "Express",
                "fastapi": "FastAPI",
                "spring": "Spring Boot",
                "rails": "Ruby on Rails",
                "tailwind": "Tailwind CSS",
                "bootstrap": "Bootstrap",
                "jquery": "jQuery",
                "gtag": "Google Analytics",
                "gtm": "Google Tag Manager",
                "facebook": "Facebook Pixel",
                "cloudflare": "Cloudflare",
                "recaptcha": "reCAPTCHA",
                "hcaptcha": "hCaptcha",
                "stripe": "Stripe",
                "midtrans": "Midtrans",
                "xendit": "Xendit",
            }

            for sig, tech in body_sigs.items():
                if sig in body_lower:
                    techs.add(tech)

            # Security headers analysis
            security = {}
            sec_headers = {
                "Strict-Transport-Security": "HSTS",
                "Content-Security-Policy": "CSP",
                "X-Frame-Options": "X-Frame-Options",
                "X-Content-Type-Options": "X-Content-Type-Options",
                "X-XSS-Protection": "X-XSS-Protection",
                "Referrer-Policy": "Referrer-Policy",
                "Permissions-Policy": "Permissions-Policy",
            }

            for header, name in sec_headers.items():
                if header in headers:
                    security[name] = "✅ Present"
                else:
                    security[name] = "❌ Missing"

            # Cookies
            cookies = []
            for cookie in resp.cookies.values():
                cookie_info = f"{cookie.key}"
                if cookie.get("secure"):
                    cookie_info += " [Secure]"
                if cookie.get("httponly"):
                    cookie_info += " [HttpOnly]"
                if cookie.get("samesite"):
                    cookie_info += f" [SameSite={cookie.get('samesite')}]"
                cookies.append(cookie_info)

            return {
                "url": str(resp.url),
                "status": resp.status,
                "technologies": sorted(techs),
                "security_headers": security,
                "cookies": cookies,
                "server": headers.get("Server", "Unknown"),
                "redirected": str(resp.url) != url,
                "final_url": str(resp.url),
            }
    except Exception as e:
        return {"url": url, "error": str(e)}


async def check_ssl(domain, port=443):
    """Check SSL certificate details."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(domain, port, ssl=ctx),
            timeout=10
        )

        ssl_object = writer.get_extra_info('ssl_object')
        cert = ssl_object.getpeercert(binary_form=False)
        cipher = ssl_object.cipher()

        writer.close()
        await writer.wait_closed()

        if cert:
            return {
                "subject": dict(x[0] for x in cert.get("subject", [])),
                "issuer": dict(x[0] for x in cert.get("issuer", [])),
                "notBefore": cert.get("notBefore"),
                "notAfter": cert.get("notAfter"),
                "serialNumber": cert.get("serialNumber"),
                "version": cert.get("version"),
                "cipher": cipher[0] if cipher else None,
            }
    except:
        pass
    return None


def display_port_results(host, open_ports):
    """Display port scan results."""
    if not open_ports:
        console.print(f"\n[yellow]⚠️  No open ports found on {host}[/]")
        return

    port_services = {
        21: "FTP", 22: "SSH", 25: "SMTP", 53: "DNS", 80: "HTTP",
        110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
        587: "SMTP/TLS", 993: "IMAPS", 995: "POP3S",
        1433: "MSSQL", 1521: "Oracle", 3000: "Node.js/Dev",
        3306: "MySQL", 3389: "RDP", 4443: "HTTPS-Alt",
        5000: "Docker/Flask", 5432: "PostgreSQL", 5900: "VNC",
        6379: "Redis", 7001: "WebLogic", 8000: "HTTP-Alt",
        8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 8888: "HTTP-Alt",
        9000: "PHP-FPM", 9090: "Web-Alt", 9200: "Elasticsearch",
        9300: "Elasticsearch", 27017: "MongoDB",
    }

    table = Table(
        title=f"🔌 Open Ports on {host}",
        box=box.ROUNDED,
        show_lines=True,
    )
    table.add_column("Port", style="bold green", width=6)
    table.add_column("Service", style="cyan")
    table.add_column("Risk", style="yellow")

    high_risk = {21, 445, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 7001, 9200, 9300, 27017}
    med_risk = {22, 25, 110, 143, 993, 995, 3000, 5000, 8000, 8080, 8888, 9000, 9090}

    for port in open_ports:
        service = port_services.get(port, "Unknown")
        if port in high_risk:
            risk = "[bold red]🔴 HIGH[/]"
        elif port in med_risk:
            risk = "[yellow]🟡 MEDIUM[/]"
        else:
            risk = "[green]🟢 LOW[/]"
        table.add_row(str(port), service, risk)

    console.print(table)


def display_fingerprint(result):
    """Display fingerprint results."""
    if "error" in result:
        console.print(f"\n[red]❌ {result['url']}: {result['error']}[/]")
        return

    console.print(f"\n[bold cyan]🔍 Fingerprinting: {result['url']}[/]")

    # Basic info
    console.print(f"  Status: [green]{result['status']}[/]")
    console.print(f"  Server: [cyan]{result['server']}[/]")
    if result.get('redirected'):
        console.print(f"  Redirected: [yellow]{result['final_url']}[/]")

    # Technologies
    if result['technologies']:
        techs = ", ".join(result['technologies'])
        console.print(f"  Technologies: [bold green]{techs}[/]")

    # Security headers
    console.print(f"\n  [bold]Security Headers:[/]")
    for header, status in result['security_headers'].items():
        console.print(f"    {header}: {status}")

    # Cookies
    if result['cookies']:
        console.print(f"\n  [bold]Cookies:[/]")
        for cookie in result['cookies']:
            console.print(f"    • {cookie}")


def display_ssl(ssl_info):
    """Display SSL certificate info."""
    if not ssl_info:
        console.print(f"\n[yellow]⚠️  No SSL certificate found[/]")
        return

    console.print(f"\n[bold cyan]🔒 SSL Certificate[/]")
    console.print(f"  Subject: {ssl_info.get('subject', {}).get('commonName', 'N/A')}")
    console.print(f"  Issuer: {ssl_info.get('issuer', {}).get('organizationName', 'N/A')}")
    console.print(f"  Valid From: {ssl_info.get('notBefore', 'N/A')}")
    console.print(f"  Valid Until: {ssl_info.get('notAfter', 'N/A')}")
    console.print(f"  Cipher: {ssl_info.get('cipher', 'N/A')}")


async def recon_target(target):
    """Full recon on a target."""
    # Parse URL
    if not target.startswith("http"):
        target = f"https://{target}"

    parsed = urlparse(target)
    domain = parsed.hostname

    console.print(Panel.fit(
        f"[bold]🎯 Target: {domain}[/]\n"
        f"URL: {target}",
        title="Bug Bounty Recon",
    ))

    # Port scan
    open_ports = await scan_ports(domain)
    display_port_results(domain, open_ports)

    # SSL check
    if 443 in open_ports:
        ssl_info = await check_ssl(domain)
        display_ssl(ssl_info)

    # Fingerprint main URL
    connector = aiohttp.TCPConnector(limit=10)
    async with aiohttp.ClientSession(connector=connector) as session:
        result = await fingerprint_url(session, target)
        display_fingerprint(result)

        # Also check common paths
        console.print(f"\n[bold cyan]📁 Common Paths[/]")
        paths = [
            "/robots.txt", "/sitemap.xml", "/.env", "/.git/HEAD",
            "/admin", "/login", "/api", "/graphql", "/swagger",
            "/debug", "/trace", "/.well-known/security.txt",
            "/wp-admin", "/wp-login.php", "/phpmyadmin",
            "/server-status", "/server-info", "/.htaccess",
        ]

        found_paths = []
        for path in paths:
            url = f"{target.rstrip('/')}{path}"
            try:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=5),
                                       allow_redirects=False, ssl=False) as resp:
                    if resp.status in [200, 301, 302, 403]:
                        status = resp.status
                        size = len(await resp.read())
                        found_paths.append((path, status, size))
            except:
                pass

        if found_paths:
            table = Table(box=box.SIMPLE)
            table.add_column("Path", style="green")
            table.add_column("Status", style="cyan")
            table.add_column("Size", style="dim")

            for path, status, size in found_paths:
                status_style = "green" if status == 200 else "yellow" if status in [301, 302] else "red"
                table.add_row(path, f"[{status_style}]{status}[/]", f"{size} bytes")

            console.print(table)
        else:
            console.print("  [dim]No interesting paths found[/]")

    # Summary
    console.print(f"\n[bold green]✅ Recon complete for {domain}[/]")
    return {
        "domain": domain,
        "open_ports": open_ports,
        "paths": found_paths,
    }


async def main():
    if len(sys.argv) < 2:
        console.print(Panel.fit(
            "[bold]Bug Bounty Quick Recon[/]\n\n"
            "Usage: python3 recon.py <target> [target2] ...\n\n"
            "Examples:\n"
            "  python3 recon.py tokopedia.com\n"
            "  python3 recon.py api.gojek.com\n"
            "  python3 recon.py traveloka.com bukalapak.com",
            title="🔍 Quick Recon",
        ))
        return

    targets = sys.argv[1:]

    for target in targets:
        await recon_target(target)
        console.print("\n" + "─" * 60 + "\n")


if __name__ == "__main__":
    asyncio.run(main())
