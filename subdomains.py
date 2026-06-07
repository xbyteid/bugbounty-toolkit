#!/usr/bin/env python3
"""
Bug Bounty Recon Toolkit - Subdomain Enumeration
For AUTHORIZED bug bounty testing only.
"""

import asyncio
import aiohttp
import dns.resolver
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.panel import Panel
from rich import box

console = Console()

# Common subdomain wordlist
SUBDOMAIN_WORDLIST = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "webmail", "mx",
    "ns1", "ns2", "dns", "dns1", "dns2", "vpn", "remote", "gateway",
    "api", "api2", "api3", "dev", "dev2", "development", "staging",
    "stage", "stg", "test", "testing", "qa", "uat", "demo", "sandbox",
    "beta", "alpha", "preview", "canary", "nightly", "rc", "pre",
    "app", "app2", "apps", "mobile", "m", "wap", "touch",
    "admin", "administrator", "cpanel", "whm", "panel", "dashboard",
    "portal", "console", "manage", "management", "backoffice",
    "cms", "wp", "wordpress", "blog", "news", "forum", "community",
    "shop", "store", "ecommerce", "cart", "checkout", "payment", "pay",
    "cdn", "static", "assets", "media", "img", "images", "video", "files",
    "upload", "download", "dl", "mirror", "cache", "edge",
    "db", "database", "mysql", "postgres", "mongo", "redis", "elastic",
    "search", "solr", "es", "log", "logs", "logging", "monitor", "monitoring",
    "grafana", "kibana", "prometheus", "nagios", "zabbix", "sentry",
    "git", "gitlab", "github", "bitbucket", "svn", "repo", "repos", "code",
    "ci", "cd", "jenkins", "travis", "circleci", "build", "deploy",
    "docker", "k8s", "kubernetes", "container", "registry", "rancher",
    "auth", "sso", "login", "signin", "signup", "register", "oauth",
    "id", "identity", "iam", "ldap", "okta", "keycloak",
    "internal", "intranet", "private", "corp", "corporate", "office",
    "hr", "crm", "erp", "jira", "confluence", "wiki", "docs", "doc",
    "support", "help", "helpdesk", "ticket", "zendesk", "freshdesk",
    "chat", "im", "messaging", "slack", "teams", "zoom",
    "analytics", "stats", "statistics", "metrics", "report", "reports",
    "data", "lake", "warehouse", "etl", "pipeline", "spark", "hadoop",
    "ml", "ai", "model", "inference", "training", "gpu",
    "backup", "bak", "bkp", "dr", "disaster", "recovery",
    "old", "legacy", "archive", "v1", "v2", "v3", "v4",
    "s3", "aws", "gcp", "azure", "cloud", "infra", "infrastructure",
    "proxy", "lb", "load", "balance", "haproxy", "nginx", "apache",
    "web", "www2", "www3", "secure", "ssl", "tls", "cert",
    "partner", "affiliate", "reseller", "vendor", "supplier",
    "client", "customer", "user", "member", "account",
    "go", "link", "url", "short", "redirect", "r",
    "status", "health", "ping", "uptime", "heartbeat",
    "exchange", "mx1", "mx2", "autodiscover", "autoconfig",
    "vpn2", "openvpn", "wireguard", "wg", "tunnel",
    "waf", "firewall", "security", "sec", "audit",
    "notify", "notification", "alert", "webhook", "hook",
    "queue", "mq", "rabbit", "kafka", "broker", "worker",
    "socket", "ws", "wss", "realtime", "rt", "live", "stream",
    "graphql", "gql", "rest", "rpc", "grpc",
    "lambda", "function", "serverless", "faas",
    "storage", "blob", "file", "fs", "nas", "nfs",
    "telnet", "ssh", "rdp", "vnc", "bastion", "jump",
    "print", "printer", "scan", "scanner",
    "voip", "sip", "pbx", "call", "phone", "tel",
    "time", "ntp", "clock",
    "ntp", "snmp", "syslog", "trap",
]


async def check_subdomain(session, domain, subdomain, resolver, timeout=5):
    """Check if a subdomain exists via DNS resolution."""
    fqdn = f"{subdomain}.{domain}"
    try:
        answers = await asyncio.get_event_loop().run_in_executor(
            None, lambda: resolver.resolve(fqdn, 'A')
        )
        ips = [str(rdata) for rdata in answers]
        return {"subdomain": fqdn, "ips": ips, "status": "active"}
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return None
    except Exception as e:
        return None


async def enumerate_subdomains(domain, threads=50, custom_wordlist=None):
    """Enumerate subdomains for a given domain."""
    wordlist = SUBDOMAIN_WORDLIST
    if custom_wordlist:
        with open(custom_wordlist, 'r') as f:
            wordlist = [line.strip() for line in f if line.strip()]

    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5
    resolver.nameservers = ['8.8.8.8', '1.1.1.1', '8.8.4.4']

    found = []
    total = len(wordlist)

    console.print(f"\n[bold cyan]🔍 Enumerating subdomains for: {domain}[/]")
    console.print(f"[dim]Wordlist: {total} entries | Threads: {threads}[/]\n")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Scanning...", total=total)

        semaphore = asyncio.Semaphore(threads)

        async def limited_check(sub):
            async with semaphore:
                result = await check_subdomain(None, domain, sub, resolver)
                progress.advance(task)
                return result

        connector = aiohttp.TCPConnector(limit=threads)
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = [limited_check(sub) for sub in wordlist]
            results = await asyncio.gather(*tasks)

    found = [r for r in results if r is not None]
    return found


def display_results(domain, results):
    """Display subdomain enumeration results."""
    if not results:
        console.print(f"\n[yellow]⚠️  No subdomains found for {domain}[/]")
        return

    table = Table(
        title=f"🎯 Subdomains Found for {domain}",
        box=box.ROUNDED,
        show_lines=True,
    )
    table.add_column("#", style="dim", width=4)
    table.add_column("Subdomain", style="bold green")
    table.add_column("IP Addresses", style="cyan")

    for i, r in enumerate(sorted(results, key=lambda x: x['subdomain']), 1):
        table.add_row(str(i), r['subdomain'], ", ".join(r['ips']))

    console.print(table)
    console.print(f"\n[bold green]✅ Found {len(results)} subdomains[/]")


def save_results(domain, results, output_dir="./output"):
    """Save results to JSON."""
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{output_dir}/subdomains_{domain}_{timestamp}.json"

    data = {
        "domain": domain,
        "timestamp": datetime.now().isoformat(),
        "total_found": len(results),
        "subdomains": sorted(results, key=lambda x: x['subdomain']),
    }

    with open(filename, 'w') as f:
        json.dump(data, f, indent=2)

    console.print(f"[dim]💾 Saved to {filename}[/]")
    return filename


async def main():
    if len(sys.argv) < 2:
        console.print(Panel.fit(
            "[bold]Bug Bounty Subdomain Enumerator[/]\n\n"
            "Usage: python3 subdomains.py <domain> [wordlist] [--threads N]\n\n"
            "Examples:\n"
            "  python3 subdomains.py tokopedia.com\n"
            "  python3 subdomains.py gojek.com --threads 100\n"
            "  python3 subdomains.py traveloka.com custom_wordlist.txt",
            title="🔍 Subdomain Enum",
        ))
        return

    domain = sys.argv[1]
    custom_wordlist = None
    threads = 50

    for i, arg in enumerate(sys.argv):
        if arg == "--threads" and i + 1 < len(sys.argv):
            threads = int(sys.argv[i + 1])
        elif i > 1 and not arg.startswith("--") and arg != domain:
            if os.path.isfile(arg):
                custom_wordlist = arg

    start = time.time()
    results = await enumerate_subdomains(domain, threads, custom_wordlist)
    elapsed = time.time() - start

    display_results(domain, results)
    save_results(domain, results)
    console.print(f"[dim]⏱️  Completed in {elapsed:.1f}s[/]")


if __name__ == "__main__":
    asyncio.run(main())
