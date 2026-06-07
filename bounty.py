#!/usr/bin/env python3
"""
Bug Bounty Recon Toolkit - Main CLI
Unified interface for all recon tools.
For AUTHORIZED bug bounty testing only.
"""

import asyncio
import sys
import os
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

console = Console()

BANNER = """
[bold red]
 ██████╗ ██╗   ██╗ ██████╗     ██████╗  ██████╗ ██╗   ██╗███╗   ██╗████████╗██╗   ██╗
 ██╔══██╗██║   ██║██╔════╝     ██╔══██╗██╔═══██╗██║   ██║████╗  ██║╚══██╔══╝╚██╗ ██╔╝
 ██████╔╝██║   ██║██║  ███╗    ██████╔╝██║   ██║██║   ██║██╔██╗ ██║   ██║    ╚████╔╝
 ██╔══██╗██║   ██║██║   ██║    ██╔══██╗██║   ██║██║   ██║██║╚██╗██║   ██║     ╚██╔╝
 ██████╔╝╚██████╔╝╚██████╔╝    ██████╔╝╚██████╔╝╚██████╔╝██║ ╚████║   ██║      ██║
 ╚═════╝  ╚═════╝  ╚═════╝     ╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝   ╚═╝      ╚═╝[/]
[dim]  Recon Toolkit v1.0 — For AUTHORIZED Bug Bounty Testing Only[/]
"""

MENU = """
[bold cyan]Available Tools:[/]

  [bold green]1[/] 🔍  [bold]Subdomain Enumeration[/]     — DNS bruteforce (310 or 52K wordlist)
  [bold green]2[/] 📜  [bold]Certificate Transparency[/]  — crt.sh subdomain discovery
  [bold green]3[/] 🔌  [bold]Quick Recon[/]               — Port scan + tech fingerprint + headers
  [bold green]4[/] ⚠️   [bold]Vulnerability Scanner[/]     — SQLi, XSS, Open Redirect, SSTI, CORS
  [bold green]5[/] 📦  [bold]S3 Bucket Scanner[/]         — Check S3/AWS bucket misconfigurations
  [bold green]6[/] 🔗  [bold]GraphQL Scanner[/]           — Introspection, sensitive queries, IDOR
  [bold green]7[/] 📁  [bold]Sensitive File Scanner[/]     — Check for .env, .git, backups, configs
  [bold green]8[/] 🔒  [bold]SSL/TLS Analysis[/]          — Certificate details + cipher info
  [bold green]9[/] 🎯  [bold]Full Scan (All Tools)[/]      — Run everything on a target

  [bold red]0[/] ❌  Exit

[bold yellow]⚠️  LEGAL: Only test targets you are AUTHORIZED to test.
   Unauthorized testing = UU ITE (UU No. 11/2008) violation.[/]
"""

INDONESIAN_TARGETS = """
[bold cyan]Indonesian Bug Bounty Programs:[/]

  🏢 [bold]Tokopedia[/]     — HackerOne    — *.tokopedia.com       — $50-2,000+
  🏢 [bold]Gojek/GoTo[/]   — HackerOne    — *.gojek.com, GoPay    — $100-5,000+
  🏢 [bold]Traveloka[/]    — Bugcrowd     — *.traveloka.com       — $50-1,500+
  🏢 [bold]Bukalapak[/]    — HackerOne    — *.bukalapak.com       — $50-1,000+
  🏢 [bold]Shopee ID[/]    — HackerOne    — *.shopee.co.id        — $100-10,000+
  🏢 [bold]Tokocrypto[/]   — HackerOne    — *.tokocrypto.com      — varies
  🏢 [bold]Grab[/]         — HackerOne    — *.grab.com            — $100-5,000+

  [dim]Register on HackerOne/Bugcrowd BEFORE testing.[/]
"""


async def run_subdomains(domain, use_big=False):
    from subdomains import enumerate_subdomains, display_results, save_results
    results = await enumerate_subdomains(domain, use_big_wordlist=use_big)
    display_results(domain, results)
    save_results(domain, results)


async def run_recon(target):
    from recon import recon_target
    await recon_target(target)


async def run_vulnscan(target):
    from vulnscan import scan_target
    await scan_target(target)


async def run_full_scan(target):
    """Run all tools on a target."""
    console.print(Panel.fit(
        f"[bold red]🎯 FULL SCAN: {target}[/]\n"
        "Running all tools sequentially...",
        title="🔥 Full Bug Bounty Scan",
    ))

    # Step 1: Subdomains
    from subdomains import enumerate_subdomains, display_results, save_results
    domain = target.replace("https://", "").replace("http://", "").split("/")[0]
    console.print("\n[bold]━━━ STEP 1: Subdomain Enumeration ━━━[/]")
    results = await enumerate_subdomains(domain)
    display_results(domain, results)
    save_results(domain, results)

    # Step 2: Quick Recon
    console.print("\n[bold]━━━ STEP 2: Quick Recon ━━━[/]")
    from recon import recon_target
    recon_result = await recon_target(target)

    # Step 3: Vuln Scan
    console.print("\n[bold]━━━ STEP 3: Vulnerability Scan ━━━[/]")
    from vulnscan import scan_target
    vuln_result = await scan_target(target)

    # Summary
    console.print(Panel.fit(
        f"[bold]Scan Complete for {domain}[/]\n\n"
        f"Subdomains: {len(results)} found\n"
        f"Open Ports: {len(recon_result.get('open_ports', []))} found\n"
        f"Vulnerabilities: {len(vuln_result)} found\n\n"
        f"Results saved to ./output/",
        title="📊 Scan Summary",
    ))


async def main():
    console.print(BANNER)

    while True:
        console.print(MENU)

        choice = console.input("[bold yellow]Select tool (0-9): [/]").strip()

        if choice == "0":
            console.print("[dim]Goodbye! 🎯[/]")
            break

        elif choice == "1":
            domain = console.input("[cyan]Target domain: [/]").strip()
            if domain:
                big = console.input("[cyan]Use big wordlist? (52K entries) [y/N]: [/]").strip().lower()
                if big == 'y':
                    await run_subdomains(domain, use_big=True)
                else:
                    await run_subdomains(domain)

        elif choice == "2":
            domain = console.input("[cyan]Target domain: [/]").strip()
            if domain:
                from crtsh import query_crtsh, display_results as crtsh_display, save_results as crtsh_save
                results = await query_crtsh(domain)
                crtsh_display(domain, results)
                crtsh_save(domain, results)

        elif choice == "3":
            console.print(INDONESIAN_TARGETS)
            target = console.input("[cyan]Target URL/domain: [/]").strip()
            if target:
                await run_recon(target)

        elif choice == "4":
            console.print(INDONESIAN_TARGETS)
            target = console.input("[cyan]Target URL (with params for SQLi/XSS): [/]").strip()
            if target:
                await run_vulnscan(target)

        elif choice == "5":
            target = console.input("[cyan]S3 bucket name or URL: [/]").strip()
            if target:
                from s3scanner import scan_bucket, display_results as s3_display
                result = await scan_bucket(target)
                s3_display([result])

        elif choice == "6":
            target = console.input("[cyan]Target URL with GraphQL endpoint: [/]").strip()
            if target:
                from graphql_scan import scan_graphql
                await scan_graphql(target)

        elif choice == "7":
            target = console.input("[cyan]Target URL: [/]").strip()
            if target:
                from vulnscan import scan_sensitive_paths, display_findings, save_findings
                import aiohttp
                if not target.startswith("http"):
                    target = f"https://{target}"
                connector = aiohttp.TCPConnector(limit=10)
                async with aiohttp.ClientSession(connector=connector) as session:
                    findings = await scan_sensitive_paths(session, target)
                    display_findings(findings)
                    if findings:
                        save_findings(findings)

        elif choice == "8":
            domain = console.input("[cyan]Target domain: [/]").strip()
            if domain:
                from recon import check_ssl, display_ssl
                ssl_info = await check_ssl(domain)
                display_ssl(ssl_info)

        elif choice == "9":
            console.print(INDONESIAN_TARGETS)
            target = console.input("[cyan]Target URL/domain: [/]").strip()
            if target:
                await run_full_scan(target)

        else:
            console.print("[red]Invalid choice[/]")

        console.input("\n[dim]Press Enter to continue...[/]")


if __name__ == "__main__":
    asyncio.run(main())
