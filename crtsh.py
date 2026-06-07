#!/usr/bin/env python3
"""crt.sh Certificate Transparency log subdomain enumerator."""

import asyncio
import json
import sys
import re
import argparse
from typing import Set, List, Dict, Any
from collections import OrderedDict

import aiohttp
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel

console = Console()

CRTSH_URL = "https://crt.sh/?q=%25.{domain}&output=json"


def deduplicate_and_expand(entries: List[Dict[str, Any]]) -> Set[str]:
    """Extract unique subdomains, expanding wildcards."""
    subdomains: Set[str] = set()
    for entry in entries:
        name = entry.get("name_value", "")
        for line in name.split("\n"):
            line = line.strip().lower()
            if not line:
                continue
            # Expand wildcards: *.example.com -> example.com
            line = line.lstrip("*.")
            # Skip entries with spaces or invalid chars
            if " " in line or not re.match(r"^[a-z0-9._-]+\.[a-z]{2,}$", line):
                continue
            subdomains.add(line)
    return subdomains


async def query_crtsh(domain: str, timeout: int = 30) -> List[Dict[str, Any]]:
    """Query crt.sh for certificate entries."""
    url = CRTSH_URL.format(domain=domain)
    async with aiohttp.ClientSession() as session:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
            if resp.status != 200:
                console.print(f"[red]crt.sh returned HTTP {resp.status}[/red]")
                return []
            text = await resp.text()
            if not text.strip():
                return []
            return json.loads(text)


async def enumerate_subdomains(domain: str, output_file: str = None, json_output: bool = False) -> Set[str]:
    """Main enumeration routine."""
    console.print(Panel(f"[bold cyan]crt.sh Subdomain Enumeration[/bold cyan]\nTarget: [bold]{domain}[/bold]", border_style="cyan"))

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
        task = progress.add_task("Querying crt.sh...", total=None)
        try:
            entries = await query_crtsh(domain)
        except Exception as e:
            console.print(f"[red]Error querying crt.sh: {e}[/red]")
            return set()
        progress.update(task, description=f"Processing {len(entries)} certificate entries...")

        subdomains = deduplicate_and_expand(entries)
        progress.update(task, description="Done!", completed=True)

    # Also add the base domain
    subdomains.add(domain)

    # Sort results
    sorted_subs = sorted(subdomains)

    if json_output:
        result = {
            "domain": domain,
            "total": len(sorted_subs),
            "subdomains": sorted_subs,
        }
        console.print_json(json.dumps(result, indent=2))
    else:
        table = Table(title=f"Subdomains for {domain} ({len(sorted_subs)} found)", show_lines=True)
        table.add_column("#", style="dim", width=6)
        table.add_column("Subdomain", style="green")
        for i, sub in enumerate(sorted_subs, 1):
            table.add_row(str(i), sub)
        console.print(table)

    # Write output file
    if output_file:
        if json_output:
            data = {"domain": domain, "total": len(sorted_subs), "subdomains": sorted_subs}
            with open(output_file, "w") as f:
                json.dump(data, f, indent=2)
        else:
            with open(output_file, "w") as f:
                f.write("\n".join(sorted_subs) + "\n")
        console.print(f"[green]Results saved to {output_file}[/green]")

    console.print(f"\n[bold green]✓ Found {len(sorted_subs)} unique subdomains[/bold green]")
    return subdomains


def main():
    parser = argparse.ArgumentParser(description="crt.sh Certificate Transparency subdomain enumerator")
    parser.add_argument("domain", help="Target domain to enumerate")
    parser.add_argument("-o", "--output", help="Output file path")
    parser.add_argument("-j", "--json", action="store_true", help="Output as JSON")
    parser.add_argument("-t", "--timeout", type=int, default=30, help="HTTP timeout in seconds (default: 30)")
    args = parser.parse_args()

    asyncio.run(enumerate_subdomains(args.domain, output_file=args.output, json_output=args.json))


if __name__ == "__main__":
    main()
