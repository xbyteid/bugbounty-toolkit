#!/usr/bin/env python3
"""S3 Bucket Misconfiguration Scanner."""

import asyncio
import json
import sys
import argparse
import xml.etree.ElementTree as ET
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field, asdict

import aiohttp
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()

SENSITIVE_EXTENSIONS = {".env", ".config", ".sql", ".bak", ".key", ".pem", ".p12", ".pfx", ".jks"}

# S3 XML namespace
S3_NS = "{http://s3.amazonaws.com/doc/2006-03-01/}"


@dataclass
class BucketResult:
    name: str
    url: str
    exists: bool = False
    listing_enabled: bool = False
    public_write: bool = False
    acl_public: bool = False
    objects: List[Dict[str, str]] = field(default_factory=list)
    sensitive_files: List[str] = field(default_factory=list)
    total_objects: int = 0
    errors: List[str] = field(default_factory=list)


async def check_bucket_exists(session: aiohttp.ClientSession, bucket: str) -> tuple[bool, str]:
    """Check if bucket exists by hitting its root URL."""
    url = f"https://{bucket}.s3.amazonaws.com/"
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
            body = await resp.text()
            if resp.status == 200:
                return True, body
            elif resp.status == 404:
                return False, ""
            elif resp.status == 403:
                # Bucket exists but access denied
                return True, ""
            else:
                return False, ""
    except Exception:
        return False, ""


async def check_listing(session: aiohttp.ClientSession, bucket: str) -> tuple[bool, List[Dict[str, str]], str]:
    """Check if bucket listing is enabled and enumerate contents."""
    url = f"https://{bucket}.s3.amazonaws.com/"
    objects = []
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
            body = await resp.text()
            if resp.status != 200:
                return False, [], ""
            # Try to parse as S3 listing XML
            try:
                root = ET.fromstring(body)
                # Check if it's a ListBucketResult
                is_listing = root.tag == f"{S3_NS}ListBucketResult" or "ListBucketResult" in root.tag
                if not is_listing:
                    # Check for html response (not listing)
                    if "<html" in body.lower()[:500]:
                        return False, [], ""
                    return False, [], ""

                for contents in root.findall(f".//{S3_NS}Contents"):
                    key = contents.findtext(f"{S3_NS}Key", "")
                    size = contents.findtext(f"{S3_NS}Size", "0")
                    if key:
                        objects.append({"key": key, "size": size})
                return True, objects, body
            except ET.ParseError:
                return False, [], ""
    except Exception:
        return False, [], ""


async def check_public_write(session: aiohttp.ClientSession, bucket: str) -> bool:
    """Check if public write is allowed by attempting a PUT request."""
    url = f"https://{bucket}.s3.amazonaws.com/__bugbounty_write_test_{bucket}"
    try:
        async with session.put(url, data=b"test", timeout=aiohttp.ClientTimeout(total=15)) as resp:
            # 200 or 201 means write succeeded -> public write
            # 403 means denied
            if resp.status in (200, 201):
                # Try to clean up
                try:
                    await session.delete(url)
                except Exception:
                    pass
                return True
            return False
    except Exception:
        return False


async def check_acl(session: aiohttp.ClientSession, bucket: str) -> tuple[bool, str]:
    """Check bucket ACL for public access."""
    url = f"https://{bucket}.s3.amazonaws.com/?acl"
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
            body = await resp.text()
            if resp.status != 200:
                return False, ""
            # Look for AllUsers or AuthenticatedUsers grants
            if "AllUsers" in body or "http://acs.amazonaws.com/groups/global/AllUsers" in body:
                return True, body
            return False, body
    except Exception:
        return False, ""


def detect_sensitive(objects: List[Dict[str, str]]) -> List[str]:
    """Find sensitive files in bucket objects."""
    sensitive = []
    for obj in objects:
        key = obj["key"].lower()
        for ext in SENSITIVE_EXTENSIONS:
            if key.endswith(ext):
                sensitive.append(obj["key"])
                break
    return sensitive


async def scan_bucket(session: aiohttp.ClientSession, bucket: str) -> BucketResult:
    """Run all checks against a single bucket."""
    result = BucketResult(name=bucket, url=f"https://{bucket}.s3.amazonaws.com/")

    # Step 1: Check existence
    exists, _ = await check_bucket_exists(session, bucket)
    result.exists = exists
    if not exists:
        result.errors.append("Bucket does not exist or is not accessible")
        return result

    # Step 2: Check listing
    listing_enabled, objects, _ = await check_listing(session, bucket)
    result.listing_enabled = listing_enabled
    result.objects = objects
    result.total_objects = len(objects)

    # Step 3: Detect sensitive files
    if objects:
        result.sensitive_files = detect_sensitive(objects)

    # Step 4: Check ACL
    acl_public, _ = await check_acl(session, bucket)
    result.acl_public = acl_public

    # Step 5: Check public write (only if listing or ACL indicate openness)
    if listing_enabled or acl_public:
        result.public_write = await check_public_write(session, bucket)

    return result


async def scan_buckets(buckets: List[str], output_file: str = None, json_output: bool = False, concurrency: int = 10):
    """Scan multiple buckets."""
    console.print(Panel(f"[bold cyan]S3 Bucket Misconfiguration Scanner[/bold cyan]\nBuckets: [bold]{len(buckets)}[/bold]", border_style="cyan"))

    sem = asyncio.Semaphore(concurrency)
    results: List[BucketResult] = []

    async def _scan(bucket: str):
        async with sem:
            return await scan_bucket(session, bucket)

    async with aiohttp.ClientSession() as session:
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
            task = progress.add_task(f"Scanning {len(buckets)} buckets...", total=len(buckets))
            tasks = []
            for b in buckets:
                tasks.append(_scan(b))
            for coro in asyncio.as_completed(tasks):
                r = await coro
                results.append(r)
                progress.advance(task)

    # Sort by name
    results.sort(key=lambda x: x.name)

    # Display results
    vuln_count = 0
    for r in results:
        is_vuln = r.listing_enabled or r.public_write or r.acl_public
        if is_vuln:
            vuln_count += 1
        if json_output:
            continue

        status = "[red]VULNERABLE[/red]" if is_vuln else "[green]OK[/green]"
        if not r.exists:
            status = "[dim]NOT FOUND[/dim]"

        panel_lines = [f"URL: {r.url}"]
        panel_lines.append(f"Exists: {r.exists}")
        if r.exists:
            panel_lines.append(f"Listing: {'[red]YES[/red]' if r.listing_enabled else '[green]No[/green]'}")
            panel_lines.append(f"Public Write: {'[red]YES[/red]' if r.public_write else '[green]No[/green]'}")
            panel_lines.append(f"Public ACL: {'[red]YES[/red]' if r.acl_public else '[green]No[/green]'}")
            panel_lines.append(f"Objects: {r.total_objects}")
            if r.sensitive_files:
                panel_lines.append(f"[red]Sensitive files: {', '.join(r.sensitive_files[:10])}[/red]")
        if r.errors:
            panel_lines.append(f"[yellow]Errors: {'; '.join(r.errors)}[/yellow]")

        border = "red" if is_vuln else "green" if r.exists else "dim"
        console.print(Panel("\n".join(panel_lines), title=f"{r.name} {status}", border_style=border))

    # Summary table
    if not json_output:
        table = Table(title="Scan Summary")
        table.add_column("Bucket", style="cyan")
        table.add_column("Exists")
        table.add_column("Listing")
        table.add_column("Write")
        table.add_column("ACL")
        table.add_column("Sensitive")
        for r in results:
            if not r.exists:
                table.add_row(r.name, "No", "-", "-", "-", "-")
            else:
                table.add_row(
                    r.name,
                    "Yes",
                    "[red]YES[/red]" if r.listing_enabled else "No",
                    "[red]YES[/red]" if r.public_write else "No",
                    "[red]YES[/red]" if r.acl_public else "No",
                    str(len(r.sensitive_files)) if r.sensitive_files else "0",
                )
        console.print(table)

    # JSON output
    json_data = {
        "total_buckets": len(results),
        "vulnerable": vuln_count,
        "results": [asdict(r) for r in results],
    }

    if json_output:
        console.print_json(json.dumps(json_data, indent=2, default=str))

    if output_file:
        with open(output_file, "w") as f:
            json.dump(json_data, f, indent=2, default=str)
        console.print(f"\n[green]Results saved to {output_file}[/green]")

    console.print(f"\n[bold]Summary: {len(results)} scanned, [red]{vuln_count} vulnerable[/red][/bold]")


def main():
    parser = argparse.ArgumentParser(description="S3 Bucket Misconfiguration Scanner")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-b", "--bucket", help="Single bucket name to scan")
    group.add_argument("-f", "--file", help="File with bucket names (one per line)")
    parser.add_argument("-o", "--output", help="JSON output file")
    parser.add_argument("-j", "--json", action="store_true", help="JSON output to console")
    parser.add_argument("-c", "--concurrency", type=int, default=10, help="Max concurrent requests (default: 10)")
    args = parser.parse_args()

    buckets = []
    if args.bucket:
        buckets = [args.bucket.strip()]
    elif args.file:
        with open(args.file) as f:
            buckets = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    if not buckets:
        console.print("[red]No buckets specified[/red]")
        sys.exit(1)

    asyncio.run(scan_buckets(buckets, output_file=args.output, json_output=args.json, concurrency=args.concurrency))


if __name__ == "__main__":
    main()
