#!/usr/bin/env python3
"""
GraphQL Endpoint Scanner
Detects GraphQL endpoints, runs introspection, enumerates types/queries/mutations,
checks for sensitive queries, and tests for IDOR vulnerabilities.
"""

import asyncio
import json
import sys
import time
from typing import Any
from urllib.parse import urljoin

import aiohttp
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()

GRAPHQL_PATHS = ["/graphql", "/gql", "/v1/graphql", "/query", "/api/graphql"]

INTROSPECTION_QUERY = """{__schema{queryType{name}mutationType{name}subscriptionType{name}types{name kind fields{name type{name kind ofType{name kind}}}}directives{name locations args{name type{name}}}}}"""

SIMPLE_INTROSPECTION = """{__schema{types{name fields{name type{name}}}}}"""

SENSITIVE_KEYWORDS = [
    "users", "admin", "internal", "user", "me", "profile",
    "password", "secret", "token", "credentials", "email",
    "accounts", "settings", "config", "debug", "private",
]

SENSITIVE_TYPE_NAMES = [
    "User", "Admin", "Account", "Profile", "Credential",
    "Token", "Session", "Internal", "Secret", "Config",
]

IDOR_TEST_QUERIES = [
    ('query GetUser($id: ID!) { user(id: $id) { id email name } }', {"id": "1"}),
    ('query GetUser($id: ID!) { user(id: $id) { id email name } }', {"id": "2"}),
    ('query GetUser($id: ID!) { user(id: $id) { id email name } }', {"id": "99999"}),
    ('{ user(id: 1) { id email name role } }', None),
    ('{ users(first: 5) { edges { node { id email } } } }', None),
    ('{ me { id email role } }', None),
    ('{ admin { users { id email role } } }', None),
]


class GraphQLScanner:
    def __init__(self, target: str, timeout: int = 10, proxy: str | None = None):
        self.target = target.rstrip("/")
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.proxy = proxy
        self.results: dict[str, Any] = {
            "target": self.target,
            "scan_time": None,
            "endpoints_found": [],
            "introspection": None,
            "types": [],
            "queries": [],
            "mutations": [],
            "sensitive_queries": [],
            "sensitive_types": [],
            "idor_results": [],
            "vulnerabilities": [],
        }

    async def detect_endpoints(self, session: aiohttp.ClientSession) -> list[str]:
        found = []
        console.print("\n[bold cyan][*] Detecting GraphQL endpoints...[/]")
        for path in GRAPHQL_PATHS:
            url = urljoin(self.target, path)
            try:
                async with session.post(
                    url,
                    json={"query": "{__typename}"},
                    timeout=self.timeout,
                    proxy=self.proxy,
                    ssl=False,
                ) as resp:
                    body = await resp.text()
                    if resp.status == 200 and ("__typename" in body or "data" in body):
                        console.print(f"  [green][+] Found: {url}[/]")
                        found.append(url)
                    elif resp.status in (200, 400, 405) and any(
                        kw in body.lower() for kw in ["graphql", "query", "mutation", "syntax"]
                    ):
                        console.print(f"  [yellow][?] Possible: {url} (status={resp.status})[/]")
                        found.append(url)
            except Exception:
                pass
        if not found:
            console.print("  [red][-] No GraphQL endpoints found[/]")
        return found

    async def run_introspection(self, session: aiohttp.ClientSession, endpoint: str) -> dict | None:
        console.print("\n[bold cyan][*] Running introspection query...[/]")
        for query in [INTROSPECTION_QUERY, SIMPLE_INTROSPECTION]:
            try:
                async with session.post(
                    endpoint,
                    json={"query": query},
                    timeout=self.timeout,
                    proxy=self.proxy,
                    ssl=False,
                ) as resp:
                    data = await resp.json()
                    if "data" in data and "__schema" in data.get("data", {}):
                        console.print("  [green][+] Introspection enabled![/]")
                        return data["data"]["__schema"]
            except Exception:
                continue
        console.print("  [red][-] Introspection disabled or failed[/]")
        return None

    def parse_schema(self, schema: dict) -> None:
        console.print("\n[bold cyan][*] Parsing schema...[/]")
        types = schema.get("types", [])

        # Extract user-defined types (skip built-in scalars/introspection types)
        builtin = {
            "String", "Int", "Float", "Boolean", "ID",
            "__Schema", "__Type", "__Field", "__InputValue",
            "__EnumValue", "__Directive", "__DirectiveLocation",
            "__TypeKind", "Query", "Mutation", "Subscription",
        }

        for t in types:
            name = t.get("name", "")
            if name.startswith("__") or name in builtin:
                continue
            fields = [f.get("name", "") for f in (t.get("fields") or [])]
            self.results["types"].append({"name": name, "kind": t.get("kind"), "fields": fields})

            if any(kw in name.lower() for kw in SENSITIVE_TYPE_NAMES):
                self.results["sensitive_types"].append(name)

        # Extract queries
        query_type_name = (schema.get("queryType") or {}).get("name", "Query")
        for t in types:
            if t.get("name") == query_type_name:
                for f in (t.get("fields") or []):
                    self.results["queries"].append(f.get("name", ""))

        # Extract mutations
        mutation_type_name = (schema.get("mutationType") or {}).get("name", "Mutation")
        for t in types:
            if t.get("name") == mutation_type_name:
                for f in (t.get("fields") or []):
                    self.results["mutations"].append(f.get("name", ""))

        # Find sensitive queries/mutations
        all_ops = set(self.results["queries"] + self.results["mutations"])
        for op in all_ops:
            for kw in SENSITIVE_KEYWORDS:
                if kw in op.lower():
                    self.results["sensitive_queries"].append(op)
                    break

        console.print(f"  [+] Types: {len(self.results['types'])}")
        console.print(f"  [+] Queries: {len(self.results['queries'])}")
        console.print(f"  [+] Mutations: {len(self.results['mutations'])}")
        console.print(f"  [!] Sensitive queries: {len(self.results['sensitive_queries'])}")

    async def test_idor(self, session: aiohttp.ClientSession, endpoint: str) -> None:
        console.print("\n[bold cyan][*] Testing for IDOR via GraphQL...[/]")
        for query_str, variables in IDOR_TEST_QUERIES:
            entry: dict[str, Any] = {"query": query_str, "variables": variables}
            try:
                payload: dict[str, Any] = {"query": query_str}
                if variables:
                    payload["variables"] = variables
                async with session.post(
                    endpoint,
                    json=payload,
                    timeout=self.timeout,
                    proxy=self.proxy,
                    ssl=False,
                ) as resp:
                    body = await resp.json()
                    has_data = "data" in body and body["data"] is not None
                    has_errors = "errors" in body
                    if has_data:
                        data_str = json.dumps(body["data"])
                        if data_str != "null" and data_str != "{}":
                            console.print(f"  [yellow][!] Got data response for: {query_str[:60]}...[/]")
                            entry["result"] = "data_returned"
                            entry["response_data"] = body["data"]
                            self.results["idor_results"].append(entry)
                        elif has_errors:
                            entry["result"] = "errors_only"
                            entry["errors"] = body.get("errors")
                            self.results["idor_results"].append(entry)
                    elif has_errors:
                        entry["result"] = "errors_only"
                        entry["errors"] = body.get("errors")
                        self.results["idor_results"].append(entry)
            except Exception as e:
                entry["result"] = "error"
                entry["error"] = str(e)
                self.results["idor_results"].append(entry)

    def check_vulnerabilities(self) -> None:
        console.print("\n[bold cyan][*] Analyzing vulnerabilities...[/]")
        if self.results["introspection"]:
            self.results["vulnerabilities"].append({
                "type": "introspection_enabled",
                "severity": "medium",
                "detail": "GraphQL introspection is enabled, exposing full schema.",
            })
        if self.results["sensitive_queries"]:
            self.results["vulnerabilities"].append({
                "type": "sensitive_queries_exposed",
                "severity": "high",
                "detail": f"Sensitive queries found: {', '.join(self.results['sensitive_queries'])}",
            })
        if self.results["sensitive_types"]:
            self.results["vulnerabilities"].append({
                "type": "sensitive_types_exposed",
                "severity": "medium",
                "detail": f"Sensitive types found: {', '.join(self.results['sensitive_types'])}",
            })
        data_leaks = [r for r in self.results["idor_results"] if r.get("result") == "data_returned"]
        if data_leaks:
            self.results["vulnerabilities"].append({
                "type": "potential_idor",
                "severity": "high",
                "detail": f"IDOR: {len(data_leaks)} queries returned data that may indicate insecure direct object references.",
            })

        for vuln in self.results["vulnerabilities"]:
            color = {"high": "red", "medium": "yellow", "low": "dim"}.get(vuln["severity"], "white")
            console.print(f"  [{color}][!] {vuln['severity'].upper()}: {vuln['type']} - {vuln['detail']}[/]")

    def display_summary(self) -> None:
        # Queries table
        if self.results["queries"]:
            table = Table(title="Queries")
            table.add_column("Name", style="cyan")
            for q in self.results["queries"]:
                sensitive = " [red bold]*SENSITIVE*[/]" if q in self.results["sensitive_queries"] else ""
                table.add_row(q + sensitive)
            console.print(table)

        # Mutations table
        if self.results["mutations"]:
            table = Table(title="Mutations")
            table.add_column("Name", style="magenta")
            for m in self.results["mutations"]:
                sensitive = " [red bold]*SENSITIVE*[/]" if m in self.results["sensitive_queries"] else ""
                table.add_row(m + sensitive)
            console.print(table)

        # Vulnerabilities panel
        if self.results["vulnerabilities"]:
            lines = []
            for v in self.results["vulnerabilities"]:
                lines.append(f"[{v['severity'].upper()}] {v['type']}: {v['detail']}")
            console.print(Panel("\n".join(lines), title="Vulnerabilities", border_style="red"))

    async def scan(self) -> dict:
        start = time.time()
        console.print(Panel(f"[bold]GraphQL Scanner[/]\nTarget: {self.target}", border_style="blue"))

        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            endpoints = await self.detect_endpoints(session)
            self.results["endpoints_found"] = endpoints

            for endpoint in endpoints:
                schema = await self.run_introspection(session, endpoint)
                if schema:
                    self.results["introspection"] = schema
                    self.parse_schema(schema)

                await self.test_idor(session, endpoint)

        self.check_vulnerabilities()
        self.display_summary()
        self.results["scan_time"] = round(time.time() - start, 2)
        return self.results


async def main():
    import argparse
    parser = argparse.ArgumentParser(description="GraphQL Endpoint Scanner")
    parser.add_argument("target", help="Target base URL (e.g. https://example.com)")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds")
    parser.add_argument("--proxy", default=None, help="HTTP proxy URL")
    parser.add_argument("-o", "--output", default=None, help="Output JSON file path")
    args = parser.parse_args()

    scanner = GraphQLScanner(args.target, timeout=args.timeout, proxy=args.proxy)
    results = await scanner.scan()

    output_path = args.output or f"graphql_scan_{args.target.replace('://', '_').replace('/', '_')}.json"
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2, default=str)
    console.print(f"\n[bold green][+] Results saved to {output_path}[/]")


if __name__ == "__main__":
    asyncio.run(main())
