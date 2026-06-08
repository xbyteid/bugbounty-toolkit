#!/usr/bin/env python3
"""
API Scope Escalation Scanner
==============================
Scans API endpoints to identify access control misconfigurations where
an auth token provides access beyond its intended scopes.

Features:
- Tests endpoints against expected scopes
- HTTP method variation testing (GET/POST/PUT/DELETE)
- Pre-loaded Shopify Admin API scope map
- Custom endpoint/scope lists via file
- JSON export

Part of the Bug Bounty Toolkit v5.0

Usage:
    python3 scope_scanner.py --base-url https://api.example.com --token eyJhbG... --endpoints endpoints.json
    python3 scope_scanner.py --base-url https://api.myshopify.com/admin/api/2024-01 --token shpat_xxx --preset shopify
"""

import argparse
import json
import os
import sys
import time
from typing import Dict, List, Optional

try:
    import requests
    from colorama import init, Fore, Style
    init(autoreset=True)
except ImportError:
    print("Install dependencies: pip install requests colorama")
    sys.exit(1)

BANNER = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗
║     ╔═╗╔═╗╔═╗  ╔═╗╔═╗╔═╗╔╗╔╔╦╗╔═╗╔═╗╔╦╗                   ║
║     ╚═╗║  ║ ║  ║  ║ ║║ ╦║║║ ║ ║╣ ║   ║                     ║
║     ╚═╝╚═╝╚═╝  ╚═╝╚═╝╚═╝╝╚╝ ╩ ╚═╝╚═╝ ╩                   ║
║     Escalation Scanner v5.0                                  ║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""

# ─────────────────────────────────────────────────────────────
# Shopify Admin API scope map (pre-loaded)
# Format: { "METHOD /path": "required_scope" }
# ─────────────────────────────────────────────────────────────
SHOPIFY_SCOPE_MAP = {
    # Products
    "GET /products.json": "read_products",
    "POST /products.json": "write_products",
    "PUT /products/{id}.json": "write_products",
    "DELETE /products/{id}.json": "write_products",
    "GET /products/{id}.json": "read_products",

    # Orders
    "GET /orders.json": "read_orders",
    "POST /orders.json": "write_orders",
    "PUT /orders/{id}.json": "write_orders",
    "DELETE /orders/{id}.json": "write_orders",
    "GET /orders/{id}.json": "read_orders",
    "GET /orders/{id}/transactions.json": "read_orders",

    # Customers
    "GET /customers.json": "read_customers",
    "POST /customers.json": "write_customers",
    "PUT /customers/{id}.json": "write_customers",
    "DELETE /customers/{id}.json": "write_customers",
    "GET /customers/{id}.json": "read_customers",
    "GET /customers/search.json": "read_customers",

    # Script Tags
    "GET /script_tags.json": "read_script_tags",
    "POST /script_tags.json": "write_script_tags",
    "PUT /script_tags/{id}.json": "write_script_tags",
    "DELETE /script_tags/{id}.json": "write_script_tags",

    # Themes
    "GET /themes.json": "read_themes",
    "POST /themes.json": "write_themes",
    "PUT /themes/{id}.json": "write_themes",
    "DELETE /themes/{id}.json": "write_themes",
    "GET /themes/{id}.json": "read_themes",
    "GET /themes/{id}/assets.json": "read_themes",
    "PUT /themes/{id}/assets.json": "write_themes",

    # Shop
    "GET /shop.json": "read_content",

    # Price Rules
    "GET /price_rules.json": "read_price_rules",
    "POST /price_rules.json": "write_price_rules",
    "PUT /price_rules/{id}.json": "write_price_rules",
    "DELETE /price_rules/{id}.json": "write_price_rules",
    "GET /price_rules/{id}.json": "read_price_rules",
    "GET /price_rules/{id}/discount_codes.json": "read_price_rules",
    "POST /price_rules/{id}/discount_codes.json": "write_price_rules",

    # Inventory
    "GET /inventory_levels.json": "read_inventory",
    "POST /inventory_levels/adjust.json": "write_inventory",
    "GET /inventory_items/{id}.json": "read_inventory",
    "PUT /inventory_items/{id}.json": "write_inventory",

    # Fulfillments
    "GET /orders/{id}/fulfillments.json": "read_fulfillments",
    "POST /orders/{id}/fulfillments.json": "write_fulfillments",
    "GET /fulfillments/{id}.json": "read_fulfillments",
    "POST /fulfillments/{id}/events.json": "write_fulfillments",

    # Webhooks
    "GET /webhooks.json": "read_script_tags",
    "POST /webhooks.json": "write_script_tags",
    "PUT /webhooks/{id}.json": "write_script_tags",
    "DELETE /webhooks/{id}.json": "write_script_tags",

    # GraphQL
    "POST /graphql.json": "graphql",

    # Collects
    "GET /collects.json": "read_products",
    "POST /collects.json": "write_products",
    "DELETE /collects/{id}.json": "write_products",

    # Metafields
    "GET /metafields.json": "read_content",
    "POST /metafields.json": "write_content",
    "PUT /metafields/{id}.json": "write_content",
    "DELETE /metafields/{id}.json": "write_content",

    # Draft Orders
    "GET /draft_orders.json": "read_draft_orders",
    "POST /draft_orders.json": "write_draft_orders",
    "PUT /draft_orders/{id}.json": "write_draft_orders",
    "DELETE /draft_orders/{id}.json": "write_draft_orders",

    # Gift Cards
    "GET /gift_cards.json": "read_gift_cards",
    "POST /gift_cards.json": "write_gift_cards",
    "PUT /gift_cards/{id}.json": "write_gift_cards",
    "GET /gift_cards/{id}.json": "read_gift_cards",

    # Carrier Service
    "GET /carrier_services.json": "read_shipping",
    "POST /carrier_services.json": "write_shipping",
    "PUT /carrier_services/{id}.json": "write_shipping",
    "DELETE /carrier_services/{id}.json": "write_shipping",

    # Files (GraphQL)
    "POST /graphql.json#files": "write_content",

    # Payouts (Shopify Payments)
    "GET /shopify_payments/payouts.json": "read_shopify_payments",

    # Transactions
    "GET /transactions.json": "read_orders",
    "POST /orders/{id}/transactions.json": "write_orders",
}

PRESETS = {
    "shopify": SHOPIFY_SCOPE_MAP,
}


class ScopeScanner:
    """API Scope Escalation Scanner."""

    def __init__(self, base_url: str, token: str, scope_map: dict = None,
                 token_header: str = "Authorization", token_prefix: str = "Bearer",
                 methods_filter: list = None, verbose: bool = False):
        self.base_url = base_url.rstrip('/')
        self.token = token
        self.scope_map = scope_map or {}
        self.token_header = token_header
        self.token_prefix = token_prefix
        self.methods_filter = methods_filter or ["GET", "POST", "PUT", "DELETE"]
        self.verbose = verbose
        self.session = requests.Session()

        # Set auth header
        if token_prefix:
            self.session.headers[token_header] = f"{token_prefix} {token}"
        else:
            self.session.headers[token_header] = token

        self.session.headers["User-Agent"] = "ScopeScanner/5.0"
        self.session.verify = True
        self.results = []

    def _log(self, level: str, message: str):
        """Log a message."""
        print(f"  {level} {message}")

    def _test_endpoint(self, method: str, path: str, expected_scope: str) -> dict:
        """Test a single endpoint with given method."""
        url = f"{self.base_url}{path}"

        # Skip path parameters for actual requests
        if "{" in path:
            return {
                "method": method,
                "path": path,
                "url": url,
                "expected_scope": expected_scope,
                "status": "SKIPPED",
                "http_status": None,
                "note": "Contains path parameters - manual testing needed",
            }

        try:
            resp = self.session.request(method, url, timeout=15, allow_redirects=False)
        except requests.exceptions.RequestException as e:
            return {
                "method": method,
                "path": path,
                "url": url,
                "expected_scope": expected_scope,
                "status": "ERROR",
                "http_status": None,
                "note": str(e)[:200],
            }

        result = {
            "method": method,
            "path": path,
            "url": url,
            "expected_scope": expected_scope,
            "http_status": resp.status_code,
            "response_size": len(resp.content),
        }

        # Determine if accessible
        if resp.status_code in (200, 201, 204):
            result["status"] = "ACCESSIBLE"
            result["note"] = "Endpoint returned success response"
        elif resp.status_code in (301, 302):
            result["status"] = "REDIRECT"
            result["note"] = f"Redirect to: {resp.headers.get('Location', 'N/A')[:150]}"
        elif resp.status_code == 401:
            result["status"] = "UNAUTHORIZED"
            result["note"] = "Token not accepted or missing"
        elif resp.status_code == 403:
            result["status"] = "FORBIDDEN"
            result["note"] = "Token valid but scope insufficient"
        elif resp.status_code == 404:
            result["status"] = "NOT_FOUND"
            result["note"] = "Endpoint does not exist"
        elif resp.status_code == 405:
            result["status"] = "METHOD_NOT_ALLOWED"
            result["note"] = "Method not supported"
        elif resp.status_code == 429:
            result["status"] = "RATE_LIMITED"
            result["note"] = "Rate limited"
        else:
            result["status"] = "OTHER"
            result["note"] = f"HTTP {resp.status_code}: {resp.text[:150]}"

        return result

    def scan(self):
        """Run the scope escalation scan."""
        print(BANNER)
        print(f"  {Fore.WHITE}Target: {self.base_url}")
        print(f"  Token: {self.token[:20]}...{self.token[-6:]}")
        print(f"  Endpoints: {len(self.scope_map)}")
        print(f"  Methods: {', '.join(self.methods_filter)}")
        print(f"  {'='*56}{Style.RESET_ALL}\n")

        if not self.scope_map:
            self._log(Fore.RED + "[ERROR]" + Style.RESET_ALL, "No endpoints to scan. Use --preset or --endpoints.")
            return

        total = len(self.scope_map)
        current = 0

        for endpoint_key, expected_scope in self.scope_map.items():
            # Parse "METHOD /path" format
            parts = endpoint_key.split(" ", 1)
            if len(parts) != 2:
                continue

            method, path = parts[0].upper(), parts[1]

            # Skip methods not in filter
            if method not in self.methods_filter:
                continue

            current += 1
            status_icon = {
                "ACCESSIBLE": Fore.GREEN + "✓" + Style.RESET_ALL,
                "FORBIDDEN": Fore.RED + "✗" + Style.RESET_ALL,
                "UNAUTHORIZED": Fore.YELLOW + "⚠" + Style.RESET_ALL,
                "NOT_FOUND": Fore.BLUE + "?" + Style.RESET_ALL,
                "METHOD_NOT_ALLOWED": Fore.MAGENTA + "⊘" + Style.RESET_ALL,
                "SKIPPED": Fore.YELLOW + "⊘" + Style.RESET_ALL,
                "ERROR": Fore.RED + "!" + Style.RESET_ALL,
                "REDIRECT": Fore.CYAN + "→" + Style.RESET_ALL,
                "OTHER": Fore.WHITE + "?" + Style.RESET_ALL,
            }

            result = self._test_endpoint(method, path, expected_scope)
            self.results.append(result)

            icon = status_icon.get(result["status"], "?")

            # Highlight potential scope escalation
            is_escalation = (result["status"] == "ACCESSIBLE" and
                           expected_scope not in ("read_products", "read_content", "graphql"))

            line = f"  [{current}/{total}] {icon} {method:6s} {path:45s} scope={expected_scope:25s} HTTP {result.get('http_status', 'N/A')}"
            if is_escalation:
                line += f" {Fore.RED}← CHECK SCOPE{Style.RESET_ALL}"
            print(line)

            if self.verbose and result.get("note"):
                print(f"           {Fore.YELLOW}↳ {result['note']}{Style.RESET_ALL}")

        self._print_summary()

    def _print_summary(self):
        """Print scan results summary."""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"  SCAN RESULTS SUMMARY")
        print(f"{'='*60}{Style.RESET_ALL}")

        accessible = [r for r in self.results if r["status"] == "ACCESSIBLE"]
        forbidden = [r for r in self.results if r["status"] == "FORBIDDEN"]
        not_found = [r for r in self.results if r["status"] == "NOT_FOUND"]
        skipped = [r for r in self.results if r["status"] == "SKIPPED"]
        errors = [r for r in self.results if r["status"] == "ERROR"]

        total_tested = len(self.results)
        print(f"  Total endpoints tested: {total_tested}")
        print(f"  {Fore.GREEN}Accessible: {len(accessible)}{Style.RESET_ALL}")
        print(f"  {Fore.RED}Forbidden (scope blocked): {len(forbidden)}{Style.RESET_ALL}")
        print(f"  {Fore.BLUE}Not Found: {len(not_found)}{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}Skipped: {len(skipped)}{Style.RESET_ALL}")
        print(f"  {Fore.RED}Errors: {len(errors)}{Style.RESET_ALL}")

        # Group accessible by expected scope
        if accessible:
            print(f"\n  {Fore.GREEN}{'='*56}")
            print(f"  ACCESSIBLE ENDPOINTS (may indicate scope escalation)")
            print(f"  {'='*56}{Style.RESET_ALL}")

            # Group by scope
            scope_groups = {}
            for r in accessible:
                scope = r["expected_scope"]
                if scope not in scope_groups:
                    scope_groups[scope] = []
                scope_groups[scope].append(r)

            for scope, endpoints in sorted(scope_groups.items()):
                print(f"\n  {Fore.YELLOW}Scope: {scope}{Style.RESET_ALL}")
                for ep in endpoints:
                    print(f"    {Fore.GREEN}✓{Style.RESET_ALL} {ep['method']:6s} {ep['path']:50s} HTTP {ep.get('http_status', 'N/A')}")

        # Identify potential escalation: accessible endpoints with write/admin scopes
        write_endpoints = [r for r in accessible
                         if any(w in r["expected_scope"] for w in ["write", "admin", "delete", "manage"])]
        if write_endpoints:
            print(f"\n  {Fore.RED}{'='*56}")
            print(f"  ⚠ POTENTIAL SCOPE ESCALATION ({len(write_endpoints)} write/admin endpoints accessible)")
            print(f"  {'='*56}{Style.RESET_ALL}")
            for ep in write_endpoints:
                print(f"    {Fore.RED}⚠{Style.RESET_ALL} {ep['method']:6s} {ep['path']:50s} scope={ep['expected_scope']}")

    def export_json(self, output_path: str = None) -> str:
        """Export results as JSON."""
        accessible = [r for r in self.results if r["status"] == "ACCESSIBLE"]
        write_accessible = [r for r in accessible
                          if any(w in r["expected_scope"] for w in ["write", "admin", "delete", "manage"])]

        report = {
            "tool": "scope_scanner",
            "version": "5.0",
            "target": self.base_url,
            "scan_time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "total_endpoints": len(self.results),
            "accessible_count": len(accessible),
            "forbidden_count": sum(1 for r in self.results if r["status"] == "FORBIDDEN"),
            "potential_escalations": len(write_accessible),
            "escalation_details": [
                {"method": r["method"], "path": r["path"], "expected_scope": r["expected_scope"]}
                for r in write_accessible
            ],
            "results": self.results,
        }
        json_str = json.dumps(report, indent=2)
        if output_path:
            with open(output_path, "w") as f:
                f.write(json_str)
        return json_str


def load_endpoints_file(filepath: str) -> dict:
    """Load endpoint/scope map from JSON file.

    Expected format:
    {
        "GET /path": "required_scope",
        "POST /path": "required_scope"
    }
    or:
    [
        {"method": "GET", "path": "/path", "scope": "read_scope"},
        ...
    ]
    """
    with open(filepath, "r") as f:
        data = json.load(f)

    if isinstance(data, dict):
        return data
    elif isinstance(data, list):
        result = {}
        for item in data:
            method = item.get("method", "GET").upper()
            path = item.get("path", "/")
            scope = item.get("scope", "unknown")
            result[f"{method} {path}"] = scope
        return result
    else:
        raise ValueError("Invalid endpoint file format. Use dict or list format.")


def main():
    parser = argparse.ArgumentParser(
        description="API Scope Escalation Scanner - Tests for endpoints accessible beyond expected auth scopes",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --base-url https://api.example.com/v1 --token eyJhbG... --endpoints endpoints.json
  %(prog)s --base-url https://api.myshopify.com/admin/api/2024-01 --token shpat_xxx --preset shopify
  %(prog)s --base-url https://api.example.com --token mytoken --endpoints endpoints.json --methods GET POST --output json

Endpoint file format (JSON):
  {
    "GET /users": "read_users",
    "POST /users": "write_users",
    "DELETE /users/{id}": "admin"
  }
        """
    )
    parser.add_argument("--base-url", required=True, help="API base URL")
    parser.add_argument("--token", required=True, help="Auth token for API requests")
    parser.add_argument("--endpoints", help="JSON file with endpoint/scope pairs")
    parser.add_argument("--preset", choices=list(PRESETS.keys()),
                        help="Use pre-loaded endpoint set (e.g., shopify)")
    parser.add_argument("--token-header", default="Authorization",
                        help="Header name for token (default: Authorization)")
    parser.add_argument("--token-prefix", default="Bearer",
                        help="Token prefix (default: Bearer, use '' for none)")
    parser.add_argument("--methods", nargs="+", default=["GET", "POST", "PUT", "DELETE"],
                        help="HTTP methods to test (default: GET POST PUT DELETE)")
    parser.add_argument("--output", choices=["json", "text"], default="text",
                        help="Output format (default: text)")
    parser.add_argument("--json-file", help="Save JSON output to file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    # Load scope map
    scope_map = {}
    if args.preset:
        scope_map = PRESETS[args.preset].copy()
        print(f"  Loaded preset '{args.preset}': {len(scope_map)} endpoints")

    if args.endpoints:
        custom = load_endpoints_file(args.endpoints)
        scope_map.update(custom)
        print(f"  Loaded from file: {len(custom)} endpoints")

    if not scope_map:
        parser.error("No endpoints specified. Use --preset or --endpoints.")

    scanner = ScopeScanner(
        base_url=args.base_url,
        token=args.token,
        scope_map=scope_map,
        token_header=args.token_header,
        token_prefix=args.token_prefix,
        methods_filter=[m.upper() for m in args.methods],
        verbose=args.verbose,
    )

    scanner.scan()

    if args.output == "json":
        json_output = scanner.export_json(args.json_file)
        print(json_output)
    elif args.json_file:
        scanner.export_json(args.json_file)
        print(f"\n  {Fore.GREEN}JSON results saved to: {args.json_file}{Style.RESET_ALL}")


if __name__ == "__main__":
    main()
