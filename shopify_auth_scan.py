#!/usr/bin/env python3
"""
Shopify Auth Scanner - Comprehensive Token & Scope Testing Tool
================================================================
Tests Shopify API tokens for scope escalation, privilege abuse, IDOR,
and various auth misconfigurations.

Usage:
    python3 shopify_auth_scan.py --token shpat_xxx --shop store.myshopify.com
    python3 shopify_auth_scan.py --token shpat_xxx --shop store.myshopify.com --output json
    python3 shopify_auth_scan.py --token shpat_xxx --shop store.myshopify.com --other-shops shop2.myshopify.com

Author: Bug Bounty Toolkit
License: MIT
"""

import argparse
import json
import sys
import time
import datetime
from typing import Optional

try:
    import requests
except ImportError:
    print("[!] requests library required. Install: pip3 install requests")
    sys.exit(1)


# ─── ANSI Colors ───────────────────────────────────────────────────────────────

class C:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"


# ─── Helpers ───────────────────────────────────────────────────────────────────

def banner():
    print(f"""{C.CYAN}{C.BOLD}
╔══════════════════════════════════════════════════════════════╗
║           Shopify Auth Scanner v1.0                         ║
║           Comprehensive Token & Scope Testing               ║
╚══════════════════════════════════════════════════════════════╝{C.RESET}
""")


def section(title: str):
    print(f"\n{C.BOLD}{C.BLUE}{'─'*60}")
    print(f"  {title}")
    print(f"{'─'*60}{C.RESET}\n")


def finding(severity: str, title: str, detail: str, cvss: str = ""):
    colors = {"CRITICAL": C.RED, "HIGH": C.RED, "MEDIUM": C.YELLOW, "LOW": C.CYAN, "INFO": C.DIM}
    icons = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "ℹ️ "}
    color = colors.get(severity, C.WHITE)
    icon = icons.get(severity, "❓")
    cvss_str = f"  {C.DIM}[CVSS: {cvss}]{C.RESET}" if cvss else ""
    print(f"  {icon} {color}{C.BOLD}[{severity}]{C.RESET} {title}{cvss_str}")
    for line in detail.split("\n"):
        print(f"     {C.DIM}{line}{C.RESET}")


def ok(msg: str):
    print(f"  {C.GREEN}✓{C.RESET} {msg}")


def fail(msg: str):
    print(f"  {C.RED}✗{C.RESET} {msg}")


def info(msg: str):
    print(f"  {C.CYAN}→{C.RESET} {msg}")


# ─── Core API Client ───────────────────────────────────────────────────────────

class ShopifyClient:
    def __init__(self, shop: str, token: str, timeout: int = 30):
        self.shop = shop.rstrip("/")
        if not self.shop.endswith(".myshopify.com"):
            self.shop += ".myshopify.com"
        self.token = token
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "X-Shopify-Access-Token": token,
            "Content-Type": "application/json",
        })
        self.findings = []
        self.cleanup_tasks = []

    def _url(self, path: str, version: str = "2025-01") -> str:
        return f"https://{self.shop}/admin/api/{version}/{path}"

    def _gql_url(self, version: str = "2025-01") -> str:
        return f"https://{self.shop}/admin/api/{version}/graphql.json"

    def rest(self, method: str, path: str, version: str = "2025-01",
             json_data: dict = None, **kwargs) -> requests.Response:
        url = self._url(path, version)
        return self.session.request(method, url, json=json_data, timeout=self.timeout, **kwargs)

    def graphql(self, query: str, variables: dict = None,
                version: str = "2025-01") -> dict:
        url = self._gql_url(version)
        payload = {"query": query}
        if variables:
            payload["variables"] = variables
        r = self.session.post(url, json=payload, timeout=self.timeout)
        try:
            return r.json()
        except Exception:
            return {"errors": [{"message": r.text}]}

    def add_finding(self, severity: str, title: str, detail: str, cvss: str = "", module: str = ""):
        self.findings.append({
            "severity": severity,
            "title": title,
            "detail": detail,
            "cvss_suggestion": cvss,
            "module": module,
        })
        finding(severity, title, detail, cvss)

    def add_cleanup(self, kind: str, identifier):
        self.cleanup_tasks.append({"kind": kind, "id": identifier})

    def cleanup(self):
        section("CLEANUP — Removing test artifacts")
        cleaned = 0
        for task in self.cleanup_tasks:
            try:
                if task["kind"] == "webhook":
                    r = self.rest("DELETE", f"webhooks/{task['id']}.json")
                    if r.status_code in (200, 204):
                        info(f"Deleted webhook {task['id']}")
                        cleaned += 1
                    else:
                        fail(f"Could not delete webhook {task['id']}: {r.status_code}")
                elif task["kind"] == "metafield":
                    r = self.rest("DELETE", f"metafields/{task['id']}.json")
                    if r.status_code in (200, 204):
                        info(f"Deleted metafield {task['id']}")
                        cleaned += 1
                    else:
                        fail(f"Could not delete metafield {task['id']}: {r.status_code}")
            except Exception as e:
                fail(f"Cleanup error for {task['kind']} {task['id']}: {e}")
        ok(f"Cleaned up {cleaned}/{len(self.cleanup_tasks)} artifacts")


# ─── Module 1: Token Scope Verification ───────────────────────────────────────

def check_scopes(client: ShopifyClient):
    section("1. TOKEN SCOPE VERIFICATION")

    # Method 1: Check response headers
    info("Checking scopes via REST API response headers...")
    r = client.rest("GET", "shop.json")
    scopes_from_header = None
    if "X-Shopify-Access-Token-Scopes" in r.headers:
        scopes_from_header = r.headers["X-Shopify-Access-Token-Scopes"]
        ok(f"Scopes from header: {scopes_from_header}")
    elif "X-Shopify-Access-Scope" in r.headers:
        scopes_from_header = r.headers["X-Shopify-Access-Scope"]
        ok(f"Scopes from header: {scopes_from_header}")

    # Method 2: GraphQL accessScopes query
    info("Checking scopes via GraphQL accessScopes query...")
    gql_result = client.graphql("""
        {
          currentAppInstallation {
            accessScopes {
              handle
            }
          }
        }
    """)
    gql_scopes = []
    if "data" in gql_result and gql_result["data"]:
        try:
            gql_scopes = [s["handle"] for s in
                          gql_result["data"]["currentAppInstallation"]["accessScopes"]]
            ok(f"GraphQL scopes ({len(gql_scopes)}): {', '.join(gql_scopes)}")
        except (KeyError, TypeError):
            fail("Could not parse GraphQL scopes response")
    else:
        fail(f"GraphQL scopes query failed: {json.dumps(gql_result.get('errors', 'unknown'))}")

    # Method 3: Check shop data accessibility
    info("Verifying shop data access...")
    if r.status_code == 200:
        shop_data = r.json().get("shop", {})
        ok(f"Shop: {shop_data.get('name', 'unknown')} | Plan: {shop_data.get('plan_name', 'unknown')}")
        info(f"Shop owner: {shop_data.get('shop_owner', 'N/A')}")
        info(f"Email: {shop_data.get('email', 'N/A')}")
        info(f"Currency: {shop_data.get('currency', 'N/A')}")
        info(f"Created: {shop_data.get('created_at', 'N/A')}")
        info(f"Domain: {shop_data.get('domain', 'N/A')}")
    elif r.status_code == 401:
        fail("Token is invalid or expired (401)")
        return scopes_from_header, gql_scopes
    else:
        fail(f"Unexpected status: {r.status_code}")

    # Report summary
    effective_scopes = set()
    if scopes_from_header:
        effective_scopes.update(s.strip() for s in scopes_from_header.split(","))
    if gql_scopes:
        effective_scopes.update(gql_scopes)

    if effective_scopes:
        ok(f"Effective scopes: {', '.join(sorted(effective_scopes))}")
    else:
        info("Could not determine exact scopes; will infer from endpoint testing")

    return scopes_from_header, gql_scopes


# ─── Module 2: Scope Escalation Scan ──────────────────────────────────────────

def scan_scope_escalation(client: ShopifyClient):
    section("2. SCOPE ESCALATION SCAN — Testing REST Endpoints")

    # Comprehensive list of REST endpoints grouped by required scope
    endpoints = {
        # read_products / write_products (expected)
        "products.json?limit=1": "read_products",
        "collections.json?limit=1": "read_products",

        # read_orders
        "orders.json?limit=1": "read_orders",
        "orders/count.json": "read_orders",
        "checkouts.json?limit=1": "read_orders",

        # read_customers
        "customers.json?limit=1": "read_customers",
        "customers/count.json": "read_customers",
        "customers/search.json?query=email:*&limit=1": "read_customers",

        # read_inventory
        "locations.json?limit=1": "read_inventory",
        "inventory_levels.json?location_ids=1&limit=1": "read_inventory",

        # read_script_tags
        "script_tags.json?limit=1": "read_script_tags",

        # read_themes
        "themes.json?limit=1": "read_themes",

        # read_content
        "pages.json?limit=1": "read_content",
        "articles.json?limit=1": "read_content",
        "blogs.json?limit=1": "read_content",

        # read_price_rules
        "price_rules.json?limit=1": "read_price_rules",
        "discount_codes.json?limit=1": "read_price_rules",

        # read_marketing_events
        "marketing_events.json?limit=1": "read_marketing_events",

        # read_shopify_payments
        "shopify_payments/balance.json": "read_shopify_payments",
        "shopify_payments/payouts.json?limit=1": "read_shopify_payments",
        "shopify_payments/disputes.json?limit=1": "read_shopify_payments",

        # read_fulfillments
        "fulfillments.json?limit=1": "read_fulfillments",
        "fulfillment_orders.json?limit=1": "read_fulfillments",

        # read_assigned_fulfillment_orders
        "assigned_fulfillment_orders.json?limit=1": "read_assigned_fulfillment_orders",

        # read_draft_orders
        "draft_orders.json?limit=1": "read_draft_orders",

        # read_gift_cards
        "gift_cards.json?limit=1": "read_gift_cards",

        # read_analytics
        "reports.json?limit=1": "read_analytics",

        # read_locales
        "locales.json?limit=1": "read_locales",

        # read_translations
        "translations.json?limit=1": "read_translations",

        # read_files
        "files.json?limit=1": "read_files",

        # read_inventory (additional)
        "inventory_items.json?limit=1": "read_inventory",

        # read_legal_policies
        "policies.json?limit=1": "read_legal_policies",

        # read_storefront_access_tokens
        "storefront_access_tokens.json?limit=1": "read_storefront_access_tokens",

        # read_users
        "users.json?limit=1": "read_users",
        "users/current.json": "read_users",

        # read_checkouts
        "checkouts.json?limit=1": "read_checkouts",

        # Billing
        "recurring_application_charges.json?limit=1": "read_apps",
        "application_charges.json?limit=1": "read_apps",
        "application_credits.json?limit=1": "read_apps",

        # Metafields (read)
        "metafields.json?limit=1": "read_metafields",

        # Shipping
        "carrier_services.json?limit=1": "read_shipping",

        # Tender transactions
        "tender_transactions.json?limit=1": "read_orders",

        # Abandoned checkouts
        "checkouts.json?limit=1&status=any": "read_checkouts",
    }

    accessible = []
    for endpoint, required_scope in endpoints.items():
        try:
            r = client.rest("GET", endpoint)
            if r.status_code == 200:
                data = r.json()
                count = len(list(data.values())[0]) if data and isinstance(list(data.values())[0], list) else "✓"
                accessible.append((endpoint, required_scope, r.status_code))
                ok(f"{endpoint} → 200 (requires: {required_scope})")
            elif r.status_code == 403:
                pass  # Expected — scope enforced
            elif r.status_code == 401:
                pass  # Auth failure
            elif r.status_code == 404:
                pass  # Not found, normal
            else:
                info(f"{endpoint} → {r.status_code}")
        except requests.RequestException as e:
            pass
        # Rate limit courtesy
        time.sleep(0.15)

    if accessible:
        for ep, scope, code in accessible:
            client.add_finding(
                "MEDIUM",
                f"Unexpected REST access: {ep}",
                f"Endpoint accessible with status {code}. Normally requires '{scope}' scope.",
                "CVSS:5.3 — Improper Authorization",
                "scope_escalation"
            )
    else:
        ok("No unexpected endpoint access found (scope enforcement appears correct)")


# ─── Module 3: Webhook Topic Enumeration ──────────────────────────────────────

def scan_webhook_topics(client: ShopifyClient):
    section("3. WEBHOOK TOPIC ENUMERATION")

    webhook_topics = [
        "app/uninstalled",
        "app/scopes_update",
        "app_subscriptions/update",
        "bulk_operations/finish",
        "carts/create",
        "carts/update",
        "checkouts/create",
        "checkouts/delete",
        "checkouts/update",
        "collections/create",
        "collections/delete",
        "collections/update",
        "companies/create",
        "companies/delete",
        "companies/update",
        "company_contacts/create",
        "company_contacts/delete",
        "company_contacts/update",
        "company_locations/create",
        "company_locations/delete",
        "company_locations/update",
        "customers/create",
        "customers/delete",
        "customers/disable",
        "customers/enable",
        "customers/update",
        "customers/data_request",
        "customers/redact",
        "customer_groups/create",
        "customer_groups/delete",
        "customer_groups/update",
        "disputes/create",
        "disputes/update",
        "domains/create",
        "domains/destroy",
        "domains/update",
        "draft_orders/create",
        "draft_orders/delete",
        "draft_orders/update",
        "fulfillments/create",
        "fulfillments/update",
        "fulfillment_events/create",
        "fulfillment_orders/cancellation_request_accepted",
        "fulfillment_orders/cancellation_request_rejected",
        "fulfillment_orders/cancellation_request_submitted",
        "fulfillment_orders/cancelled",
        "fulfillment_orders/moved",
        "fulfillment_orders/order_routing_complete",
        "fulfillment_orders/fulfillment_request_accepted",
        "fulfillment_orders/fulfillment_request_rejected",
        "fulfillment_orders/fulfillment_request_submitted",
        "fulfillment_orders/hold_released",
        "fulfillment_orders/line_items_prepared_for_local_delivery",
        "fulfillment_orders/line_items_prepared_for_pickup",
        "fulfillment_orders/placed_on_hold",
        "fulfillment_orders/scheduled_fulfillment_order_ready",
        "inventory_items/create",
        "inventory_items/delete",
        "inventory_items/update",
        "inventory_levels/connect",
        "inventory_levels/disconnect",
        "inventory_levels/update",
        "locales/create",
        "locales/destroy",
        "locales/update",
        "locations/activate",
        "locations/create",
        "locations/deactivate",
        "locations/delete",
        "locations/update",
        "markets/create",
        "markets/delete",
        "markets/update",
        "order_transactions/create",
        "orders/cancelled",
        "orders/create",
        "orders/delete",
        "orders/edited",
        "orders/fulfilled",
        "orders/paid",
        "orders/partially_fulfilled",
        "orders/updated",
        "order_risk_assessments/create",
        "payment_schedules/due",
        "payment_terms/create",
        "payment_terms/delete",
        "payment_terms/update",
        "products/create",
        "products/delete",
        "products/update",
        "product_listings/add",
        "product_listings/remove",
        "product_listings/update",
        "profiles/create",
        "profiles/delete",
        "profiles/update",
        "refunds/create",
        "returns/approve",
        "returns/cancel",
        "returns/close",
        "returns/decline",
        "returns/reopen",
        "returns/request",
        "returns/update",
        "reverse_fulfillment_orders/dispose",
        "reverse_fulfillment_orders/exchange",
        "segments/create",
        "segments/delete",
        "segments/update",
        "selling_plan_groups/create",
        "selling_plan_groups/delete",
        "selling_plan_groups/update",
        "shop/update",
        "subscription_billing_attempts/challenged",
        "subscription_billing_attempts/failure",
        "subscription_billing_attempts/success",
        "subscription_contracts/create",
        "subscription_contracts/update",
        "tender_transactions/create",
        "themes/create",
        "themes/delete",
        "themes/publish",
        "themes/update",
    ]

    allowed_topics = []
    denied_topics = []
    webhook_ids_to_cleanup = []

    test_callback = "https://httpbin.org/post"

    for topic in webhook_topics:
        try:
            r = client.rest("POST", "webhooks.json", json_data={
                "webhook": {
                    "topic": topic,
                    "address": test_callback,
                    "format": "json",
                }
            })
            if r.status_code in (200, 201):
                wh_id = r.json().get("webhook", {}).get("id")
                if wh_id:
                    webhook_ids_to_cleanup.append(wh_id)
                    client.add_cleanup("webhook", wh_id)
                allowed_topics.append(topic)
                ok(f"  ✓ {topic}")
            elif r.status_code == 403:
                denied_topics.append(topic)
            elif r.status_code == 422:
                # Unprocessable — topic may not exist or validation error
                denied_topics.append(topic)
            elif r.status_code == 429:
                # Rate limited — back off
                time.sleep(2)
                # Retry once
                r2 = client.rest("POST", "webhooks.json", json_data={
                    "webhook": {"topic": topic, "address": test_callback, "format": "json"}
                })
                if r2.status_code in (200, 201):
                    wh_id = r2.json().get("webhook", {}).get("id")
                    if wh_id:
                        webhook_ids_to_cleanup.append(wh_id)
                        client.add_cleanup("webhook", wh_id)
                    allowed_topics.append(topic)
                    ok(f"  ✓ {topic} (after rate limit)")
                else:
                    denied_topics.append(topic)
            else:
                denied_topics.append(topic)
        except requests.RequestException:
            denied_topics.append(topic)
        time.sleep(0.2)

    if allowed_topics:
        client.add_finding(
            "HIGH",
            f"Webhook creation allowed for {len(allowed_topics)} topics",
            f"Can create webhooks for: {', '.join(allowed_topics[:20])}{'...' if len(allowed_topics)>20 else ''}",
            "CVSS:7.5 — Excessive Webhook Permissions",
            "webhook_enumeration"
        )
    else:
        ok("No webhook topics accessible beyond granted scope")

    # Check for shop/update specifically (privacy concern)
    if "shop/update" in allowed_topics:
        client.add_finding(
            "MEDIUM",
            "Can monitor shop/update events",
            "Token can create webhook for shop/update, allowing monitoring of shop configuration changes.",
            "CVSS:5.3 — Information Disclosure",
            "webhook_enumeration"
        )

    if "app/uninstalled" in allowed_topics:
        client.add_finding(
            "LOW",
            "Can monitor app/uninstalled events",
            "Token can create webhook for app/uninstalled.",
            "CVSS:3.1 — Information Disclosure",
            "webhook_enumeration"
        )

    info(f"Total allowed: {len(allowed_topics)}, Denied: {len(denied_topics)}")
    return allowed_topics


# ─── Module 4: Metafield Namespace Scan ───────────────────────────────────────

def scan_metafield_namespaces(client: ShopifyClient):
    section("4. METAFIELD NAMESPACE SCAN")

    namespaces_to_test = [
        ("global", "test_key", "test_value"),
        ("custom", "test_key", "test_value"),
        ("customers", "test_key", "test_value"),
        ("shopify", "test_key", "test_value"),
        ("shopify_app", "test_key", "test_value"),
        ("app--1234567890", "test_key", "test_value"),
        ("inventory", "test_key", "test_value"),
        ("theme", "test_key", "test_value"),
        ("seo", "test_key", "test_value"),
        ("private", "test_key", "test_value"),
        ("hidden", "test_key", "test_value"),
        ("internal", "test_key", "test_value"),
        ("admin", "test_key", "test_value"),
        ("system", "test_key", "test_value"),
        ("payment", "test_key", "test_value"),
        ("shipping", "test_key", "test_value"),
        ("checkout", "test_key", "test_value"),
        ("pricing", "test_key", "test_value"),
        ("discounts", "test_key", "test_value"),
        ("billing", "test_key", "test_value"),
    ]

    writable = []
    metafield_ids_to_cleanup = []

    for namespace, key, value in namespaces_to_test:
        # Try writing to shop-level metafields
        try:
            r = client.rest("POST", "metafields.json", json_data={
                "metafield": {
                    "namespace": namespace,
                    "key": key,
                    "value": value,
                    "type": "single_line_text_field",
                }
            })
            if r.status_code in (200, 201):
                mf_id = r.json().get("metafield", {}).get("id")
                if mf_id:
                    metafield_ids_to_cleanup.append(mf_id)
                    client.add_cleanup("metafield", mf_id)
                writable.append(namespace)
                ok(f"  ✓ namespace '{namespace}' → writable (shop-level)")
            elif r.status_code == 403:
                pass  # Expected
            elif r.status_code == 422:
                # Validation error — namespace may be reserved but still accessible
                errors = r.json().get("errors", {})
                if "taken" in str(errors).lower() or "already" in str(errors).lower():
                    info(f"  ~ namespace '{namespace}' → exists but not writable")
            elif r.status_code == 429:
                time.sleep(2)
            else:
                pass
        except requests.RequestException:
            pass
        time.sleep(0.2)

    # Also try product-level metafields
    info("Testing product-level metafield write...")
    # Get a product first
    r = client.rest("GET", "products.json?limit=1")
    if r.status_code == 200:
        products = r.json().get("products", [])
        if products:
            prod_id = products[0]["id"]
            for namespace in ["custom", "global", "shopify", "internal", "admin"]:
                try:
                    r2 = client.rest("POST", f"products/{prod_id}/metafields.json", json_data={
                        "metafield": {
                            "namespace": namespace,
                            "key": "scan_test",
                            "value": "test",
                            "type": "single_line_text_field",
                        }
                    })
                    if r2.status_code in (200, 201):
                        mf_id = r2.json().get("metafield", {}).get("id")
                        if mf_id:
                            metafield_ids_to_cleanup.append(mf_id)
                            client.add_cleanup("metafield", mf_id)
                        ok(f"  ✓ product namespace '{namespace}' → writable")
                    time.sleep(0.2)
                except Exception:
                    pass

    # GraphQL metafield check
    info("Testing GraphQL metafield mutations...")
    gql_metafields = client.graphql("""
        mutation metafieldStorefrontVisibilityCreate($input: MetafieldStorefrontVisibilityInput!) {
            metafieldStorefrontVisibilityCreate(input: $input) {
                metafieldStorefrontVisibility {
                    id
                }
                userErrors {
                    field
                    message
                }
            }
        }
    """, variables={
        "input": {
            "namespace": "test",
            "key": "scan_test",
            "ownerType": "PRODUCT"
        }
    })
    if gql_metafields and "data" in gql_metafields:
        if gql_metafields["data"].get("metafieldStorefrontVisibilityCreate"):
            errors = gql_metafields["data"]["metafieldStorefrontVisibilityCreate"].get("userErrors", [])
            if not errors:
                client.add_finding(
                    "HIGH",
                    "Can create metafield storefront visibility",
                    "GraphQL mutation metafieldStorefrontVisibilityCreate succeeded — can expose metafields to storefront.",
                    "CVSS:7.5 — Privilege Escalation",
                    "metafield_scan"
                )
            else:
                info(f"  metafieldStorefrontVisibilityCreate: {errors[0].get('message', 'denied')}")

    if writable:
        sensitive = [ns for ns in writable if ns in ("shopify", "shopify_app", "admin", "system", "internal", "payment", "billing")]
        if sensitive:
            client.add_finding(
                "HIGH",
                f"Can write to sensitive metafield namespaces: {', '.join(sensitive)}",
                f"Token with limited scopes can write metafields to reserved/sensitive namespaces.",
                "CVSS:7.5 — Improper Access Control",
                "metafield_scan"
            )
        # Report all writable namespaces
        client.add_finding(
            "MEDIUM",
            f"Writable metafield namespaces: {', '.join(writable)}",
            "Token can write metafields to these namespaces, which may exceed expected scope.",
            "CVSS:5.3 — Scope Violation",
            "metafield_scan"
        )
    else:
        ok("No unexpected metafield namespace writes succeeded")

    return writable


# ─── Module 5: GraphQL Mutation Scan ──────────────────────────────────────────

def scan_graphql_mutations(client: ShopifyClient):
    section("5. GRAPHQL MUTATION SCAN")

    mutations = [
        # Sensitive mutations to test
        {
            "name": "delegateAccessTokenCreate",
            "query": """
                mutation {
                    delegateAccessTokenCreate(input: {
                        delegateAccessScope: ["write_products"]
                        expiresAt: "2026-12-31"
                    }) {
                        delegateAccessToken {
                            accessToken
                        }
                        userErrors {
                            field message
                        }
                    }
                }
            """,
            "severity": "CRITICAL",
            "cvss": "CVSS:9.8 — Token Creation/Privilege Escalation",
            "desc": "Can create delegate access tokens"
        },
        {
            "name": "storefrontAccessTokenCreate",
            "query": """
                mutation {
                    storefrontAccessTokenCreate(input: {
                        title: "scan_test_token"
                    }) {
                        storefrontAccessToken {
                            accessToken
                            id
                        }
                        userErrors {
                            field message
                        }
                    }
                }
            """,
            "severity": "HIGH",
            "cvss": "CVSS:8.1 — Storefront Token Creation",
            "desc": "Can create storefront access tokens"
        },
        {
            "name": "appSubscriptionCreate",
            "query": """
                mutation {
                    appSubscriptionCreate(
                        name: "Test Plan"
                        returnUrl: "https://example.com"
                        lineItems: [{
                            plan: {
                                appRecurringPricingDetails: {
                                    price: {amount: 0, currencyCode: USD}
                                    interval: EVERY_30_DAYS
                                }
                            }
                        }]
                    ) {
                        appSubscription {
                            id
                        }
                        userErrors {
                            field message
                        }
                    }
                }
            """,
            "severity": "CRITICAL",
            "cvss": "CVSS:9.1 — Billing Manipulation",
            "desc": "Can create app subscriptions (billing manipulation)"
        },
        {
            "name": "appPurchaseOneTimeCreate",
            "query": """
                mutation {
                    appPurchaseOneTimeCreate(
                        name: "Test Purchase"
                        price: {amount: 0, currencyCode: USD}
                        returnUrl: "https://example.com"
                    ) {
                        appPurchaseOneTime {
                            id
                        }
                        userErrors {
                            field message
                        }
                    }
                }
            """,
            "severity": "CRITICAL",
            "cvss": "CVSS:9.1 — Billing Manipulation",
            "desc": "Can create one-time app purchases"
        },
        {
            "name": "shopLocaleUpdate (locale changes)",
            "query": """
                mutation {
                    shopLocaleUpdate(locale: {locale: "en", published: true}) {
                        shopLocale {
                            locale
                        }
                        userErrors {
                            field message
                        }
                    }
                }
            """,
            "severity": "MEDIUM",
            "cvss": "CVSS:5.3 — Shop Configuration Change",
            "desc": "Can modify shop locale settings"
        },
        {
            "name": "webhookSubscriptionCreate (sensitive topics)",
            "query": """
                mutation {
                    webhookSubscriptionCreate(
                        topic: ORDERS_CREATE
                        webhookSubscription: {
                            callbackUrl: "https://example.com/hook"
                            format: JSON
                        }
                    ) {
                        webhookSubscription {
                            id
                        }
                        userErrors {
                            field message
                        }
                    }
                }
            """,
            "severity": "HIGH",
            "cvss": "CVSS:7.5 — Webhook Abuse",
            "desc": "Can create webhook subscriptions via GraphQL for sensitive topics"
        },
        {
            "name": "metafieldDefinitionCreate",
            "query": """
                mutation {
                    metafieldDefinitionCreate(definition: {
                        name: "Scan Test"
                        namespace: "scan_test"
                        key: "test_key"
                        type: "single_line_text_field"
                        ownerType: PRODUCT
                    }) {
                        createdDefinition {
                            id
                        }
                        userErrors {
                            field message
                        }
                    }
                }
            """,
            "severity": "MEDIUM",
            "cvss": "CVSS:5.3 — Schema Modification",
            "desc": "Can create metafield definitions"
        },
        {
            "name": "customerSegmentMembersQuery (bulk export)",
            "query": """
                mutation {
                    customerSegmentMembers(
                        query: "email_subscription_status = 'subscribed'"
                        first: 1
                    ) {
                        members {
                            id
                        }
                        userErrors {
                            field message
                        }
                    }
                }
            """,
            "severity": "HIGH",
            "cvss": "CVSS:7.5 — Data Exfiltration",
            "desc": "Can query customer segment members (potential data exfiltration)"
        },
        {
            "name": "scriptTagCreate",
            "query": """
                mutation {
                    scriptTagCreate(input: {
                        src: "https://example.com/script.js"
                        displayScope: ONLINE_STORE
                    }) {
                        scriptTag {
                            id
                        }
                        userErrors {
                            field message
                        }
                    }
                }
            """,
            "severity": "CRITICAL",
            "cvss": "CVSS:9.8 — Script Injection / XSS",
            "desc": "Can inject script tags into storefront (XSS vector)"
        },
        {
            "name": "themeFilesUpsert (code injection)",
            "query": """
                mutation themeFilesUpsert($files: [OnlineStoreThemeFilesUpsertFileInput!]!) {
                    themeFilesUpsert(files: $files) {
                        job {
                            id
                        }
                        userErrors {
                            field message
                        }
                    }
                }
            """,
            "variables": {
                "files": [{
                    "filename": "templates/test_scan.json",
                    "body": {"type": "onlineStoreThemeFileBodyText", "content": "{}"}
                }]
            },
            "severity": "CRITICAL",
            "cvss": "CVSS:9.8 — Code Injection",
            "desc": "Can modify theme files (potential code injection)"
        },
        {
            "name": "shopPolicyUpdate",
            "query": """
                mutation {
                    shopPolicyUpdate(shopPolicy: {
                        type: REFUND_POLICY
                        body: "Test policy update"
                    }) {
                        shopPolicy {
                            id
                        }
                        userErrors {
                            field message
                        }
                    }
                }
            """,
            "severity": "HIGH",
            "cvss": "CVSS:7.5 — Policy Manipulation",
            "desc": "Can update shop policies"
        },
        {
            "name": "priceRuleCreate",
            "query": """
                mutation {
                    priceRuleCreate(priceRule: {
                        title: "scan_test_discount"
                        target: LINE_ITEM
                        customerSelection: {all: true}
                        valueType: PERCENTAGE
                        value: -100
                        startsAt: "2026-01-01"
                    }) {
                        priceRule {
                            id
                        }
                        userErrors {
                            field message
                        }
                    }
                }
            """,
            "severity": "CRITICAL",
            "cvss": "CVSS:9.1 — Financial Manipulation",
            "desc": "Can create price rules / discount codes"
        },
    ]

    dangerous_found = []
    for mutation in mutations:
        try:
            variables = mutation.get("variables")
            result = client.graphql(mutation["query"], variables=variables)

            if not result:
                fail(f"  {mutation['name']}: no response")
                continue

            data = result.get("data", {})
            if not data:
                errors = result.get("errors", [])
                if errors:
                    msg = errors[0].get("message", "")
                    if "access denied" in msg.lower() or "permission" in msg.lower():
                        info(f"  {mutation['name']}: access denied ✓")
                    elif "doesn't exist" in msg.lower() or "undefined" in msg.lower():
                        info(f"  {mutation['name']}: mutation not available")
                    else:
                        info(f"  {mutation['name']}: {msg[:80]}")
                continue

            # Check mutation result
            mutation_data = list(data.values())[0] if data else None
            if mutation_data:
                user_errors = mutation_data.get("userErrors", [])
                if user_errors:
                    error_msg = user_errors[0].get("message", "")
                    if "access" in error_msg.lower() or "permission" in error_msg.lower() or "scope" in error_msg.lower():
                        info(f"  {mutation['name']}: permission denied ✓")
                    elif "must have" in error_msg.lower() or "required" in error_msg.lower():
                        info(f"  {mutation['name']}: missing required scope ✓")
                    else:
                        info(f"  {mutation['name']}: {error_msg[:80]}")
                else:
                    # Mutation succeeded!
                    obj_id = None
                    for k, v in mutation_data.items():
                        if isinstance(v, dict) and "id" in v:
                            obj_id = v["id"]
                            break
                    dangerous_found.append(mutation)
                    client.add_finding(
                        mutation["severity"],
                        f"{mutation['name']} succeeded",
                        f"{mutation['desc']}. Object ID: {obj_id or 'N/A'}",
                        mutation["cvss"],
                        "graphql_mutations"
                    )
            time.sleep(0.3)
        except Exception as e:
            fail(f"  {mutation['name']}: error — {e}")

    if not dangerous_found:
        ok("No dangerous GraphQL mutations succeeded")

    return dangerous_found


# ─── Module 6: Cross-Store IDOR Test ──────────────────────────────────────────

def scan_cross_store_idor(client: ShopifyClient, other_shops: list):
    section("6. CROSS-STORE IDOR TEST")

    if not other_shops:
        info("No other shops provided. Testing with common patterns...")
        # Try to discover other shops from the current shop's data
        r = client.rest("GET", "shop.json")
        if r.status_code == 200:
            shop_data = r.json().get("shop", {})
            info(f"Current shop domain: {shop_data.get('domain', 'unknown')}")
            info(f"Myshopify domain: {shop_data.get('myshopify_domain', 'unknown')}")

        # Generate test shops
        other_shops = [
            "nonexistent-store-12345.myshopify.com",
            "admin.myshopify.com",
            "test.myshopify.com",
        ]
        info("Testing against dummy shops to verify token boundary enforcement")

    for shop in other_shops:
        shop = shop.strip()
        if not shop.endswith(".myshopify.com"):
            shop += ".myshopify.com"

        info(f"Testing token against: {shop}")
        test_url = f"https://{shop}/admin/api/2025-01/shop.json"
        try:
            r = requests.get(test_url, headers={
                "X-Shopify-Access-Token": client.token,
                "Content-Type": "application/json",
            }, timeout=10)

            if r.status_code == 200:
                shop_data = r.json().get("shop", {})
                client.add_finding(
                    "CRITICAL",
                    f"Cross-store IDOR: Token works on {shop}",
                    f"Token granted access to different store! Shop: {shop_data.get('name', 'unknown')}. "
                    f"This is a critical authorization bypass.",
                    "CVSS:9.8 — Broken Access Control (IDOR)",
                    "cross_store_idor"
                )
            elif r.status_code == 401:
                ok(f"  {shop}: token rejected (401) ✓")
            elif r.status_code == 403:
                ok(f"  {shop}: access forbidden (403) ✓")
            else:
                info(f"  {shop}: status {r.status_code}")
        except requests.RequestException as e:
            info(f"  {shop}: connection error — {e}")
        time.sleep(0.3)


# ─── Module 7: API Version Confusion ──────────────────────────────────────────

def scan_api_versions(client: ShopifyClient):
    section("7. API VERSION CONFUSION SCAN")

    versions = [
        "2020-01", "2020-04", "2020-07", "2020-10",
        "2021-01", "2021-04", "2021-07", "2021-10",
        "2022-01", "2022-04", "2022-07", "2022-10",
        "2023-01", "2023-04", "2023-07", "2023-10",
        "2024-01", "2024-04", "2024-07", "2024-10",
        "2025-01", "2025-04",
        "unstable",
        "2019-10",  # Very old
        "2019-07",
        "2019-04",
    ]

    accessible_versions = []
    deprecated_accessible = []

    for version in versions:
        try:
            r = client.rest("GET", "shop.json", version=version)
            if r.status_code == 200:
                accessible_versions.append(version)
                if version < "2024-01" or version in ("unstable",):
                    deprecated_accessible.append(version)
                    client.add_finding(
                        "LOW" if version != "unstable" else "MEDIUM",
                        f"Access via deprecated/unstable API version: {version}",
                        f"Token works with API version {version}. {'Unstable API may expose unreleased features.' if version == 'unstable' else 'Deprecated versions may have known vulnerabilities.'}",
                        "CVSS:3.7 — Deprecated API Access" if version != "unstable" else "CVSS:5.3 — Unstable API Access",
                        "api_version_confusion"
                    )
                else:
                    ok(f"  {version}: accessible ✓")
            elif r.status_code == 400:
                # Bad request — version may be invalid
                pass
            elif r.status_code == 404:
                pass
            else:
                pass
        except requests.RequestException:
            pass
        time.sleep(0.15)

    info(f"Accessible versions: {', '.join(accessible_versions)}")
    if deprecated_accessible:
        info(f"Deprecated/unstable versions accessible: {', '.join(deprecated_accessible)}")
    else:
        ok("No deprecated or unstable API versions accessible")

    return accessible_versions


# ─── Module 8: Bulk Operation Test ────────────────────────────────────────────

def scan_bulk_operations(client: ShopifyClient):
    section("8. BULK OPERATION TEST")

    # Test bulk query operation
    info("Testing GraphQL bulk query operation...")
    inner_query = (
        '{ products(first: 10) { edges { node { id title handle '
        'variants(first: 5) { edges { node { id title price } } } } } } }'
    )
    bulk_query = 'mutation { bulkOperationRunQuery(query: "' + inner_query.replace('"', '\\"') + '") { bulkOperation { id status } userErrors { field message } } }'

    result = client.graphql(bulk_query)
    bulk_success = False
    if result and "data" in result:
        bulk_data = result["data"].get("bulkOperationRunQuery", {})
        if bulk_data:
            user_errors = bulk_data.get("userErrors", [])
            if user_errors:
                error_msg = user_errors[0].get("message", "")
                if "access" in error_msg.lower() or "permission" in error_msg.lower():
                    ok(f"  Bulk operations: access denied ✓")
                else:
                    info(f"  Bulk operations: {error_msg[:80]}")
            else:
                op = bulk_data.get("bulkOperation", {})
                if op:
                    bulk_success = True
                    client.add_finding(
                        "MEDIUM",
                        "Bulk data export accessible",
                        f"Can run bulk GraphQL queries. Operation ID: {op.get('id', 'N/A')}, "
                        f"Status: {op.get('status', 'N/A')}. "
                        f"This could be used for data exfiltration.",
                        "CVSS:5.3 — Data Exposure via Bulk Operations",
                        "bulk_operations"
                    )
    else:
        errors = result.get("errors", [])
        if errors:
            msg = errors[0].get("message", "")
            info(f"  Bulk operation response: {msg[:80]}")
        else:
            info(f"  Bulk operation: unexpected response")

    # Test bulk mutation operation
    info("Testing GraphQL bulk mutation operation (sample)...")
    bulk_mutation = """
        mutation {
            bulkOperationRunMutation(
                mutation: "mutation call($input: ProductInput!) { productUpdate(input: $input) { product { id } userErrors { message } } }"
                stagedUploadPath: "test"
            ) {
                bulkOperation {
                    id
                    status
                }
                userErrors {
                    field
                    message
                }
            }
        }
    """
    result2 = client.graphql(bulk_mutation)
    if result2 and "data" in result2:
        bm_data = result2["data"].get("bulkOperationRunMutation", {})
        if bm_data:
            user_errors = bm_data.get("userErrors", [])
            if user_errors:
                ok(f"  Bulk mutations: not accessible ✓")
            else:
                client.add_finding(
                    "HIGH",
                    "Bulk mutation operations accessible",
                    "Can run bulk mutations via GraphQL — potential for mass data modification.",
                    "CVSS:7.5 — Mass Data Modification",
                    "bulk_operations"
                )

    if not bulk_success:
        ok("Bulk operations appear to be properly restricted")


# ─── Module 9: Billing API Access ──────────────────────────────────────────────

def scan_billing_api(client: ShopifyClient):
    section("9. BILLING API ACCESS TEST")

    billing_endpoints = [
        ("GET", "recurring_application_charges.json?limit=10", "read_apps", "Recurring app charges"),
        ("GET", "application_charges.json?limit=10", "read_apps", "One-time app charges"),
        ("GET", "application_credits.json?limit=10", "read_apps", "Application credits"),
        ("GET", "shopify_payments/balance.json", "read_shopify_payments", "Payment balance"),
        ("GET", "shopify_payments/payouts.json?limit=5", "read_shopify_payments", "Payouts"),
        ("GET", "shopify_payments/disputes.json?limit=5", "read_shopify_payments", "Disputes"),
        ("GET", "shopify_payments/transactions.json?limit=5", "read_shopify_payments", "Transactions"),
    ]

    billing_accessible = []

    for method, endpoint, required_scope, description in billing_endpoints:
        try:
            r = client.rest(method, endpoint)
            if r.status_code == 200:
                data = r.json()
                # Try to count results
                key = list(data.keys())[0] if data else None
                count = len(data[key]) if key and isinstance(data[key], list) else "N/A"
                billing_accessible.append((endpoint, description, count, required_scope))
                ok(f"  {description}: accessible ({count} records)")
            elif r.status_code == 403:
                pass
            elif r.status_code == 404:
                pass
            else:
                info(f"  {description}: status {r.status_code}")
        except requests.RequestException:
            pass
        time.sleep(0.2)

    # GraphQL billing queries
    info("Testing GraphQL billing queries...")
    billing_gql = client.graphql("""
        {
            currentAppInstallation {
                activeSubscriptions {
                    id
                    name
                    status
                    test
                    lineItems {
                        id
                        plan {
                            pricingDetails {
                                ... on AppRecurringPricing {
                                    price {
                                        amount
                                        currencyCode
                                    }
                                    interval
                                }
                            }
                        }
                    }
                }
                oneTimePurchases(first: 10) {
                    edges {
                        node {
                            id
                            name
                            status
                            test
                        }
                    }
                }
            }
        }
    """)
    if billing_gql and "data" in billing_gql and billing_gql["data"]:
        try:
            installation = billing_gql["data"]["currentAppInstallation"]
            subs = installation.get("activeSubscriptions", [])
            purchases = installation.get("oneTimePurchases", {}).get("edges", [])
            if subs or purchases:
                billing_accessible.append(("GraphQL billing", "Billing subscriptions/purchases", len(subs) + len(purchases), "read_apps"))
                client.add_finding(
                    "HIGH",
                    "Full billing data accessible via GraphQL",
                    f"Active subscriptions: {len(subs)}, One-time purchases: {len(purchases)}. "
                    f"Can enumerate billing state, pricing, and subscription details.",
                    "CVSS:7.5 — Financial Data Exposure",
                    "billing_scan"
                )
        except (KeyError, TypeError):
            pass

    # Try creating a test subscription (destructive test - report only)
    info("Testing app subscription creation (read-only check)...")
    sub_test = client.graphql("""
        mutation {
            appSubscriptionCreate(
                name: "Test"
                returnUrl: "https://test.invalid"
                lineItems: [{
                    plan: {
                        appRecurringPricingDetails: {
                            price: {amount: 0.01, currencyCode: USD}
                            interval: EVERY_30_DAYS
                        }
                    }
                }]
            ) {
                appSubscription {
                    id
                    status
                }
                confirmationUrl
                userErrors {
                    field
                    message
                }
            }
        }
    """)
    if sub_test and "data" in sub_test:
        sub_data = sub_test["data"].get("appSubscriptionCreate", {})
        if sub_data:
            if sub_data.get("confirmationUrl"):
                client.add_finding(
                    "CRITICAL",
                    "Can initiate billing subscriptions",
                    f"appSubscriptionCreate returned a confirmation URL: {sub_data['confirmationUrl'][:50]}... "
                    f"An attacker could potentially create unauthorized charges.",
                    "CVSS:9.1 — Financial Manipulation",
                    "billing_scan"
                )
            elif sub_data.get("userErrors"):
                err = sub_data["userErrors"][0].get("message", "")
                if "access" in err.lower() or "scope" in err.lower():
                    ok(f"  Subscription creation: properly denied ✓")
                else:
                    info(f"  Subscription creation: {err[:80]}")

    if billing_accessible:
        client.add_finding(
            "HIGH",
            f"Billing data accessible ({len(billing_accessible)} endpoints)",
            "Financial data exposure: " + "; ".join(f"{d} ({c} records)" for _, d, c, _ in billing_accessible),
            "CVSS:7.5 — Financial Data Exposure",
            "billing_scan"
        )
    else:
        ok("No billing endpoints accessible — scope enforcement appears correct")


# ─── Module 10: GraphQL Introspection ─────────────────────────────────────────

def scan_graphql_introspection(client: ShopifyClient):
    section("10. GRAPHQL INTROSPECTION")

    info("Running GraphQL introspection...")
    introspection = client.graphql("""
        query IntrospectionQuery {
            __schema {
                queryType { name }
                mutationType { name }
                types {
                    name
                    kind
                }
                directives {
                    name
                    locations
                }
            }
        }
    """)

    if introspection and "data" in introspection and introspection["data"]:
        schema = introspection["data"]["__schema"]
        types = schema.get("types", [])
        query_types = [t for t in types if t["kind"] == "OBJECT" and not t["name"].startswith("__")]
        ok(f"Introspection allowed — {len(types)} types exposed")

        # Count queries and mutations
        queries = client.graphql("""
            { __type(name: "QueryRoot") { fields { name } } }
        """)
        mutations = client.graphql("""
            { __type(name: "MutationRoot") { fields { name } } }
        """)

        query_count = 0
        mutation_count = 0
        if queries and "data" in queries:
            try:
                query_count = len(queries["data"]["__type"]["fields"])
                ok(f"Queries exposed: {query_count}")
            except (KeyError, TypeError):
                pass
        if mutations and "data" in mutations:
            try:
                mutation_count = len(mutations["data"]["__type"]["fields"])
                ok(f"Mutations exposed: {mutation_count}")
            except (KeyError, TypeError):
                pass

        client.add_finding(
            "LOW",
            "GraphQL introspection fully enabled",
            f"Schema exposes {len(types)} types, {query_count} queries, {mutation_count} mutations. "
            f"This aids attackers in understanding the API surface.",
            "CVSS:3.7 — Information Disclosure",
            "graphql_introspection"
        )
    else:
        errors = introspection.get("errors", []) if introspection else []
        if errors:
            ok(f"Introspection appears restricted: {errors[0].get('message', 'unknown')[:80]}")
        else:
            info("Could not determine introspection status")


# ─── Report Generation ────────────────────────────────────────────────────────

def generate_report(client: ShopifyClient, output_format: str = "text"):
    section("SCAN SUMMARY")

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    sorted_findings = sorted(client.findings, key=lambda f: severity_order.get(f["severity"], 5))

    counts = {}
    for f in client.findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    print(f"\n  {C.BOLD}Total findings: {len(client.findings)}{C.RESET}")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        c = counts.get(sev, 0)
        colors = {"CRITICAL": C.RED, "HIGH": C.RED, "MEDIUM": C.YELLOW, "LOW": C.CYAN, "INFO": C.DIM}
        if c > 0:
            print(f"    {colors[sev]}{sev}: {c}{C.RESET}")
    print()

    if output_format == "json":
        report = {
            "scan_time": datetime.datetime.now().isoformat(),
            "shop": client.shop,
            "total_findings": len(client.findings),
            "severity_counts": counts,
            "findings": sorted_findings,
        }
        json_path = f"/root/bugbounty-toolkit/scan_report_{client.shop.replace('.', '_')}_{int(time.time())}.json"
        with open(json_path, "w") as f:
            json.dump(report, f, indent=2)
        ok(f"JSON report saved: {json_path}")
        return json_path

    # Text report
    print(f"  {C.BOLD}{'Severity':<12} {'Title':<50} {'CVSS':<30}{C.RESET}")
    print(f"  {'─'*92}")
    for f in sorted_findings:
        colors = {"CRITICAL": C.RED, "HIGH": C.RED, "MEDIUM": C.YELLOW, "LOW": C.CYAN, "INFO": C.DIM}
        color = colors.get(f["severity"], C.WHITE)
        print(f"  {color}{f['severity']:<12}{C.RESET} {f['title'][:48]:<50} {C.DIM}{f.get('cvss_suggestion', '')[:28]:<30}{C.RESET}")

    print(f"\n  {C.DIM}Scan completed at {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{C.RESET}")
    return None


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Shopify Auth Scanner — Comprehensive Token & Scope Testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 shopify_auth_scan.py --token shpat_xxx --shop mystore.myshopify.com
  python3 shopify_auth_scan.py --token shpat_xxx --shop mystore --output json
  python3 shopify_auth_scan.py --token shpat_xxx --shop mystore --other-shops shop2.myshopify.com shop3.myshopify.com
  python3 shopify_auth_scan.py --token shpat_xxx --shop mystore --skip-cleanup
        """
    )
    parser.add_argument("--token", required=True, help="Shopify access token (shpat_xxx)")
    parser.add_argument("--shop", required=True, help="Shop domain (store.myshopify.com)")
    parser.add_argument("--output", choices=["text", "json"], default="text",
                        help="Output format (default: text, json saves to file)")
    parser.add_argument("--other-shops", nargs="*", default=[],
                        help="Other shop domains to test for cross-store IDOR")
    parser.add_argument("--skip-cleanup", action="store_true",
                        help="Don't clean up test artifacts (webhooks, metafields)")
    parser.add_argument("--skip-modules", nargs="*", default=[],
                        help="Skip specific modules (scopes, escalation, webhooks, metafields, "
                             "mutations, idor, versions, bulk, billing, introspection)")
    parser.add_argument("--timeout", type=int, default=30,
                        help="HTTP request timeout in seconds (default: 30)")

    args = parser.parse_args()

    banner()

    client = ShopifyClient(args.shop, args.token, timeout=args.timeout)

    info(f"Target: {client.shop}")
    info(f"Token: {args.token[:8]}...{args.token[-4:]}")
    info(f"Time: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()

    # Check connectivity first
    info("Verifying connectivity...")
    try:
        r = client.rest("GET", "shop.json")
        if r.status_code == 401:
            fail("Token is invalid (401 Unauthorized)")
            sys.exit(1)
        elif r.status_code == 403:
            fail("Access forbidden (403). Token may be revoked or shop may be unavailable.")
            sys.exit(1)
        ok(f"Connected to {client.shop} (HTTP {r.status_code})")
    except requests.RequestException as e:
        fail(f"Connection failed: {e}")
        sys.exit(1)

    skip = set(args.skip_modules)

    # Run modules
    if "scopes" not in skip:
        check_scopes(client)

    if "escalation" not in skip:
        scan_scope_escalation(client)

    if "webhooks" not in skip:
        scan_webhook_topics(client)

    if "metafields" not in skip:
        scan_metafield_namespaces(client)

    if "mutations" not in skip:
        scan_graphql_mutations(client)

    if "idor" not in skip:
        scan_cross_store_idor(client, args.other_shops)

    if "versions" not in skip:
        scan_api_versions(client)

    if "bulk" not in skip:
        scan_bulk_operations(client)

    if "billing" not in skip:
        scan_billing_api(client)

    if "introspection" not in skip:
        scan_graphql_introspection(client)

    # Cleanup
    if not args.skip_cleanup and client.cleanup_tasks:
        client.cleanup()
    elif args.skip_cleanup:
        info(f"Skipping cleanup ({len(client.cleanup_tasks)} artifacts to clean)")

    # Generate report
    json_path = generate_report(client, args.output)

    if args.output == "json" and json_path:
        print(f"\n  {C.GREEN}{C.BOLD}Report saved to: {json_path}{C.RESET}")

    print(f"\n  {C.CYAN}{'─'*60}")
    print(f"  Scan complete. Review findings above.")
    print(f"  {'─'*60}{C.RESET}\n")


if __name__ == "__main__":
    main()
