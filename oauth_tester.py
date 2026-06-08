#!/usr/bin/env python3
"""
OAuth 2.0 Security Tester
==========================
Tests OAuth 2.0 implementations for common security misconfigurations including:
- Redirect URI validation bypass
- State parameter (CSRF) weaknesses
- PKCE enforcement gaps
- Token exchange vulnerabilities
- Scope escalation
- Grant type abuse

Part of the Bug Bounty Toolkit v5.0

Usage:
    python3 oauth_tester.py --base-url https://example.com/oauth --client-id abc123 --redirect-uri https://app.example.com/callback
    python3 oauth_tester.py --base-url https://example.com/oauth --client-id abc123 --redirect-uri https://app.example.com/callback --output json
"""

import argparse
import json
import sys
import time
from urllib.parse import urlencode, urlparse, parse_qs, urljoin
from typing import Dict, List, Optional, Tuple

try:
    import requests
    from colorama import init, Fore, Style, Back
    init(autoreset=True)
except ImportError:
    print("Install dependencies: pip install requests colorama")
    sys.exit(1)

BANNER = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗
║        ╔═╗╔═╗╔╦╗╔═╗  ╔═╗╔╦╗╔═╗╦═╗╔╦╗                     ║
║        ║ ╦╠═╣║║║║ │  ╚═╗ ║ ╠═╣╠╦╝ ║                       ║
║        ╚═╝╩ ╩╩ ╩╚═╝  ╚═╝ ╩ ╩ ╩╩╚═ ╩                       ║
║            Security Tester v5.0                             ║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""

REPORT_VULN = f"{Fore.RED}[VULN]{Style.RESET_ALL}"
REPORT_SAFE = f"{Fore.GREEN}[SAFE]{Style.RESET_ALL}"
REPORT_INFO = f"{Fore.YELLOW}[INFO]{Style.RESET_ALL}"
REPORT_TEST = f"{Fore.CYAN}[TEST]{Style.RESET_ALL}"

# Common redirect URI bypass payloads
REDIRECT_BYPASS_PAYLOADS = [
    # Open redirect variants
    {"suffix": "/../evil.com", "desc": "Path traversal to external domain"},
    {"suffix": "//evil.com", "desc": "Protocol-relative redirect"},
    {"suffix": "/evil.com", "desc": "Path-based open redirect"},
    {"suffix": "@evil.com", "desc": "UserInfo-style redirect"},
    {"suffix": ".evil.com", "desc": "Subdomain prefix bypass"},
    {"suffix": "%2f%2fevil.com", "desc": "URL-encoded protocol-relative"},
    {"suffix": "/..%2fevil.com", "desc": "Mixed encoding path traversal"},
    {"suffix": "#evil.com", "desc": "Fragment-based redirect"},
    {"suffix": "?next=https://evil.com", "desc": "Query parameter redirect"},
    {"suffix": "\\evil.com", "desc": "Backslash redirect"},
    {"suffix": "/./evil.com", "desc": "Dot-segment redirect"},
    {"suffix": "///evil.com", "desc": "Triple-slash redirect"},
]


class OAuthTester:
    """OAuth 2.0 Security Tester with comprehensive test suite."""

    def __init__(self, base_url: str, client_id: str, redirect_uri: str,
                 client_secret: str = None, verbose: bool = False):
        self.base_url = base_url.rstrip('/')
        self.client_id = client_id
        self.redirect_uri = redirect_uri
        self.client_secret = client_secret or "test_secret"
        self.verbose = verbose
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "OAuthTester/5.0"})
        self.session.verify = True
        self.results = []

    def _log(self, level: str, message: str):
        """Log a message to stdout."""
        print(f"  {level} {message}")

    def _record(self, test_name: str, category: str, result: str,
                evidence: str = "", severity: str = "info"):
        """Record a test result."""
        entry = {
            "test": test_name,
            "category": category,
            "result": result,
            "evidence": evidence,
            "severity": severity,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        self.results.append(entry)

    def _build_auth_url(self, extra_params: dict = None) -> str:
        """Build an OAuth authorization URL."""
        params = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "scope": "openid profile email",
            "state": "random_state_value_12345",
        }
        if extra_params:
            params.update(extra_params)
        return f"{self.base_url}/authorize?{urlencode(params)}"

    def _make_request(self, url: str, method: str = "GET",
                      data: dict = None, allow_redirects: bool = False) -> Optional[requests.Response]:
        """Make an HTTP request, catching errors."""
        try:
            if method == "GET":
                resp = self.session.get(url, allow_redirects=allow_redirects, timeout=15)
            else:
                resp = self.session.post(url, data=data, allow_redirects=allow_redirects, timeout=15)
            return resp
        except requests.exceptions.RequestException as e:
            if self.verbose:
                self._log(REPORT_INFO, f"Request error: {e}")
            return None

    # ─────────────────────────────────────────────
    # TEST 1: Redirect URI Validation
    # ─────────────────────────────────────────────
    def test_redirect_uri_validation(self):
        """Test redirect_uri for open redirect and bypass vulnerabilities."""
        print(f"\n{Fore.YELLOW}{'='*60}")
        print(f"  TEST 1: Redirect URI Validation")
        print(f"{'='*60}{Style.RESET_ALL}")

        parsed = urlparse(self.redirect_uri)
        base_redirect = f"{parsed.scheme}://{parsed.netloc}"

        # Test 1a: Completely different redirect_uri
        evil_redirects = [
            ("https://evil.com/callback", "Completely different domain"),
            ("http://evil.com/callback", "Different scheme + domain"),
            ("https://evil" + parsed.netloc, "Prepended domain"),
            (self.redirect_uri + ".evil.com", "Appended domain"),
            (self.redirect_uri.replace("https://", "http://"), "HTTP downgrade"),
        ]

        for evil_uri, desc in evil_redirects:
            url = self._build_auth_url({"redirect_uri": evil_uri})
            resp = self._make_request(url)

            if resp is None:
                self._log(REPORT_INFO, f"Could not test: {desc}")
                continue

            # If server returns 302 to evil_uri or doesn't reject, it's vulnerable
            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("Location", "")
                if "evil" in location.lower():
                    self._log(REPORT_VULN, f"Redirect to different domain accepted: {desc}")
                    self._log(REPORT_INFO, f"  Location: {location[:120]}")
                    self._record("redirect_uri_different_domain", "redirect_uri",
                                "FAIL", f"{desc} -> {location[:200]}", "high")
                    continue

            if resp.status_code == 200:
                # Might be showing consent page with evil redirect
                self._log(REPORT_VULN, f"Evil redirect_uri not rejected (200): {desc}")
                self._record("redirect_uri_different_domain", "redirect_uri",
                            "FAIL", f"{desc} returned 200 (not rejected)", "high")
            else:
                self._log(REPORT_SAFE, f"Redirect blocked: {desc} (HTTP {resp.status_code})")
                self._record("redirect_uri_different_domain", "redirect_uri",
                            "PASS", f"{desc} rejected with HTTP {resp.status_code}")

        # Test 1b: Path traversal / manipulation on valid redirect_uri
        for payload in REDIRECT_BYPASS_PAYLOADS:
            evil_uri = self.redirect_uri + payload["suffix"]
            url = self._build_auth_url({"redirect_uri": evil_uri})
            resp = self._make_request(url)

            if resp is None:
                continue

            if resp.status_code in (200, 301, 302, 303, 307, 308):
                location = resp.headers.get("Location", "")
                if resp.status_code in (301, 302, 303, 307, 308) and "evil" in location.lower():
                    self._log(REPORT_VULN, f"Bypass successful: {payload['desc']}")
                    self._record("redirect_uri_bypass", "redirect_uri", "FAIL",
                                f"{payload['desc']} -> {location[:200]}", "high")
                elif resp.status_code == 200:
                    self._log(REPORT_VULN, f"Bypass not rejected: {payload['desc']}")
                    self._record("redirect_uri_bypass", "redirect_uri", "FAIL",
                                f"{payload['desc']} returned 200", "medium")
                else:
                    self._log(REPORT_SAFE, f"Bypass blocked: {payload['desc']}")
                    self._record("redirect_uri_bypass", "redirect_uri", "PASS",
                                f"{payload['desc']} rejected")
            else:
                self._log(REPORT_SAFE, f"Bypass blocked: {payload['desc']} (HTTP {resp.status_code})")
                self._record("redirect_uri_bypass", "redirect_uri", "PASS",
                            f"{payload['desc']} rejected HTTP {resp.status_code}")

        # Test 1c: Wildcard redirect_uri
        wildcard_tests = [
            ("*", "Wildcard redirect_uri"),
            ("https://*.example.com/callback", "Wildcard subdomain"),
        ]
        for uri, desc in wildcard_tests:
            url = self._build_auth_url({"redirect_uri": uri})
            resp = self._make_request(url)
            if resp and resp.status_code in (200, 302):
                self._log(REPORT_VULN, f"Wildcard accepted: {desc}")
                self._record("redirect_uri_wildcard", "redirect_uri", "FAIL",
                            f"{desc} accepted (HTTP {resp.status_code})", "high")
            elif resp:
                self._log(REPORT_SAFE, f"Wildcard rejected: {desc}")
                self._record("redirect_uri_wildcard", "redirect_uri", "PASS",
                            f"{desc} rejected")

    # ─────────────────────────────────────────────
    # TEST 2: State Parameter (CSRF)
    # ─────────────────────────────────────────────
    def test_state_parameter(self):
        """Test state parameter for CSRF protection."""
        print(f"\n{Fore.YELLOW}{'='*60}")
        print(f"  TEST 2: State Parameter (CSRF Protection)")
        print(f"{'='*60}{Style.RESET_ALL}")

        # Test 2a: No state parameter
        params = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "scope": "openid",
        }
        url = f"{self.base_url}/authorize?{urlencode(params)}"
        resp = self._make_request(url)

        if resp and resp.status_code in (200, 302):
            self._log(REPORT_VULN, "Authorization works without state parameter")
            self._record("state_missing", "state_csrf", "FAIL",
                        "No state parameter, still authorized (HTTP "
                        f"{resp.status_code})", "high")
        elif resp:
            self._log(REPORT_SAFE, "State parameter appears required")
            self._record("state_missing", "state_csrf", "PASS",
                        f"Rejected without state (HTTP {resp.status_code})")
        else:
            self._log(REPORT_INFO, "Could not test missing state")
            self._record("state_missing", "state_csrf", "ERROR", "Connection failed")

        # Test 2b: Empty state parameter
        url = self._build_auth_url({"state": ""})
        resp = self._make_request(url)
        if resp and resp.status_code in (200, 302):
            self._log(REPORT_VULN, "Authorization works with empty state parameter")
            self._record("state_empty", "state_csrf", "FAIL",
                        "Empty state accepted", "high")
        elif resp:
            self._log(REPORT_SAFE, "Empty state rejected")
            self._record("state_empty", "state_csrf", "PASS",
                        "Empty state rejected")
        else:
            self._record("state_empty", "state_csrf", "ERROR", "Connection failed")

        # Test 2c: Predictable/static state
        static_states = ["state", "1234", "test", "abc", "1", "csrf_token"]
        for state_val in static_states:
            url = self._build_auth_url({"state": state_val})
            resp = self._make_request(url)
            if resp and resp.status_code in (200, 302):
                self._log(REPORT_VULN, f"Static state accepted: '{state_val}'")
                self._record("state_predictable", "state_csrf", "FAIL",
                            f"Static state '{state_val}' accepted", "medium")
                break
        else:
            self._log(REPORT_INFO, "Static states tested - server accepted at least one (OAuth servers typically don't validate state on the authorization request)")

        # Test 2d: State not echoed back
        test_state = "unique_test_state_98765"
        url = self._build_auth_url({"state": test_state})
        resp = self._make_request(url, allow_redirects=False)
        if resp and resp.status_code in (301, 302, 303, 307, 308):
            location = resp.headers.get("Location", "")
            if test_state not in location and "state=" not in location:
                self._log(REPORT_VULN, "State parameter NOT echoed in redirect response")
                self._record("state_not_echoed", "state_csrf", "FAIL",
                            "State not returned in redirect", "high")
            else:
                self._log(REPORT_SAFE, "State parameter echoed in redirect")
                self._record("state_not_echoed", "state_csrf", "PASS",
                            "State echoed back correctly")

    # ─────────────────────────────────────────────
    # TEST 3: PKCE Enforcement
    # ─────────────────────────────────────────────
    def test_pkce_enforcement(self):
        """Test if PKCE (Proof Key for Code Exchange) is enforced."""
        print(f"\n{Fore.YELLOW}{'='*60}")
        print(f"  TEST 3: PKCE Enforcement")
        print(f"{'='*60}{Style.RESET_ALL}")

        # Test 3a: Authorization request without code_challenge
        url = self._build_auth_url()
        resp = self._make_request(url)

        if resp and resp.status_code in (200, 302):
            self._log(REPORT_VULN, "Authorization works without PKCE (no code_challenge)")
            self._record("pkce_not_required", "pkce", "FAIL",
                        "No code_challenge required for authorization", "medium")
        elif resp:
            self._log(REPORT_SAFE, "PKCE appears to be required")
            self._record("pkce_not_required", "pkce", "PASS",
                        f"Rejected without code_challenge (HTTP {resp.status_code})")
        else:
            self._record("pkce_not_required", "pkce", "ERROR", "Connection failed")

        # Test 3b: Token exchange without code_verifier
        # We attempt to exchange a dummy code without providing code_verifier
        token_url = f"{self.base_url}/token"
        token_data = {
            "grant_type": "authorization_code",
            "code": "dummy_code_for_pkce_test",
            "redirect_uri": self.redirect_uri,
            "client_id": self.client_id,
        }
        if self.client_secret:
            token_data["client_secret"] = self.client_secret

        resp = self._make_request(token_url, method="POST", data=token_data)
        if resp:
            try:
                body = resp.json()
            except Exception:
                body = {"raw": resp.text[:500]}

            # If error is NOT about missing code_verifier, PKCE isn't enforced
            err_str = json.dumps(body).lower()
            if "code_verifier" in err_str or "pkce" in err_str:
                self._log(REPORT_SAFE, "Token endpoint requires code_verifier (PKCE enforced)")
                self._record("pkce_token_exchange", "pkce", "PASS",
                            "code_verifier required at token endpoint")
            elif resp.status_code == 400 and ("invalid_grant" in err_str or "code" in err_str):
                # Got invalid_grant but not about PKCE - code_verifier not checked
                self._log(REPORT_VULN, "Token exchange doesn't mention code_verifier - PKCE may not be enforced")
                self._record("pkce_token_exchange", "pkce", "FAIL",
                            f"Error about code but not code_verifier: {json.dumps(body)[:200]}", "medium")
            else:
                self._log(REPORT_INFO, f"Token response: {json.dumps(body)[:200]}")
                self._record("pkce_token_exchange", "pkce", "INFO",
                            f"Response: {json.dumps(body)[:200]}")

    # ─────────────────────────────────────────────
    # TEST 4: Token Exchange
    # ─────────────────────────────────────────────
    def test_token_exchange(self):
        """Test token endpoint for code replay, expired code, wrong client_id."""
        print(f"\n{Fore.YELLOW}{'='*60}")
        print(f"  TEST 4: Token Exchange Vulnerabilities")
        print(f"{'='*60}{Style.RESET_ALL}")

        token_url = f"{self.base_url}/token"

        # Test 4a: Code replay (using same code twice)
        code_data = {
            "grant_type": "authorization_code",
            "code": "test_code_replay_12345",
            "redirect_uri": self.redirect_uri,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
        }

        resp1 = self._make_request(token_url, method="POST", data=code_data)
        resp2 = self._make_request(token_url, method="POST", data=code_data)

        if resp1 and resp2:
            # If both return same error, code is invalid. If first succeeds and second fails, good.
            self._log(REPORT_INFO, "Code replay test (using dummy code)")
            if resp1.status_code == 200 and resp2.status_code == 200:
                self._log(REPORT_VULN, "Same authorization code accepted twice!")
                self._record("code_replay", "token_exchange", "FAIL",
                            "Authorization code accepted on replay", "critical")
            else:
                err1 = resp1.text[:200]
                err2 = resp2.text[:200]
                self._log(REPORT_SAFE, "Code replay returned errors (expected with dummy code)")
                self._record("code_replay", "token_exchange", "PASS",
                            f"First: {err1[:100]}, Second: {err2[:100]}")

        # Test 4b: Wrong client_id in token exchange
        wrong_data = {
            "grant_type": "authorization_code",
            "code": "test_code_wrong_client",
            "redirect_uri": self.redirect_uri,
            "client_id": "wrong_client_id_99999",
            "client_secret": self.client_secret,
        }
        resp = self._make_request(token_url, method="POST", data=wrong_data)
        if resp:
            if resp.status_code == 200:
                self._log(REPORT_VULN, "Token exchange accepted wrong client_id!")
                self._record("wrong_client_id", "token_exchange", "FAIL",
                            "Wrong client_id accepted in token exchange", "critical")
            else:
                self._log(REPORT_SAFE, f"Wrong client_id rejected (HTTP {resp.status_code})")
                self._record("wrong_client_id", "token_exchange", "PASS",
                            f"Wrong client_id rejected: HTTP {resp.status_code}")

        # Test 4c: Wrong redirect_uri in token exchange
        wrong_redirect_data = {
            "grant_type": "authorization_code",
            "code": "test_code_wrong_redirect",
            "redirect_uri": "https://evil.com/callback",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
        }
        resp = self._make_request(token_url, method="POST", data=wrong_redirect_data)
        if resp:
            if resp.status_code == 200:
                self._log(REPORT_VULN, "Token exchange accepted wrong redirect_uri!")
                self._record("wrong_redirect_uri", "token_exchange", "FAIL",
                            "Wrong redirect_uri accepted in token exchange", "critical")
            else:
                self._log(REPORT_SAFE, f"Wrong redirect_uri rejected (HTTP {resp.status_code})")
                self._record("wrong_redirect_uri", "token_exchange", "PASS",
                            f"Wrong redirect_uri rejected: HTTP {resp.status_code}")

        # Test 4d: Missing client_secret (public client misconfiguration)
        no_secret_data = {
            "grant_type": "authorization_code",
            "code": "test_code_no_secret",
            "redirect_uri": self.redirect_uri,
            "client_id": self.client_id,
        }
        resp = self._make_request(token_url, method="POST", data=no_secret_data)
        if resp and resp.status_code == 200:
            self._log(REPORT_VULN, "Token exchange works without client_secret!")
            self._record("no_client_secret", "token_exchange", "FAIL",
                        "client_secret not required for confidential client", "high")
        elif resp:
            self._log(REPORT_SAFE, f"client_secret required (HTTP {resp.status_code})")
            self._record("no_client_secret", "token_exchange", "PASS",
                        "client_secret required")

    # ─────────────────────────────────────────────
    # TEST 5: Scope Escalation
    # ─────────────────────────────────────────────
    def test_scope_escalation(self):
        """Test for scope escalation vulnerabilities."""
        print(f"\n{Fore.YELLOW}{'='*60}")
        print(f"  TEST 5: Scope Escalation")
        print(f"{'='*60}{Style.RESET_ALL}")

        # Test with dangerous/elevated scopes
        dangerous_scopes = [
            "admin",
            "write",
            "delete",
            "superuser",
            "root",
            "internal",
            "manage_all",
            "full_access",
            "offline_access",
            "read write delete admin",
        ]

        token_url = f"{self.base_url}/token"

        for scope in dangerous_scopes:
            # Test at authorization endpoint
            auth_url = self._build_auth_url({"scope": scope})
            resp = self._make_request(auth_url)

            if resp and resp.status_code in (200, 302):
                self._log(REPORT_VULN, f"Elevated scope accepted at auth: '{scope}'")
                self._record(f"scope_escalation_{scope}", "scope_escalation", "FAIL",
                            f"Scope '{scope}' not rejected at authorization", "high")
            elif resp:
                self._log(REPORT_SAFE, f"Elevated scope rejected: '{scope}'")
                self._record(f"scope_escalation_{scope}", "scope_escalation", "PASS",
                            f"Scope '{scope}' rejected at authorization")

            # Test at token endpoint with scope param
            token_data = {
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "scope": scope,
            }
            resp = self._make_request(token_url, method="POST", data=token_data)
            if resp and resp.status_code == 200:
                try:
                    body = resp.json()
                    granted = body.get("scope", "")
                    if scope in granted or granted == scope:
                        self._log(REPORT_VULN, f"Scope '{scope}' granted via client_credentials!")
                        self._record(f"scope_grant_{scope}", "scope_escalation", "FAIL",
                                    f"Scope '{scope}' fully granted", "critical")
                    else:
                        self._log(REPORT_INFO, f"Scope narrowed: requested '{scope}', got '{granted}'")
                        self._record(f"scope_grant_{scope}", "scope_escalation", "PASS",
                                    f"Scope narrowed to '{granted}'")
                except json.JSONDecodeError:
                    pass

    # ─────────────────────────────────────────────
    # TEST 6: Grant Type Abuse
    # ─────────────────────────────────────────────
    def test_grant_type_abuse(self):
        """Test for grant type abuse vulnerabilities."""
        print(f"\n{Fore.YELLOW}{'='*60}")
        print(f"  TEST 6: Grant Type Abuse")
        print(f"{'='*60}{Style.RESET_ALL}")

        token_url = f"{self.base_url}/token"

        # Test 6a: client_credentials grant (shouldn't be available for public clients)
        cc_data = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "scope": "openid profile",
        }
        resp = self._make_request(token_url, method="POST", data=cc_data)
        if resp:
            if resp.status_code == 200:
                self._log(REPORT_VULN, "client_credentials grant accepted!")
                self._record("client_credentials", "grant_type_abuse", "FAIL",
                            "client_credentials grant type accepted", "high")
            else:
                self._log(REPORT_SAFE, f"client_credentials rejected (HTTP {resp.status_code})")
                self._record("client_credentials", "grant_type_abuse", "PASS",
                            f"client_credentials rejected: HTTP {resp.status_code}")

        # Test 6b: Token exchange grant (urn:ietf:params:oauth:grant-type:token-exchange)
        te_data = {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "subject_token": "dummy_token",
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
        }
        resp = self._make_request(token_url, method="POST", data=te_data)
        if resp:
            if resp.status_code == 200:
                self._log(REPORT_VULN, "Token exchange grant type accepted!")
                self._record("token_exchange_grant", "grant_type_abuse", "FAIL",
                            "Token exchange grant accepted", "high")
            else:
                self._log(REPORT_SAFE, f"Token exchange rejected (HTTP {resp.status_code})")
                self._record("token_exchange_grant", "grant_type_abuse", "PASS",
                            f"Token exchange rejected: HTTP {resp.status_code}")

        # Test 6c: Device authorization grant
        device_data = {
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "client_id": self.client_id,
            "device_code": "dummy_device_code",
        }
        resp = self._make_request(token_url, method="POST", data=device_data)
        if resp:
            if resp.status_code == 200:
                self._log(REPORT_VULN, "Device code grant accepted!")
                self._record("device_code_grant", "grant_type_abuse", "FAIL",
                            "Device code grant accepted", "medium")
            else:
                self._log(REPORT_SAFE, f"Device code grant rejected (HTTP {resp.status_code})")
                self._record("device_code_grant", "grant_type_abuse", "PASS",
                            f"Device code rejected: HTTP {resp.status_code}")

        # Test 6d: Password grant (Resource Owner Password Credentials)
        pw_data = {
            "grant_type": "password",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "username": "test_user@example.com",
            "password": "test_password_123",
        }
        resp = self._make_request(token_url, method="POST", data=pw_data)
        if resp:
            if resp.status_code == 200:
                self._log(REPORT_VULN, "Password grant (ROPC) accepted!")
                self._record("password_grant", "grant_type_abuse", "FAIL",
                            "Resource Owner Password Credentials grant accepted", "critical")
            else:
                self._log(REPORT_SAFE, f"Password grant rejected (HTTP {resp.status_code})")
                self._record("password_grant", "grant_type_abuse", "PASS",
                            f"ROPC grant rejected: HTTP {resp.status_code}")

        # Test 6e: Refresh token with elevated scope
        refresh_data = {
            "grant_type": "refresh_token",
            "refresh_token": "dummy_refresh_token",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "scope": "admin write delete",
        }
        resp = self._make_request(token_url, method="POST", data=refresh_data)
        if resp:
            if resp.status_code == 200:
                try:
                    body = resp.json()
                    granted = body.get("scope", "")
                    self._log(REPORT_VULN, f"Refresh token accepted with elevated scope: {granted}")
                    self._record("refresh_scope_escalation", "grant_type_abuse", "FAIL",
                                f"Refresh with elevated scope: {granted}", "high")
                except json.JSONDecodeError:
                    pass
            else:
                self._log(REPORT_INFO, f"Refresh token test: HTTP {resp.status_code}")
                self._record("refresh_scope_escalation", "grant_type_abuse", "INFO",
                            f"Refresh token response: HTTP {resp.status_code}")

    # ─────────────────────────────────────────────
    # Discovery: Check common OAuth endpoints
    # ─────────────────────────────────────────────
    def discover_endpoints(self):
        """Discover OAuth endpoints by probing common paths."""
        print(f"\n{Fore.YELLOW}{'='*60}")
        print(f"  Endpoint Discovery")
        print(f"{'='*60}{Style.RESET_ALL}")

        paths = [
            "/.well-known/oauth-authorization-server",
            "/.well-known/openid-configuration",
            "/.well-known/oauth-oidc-discovery",
            "/oauth/authorize",
            "/oauth/token",
            "/oauth/revoke",
            "/oauth/introspect",
            "/connect/authorize",
            "/connect/token",
            "/o/authorize",
            "/o/token",
        ]

        found = []
        parsed = urlparse(self.base_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        for path in paths:
            url = origin + path
            resp = self._make_request(url)
            if resp and resp.status_code in (200, 301, 302):
                self._log(REPORT_INFO, f"Found: {path} (HTTP {resp.status_code})")
                found.append({"path": path, "status": resp.status_code})
            elif self.verbose:
                self._log(REPORT_INFO, f"Not found: {path}")

        if not found:
            self._log(REPORT_INFO, "No additional endpoints discovered")

        return found

    def run_all(self):
        """Run all OAuth security tests."""
        print(BANNER)
        print(f"  {Fore.WHITE}Target: {self.base_url}")
        print(f"  Client ID: {self.client_id}")
        print(f"  Redirect URI: {self.redirect_uri}")
        print(f"  {'='*56}{Style.RESET_ALL}")

        # Discover endpoints first
        self.discover_endpoints()

        # Run all test suites
        self.test_redirect_uri_validation()
        self.test_state_parameter()
        self.test_pkce_enforcement()
        self.test_token_exchange()
        self.test_scope_escalation()
        self.test_grant_type_abuse()

        # Print summary
        self._print_summary()
        return self.results

    def _print_summary(self):
        """Print test results summary."""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"  SCAN SUMMARY")
        print(f"{'='*60}{Style.RESET_ALL}")

        total = len(self.results)
        vulns = sum(1 for r in self.results if r["result"] == "FAIL")
        safe = sum(1 for r in self.results if r["result"] == "PASS")
        errors = sum(1 for r in self.results if r["result"] in ("ERROR", "INFO"))

        print(f"  Total tests: {total}")
        print(f"  {Fore.RED}Vulnerabilities: {vulns}{Style.RESET_ALL}")
        print(f"  {Fore.GREEN}Passed: {safe}{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}Info/Error: {errors}{Style.RESET_ALL}")

        if vulns > 0:
            print(f"\n  {Fore.RED}⚠  {vulns} potential issues found!{Style.RESET_ALL}")
            # Show high/critical findings
            critical = [r for r in self.results
                       if r["result"] == "FAIL" and r["severity"] in ("critical", "high")]
            if critical:
                print(f"\n  {Fore.RED}Critical/High findings:{Style.RESET_ALL}")
                for r in critical:
                    print(f"    • [{r['severity'].upper()}] {r['test']}: {r['evidence'][:100]}")
        else:
            print(f"\n  {Fore.GREEN}✓ No obvious vulnerabilities detected{Style.RESET_ALL}")

    def export_json(self, output_path: str = None) -> str:
        """Export results as JSON."""
        report = {
            "tool": "oauth_tester",
            "version": "5.0",
            "target": self.base_url,
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "scan_time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "total_tests": len(self.results),
            "vulnerabilities": sum(1 for r in self.results if r["result"] == "FAIL"),
            "passed": sum(1 for r in self.results if r["result"] == "PASS"),
            "results": self.results,
        }
        json_str = json.dumps(report, indent=2)
        if output_path:
            with open(output_path, "w") as f:
                f.write(json_str)
        return json_str


def main():
    parser = argparse.ArgumentParser(
        description="OAuth 2.0 Security Tester - Tests OAuth implementations for common vulnerabilities",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --base-url https://auth.example.com --client-id abc123 --redirect-uri https://app.example.com/callback
  %(prog)s --base-url https://auth.example.com --client-id abc123 --redirect-uri https://app.example.com/callback --output json --json-file results.json
  %(prog)s --base-url https://auth.example.com --client-id abc123 --redirect-uri https://app.example.com/callback --client-secret secret123 -v
        """
    )
    parser.add_argument("--base-url", required=True, help="Base OAuth URL (e.g., https://auth.example.com)")
    parser.add_argument("--client-id", required=True, help="OAuth client ID")
    parser.add_argument("--redirect-uri", required=True, help="Expected redirect URI")
    parser.add_argument("--client-secret", default=None, help="OAuth client secret (optional)")
    parser.add_argument("--output", choices=["json", "text"], default="text",
                        help="Output format (default: text)")
    parser.add_argument("--json-file", help="Save JSON output to file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    tester = OAuthTester(
        base_url=args.base_url,
        client_id=args.client_id,
        redirect_uri=args.redirect_uri,
        client_secret=args.client_secret,
        verbose=args.verbose,
    )

    results = tester.run_all()

    if args.output == "json":
        json_output = tester.export_json(args.json_file)
        if args.output == "json":
            print(json_output)
    elif args.json_file:
        tester.export_json(args.json_file)
        print(f"\n  {Fore.GREEN}JSON results saved to: {args.json_file}{Style.RESET_ALL}")


if __name__ == "__main__":
    main()
