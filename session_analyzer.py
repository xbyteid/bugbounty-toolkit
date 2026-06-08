#!/usr/bin/env python3
"""
Session Cookie Security Analyzer
=================================
Analyzes session cookies for security misconfigurations including:
- Missing security flags (SameSite, HttpOnly, Secure)
- Domain scope issues
- Session fixation vulnerabilities
- CSRF token presence in forms
- Cookie tossing attack surface

Part of the Bug Bounty Toolkit v5.0

Usage:
    python3 session_analyzer.py --url https://example.com
    python3 session_analyzer.py --url https://example.com --login-url https://example.com/login --login-data "user=admin&pass=test"
    python3 session_analyzer.py --url https://example.com --output json --json-file results.json
"""

import argparse
import json
import re
import sys
import time
from http.cookiejar import CookieJar
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, urljoin

try:
    import requests
    from colorama import init, Fore, Style
    init(autoreset=True)
except ImportError:
    print("Install dependencies: pip install requests colorama")
    sys.exit(1)

BANNER = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗
║  ╔═╗╔═╗╔═╗  ╔═╗╔═╗╔═╗╦═╗╦╔═╗┌─┐┌┬┐                        ║
║  ╚═╗║  ║ ║  ║  ║ ║║ ║╠╦╝║╚═╗├┤  ││                        ║
║  ╚═╝╚═╝╚═╝  ╚═╝╚═╝╚═╝╩╚═╩╚═╝└─┘─┴┘                        ║
║  Security Analyzer v5.0                                      ║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""

# Known session cookie names
SESSION_COOKIE_NAMES = {
    "session", "sessionid", "session_id", "sess", "sid",
    "phpsessid", "phpsess", "aspsessionid", "asp.net_sessionid",
    "jsessionid", "jessionid", "jsession",
    "connect.sid", "express.sid",
    "_session", "_session_id", "rack.session",
    "laravel_session", "xsrftoken", "csrf_token",
    "remember_token", "auth_token", "access_token",
    "jwt", "token", "bearer",
    "ssession", "sessioncookie", "appsession",
    "user_session", "usersession", "logged_in",
    "wordpress_logged_in", "wp-settings",
    "__session", "__cfduid", "__cfruid",
}

# Patterns for detecting session-like cookies
SESSION_PATTERNS = [
    r"sess",
    r"sid$",
    r"session",
    r"auth",
    r"token",
    r"login",
    r"jwt",
    r"bearer",
]


class SessionAnalyzer:
    """Session Cookie Security Analyzer."""

    def __init__(self, url: str, verbose: bool = False, timeout: int = 15):
        self.url = url
        self.verbose = verbose
        self.timeout = timeout
        self.parsed_url = urlparse(url)
        self.domain = self.parsed_url.netloc
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "SessionAnalyzer/5.0 (Security Audit)"
        })
        self.session.verify = True
        self.cookie_results = []
        self.general_results = []

    def _log(self, level: str, message: str):
        """Log a message."""
        print(f"  {level} {message}")

    def _record_cookie(self, cookie_name: str, check: str, result: str,
                       evidence: str = "", severity: str = "info"):
        """Record a cookie check result."""
        self.cookie_results.append({
            "cookie": cookie_name,
            "check": check,
            "result": result,
            "evidence": evidence,
            "severity": severity,
        })

    def _record_general(self, check: str, result: str, evidence: str = "",
                        severity: str = "info"):
        """Record a general check result."""
        self.general_results.append({
            "check": check,
            "result": result,
            "evidence": evidence,
            "severity": severity,
        })

    def _is_session_cookie(self, name: str) -> bool:
        """Determine if a cookie is likely a session cookie."""
        name_lower = name.lower()
        if name_lower in SESSION_COOKIE_NAMES:
            return True
        for pattern in SESSION_PATTERNS:
            if re.search(pattern, name_lower):
                return True
        return False

    def _parse_set_cookie(self, set_cookie_header: str) -> dict:
        """Parse a Set-Cookie header into components."""
        parts = set_cookie_header.split(";")
        cookie = {"raw": set_cookie_header, "attributes": {}}

        # First part is name=value
        if parts:
            nv = parts[0].strip()
            if "=" in nv:
                name, value = nv.split("=", 1)
                cookie["name"] = name.strip()
                cookie["value"] = value.strip()
            else:
                cookie["name"] = nv
                cookie["value"] = ""

        # Parse attributes
        for part in parts[1:]:
            part = part.strip()
            if "=" in part:
                key, val = part.split("=", 1)
                cookie["attributes"][key.strip().lower()] = val.strip()
            else:
                cookie["attributes"][part.lower()] = True

        return cookie

    # ─────────────────────────────────────────────
    # TEST 1: Cookie Security Flags
    # ─────────────────────────────────────────────
    def analyze_cookie_flags(self, cookies: List[dict]):
        """Analyze security flags on all cookies."""
        print(f"\n{Fore.YELLOW}{'='*60}")
        print(f"  TEST 1: Cookie Security Flags Analysis")
        print(f"{'='*60}{Style.RESET_ALL}")

        if not cookies:
            self._log(Fore.YELLOW + "[INFO]" + Style.RESET_ALL, "No Set-Cookie headers found")
            self._record_general("cookies_found", "INFO", "No cookies in response")
            return

        for cookie in cookies:
            name = cookie.get("name", "unknown")
            attrs = cookie.get("attributes", {})
            is_session = self._is_session_cookie(name)

            marker = f"{Fore.CYAN}[SESSION]{Style.RESET_ALL}" if is_session else f"{Fore.WHITE}[COOKIE]{Style.RESET_ALL}"
            print(f"\n  {marker} Cookie: {Fore.WHITE}{name}{Style.RESET_ALL}")
            print(f"    Value: {cookie.get('value', '')[:60]}{'...' if len(cookie.get('value', '')) > 60 else ''}")

            # Check HttpOnly
            if "httponly" in attrs:
                print(f"    {Fore.GREEN}✓{Style.RESET_ALL} HttpOnly: Set")
                self._record_cookie(name, "httponly", "PASS", "HttpOnly flag is set")
            else:
                severity = "high" if is_session else "medium"
                print(f"    {Fore.RED}✗{Style.RESET_ALL} HttpOnly: NOT set {'(CRITICAL for session cookie)' if is_session else ''}")
                self._record_cookie(name, "httponly", "FAIL",
                                  "HttpOnly flag missing", severity)

            # Check Secure
            if "secure" in attrs:
                print(f"    {Fore.GREEN}✓{Style.RESET_ALL} Secure: Set")
                self._record_cookie(name, "secure", "PASS", "Secure flag is set")
            else:
                severity = "high" if is_session else "medium"
                print(f"    {Fore.RED}✗{Style.RESET_ALL} Secure: NOT set {'(CRITICAL for session cookie)' if is_session else ''}")
                self._record_cookie(name, "secure", "FAIL",
                                  "Secure flag missing - cookie sent over HTTP", severity)

            # Check SameSite
            samesite = attrs.get("samesite", None)
            if samesite:
                ss_lower = str(samesite).lower()
                if ss_lower == "strict":
                    print(f"    {Fore.GREEN}✓{Style.RESET_ALL} SameSite: Strict (best)")
                    self._record_cookie(name, "samesite", "PASS", "SameSite=Strict")
                elif ss_lower == "lax":
                    print(f"    {Fore.GREEN}✓{Style.RESET_ALL} SameSite: Lax (acceptable)")
                    self._record_cookie(name, "samesite", "PASS", "SameSite=Lax")
                elif ss_lower == "none":
                    if "secure" in attrs:
                        print(f"    {Fore.YELLOW}⚠{Style.RESET_ALL} SameSite: None (requires Secure)")
                        self._record_cookie(name, "samesite", "WARN",
                                          "SameSite=None (cross-site allowed)", "medium")
                    else:
                        print(f"    {Fore.RED}✗{Style.RESET_ALL} SameSite: None WITHOUT Secure flag!")
                        self._record_cookie(name, "samesite", "FAIL",
                                          "SameSite=None without Secure", "high")
                else:
                    print(f"    {Fore.YELLOW}⚠{Style.RESET_ALL} SameSite: {samesite} (unusual)")
                    self._record_cookie(name, "samesite", "WARN",
                                      f"SameSite={samesite}", "low")
            else:
                print(f"    {Fore.YELLOW}⚠{Style.RESET_ALL} SameSite: NOT set (browser default: Lax)")
                self._record_cookie(name, "samesite", "WARN",
                                  "SameSite not set - relies on browser default", "medium")

            # Check Domain
            domain = attrs.get("domain", None)
            if domain:
                if domain.startswith("."):
                    check_domain = domain[1:]
                else:
                    check_domain = domain

                if check_domain == self.domain:
                    print(f"    {Fore.GREEN}✓{Style.RESET_ALL} Domain: {domain} (matches request domain)")
                    self._record_cookie(name, "domain", "PASS",
                                      f"Domain={domain} matches request domain")
                elif check_domain.endswith(f".{self.domain.split(':')[0]}"):
                    print(f"    {Fore.YELLOW}⚠{Style.RESET_ALL} Domain: {domain} (broader scope)")
                    self._record_cookie(name, "domain", "WARN",
                                      f"Domain={domain} broader than request domain", "medium")
                else:
                    print(f"    {Fore.RED}✗{Style.RESET_ALL} Domain: {domain} (DIFFERENT from request domain!)")
                    self._record_cookie(name, "domain", "FAIL",
                                      f"Domain={domain} mismatches request", "high")
            else:
                print(f"    {Fore.GREEN}✓{Style.RESET_ALL} Domain: Not set (default: request host only)")
                self._record_cookie(name, "domain", "PASS",
                                  "No Domain attribute (host-only)")

            # Check Path
            path = attrs.get("path", None)
            if path:
                if path == "/":
                    print(f"    {Fore.YELLOW}⚠{Style.RESET_ALL} Path: / (entire site)")
                    self._record_cookie(name, "path", "WARN",
                                      "Path=/ (cookie sent for all paths)", "low")
                else:
                    print(f"    {Fore.GREEN}✓{Style.RESET_ALL} Path: {path}")
                    self._record_cookie(name, "path", "PASS", f"Path={path}")
            else:
                print(f"    {Fore.YELLOW}⚠{Style.RESET_ALL} Path: Not set (default: current path)")
                self._record_cookie(name, "path", "INFO", "Path not set")

            # Check Expiry
            expires = attrs.get("expires", None)
            max_age = attrs.get("max-age", None)
            if expires:
                print(f"    {Fore.CYAN}ℹ{Style.RESET_ALL} Expires: {expires}")
                self._record_cookie(name, "expiry", "INFO", f"Expires={expires}")
            elif max_age:
                try:
                    age = int(max_age)
                    if age > 86400 * 365:
                        print(f"    {Fore.YELLOW}⚠{Style.RESET_ALL} Max-Age: {max_age}s ({age // 86400} days - very long!)")
                        self._record_cookie(name, "expiry", "WARN",
                                          f"Max-Age={max_age} ({age // 86400} days)", "medium")
                    else:
                        print(f"    {Fore.GREEN}✓{Style.RESET_ALL} Max-Age: {max_age}s ({age // 86400} days)")
                        self._record_cookie(name, "expiry", "PASS", f"Max-Age={max_age}")
                except ValueError:
                    print(f"    {Fore.YELLOW}⚠{Style.RESET_ALL} Max-Age: {max_age}")
                    self._record_cookie(name, "expiry", "INFO", f"Max-Age={max_age}")
            else:
                print(f"    {Fore.YELLOW}⚠{Style.RESET_ALL} Expiry: Session cookie (no persistent expiry)")
                self._record_cookie(name, "expiry", "INFO",
                                  "Session cookie - no Expires/Max-Age")

    # ─────────────────────────────────────────────
    # TEST 2: Session Fixation
    # ─────────────────────────────────────────────
    def test_session_fixation(self, login_url: str = None, login_data: dict = None,
                              login_method: str = "POST"):
        """Test for session fixation by comparing cookies before and after login."""
        print(f"\n{Fore.YELLOW}{'='*60}")
        print(f"  TEST 2: Session Fixation Test")
        print(f"{'='*60}{Style.RESET_ALL}")

        if not login_url:
            self._log(Fore.YELLOW + "[INFO]" + Style.RESET_ALL,
                      "No login URL provided. Use --login-url to test session fixation.")
            self._record_general("session_fixation", "SKIPPED",
                               "No login URL provided")
            return

        # Step 1: Get pre-login session cookies
        self._log(Fore.CYAN + "[TEST]" + Style.RESET_ALL, "Fetching pre-login cookies...")
        try:
            resp1 = self.session.get(self.url, timeout=self.timeout, allow_redirects=True)
            pre_cookies = {c.name: c.value for c in self.session.cookies}
            pre_session_ids = {}
            for name, value in pre_cookies.items():
                if self._is_session_cookie(name):
                    pre_session_ids[name] = value
            self._log(Fore.CYAN + "[INFO]" + Style.RESET_ALL,
                      f"Pre-login session cookies: {list(pre_session_ids.keys())}")
        except requests.exceptions.RequestException as e:
            self._log(Fore.RED + "[ERROR]" + Style.RESET_ALL, f"Failed to fetch pre-login cookies: {e}")
            self._record_general("session_fixation", "ERROR", str(e))
            return

        # Step 2: Attempt login
        self._log(Fore.CYAN + "[TEST]" + Style.RESET_ALL, f"Attempting login at {login_url}...")
        try:
            if login_method.upper() == "POST":
                resp2 = self.session.post(login_url, data=login_data, timeout=self.timeout,
                                         allow_redirects=True)
            else:
                resp2 = self.session.get(login_url, params=login_data, timeout=self.timeout,
                                        allow_redirects=True)

            post_cookies = {c.name: c.value for c in self.session.cookies}
            post_session_ids = {}
            for name, value in post_cookies.items():
                if self._is_session_cookie(name):
                    post_session_ids[name] = value

            self._log(Fore.CYAN + "[INFO]" + Style.RESET_ALL,
                      f"Post-login cookies: HTTP {resp2.status_code}")
        except requests.exceptions.RequestException as e:
            self._log(Fore.RED + "[ERROR]" + Style.RESET_ALL, f"Login request failed: {e}")
            self._record_general("session_fixation", "ERROR", str(e))
            return

        # Step 3: Compare session IDs
        if not pre_session_ids and not post_session_ids:
            self._log(Fore.YELLOW + "[INFO]" + Style.RESET_ALL,
                      "No session cookies found before or after login")
            self._record_general("session_fixation", "INFO",
                               "No session cookies detected")
            return

        all_names = set(pre_session_ids.keys()) | set(post_session_ids.keys())
        for name in all_names:
            pre_val = pre_session_ids.get(name)
            post_val = post_session_ids.get(name)

            if pre_val is None and post_val is not None:
                print(f"    {Fore.YELLOW}⚠{Style.RESET_ALL} {name}: New cookie after login (not in pre-login)")
                self._record_cookie(name, "session_fixation", "INFO",
                                  "Cookie appeared after login", "low")
            elif pre_val is not None and post_val is None:
                print(f"    {Fore.YELLOW}⚠{Style.RESET_ALL} {name}: Cookie removed after login")
                self._record_cookie(name, "session_fixation", "WARN",
                                  "Cookie removed after login", "medium")
            elif pre_val == post_val:
                print(f"    {Fore.RED}✗{Style.RESET_ALL} {name}: Session ID UNCHANGED after login!")
                print(f"         Pre:  {pre_val[:40]}...")
                print(f"         Post: {post_val[:40]}...")
                self._record_cookie(name, "session_fixation", "FAIL",
                                  f"Session ID unchanged: {pre_val[:30]}...", "critical")
            else:
                print(f"    {Fore.GREEN}✓{Style.RESET_ALL} {name}: Session ID CHANGED after login (good)")
                self._record_cookie(name, "session_fixation", "PASS",
                                  "Session ID rotated after login")

    # ─────────────────────────────────────────────
    # TEST 3: CSRF Token Detection
    # ─────────────────────────────────────────────
    def test_csrf_tokens(self):
        """Check for CSRF tokens in HTML forms."""
        print(f"\n{Fore.YELLOW}{'='*60}")
        print(f"  TEST 3: CSRF Token Detection")
        print(f"{'='*60}{Style.RESET_ALL}")

        try:
            resp = self.session.get(self.url, timeout=self.timeout, allow_redirects=True)
        except requests.exceptions.RequestException as e:
            self._log(Fore.RED + "[ERROR]" + Style.RESET_ALL, f"Failed to fetch page: {e}")
            self._record_general("csrf_tokens", "ERROR", str(e))
            return

        html = resp.text

        # Find all forms
        forms = re.findall(r'<form[^>]*>(.*?)</form>', html, re.DOTALL | re.IGNORECASE)
        if not forms:
            self._log(Fore.YELLOW + "[INFO]" + Style.RESET_ALL, "No forms found on page")
            self._record_general("csrf_forms", "INFO", "No forms found")
            return

        self._log(Fore.CYAN + "[INFO]" + Style.RESET_ALL, f"Found {len(forms)} form(s)")

        csrf_field_names = [
            "csrf", "csrftoken", "csrf_token", "csrf-token", "_csrf",
            "xsrf", "xsrf-token", "xsrftoken", "_token", "authenticity_token",
            "__RequestVerificationToken", "token", "nonce", "_wpnonce",
            "antiforgery", "__token",
        ]

        for i, form_html in enumerate(forms):
            print(f"\n  {Fore.CYAN}Form #{i+1}:{Style.RESET_ALL}")

            # Extract form method
            form_match = re.search(r'<form([^>]*)>', html.split(form_html)[0][-500:] if form_html in html else "", re.IGNORECASE)
            method_match = re.search(r'method=["\']?(\w+)', html, re.IGNORECASE)

            # Find all hidden inputs
            hidden_inputs = re.findall(
                r'<input[^>]*type=["\']hidden["\'][^>]*>',
                form_html, re.IGNORECASE
            )
            # Also check without type=hidden
            all_inputs = re.findall(
                r'<input[^>]*name=["\']([^"\']+)["\'][^>]*>',
                form_html, re.IGNORECASE
            )

            has_csrf = False
            csrf_field = None

            for inp in hidden_inputs:
                name_match = re.search(r'name=["\']([^"\']+)["\']', inp, re.IGNORECASE)
                if name_match:
                    name = name_match.group(1).lower()
                    if any(csrf_name in name for csrf_name in csrf_field_names):
                        has_csrf = True
                        csrf_field = name_match.group(1)
                        print(f"    {Fore.GREEN}✓{Style.RESET_ALL} CSRF field found: {csrf_field}")
                        self._record_general(f"csrf_form_{i+1}", "PASS",
                                           f"CSRF token field: {csrf_field}")
                        break

            if not has_csrf:
                print(f"    {Fore.RED}✗{Style.RESET_ALL} No CSRF token found in hidden fields")
                print(f"         Fields found: {all_inputs[:5]}")
                self._record_general(f"csrf_form_{i+1}", "FAIL",
                                   f"No CSRF field. Found: {all_inputs[:5]}", "high")

    # ─────────────────────────────────────────────
    # TEST 4: Cookie Tossing
    # ─────────────────────────────────────────────
    def test_cookie_tossing(self):
        """Check for cookie tossing attack surface (subdomain cookie scope)."""
        print(f"\n{Fore.YELLOW}{'='*60}")
        print(f"  TEST 4: Cookie Tossing Attack Surface")
        print(f"{'='*60}{Style.RESET_ALL}")

        # Fetch page to collect cookies
        try:
            resp = self.session.get(self.url, timeout=self.timeout, allow_redirects=True)
        except requests.exceptions.RequestException as e:
            self._log(Fore.RED + "[ERROR]" + Style.RESET_ALL, f"Request failed: {e}")
            return

        # Analyze Set-Cookie headers from response
        set_cookie_headers = resp.headers.get("Set-Cookie", "")

        # Also check all response headers for Set-Cookie
        all_set_cookies = []
        for header_name, header_value in resp.headers.items():
            if header_name.lower() == "set-cookie":
                all_set_cookies.append(header_value)

        # Also check for comma-separated cookies in a single header
        if set_cookie_headers and not all_set_cookies:
            all_set_cookies = [set_cookie_headers]

        if not all_set_cookies:
            self._log(Fore.YELLOW + "[INFO]" + Style.RESET_ALL,
                      "No Set-Cookie headers in response (checking session cookies)")
            # Check session cookies that might have domain issues
            for cookie in self.session.cookies:
                if cookie.domain:
                    self._analyze_cookie_domain(cookie.name, cookie.domain)
            return

        for cookie_header in all_set_cookies:
            cookie = self._parse_set_cookie(cookie_header)
            name = cookie.get("name", "unknown")
            domain = cookie.get("attributes", {}).get("domain", None)

            self._analyze_cookie_domain(name, domain)

    def _analyze_cookie_domain(self, name: str, domain: Optional[str]):
        """Analyze a cookie's domain for tossing risk."""
        if not domain:
            print(f"    {Fore.GREEN}✓{Style.RESET_ALL} {name}: No Domain attribute (host-only, safe)")
            self._record_cookie(name, "cookie_tossing", "PASS",
                              "No Domain attribute - host-only cookie")
            return

        # Clean domain
        clean_domain = domain.lstrip(".")

        # Check if domain is overly broad
        request_parts = self.domain.split(".")
        domain_parts = clean_domain.split(".")

        if clean_domain == self.domain:
            print(f"    {Fore.GREEN}✓{Style.RESET_ALL} {name}: Domain={domain} (exact match)")
            self._record_cookie(name, "cookie_tossing", "PASS",
                              f"Domain={domain} exact match")
        elif len(domain_parts) < len(request_parts):
            # Domain is a parent domain
            print(f"    {Fore.RED}✗{Style.RESET_ALL} {name}: Domain={domain} (PARENT domain - cookie tossing risk!)")
            print(f"         Any subdomain can set/overwrite this cookie")
            self._record_cookie(name, "cookie_tossing", "FAIL",
                              f"Domain={domain} is parent domain - subdomain can overwrite", "high")
        elif domain.startswith(".") or clean_domain != self.domain:
            # Subdomain or sibling domain
            if self.domain.endswith(clean_domain):
                print(f"    {Fore.YELLOW}⚠{Style.RESET_ALL} {name}: Domain={domain} (includes subdomains)")
                self._record_cookie(name, "cookie_tossing", "WARN",
                                  f"Domain={domain} covers subdomains", "medium")
            else:
                print(f"    {Fore.RED}✗{Style.RESET_ALL} {name}: Domain={domain} (DIFFERENT domain!)")
                self._record_cookie(name, "cookie_tossing", "FAIL",
                                  f"Domain={domain} different from request domain", "high")
        else:
            print(f"    {Fore.GREEN}✓{Style.RESET_ALL} {name}: Domain={domain}")
            self._record_cookie(name, "cookie_tossing", "PASS",
                              f"Domain={domain}")

    # ─────────────────────────────────────────────
    # TEST 5: Additional Security Headers
    # ─────────────────────────────────────────────
    def check_security_headers(self):
        """Check for important security headers."""
        print(f"\n{Fore.YELLOW}{'='*60}")
        print(f"  TEST 5: Security Headers")
        print(f"{'='*60}{Style.RESET_ALL}")

        try:
            resp = self.session.get(self.url, timeout=self.timeout, allow_redirects=True)
        except requests.exceptions.RequestException as e:
            self._log(Fore.RED + "[ERROR]" + Style.RESET_ALL, f"Request failed: {e}")
            return

        headers = {k.lower(): v for k, v in resp.headers.items()}

        security_headers = {
            "strict-transport-security": {
                "desc": "HSTS",
                "severity": "high",
            },
            "x-content-type-options": {
                "desc": "X-Content-Type-Options",
                "severity": "medium",
            },
            "x-frame-options": {
                "desc": "X-Frame-Options",
                "severity": "medium",
            },
            "content-security-policy": {
                "desc": "Content-Security-Policy",
                "severity": "high",
            },
            "x-xss-protection": {
                "desc": "X-XSS-Protection",
                "severity": "low",
            },
            "referrer-policy": {
                "desc": "Referrer-Policy",
                "severity": "medium",
            },
            "permissions-policy": {
                "desc": "Permissions-Policy",
                "severity": "low",
            },
            "set-cookie": {
                "desc": "Set-Cookie",
                "severity": "info",
            },
        }

        for header_name, info in security_headers.items():
            value = headers.get(header_name)
            if value:
                if header_name == "set-cookie":
                    continue  # Already analyzed
                print(f"    {Fore.GREEN}✓{Style.RESET_ALL} {info['desc']}: {value[:80]}{'...' if len(str(value)) > 80 else ''}")
                self._record_general(f"header_{header_name}", "PASS",
                                   f"{info['desc']} present: {value[:100]}")
            else:
                severity = info["severity"]
                icon = Fore.RED + "✗" + Style.RESET_ALL if severity in ("high", "medium") else Fore.YELLOW + "⚠" + Style.RESET_ALL
                print(f"    {icon} {info['desc']}: NOT set")
                self._record_general(f"header_{header_name}", "FAIL" if severity == "high" else "WARN",
                                   f"{info['desc']} header missing", severity)

    def run_all(self, login_url: str = None, login_data: dict = None,
                login_method: str = "POST"):
        """Run all session analysis tests."""
        print(BANNER)
        print(f"  {Fore.WHITE}Target: {self.url}")
        print(f"  Domain: {self.domain}")
        if login_url:
            print(f"  Login URL: {login_url}")
        print(f"  {'='*56}{Style.RESET_ALL}")

        # Step 1: Fetch initial page and collect cookies
        self._log(Fore.CYAN + "[*]" + Style.RESET_ALL, "Fetching target URL...")
        try:
            resp = self.session.get(self.url, timeout=self.timeout, allow_redirects=True)
            self._log(Fore.CYAN + "[*]" + Style.RESET_ALL,
                      f"Response: HTTP {resp.status_code} ({len(resp.content)} bytes)")

            # Parse Set-Cookie headers
            cookies = []
            for header_name, header_value in resp.headers.items():
                if header_name.lower() == "set-cookie":
                    parsed = self._parse_set_cookie(header_value)
                    cookies.append(parsed)

            # Also add cookies from jar
            for c in self.session.cookies:
                if not any(co.get("name") == c.name for co in cookies):
                    cookies.append({
                        "name": c.name,
                        "value": c.value,
                        "attributes": {
                            "domain": c.domain,
                            "path": c.path,
                        },
                    })

            self._log(Fore.CYAN + "[*]" + Style.RESET_ALL,
                      f"Found {len(cookies)} cookie(s)")

        except requests.exceptions.RequestException as e:
            self._log(Fore.RED + "[ERROR]" + Style.RESET_ALL, f"Failed to fetch target: {e}")
            return

        # Run tests
        self.analyze_cookie_flags(cookies)
        self.test_session_fixation(login_url, login_data, login_method)
        self.test_csrf_tokens()
        self.test_cookie_tossing()
        self.check_security_headers()

        # Summary
        self._print_summary()
        return self.cookie_results + self.general_results

    def _print_summary(self):
        """Print analysis summary."""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"  ANALYSIS SUMMARY")
        print(f"{'='*60}{Style.RESET_ALL}")

        all_results = self.cookie_results + self.general_results
        total = len(all_results)
        fails = sum(1 for r in all_results if r["result"] == "FAIL")
        passes = sum(1 for r in all_results if r["result"] == "PASS")
        warns = sum(1 for r in all_results if r["result"] in ("WARN", "INFO"))

        print(f"  Total checks: {total}")
        print(f"  {Fore.GREEN}Passed: {passes}{Style.RESET_ALL}")
        print(f"  {Fore.RED}Failed: {fails}{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}Warnings: {warns}{Style.RESET_ALL}")

        # Show critical/high findings
        critical = [r for r in all_results
                   if r["result"] == "FAIL" and r.get("severity") in ("critical", "high")]
        if critical:
            print(f"\n  {Fore.RED}{'='*56}")
            print(f"  ⚠ CRITICAL/HIGH FINDINGS ({len(critical)})")
            print(f"  {'='*56}{Style.RESET_ALL}")
            for r in critical:
                cookie = r.get("cookie", "")
                check = r.get("check", "")
                evidence = r.get("evidence", "")[:100]
                print(f"    {Fore.RED}•{Style.RESET_ALL} [{cookie or 'general'}] {check}: {evidence}")

        if fails == 0:
            print(f"\n  {Fore.GREEN}✓ No critical cookie security issues detected{Style.RESET_ALL}")

    def export_json(self, output_path: str = None) -> str:
        """Export results as JSON."""
        all_results = self.cookie_results + self.general_results
        report = {
            "tool": "session_analyzer",
            "version": "5.0",
            "target": self.url,
            "domain": self.domain,
            "scan_time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "total_checks": len(all_results),
            "failures": sum(1 for r in all_results if r["result"] == "FAIL"),
            "passes": sum(1 for r in all_results if r["result"] == "PASS"),
            "cookie_checks": self.cookie_results,
            "general_checks": self.general_results,
        }
        json_str = json.dumps(report, indent=2)
        if output_path:
            with open(output_path, "w") as f:
                f.write(json_str)
        return json_str


def main():
    parser = argparse.ArgumentParser(
        description="Session Cookie Security Analyzer - Tests session cookies for security misconfigurations",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --url https://example.com
  %(prog)s --url https://example.com --login-url https://example.com/login --login-data "user=admin&pass=test"
  %(prog)s --url https://example.com --login-url https://example.com/login --login-method POST --output json
  %(prog)s --url https://example.com --json-file session_report.json
        """
    )
    parser.add_argument("--url", required=True, help="Target URL to analyze")
    parser.add_argument("--login-url", help="Login URL for session fixation testing")
    parser.add_argument("--login-data", help="Login form data (key=value&key2=value2)")
    parser.add_argument("--login-method", default="POST", choices=["GET", "POST"],
                        help="Login method (default: POST)")
    parser.add_argument("--output", choices=["json", "text"], default="text",
                        help="Output format (default: text)")
    parser.add_argument("--json-file", help="Save JSON output to file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--timeout", type=int, default=15, help="Request timeout (default: 15)")

    args = parser.parse_args()

    # Parse login data
    login_data = None
    if args.login_data:
        login_data = {}
        for pair in args.login_data.split("&"):
            if "=" in pair:
                key, value = pair.split("=", 1)
                login_data[key] = value

    analyzer = SessionAnalyzer(
        url=args.url,
        verbose=args.verbose,
        timeout=args.timeout,
    )

    results = analyzer.run_all(
        login_url=args.login_url,
        login_data=login_data,
        login_method=args.login_method,
    )

    if args.output == "json":
        json_output = analyzer.export_json(args.json_file)
        print(json_output)
    elif args.json_file:
        analyzer.export_json(args.json_file)
        print(f"\n  {Fore.GREEN}JSON results saved to: {args.json_file}{Style.RESET_ALL}")


if __name__ == "__main__":
    main()
