#!/usr/bin/env python3
"""
Shopify GitHub Secret Scanner
Scans GitHub for leaked secrets in Shopify's public repositories.
For authorized bug bounty research only.
"""

import argparse
import json
import logging
import re
import sys
import time
from collections import OrderedDict
from datetime import datetime
from urllib.parse import quote_plus

try:
    import requests
except ImportError:
    print("[!] requests library required. Install: pip install requests")
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

# ─── Banner ────────────────────────────────────────────────────────────────────

BANNER = f"""{C.CYAN}{C.BOLD}
  ____  _  __  __            _  _____      _               ____       _               
 / ___|| |/ / / _|_   _  __| ||  ___|__  | |_ ___ _ __   / ___|  ___| |_ _   _ _ __  
 \\___ \\| ' / | |_| | | |/ _` || |_ / _ \\ | __/ _ \\ '__| \\___ \\ / _ \\ __| | | | '_ \\ 
  ___) | . \\ |  _| |_| | (_| ||  _|  __/ | ||  __/ |     ___) |  __/ |_| |_| | |_) |
 |____/|_|\\_\\|_|  \\__, |\\__,_||_|  \\___|  \\__\\___|_|    |____/ \\___|\\__|\\__,_| .__/ 
                   |___/                                                      |_|    
{C.RESET}{C.DIM}  GitHub Secret Scanner for Shopify Bug Bounty{C.RESET}
{C.DIM}  For authorized security research only.{C.RESET}
"""

# ─── Constants ─────────────────────────────────────────────────────────────────

GITHUB_API = "https://api.github.com"
LOG_FILE = "/tmp/shopify_github_secrets.log"

# Shopify-specific token prefixes
SHOPIFY_TOKEN_PATTERNS = [
    (r'shpat_[A-Za-z0-9]{32,}', "Shopify Private App Access Token"),
    (r'shpss_[A-Za-z0-9]{32,}', "Shopify Shared Secret"),
    (r'shppa_[A-Za-z0-9]{32,}', "Shopify Public App Access Token"),
    (r'shpca_[A-Za-z0-9]{32,}', "Shopify Custom App Token"),
    (r'atkn_[A-Za-z0-9]{32,}', "Shopify Admin Token"),
]

GENERIC_SECRET_PATTERNS = [
    (r'(?i)(?:api[_-]?key|apikey)\s*[:=]\s*["\']?([A-Za-z0-9_\-]{20,})', "API Key"),
    (r'(?i)(?:api[_-]?secret|apisecret)\s*[:=]\s*["\']?([A-Za-z0-9_\-]{20,})', "API Secret"),
    (r'(?i)(?:password|passwd|pwd)\s*[:=]\s*["\']?([^\s"\']{8,})', "Password"),
    (r'(?i)(?:secret[_-]?key|secretkey)\s*[:=]\s*["\']?([A-Za-z0-9_\-]{20,})', "Secret Key"),
    (r'(?i)(?:private[_-]?key|privatekey)\s*[:=]\s*["\']?([A-Za-z0-9_\-/+=]{20,})', "Private Key"),
    (r'(?i)(?:access[_-]?token|accesstoken)\s*[:=]\s*["\']?([A-Za-z0-9_\-]{20,})', "Access Token"),
    (r'(?i)(?:auth[_-]?token|authtoken)\s*[:=]\s*["\']?([A-Za-z0-9_\-]{20,})', "Auth Token"),
]

AWS_PATTERNS = [
    (r'AKIA[0-9A-Z]{16}', "AWS Access Key ID"),
    (r'(?i)aws[_-]?access[_-]?key[_-]?id\s*[:=]\s*["\']?(AKIA[0-9A-Z]{16})', "AWS Access Key ID (var)"),
    (r'(?i)aws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*["\']?([A-Za-z0-9/+=]{40})', "AWS Secret Access Key"),
]

DATABASE_PATTERNS = [
    (r'(?i)(?:database[_-]?url|db[_-]?url)\s*[:=]\s*["\']?([^\s"\']+)', "Database URL"),
    (r'(?i)(?:db[_-]?password|database[_-]?password)\s*[:=]\s*["\']?([^\s"\']{6,})', "DB Password"),
    (r'mysql://[^\s"\']+', "MySQL Connection String"),
    (r'postgres(?:ql)?://[^\s"\']+', "PostgreSQL Connection String"),
    (r'mongodb(?:\+srv)?://[^\s"\']+', "MongoDB Connection String"),
    (r'redis://[^\s"\']+', "Redis Connection String"),
]

JWT_PATTERNS = [
    (r'(?i)(?:jwt[_-]?secret|jwtsecret)\s*[:=]\s*["\']?([A-Za-z0-9_\-]{16,})', "JWT Secret"),
    (r'(?i)(?:signing[_-]?key|signingkey|hmac[_-]?secret|hmacsecret)\s*[:=]\s*["\']?([A-Za-z0-9_\-]{16,})', "Signing Key / HMAC Secret"),
    (r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+', "JWT Token (hardcoded)"),
]

OAUTH_PATTERNS = [
    (r'(?i)(?:client[_-]?secret)\s*[:=]\s*["\']?([A-Za-z0-9_\-]{20,})', "OAuth Client Secret"),
    (r'(?i)(?:client[_-]?id)\s*[:=]\s*["\']?([A-Za-z0-9_\-]{10,})', "OAuth Client ID"),
    (r'(?i)(?:oauth[_-]?token)\s*[:=]\s*["\']?([A-Za-z0-9_\-]{20,})', "OAuth Token"),
]

INTERNAL_PATTERNS = [
    (r'(?i)shopify[_-]?internal\s*[:=]\s*["\']?([A-Za-z0-9_\-]{10,})', "Shopify Internal Token"),
    (r'(?i)internal[_-]?api\s*[:=]\s*["\']?([A-Za-z0-9_\-]{10,})', "Internal API Key"),
    (r'(?i)admin[_-]?token\s*[:=]\s*["\']?([A-Za-z0-9_\-]{20,})', "Admin Token"),
]

ALL_PATTERNS = {
    "shopify_token": SHOPIFY_TOKEN_PATTERNS,
    "generic_secret": GENERIC_SECRET_PATTERNS,
    "aws": AWS_PATTERNS,
    "database": DATABASE_PATTERNS,
    "jwt": JWT_PATTERNS,
    "oauth": OAUTH_PATTERNS,
    "internal": INTERNAL_PATTERNS,
}

CONFIG_FILE_PATTERNS = [
    ".env", ".env.local", ".env.production", ".env.staging",
    "config.yml", "config.yaml", "config.json", "config.js",
    "credentials.json", "credentials.yml", "credentials.yaml",
    "secrets.json", "secrets.yml", "secrets.yaml",
    "database.yml", "database.yaml",
    ".npmrc", ".pypirc", ".netrc",
    "wp-config.php", "settings.py",
]

# Severity: CRITICAL = actual tokens, HIGH = likely secrets, MEDIUM = config files
SEVERITY_CRITICAL = "CRITICAL"
SEVERITY_HIGH = "HIGH"
SEVERITY_MEDIUM = "MEDIUM"

# ─── Logger Setup ──────────────────────────────────────────────────────────────

def setup_logging(verbose=False):
    logger = logging.getLogger("shopify_scanner")
    logger.setLevel(logging.DEBUG)
    # File handler
    fh = logging.FileHandler(LOG_FILE, mode="a")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    logger.addHandler(fh)
    # Console handler (only if verbose)
    if verbose:
        ch = logging.StreamHandler(sys.stderr)
        ch.setLevel(logging.DEBUG)
        ch.setFormatter(logging.Formatter(f"{C.DIM}%(asctime)s{C.RESET} [%(levelname)s] %(message)s"))
        logger.addHandler(ch)
    return logger

# ─── Rate Limiter ──────────────────────────────────────────────────────────────

class RateLimiter:
    """Simple rate limiter tracking remaining GitHub API calls."""
    def __init__(self):
        self.remaining = 60
        self.reset_at = 0

    def update(self, response):
        self.remaining = int(response.headers.get("X-RateLimit-Remaining", 60))
        self.reset_at = int(response.headers.get("X-RateLimit-Reset", 0))

    def wait_if_needed(self, logger):
        if self.remaining <= 2:
            wait = max(self.reset_at - int(time.time()), 5)
            logger.warning(f"Rate limit nearly exhausted. Waiting {wait}s...")
            print(f"{C.YELLOW}[!] Rate limit nearly exhausted. Waiting {wait}s...{C.RESET}")
            time.sleep(wait + 1)

# ─── GitHub API Client ─────────────────────────────────────────────────────────

class GitHubClient:
    def __init__(self, token=None, logger=None, verbose=False):
        self.session = requests.Session()
        self.session.headers.update({
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "Shopify-GitHub-Secret-Scanner/1.0",
        })
        if token:
            self.session.headers["Authorization"] = f"token {token}"
        self.rate_limiter = RateLimiter()
        self.logger = logger
        self.verbose = verbose

    def _request(self, method, url, **kwargs):
        self.rate_limiter.wait_if_needed(self.logger)
        try:
            resp = self.session.request(method, url, timeout=30, **kwargs)
            self.rate_limiter.update(resp)
            if resp.status_code == 403 and "rate limit" in resp.text.lower():
                self.logger.error("Rate limited by GitHub API")
                print(f"{C.RED}[!] Rate limited. Use --token for higher limits.{C.RESET}")
                self.rate_limiter.wait_if_needed(self.logger)
                resp = self.session.request(method, url, timeout=30, **kwargs)
                self.rate_limiter.update(resp)
            return resp
        except requests.RequestException as e:
            self.logger.error(f"Request failed: {e}")
            return None

    def get(self, url, **kwargs):
        return self._request("GET", url, **kwargs)

    def get_paginated(self, url, max_pages=10, params=None):
        """Fetch paginated results."""
        results = []
        params = params or {}
        params.setdefault("per_page", 100)
        page = 1
        while page <= max_pages:
            params["page"] = page
            resp = self.get(url, params=params)
            if resp is None or resp.status_code != 200:
                break
            data = resp.json()
            if not data:
                break
            results.extend(data)
            page += 1
        return results

# ─── Pattern Scanner ───────────────────────────────────────────────────────────

class PatternScanner:
    def __init__(self, logger):
        self.logger = logger
        self.seen = set()

    def _dedup_key(self, finding):
        key = f"{finding.get('repo','')}-{finding.get('file','')}-{finding.get('matched','')}"
        return key

    def scan_text(self, text, source="", repo="", filename=""):
        findings = []
        for category, patterns in ALL_PATTERNS.items():
            for pattern, label in patterns:
                for match in re.finditer(pattern, text):
                    matched_text = match.group(0)
                    # Try to get the captured group (the actual secret)
                    secret = match.group(1) if match.lastindex and match.lastindex >= 1 else matched_text

                    # Determine severity
                    if category == "shopify_token":
                        severity = SEVERITY_CRITICAL
                    elif category in ("aws", "database", "jwt") and len(secret) > 15:
                        severity = SEVERITY_CRITICAL
                    elif category in ("generic_secret", "oauth", "internal"):
                        severity = SEVERITY_HIGH
                    else:
                        severity = SEVERITY_HIGH

                    finding = {
                        "severity": severity,
                        "category": category,
                        "label": label,
                        "matched": matched_text[:80] + ("..." if len(matched_text) > 80 else ""),
                        "repo": repo,
                        "file": filename,
                        "source": source,
                        "timestamp": datetime.utcnow().isoformat() + "Z",
                    }

                    dedup = self._dedup_key(finding)
                    if dedup not in self.seen:
                        self.seen.add(dedup)
                        findings.append(finding)
        return findings

# ─── Scanner Modules ───────────────────────────────────────────────────────────

def enumerate_repos(client, org, logger):
    """List all public repos for the org."""
    print(f"\n{C.BLUE}[*] Enumerating public repos for {org}...{C.RESET}")
    repos = client.get_paginated(f"{GITHUB_API}/orgs/{org}/repos", max_pages=20, params={"type": "public"})
    logger.info(f"Found {len(repos)} public repos for {org}")
    print(f"{C.GREEN}[+] Found {len(repos)} public repos{C.RESET}")
    return [r["full_name"] for r in repos]

def search_code(client, org, scanner, logger):
    """Search code in org repos for secret patterns."""
    print(f"\n{C.BLUE}[*] Searching code for secrets in {org}...{C.RESET}")
    all_findings = []

    search_queries = []
    # Shopify-specific
    for prefix in ["shpat_", "shpss_", "shppa_", "shpca_", "atkn_"]:
        search_queries.append(f"{prefix} org:{org}")
    # Generic secret patterns
    for term in ["api_key", "api_secret", "secret_key", "private_key", "password",
                 "AKIA", "aws_access_key_id", "aws_secret_access_key",
                 "database_url", "db_password", "jwt_secret", "client_secret",
                 "admin_token", "shopify_internal"]:
        search_queries.append(f"{term} org:{org}")

    for query in search_queries:
        encoded = quote_plus(query)
        url = f"{GITHUB_API}/search/code?q={encoded}&per_page=30"
        logger.info(f"Code search: {query}")
        if client.verbose:
            print(f"  {C.DIM}Searching: {query}{C.RESET}")

        resp = client.get(url)
        if resp is None:
            continue
        if resp.status_code == 403:
            logger.warning(f"Code search rate limited for: {query}")
            print(f"  {C.YELLOW}[!] Rate limited on code search. Use --token.{C.RESET}")
            break
        if resp.status_code != 200:
            logger.warning(f"Code search failed ({resp.status_code}): {query}")
            continue

        data = resp.json()
        items = data.get("items", [])
        logger.info(f"  Found {len(items)} code results for: {query}")

        for item in items:
            repo_name = item.get("repository", {}).get("full_name", "")
            file_path = item.get("path", "")
            # We can't get file content from search/code without fetching the raw URL
            # but we note the match location
            finding = {
                "severity": SEVERITY_HIGH,
                "category": "code_match",
                "label": f"Code match for '{query.split(' org:')[0]}'",
                "matched": f"{repo_name}/{file_path}",
                "repo": repo_name,
                "file": file_path,
                "source": "code_search",
                "html_url": item.get("html_url", ""),
                "timestamp": datetime.utcnow().isoformat() + "Z",
            }
            dedup_key = scanner._dedup_key(finding)
            if dedup_key not in scanner.seen:
                scanner.seen.add(dedup_key)
                all_findings.append(finding)

        # Be respectful with rate limits
        time.sleep(2)

    print(f"{C.GREEN}[+] Code search found {len(all_findings)} potential matches{C.RESET}")
    return all_findings

def search_gists(client, org, scanner, logger):
    """Search public gists for Shopify-related secrets."""
    print(f"\n{C.BLUE}[*] Searching public gists for {org} secrets...{C.RESET}")
    all_findings = []

    # Search gists via the search/issues endpoint or iterate public gists
    # GitHub doesn't have a direct gist search API, so we search via search/issues
    search_terms = ["shopify", "shpat_", "shpss_", "shopify_api", "shopify_secret"]

    for term in search_terms:
        url = f"{GITHUB_API}/gists/public?per_page=100"
        logger.info(f"Gist search: {term}")
        if client.verbose:
            print(f"  {C.DIM}Searching gists for: {term}{C.RESET}")

        resp = client.get(url)
        if resp is None or resp.status_code != 200:
            continue

        gists = resp.json()
        for gist in gists:
            gist_id = gist.get("id", "")
            gist_url = gist.get("html_url", "")
            for fname, fdata in gist.get("files", {}).items():
                content = fdata.get("content", "")
                if term.lower() in content.lower() or term.lower() in fname.lower():
                    findings = scanner.scan_text(content, source="gist", repo=f"gist:{gist_id}", filename=fname)
                    for f in findings:
                        f["html_url"] = gist_url
                    all_findings.extend(findings)

        time.sleep(2)

    print(f"{C.GREEN}[+] Gist search found {len(all_findings)} findings{C.RESET}")
    return all_findings

def search_commits(client, org, scanner, logger):
    """Search recent commits for accidentally committed secrets."""
    print(f"\n{C.BLUE}[*] Searching recent commits in {org}...{C.RESET}")
    all_findings = []

    search_terms = ["secret", "password", "api_key", "token", "credential", "private_key"]

    for term in search_terms:
        url = f"{GITHUB_API}/search/commits?q={quote_plus(term + ' org:' + org)}&sort=committer-date&order=desc&per_page=30"
        logger.info(f"Commit search: {term}")

        # commits search requires the preview header
        headers = {"Accept": "application/vnd.github.cloak-preview+json"}
        resp = client.get(url, headers=headers)
        if resp is None:
            continue
        if resp.status_code == 403:
            print(f"  {C.YELLOW}[!] Rate limited on commit search.{C.RESET}")
            break
        if resp.status_code != 200:
            logger.warning(f"Commit search failed ({resp.status_code}): {term}")
            continue

        data = resp.json()
        items = data.get("items", [])
        for item in items:
            commit_msg = item.get("commit", {}).get("message", "")
            repo_name = item.get("repository", {}).get("full_name", "")
            html_url = item.get("html_url", "")

            findings = scanner.scan_text(commit_msg, source="commit", repo=repo_name, filename="commit message")
            for f in findings:
                f["html_url"] = html_url
            all_findings.extend(findings)

        time.sleep(2)

    print(f"{C.GREEN}[+] Commit search found {len(all_findings)} findings{C.RESET}")
    return all_findings

def search_configs(client, org, scanner, logger):
    """Search for config files that might contain secrets."""
    print(f"\n{C.BLUE}[*] Searching for config files in {org}...{C.RESET}")
    all_findings = []

    for config_file in CONFIG_FILE_PATTERNS:
        query = f"filename:{config_file} org:{org}"
        url = f"{GITHUB_API}/search/code?q={quote_plus(query)}&per_page=20"
        logger.info(f"Config search: {config_file}")

        resp = client.get(url)
        if resp is None:
            continue
        if resp.status_code == 403:
            print(f"  {C.YELLOW}[!] Rate limited on config search.{C.RESET}")
            break
        if resp.status_code != 200:
            continue

        data = resp.json()
        items = data.get("items", [])
        for item in items:
            repo_name = item.get("repository", {}).get("full_name", "")
            file_path = item.get("path", "")
            html_url = item.get("html_url", "")

            finding = {
                "severity": SEVERITY_MEDIUM,
                "category": "config_file",
                "label": f"Sensitive config file: {config_file}",
                "matched": f"{repo_name}/{file_path}",
                "repo": repo_name,
                "file": file_path,
                "source": "config_search",
                "html_url": html_url,
                "timestamp": datetime.utcnow().isoformat() + "Z",
            }
            dedup_key = scanner._dedup_key(finding)
            if dedup_key not in scanner.seen:
                scanner.seen.add(dedup_key)
                all_findings.append(finding)

        time.sleep(2)

    print(f"{C.GREEN}[+] Config search found {len(all_findings)} config files{C.RESET}")
    return all_findings

def search_issues(client, org, scanner, logger):
    """Search issues and PRs for leaked tokens in comments."""
    print(f"\n{C.BLUE}[*] Searching issues/PRs in {org} for leaked secrets...{C.RESET}")
    all_findings = []

    search_terms = ["shpat_", "shpss_", "api_key", "secret", "password", "token", "credential"]

    for term in search_terms:
        url = f"{GITHUB_API}/search/issues?q={quote_plus(term + ' org:' + org)}&sort=updated&order=desc&per_page=30"
        logger.info(f"Issue search: {term}")

        resp = client.get(url)
        if resp is None:
            continue
        if resp.status_code == 403:
            print(f"  {C.YELLOW}[!] Rate limited on issue search.{C.RESET}")
            break
        if resp.status_code != 200:
            continue

        data = resp.json()
        items = data.get("items", [])
        for item in items:
            title = item.get("title", "")
            body = item.get("body", "") or ""
            html_url = item.get("html_url", "")
            repo_url = item.get("repository_url", "")
            repo_name = "/".join(repo_url.rstrip("/").split("/")[-2:]) if repo_url else ""
            text = f"{title}\n{body}"

            findings = scanner.scan_text(text, source="issue", repo=repo_name, filename="issue/PR")
            for f in findings:
                f["html_url"] = html_url
            all_findings.extend(findings)

        time.sleep(2)

    print(f"{C.GREEN}[+] Issue/PR search found {len(all_findings)} findings{C.RESET}")
    return all_findings

# ─── Output ────────────────────────────────────────────────────────────────────

def severity_color(sev):
    if sev == SEVERITY_CRITICAL:
        return C.RED + C.BOLD
    elif sev == SEVERITY_HIGH:
        return C.YELLOW
    else:
        return C.CYAN

def print_summary(findings, verbose=False):
    """Print a colored summary of findings."""
    print(f"\n{'='*70}")
    print(f"{C.BOLD}{C.WHITE}  SCAN RESULTS SUMMARY{C.RESET}")
    print(f"{'='*70}\n")

    if not findings:
        print(f"{C.GREEN}  [✓] No secrets found.{C.RESET}\n")
        return

    # Count by severity
    sev_counts = {SEVERITY_CRITICAL: 0, SEVERITY_HIGH: 0, SEVERITY_MEDIUM: 0}
    for f in findings:
        sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1

    print(f"  {C.RED}{C.BOLD}CRITICAL: {sev_counts[SEVERITY_CRITICAL]}{C.RESET}")
    print(f"  {C.YELLOW}HIGH:     {sev_counts[SEVERITY_HIGH]}{C.RESET}")
    print(f"  {C.CYAN}MEDIUM:   {sev_counts[SEVERITY_MEDIUM]}{C.RESET}")
    print(f"  {C.WHITE}TOTAL:    {len(findings)}{C.RESET}\n")

    # Count by category
    cat_counts = {}
    for f in findings:
        cat_counts[f["category"]] = cat_counts.get(f["category"], 0) + 1

    print(f"  {C.BOLD}By Category:{C.RESET}")
    for cat, count in sorted(cat_counts.items(), key=lambda x: -x[1]):
        print(f"    {cat}: {count}")

    # Print critical/high findings
    critical_high = [f for f in findings if f["severity"] in (SEVERITY_CRITICAL, SEVERITY_HIGH)]
    if critical_high:
        print(f"\n  {C.BOLD}Top Findings:{C.RESET}")
        for f in critical_high[:20]:
            col = severity_color(f["severity"])
            print(f"    {col}[{f['severity']}]{C.RESET} {f['label']}")
            print(f"      {C.DIM}Repo: {f.get('repo', 'N/A')}  File: {f.get('file', 'N/A')}{C.RESET}")
            print(f"      {C.DIM}Match: {f.get('matched', 'N/A')[:60]}{C.RESET}")
            if f.get("html_url"):
                print(f"      {C.BLUE}{f['html_url']}{C.RESET}")

    if verbose:
        print(f"\n  {C.BOLD}All Findings:{C.RESET}")
        for f in findings:
            col = severity_color(f["severity"])
            print(f"    {col}[{f['severity']}]{C.RESET} [{f['category']}] {f['label']}")
            print(f"      Repo: {f.get('repo', 'N/A')} | File: {f.get('file', 'N/A')}")
            print(f"      Match: {f.get('matched', 'N/A')}")

    print(f"\n{'='*70}\n")

# ─── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Shopify GitHub Secret Scanner - Scan for leaked secrets",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="For authorized bug bounty research only."
    )
    parser.add_argument("--org", default="Shopify", help="GitHub org to scan (default: Shopify)")
    parser.add_argument("--token", default=None, help="GitHub PAT for higher rate limits")
    parser.add_argument("--scan-type", default="all",
                        choices=["code", "gist", "commit", "config", "issue", "all"],
                        help="Type of scan to perform (default: all)")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--output", default=None, help="Save JSON results to file")

    args = parser.parse_args()

    print(BANNER)

    logger = setup_logging(args.verbose)
    logger.info(f"Starting scan of {args.org} (scan_type={args.scan_type})")

    client = GitHubClient(token=args.token, logger=logger, verbose=args.verbose)
    scanner = PatternScanner(logger)

    if args.token:
        print(f"{C.GREEN}[✓] Authenticated mode (5000 req/hr){C.RESET}")
    else:
        print(f"{C.YELLOW}[!] Unauthenticated mode (60 req/hr). Use --token for higher limits.{C.RESET}")

    all_findings = []
    scan_all = args.scan_type == "all"

    # Enumerate repos (informational)
    repos = enumerate_repos(client, args.org, logger)

    # Run selected scans
    if scan_all or args.scan_type == "code":
        all_findings.extend(search_code(client, args.org, scanner, logger))

    if scan_all or args.scan_type == "gist":
        all_findings.extend(search_gists(client, args.org, scanner, logger))

    if scan_all or args.scan_type == "commit":
        all_findings.extend(search_commits(client, args.org, scanner, logger))

    if scan_all or args.scan_type == "config":
        all_findings.extend(search_configs(client, args.org, scanner, logger))

    if scan_all or args.scan_type == "issue":
        all_findings.extend(search_issues(client, args.org, scanner, logger))

    # Print summary
    print_summary(all_findings, verbose=args.verbose)

    # Output JSON
    output = {
        "tool": "Shopify GitHub Secret Scanner",
        "org": args.org,
        "scan_type": args.scan_type,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "repos_found": len(repos),
        "total_findings": len(all_findings),
        "findings": all_findings,
    }

    if args.output:
        with open(args.output, "w") as f:
            json.dump(output, f, indent=2)
        print(f"{C.GREEN}[✓] Results saved to {args.output}{C.RESET}")
        logger.info(f"Results saved to {args.output}")

    # Always output to stdout
    print(json.dumps(output, indent=2))

    logger.info(f"Scan complete. {len(all_findings)} findings.")
    return 0 if not any(f["severity"] == SEVERITY_CRITICAL for f in all_findings) else 1

if __name__ == "__main__":
    sys.exit(main())
