#!/usr/bin/env python3
"""
Shopify Developer Account Creator (Playwright)
Creates a Shopify Partners account and captures session cookies for auth testing.

Usage:
    python3 shopify_signup.py [--headless]
    
Flow:
    1. Opens Shopify Partners signup
    2. Fills email/password
    3. Pauses for CAPTCHA (manual if needed)
    4. Waits for email verification code
    5. Captures session cookies
    6. Saves cookies to output/shopify_cookies.json
"""

import argparse
import json
import time
import os
from datetime import datetime

def main():
    parser = argparse.ArgumentParser(description="Shopify Account Creator")
    parser.add_argument("--headless", action="store_true", help="Run headless (default: headed)")
    parser.add_argument("--email", default="kucingwhite911@gmail.com", help="Email for signup")
    parser.add_argument("--password", default="", help="Password (will prompt if empty)")
    parser.add_argument("--store", default="xbyte-security-test", help="Store name")
    args = parser.parse_args()
    
    if not args.password:
        import getpass
        args.password = getpass.getpass("Password for Shopify account: ")
    
    from playwright.sync_api import sync_playwright
    from playwright_stealth import Stealth
    stealth_obj = Stealth()
    
    print(f"\n{'='*60}")
    print(f"🛡️  Shopify Account Creator")
    print(f"Email: {args.email}")
    print(f"Store: {args.store}.myshopify.com")
    print(f"{'='*60}\n")
    
    with sync_playwright() as p:
        # Launch browser with stealth
        browser = p.chromium.launch(
            headless=args.headless,
            args=[
                '--disable-blink-features=AutomationControlled',
                '--disable-features=IsolateOrigins,site-per-process',
                '--no-sandbox',
            ]
        )
        
        context = browser.new_context(
            viewport={'width': 1280, 'height': 800},
            user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
            locale='en-US',
            timezone_id='America/New_York',
        )
        
        page = context.new_page()
        stealth_obj.apply_stealth_sync(page)
        
        # ==========================================
        # STEP 1: Navigate to Shopify Partners signup
        # ==========================================
        print("[1/6] Navigating to Shopify Partners signup...")
        try:
            page.goto("https://accounts.shopify.com/lookup?signup_url=https%3A%2F%2Fwww.shopify.com%2Fpartners", 
                      wait_until="domcontentloaded", timeout=30000)
        except Exception as e:
            print(f"⚠️  Page load timeout (likely Cloudflare): {e}")
            print("    Waiting for Cloudflare challenge to resolve...")
            time.sleep(10)
        
        # Check for Cloudflare challenge
        if "challenge" in page.url or "Verifying" in page.content():
            print("⚠️  Cloudflare challenge detected!")
            print("    Please solve the CAPTCHA manually in the browser window.")
            print("    Waiting up to 120 seconds...")
            
            # Wait for challenge to resolve
            for i in range(120):
                time.sleep(1)
                if "challenge" not in page.url and "Verifying" not in page.content():
                    print("✅ Challenge resolved!")
                    break
                if i % 10 == 0:
                    print(f"    Still waiting... ({i}s)")
            else:
                print("❌ Challenge timeout. Please try again.")
                browser.close()
                return
        
        time.sleep(2)
        page.screenshot(path="output/shopify_step1_lookup.png")
        print(f"    Current URL: {page.url}")
        
        # ==========================================
        # STEP 2: Fill signup form
        # ==========================================
        print("\n[2/6] Filling signup form...")
        
        # Try to find and fill email field
        email_selectors = [
            'input[name="email"]',
            'input[type="email"]',
            '#email',
            'input[placeholder*="email"]',
            'input[aria-label*="email"]',
        ]
        
        email_filled = False
        for sel in email_selectors:
            try:
                el = page.wait_for_selector(sel, timeout=5000)
                if el:
                    el.fill(args.email)
                    email_filled = True
                    print(f"    ✅ Email filled: {args.email}")
                    break
            except:
                continue
        
        if not email_filled:
            print("    ⚠️  Could not find email field automatically.")
            print("    Please fill in the email manually and press Enter.")
            page.screenshot(path="output/shopify_step2_no_email_field.png")
            input("    Press Enter after filling email...")
        
        # Try to find and fill password field
        pw_selectors = [
            'input[name="password"]',
            'input[type="password"]',
            '#password',
        ]
        
        pw_filled = False
        for sel in pw_selectors:
            try:
                el = page.wait_for_selector(sel, timeout=5000)
                if el:
                    el.fill(args.password)
                    pw_filled = True
                    print(f"    ✅ Password filled")
                    break
            except:
                continue
        
        if not pw_filled:
            print("    ⚠️  Could not find password field. Fill manually.")
        
        # Try to find and fill store name field
        store_selectors = [
            'input[name="store_name"]',
            'input[name="shop[name]"]',
            'input[name="shop_name"]',
            '#store-name',
            'input[placeholder*="store"]',
        ]
        
        for sel in store_selectors:
            try:
                el = page.wait_for_selector(sel, timeout=3000)
                if el:
                    el.fill(args.store)
                    print(f"    ✅ Store name filled: {args.store}")
                    break
            except:
                continue
        
        time.sleep(1)
        page.screenshot(path="output/shopify_step2_form_filled.png")
        
        # ==========================================
        # STEP 3: Submit form + handle CAPTCHA
        # ==========================================
        print("\n[3/6] Submitting form...")
        
        submit_selectors = [
            'button[type="submit"]',
            'button:has-text("Create")',
            'button:has-text("Sign up")',
            'button:has-text("Start")',
            'input[type="submit"]',
        ]
        
        submitted = False
        for sel in submit_selectors:
            try:
                el = page.wait_for_selector(sel, timeout=3000)
                if el:
                    el.click()
                    submitted = True
                    print("    ✅ Form submitted")
                    break
            except:
                continue
        
        if not submitted:
            print("    ⚠️  Could not find submit button. Click manually.")
        
        time.sleep(3)
        page.screenshot(path="output/shopify_step3_submitted.png")
        
        # Check for CAPTCHA
        captcha_selectors = [
            'iframe[src*="captcha"]',
            'iframe[src*="recaptcha"]',
            'iframe[src*="hcaptcha"]',
            '.g-recaptcha',
            '#captcha',
            '[class*="captcha"]',
        ]
        
        for sel in captcha_selectors:
            try:
                el = page.query_selector(sel)
                if el:
                    print("\n⚠️  CAPTCHA detected!")
                    print("    Please solve it manually in the browser window.")
                    print("    Waiting up to 120 seconds...")
                    
                    for i in range(120):
                        time.sleep(1)
                        # Check if CAPTCHA is gone
                        still_captcha = False
                        for cs in captcha_selectors:
                            if page.query_selector(cs):
                                still_captcha = True
                                break
                        if not still_captcha:
                            print("    ✅ CAPTCHA solved!")
                            break
                        if i % 10 == 0:
                            print(f"    Still waiting... ({i}s)")
                    break
            except:
                continue
        
        time.sleep(3)
        page.screenshot(path="output/shopify_step3_post_captcha.png")
        print(f"    Current URL: {page.url}")
        
        # ==========================================
        # STEP 4: Wait for email verification
        # ==========================================
        print("\n[4/6] Email verification...")
        print(f"    Check {args.email} for verification code/link.")
        print("    Options:")
        print("    a) Click the verification link in the email")
        print("    b) Enter the verification code here")
        print("    c) Skip (if already verified)")
        
        verif = input("\n    Enter verification code or 'skip': ").strip()
        
        if verif.lower() != 'skip' and verif:
            # Try to enter verification code
            code_selectors = [
                'input[name="code"]',
                'input[name="verification_code"]',
                'input[type="text"]',
                'input[type="number"]',
                '#code',
            ]
            
            for sel in code_selectors:
                try:
                    el = page.wait_for_selector(sel, timeout=5000)
                    if el:
                        el.fill(verif)
                        print(f"    ✅ Code filled: {verif}")
                        # Submit
                        try:
                            page.keyboard.press("Enter")
                            print("    ✅ Code submitted")
                        except:
                            pass
                        break
                except:
                    continue
        
        time.sleep(5)
        page.screenshot(path="output/shopify_step4_verified.png")
        print(f"    Current URL: {page.url}")
        
        # ==========================================
        # STEP 5: Wait for user to complete setup
        # ==========================================
        print("\n[5/6] Complete any remaining setup steps in the browser.")
        print("    When you're logged into the Shopify admin/dashboard,")
        print("    press Enter here to capture session cookies.")
        
        input("\n    Press Enter when logged in...")
        
        # ==========================================
        # STEP 6: Capture session cookies
        # ==========================================
        print("\n[6/6] Capturing session cookies...")
        
        all_cookies = context.cookies()
        
        # Filter relevant cookies
        relevant_domains = [
            'accounts.shopify.com',
            'admin.shopify.com',
            'partners.shopify.com',
            'shop.app',
            '.shopify.com',
            'shopify.com',
        ]
        
        relevant_cookies = [c for c in all_cookies 
                          if any(d in c.get('domain', '') for d in relevant_domains)]
        
        # Save all cookies
        os.makedirs("output", exist_ok=True)
        
        with open("output/shopify_all_cookies.json", "w") as f:
            json.dump(all_cookies, f, indent=2)
        
        with open("output/shopify_cookies.json", "w") as f:
            json.dump(relevant_cookies, f, indent=2)
        
        print(f"\n✅ Captured {len(all_cookies)} total cookies")
        print(f"✅ {len(relevant_cookies)} relevant cookies saved to output/shopify_cookies.json")
        
        # Print relevant cookies summary
        print(f"\n{'='*60}")
        print("📋 Relevant Cookies:")
        print(f"{'='*60}")
        for c in relevant_cookies:
            print(f"  {c['domain']:40s} {c['name']:30s} {c.get('value', '')[:30]}...")
        
        # Navigate to key auth pages and capture
        auth_pages = [
            ("accounts.shopify.com OIDC", "https://accounts.shopify.com/.well-known/openid-configuration"),
            ("admin.shopify.com session", "https://admin.shopify.com/admin"),
            ("partners.shopify.com", "https://partners.shopify.com"),
        ]
        
        for name, url in auth_pages:
            try:
                page.goto(url, wait_until="domcontentloaded", timeout=15000)
                time.sleep(2)
                page.screenshot(path=f"output/shopify_auth_{name.split('.')[0]}.png")
                print(f"  📸 Screenshot: {name}")
            except:
                print(f"  ⚠️  Could not load: {name}")
        
        # Final cookie dump
        final_cookies = context.cookies()
        with open("output/shopify_final_cookies.json", "w") as f:
            json.dump(final_cookies, f, indent=2)
        
        print(f"\n{'='*60}")
        print(f"✅ Done! Cookies saved to output/shopify_cookies.json")
        print(f"   Total cookies: {len(final_cookies)}")
        print(f"{'='*60}")
        
        # Keep browser open for manual inspection
        print("\nBrowser is still open. Press Enter to close.")
        input()
        
        browser.close()

if __name__ == "__main__":
    main()
