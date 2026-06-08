#!/usr/bin/env python3
"""Technology & CMS Detection
Fingerprints web technologies via headers, HTML patterns, meta tags,
script sources, cookies, and known paths. Detects 100+ technologies.
"""

import argparse
import json
import re
import requests
import urllib3
urllib3.disable_warnings()

TECH_SIGNATURES = {
    # Web Servers
    "Nginx": {"headers": {"server": "nginx"}, "type": "web-server"},
    "Apache": {"headers": {"server": "apache"}, "type": "web-server"},
    "IIS": {"headers": {"server": "microsoft-iis"}, "type": "web-server"},
    "LiteSpeed": {"headers": {"server": "litespeed"}, "type": "web-server"},
    "Caddy": {"headers": {"server": "caddy"}, "type": "web-server"},
    "Gunicorn": {"headers": {"server": "gunicorn"}, "type": "web-server"},
    "Uvicorn": {"headers": {"server": "uvicorn"}, "type": "web-server"},
    "OpenResty": {"headers": {"server": "openresty"}, "type": "web-server"},
    "Varnish": {"headers": {"server": "varnish", "x-varnish": None}, "type": "cache"},
    "Tengine": {"headers": {"server": "tengine"}, "type": "web-server"},
    
    # CDN / Proxy
    "Cloudflare": {"headers": {"server": "cloudflare", "cf-ray": None}, "type": "cdn"},
    "CloudFront": {"headers": {"x-amz-cf-id": None, "x-amz-cf-pop": None}, "type": "cdn"},
    "Fastly": {"headers": {"x-served-by": "cache-", "x-cache": None}, "type": "cdn"},
    "Akamai": {"headers": {"x-akamai-transformed": None}, "type": "cdn"},
    "Vercel": {"headers": {"x-vercel-id": None, "server": "vercel"}, "type": "cdn"},
    "Netlify": {"headers": {"server": "netlify", "x-nf-request-id": None}, "type": "cdn"},
    "Fly.io": {"headers": {"fly-request-id": None, "server": "fly"}, "type": "cdn"},
    
    # Frameworks
    "Next.js": {"body": ["__NEXT_DATA__", "__next", "/_next/"], "type": "framework"},
    "Nuxt.js": {"body": ["__NUXT__", "/_nuxt/"], "type": "framework"},
    "React": {"body": ["react.production.min.js", "react-dom", "__REACT_DEVTOOLS", "_reactRootContainer"], "type": "framework"},
    "Vue.js": {"body": ["vue.min.js", "vue.runtime", "__vue__", "data-v-"], "type": "framework"},
    "Angular": {"body": ["ng-version", "ng-app", "angular.min.js", "ng-controller"], "type": "framework"},
    "Svelte": {"body": ["svelte", "__svelte"], "type": "framework"},
    "Gatsby": {"body": ["gatsby-", "___gatsby"], "type": "framework"},
    "Remix": {"headers": {"x-remix-request-id": None}, "type": "framework"},
    
    # Languages
    "PHP": {"headers": {"x-powered-by": "php"}, "body": [".php"], "type": "language"},
    "ASP.NET": {"headers": {"x-powered-by": "asp.net", "x-aspnet-version": None}, "body": ["__VIEWSTATE", "__EVENTVALIDATION"], "type": "language"},
    "Express.js": {"headers": {"x-powered-by": "express"}, "type": "language"},
    "Django": {"body": ["csrfmiddlewaretoken", "django"], "type": "language"},
    "Rails": {"headers": {"x-powered-by": "phusion passenger", "x-runtime": None}, "body": ["csrf-token", "data-remote"], "type": "language"},
    "Laravel": {"body": ["laravel", "laravel_session"], "cookies": ["laravel_session", "XSRF-TOKEN"], "type": "language"},
    "Spring": {"headers": {"x-application-context": None}, "type": "language"},
    "FastAPI": {"body": ["fastapi", "openapi.json"], "type": "language"},
    
    # CMS
    "WordPress": {"body": ["wp-content", "wp-includes", "wp-json", "wordpress"], "type": "cms"},
    "Drupal": {"body": ["drupal.js", "drupal.min.js", "sites/default/files"], "headers": {"x-generator": "drupal"}, "type": "cms"},
    "Joomla": {"body": ["/media/jui/", "joomla", "com_content"], "type": "cms"},
    "Shopify": {"body": ["shopify", "cdn.shopify.com"], "type": "cms"},
    "Magento": {"body": ["magento", "mage/cookies", "skin/frontend"], "type": "cms"},
    "Squarespace": {"body": ["squarespace.com", "static.squarespace.com"], "type": "cms"},
    "Wix": {"body": ["wix.com", "static.wixstatic.com"], "type": "cms"},
    "Ghost": {"body": ["ghost-", "ghost.io"], "headers": {"x-ghost": None}, "type": "cms"},
    "Strapi": {"body": ["strapi", "/admin/"], "type": "cms"},
    "Contentful": {"body": ["contentful", "ctfassets.net"], "type": "cms"},
    "Sanity": {"body": ["sanity.io", "cdn.sanity.io"], "type": "cms"},
    
    # JavaScript Libraries
    "jQuery": {"body": ["jquery.min.js", "jquery-"], "type": "js-lib"},
    "Bootstrap": {"body": ["bootstrap.min.js", "bootstrap.min.css"], "type": "js-lib"},
    "Tailwind CSS": {"body": ["tailwindcss", "tailwind.min.css"], "type": "js-lib"},
    "Lodash": {"body": ["lodash.min.js", "lodash.js"], "type": "js-lib"},
    "Moment.js": {"body": ["moment.min.js", "moment.js"], "type": "js-lib"},
    "D3.js": {"body": ["d3.min.js", "d3.js"], "type": "js-lib"},
    "Three.js": {"body": ["three.min.js", "three.js"], "type": "js-lib"},
    "Socket.io": {"body": ["socket.io.min.js", "socket.io"], "type": "js-lib"},
    
    # Analytics & Marketing
    "Google Analytics": {"body": ["google-analytics.com", "googletagmanager.com", "gtag/js", "UA-"], "type": "analytics"},
    "Google Tag Manager": {"body": ["googletagmanager.com/gtm.js", "GTM-"], "type": "analytics"},
    "Hotjar": {"body": ["hotjar.com", "hj.js"], "type": "analytics"},
    "Segment": {"body": ["segment.com/analytics", "analytics.min.js"], "type": "analytics"},
    "Mixpanel": {"body": ["mixpanel.com", "mixpanel.min.js"], "type": "analytics"},
    "Amplitude": {"body": ["amplitude.com", "amplitude-min.js"], "type": "analytics"},
    "Sentry": {"body": ["sentry.io", "sentry.min.js", "browser.sentry-cdn.com"], "type": "monitoring"},
    "New Relic": {"body": ["newrelic.com", "nr-"], "type": "monitoring"},
    "Datadog": {"body": ["datadoghq.com", "dd-rum"], "type": "monitoring"},
    
    # Auth
    "Auth0": {"body": ["auth0.com", "auth0.min.js"], "type": "auth"},
    "Firebase Auth": {"body": ["firebaseauth", "firebase-app.min.js", "firebase.js"], "type": "auth"},
    "AWS Cognito": {"body": ["amazoncognito.com", "cognito-idp"], "type": "auth"},
    "Okta": {"body": ["okta.com", "okta-sign-in.min.js"], "type": "auth"},
    "Keycloak": {"body": ["keycloak", "/auth/realms/"], "type": "auth"},
    
    # Cloud
    "AWS": {"headers": {"x-amz-request-id": None, "server": "amazons3"}, "type": "cloud"},
    "Google Cloud": {"headers": {"via": "1.1 google"}, "type": "cloud"},
    "Azure": {"headers": {"x-azure-ref": None, "x-ms-request-id": None}, "type": "cloud"},
    "Heroku": {"headers": {"via": "vegur"}, "type": "cloud"},
    
    # Databases (from error messages)
    "MySQL": {"body": ["mysql", "mysqli", "sql syntax"], "type": "database"},
    "PostgreSQL": {"body": ["postgresql", "pg_query", "psql"], "type": "database"},
    "MongoDB": {"body": ["mongodb", "mongo"], "type": "database"},
    "Redis": {"body": ["redis", "redis-server"], "type": "database"},
    "Elasticsearch": {"body": ["elasticsearch", "elastic"], "type": "database"},
    
    # Security
    "reCAPTCHA": {"body": ["recaptcha", "google.com/recaptcha"], "type": "security"},
    "hCaptcha": {"body": ["hcaptcha.com", "hcaptcha"], "type": "security"},
    "Cloudflare Turnstile": {"body": ["turnstile", "challenges.cloudflare.com"], "type": "security"},
    
    # E-commerce
    "Stripe": {"body": ["stripe.com", "stripe.min.js", "js.stripe.com"], "type": "payment"},
    "PayPal": {"body": ["paypal.com", "paypalobjects.com"], "type": "payment"},
    "Razorpay": {"body": ["razorpay.com", "razorpay.min.js"], "type": "payment"},
    
    # Misc
    "GraphQL": {"body": ["graphql", "__schema", "__type"], "type": "api"},
    "Swagger/OpenAPI": {"body": ["swagger-ui", "openapi.json", "swagger.json"], "type": "api"},
    "WebSocket": {"body": ["websocket", "ws://", "wss://"], "type": "protocol"},
    "gRPC": {"headers": {"content-type": "application/grpc"}, "type": "protocol"},
}


def detect_tech(url, timeout=10):
    """Detect technologies used by a web application."""
    results = {}
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    
    try:
        r = requests.get(url, headers=headers, timeout=timeout, verify=False)
    except Exception as e:
        print(f"\033[91m[-]\033[0m Cannot connect: {e}")
        return {}
    
    resp_headers = {k.lower(): v for k, v in r.headers.items()}
    body = r.text.lower()
    cookies = {c.name: c.value for c in r.cookies}
    
    # Check each technology
    for tech_name, sig in TECH_SIGNATURES.items():
        evidence = []
        
        # Check headers
        if "headers" in sig:
            for hkey, hval in sig["headers"].items():
                if hkey in resp_headers:
                    if hval is None or hval.lower() in resp_headers[hkey].lower():
                        evidence.append(f"Header: {hkey}: {resp_headers[hkey]}")
        
        # Check body patterns
        if "body" in sig:
            for pattern in sig["body"]:
                if pattern.lower() in body:
                    evidence.append(f"Body: '{pattern}'")
                    break
        
        # Check cookies
        if "cookies" in sig:
            for cookie_name in sig["cookies"]:
                if any(cookie_name.lower() in c.lower() for c in cookies):
                    evidence.append(f"Cookie: {cookie_name}")
        
        if evidence:
            results[tech_name] = {
                "type": sig["type"],
                "evidence": evidence,
            }
    
    # Additional checks
    # Check robots.txt
    try:
        robots = requests.get(f"{url.rstrip('/')}/robots.txt", headers=headers, timeout=timeout, verify=False)
        if robots.status_code == 200 and "user-agent" in robots.text.lower():
            results["robots.txt"] = {"type": "config", "evidence": ["robots.txt found"]}
    except:
        pass
    
    # Check security.txt
    try:
        sec = requests.get(f"{url.rstrip('/')}/.well-known/security.txt", headers=headers, timeout=timeout, verify=False)
        if sec.status_code == 200 and ("contact" in sec.text.lower() or "security" in sec.text.lower()):
            results["security.txt"] = {"type": "config", "evidence": ["security.txt found"]}
    except:
        pass
    
    # Check sitemap
    try:
        sitemap = requests.get(f"{url.rstrip('/')}/sitemap.xml", headers=headers, timeout=timeout, verify=False)
        if sitemap.status_code == 200 and "urlset" in sitemap.text.lower():
            results["Sitemap"] = {"type": "config", "evidence": ["sitemap.xml found"]}
    except:
        pass
    
    # Extract version info
    version_patterns = {
        "WordPress": r'content="WordPress ([^"]+)"',
        "Drupal": r'content="Drupal ([^"]+)"',
        "jQuery": r'jquery[.-](\d+\.\d+\.\d+)',
        "Bootstrap": r'bootstrap[.-](\d+\.\d+\.\d+)',
        "PHP": r'X-Powered-By: PHP/(\d+\.\d+\.\d+)',
        "ASP.NET": r'X-AspNet-Version: (\d+\.\d+)',
    }
    
    for tech, pattern in version_patterns.items():
        if tech in results:
            m = re.search(pattern, r.text + str(dict(r.headers)), re.I)
            if m:
                results[tech]["version"] = m.group(1)
    
    # Extract from headers
    for h in ["x-powered-by", "server", "x-aspnet-version", "x-generator"]:
        if h in resp_headers:
            results.setdefault("_header_" + h, {"type": "header", "evidence": [resp_headers[h]]})
    
    return results


def main():
    parser = argparse.ArgumentParser(description="Technology & CMS Detection")
    parser.add_argument("url", help="Target URL")
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument("--type", help="Filter by type (framework, cms, language, etc.)")
    args = parser.parse_args()
    
    url = args.url.rstrip("/")
    if not url.startswith("http"):
        url = "https://" + url
    
    print(f"\033[95m[+]\033[0m Technology Detection — {url}")
    print("=" * 60)
    
    results = detect_tech(url, args.timeout)
    
    if not results:
        print("\033[93m[!]\033[0m No technologies detected")
        return
    
    # Group by type
    by_type = {}
    for tech, info in results.items():
        if tech.startswith("_header_"):
            continue
        t = info["type"]
        by_type.setdefault(t, []).append((tech, info))
    
    type_labels = {
        "web-server": "🖥️  Web Server",
        "cdn": "🌐 CDN/Proxy",
        "framework": "⚡ Framework",
        "language": "💻 Language",
        "cms": "📝 CMS",
        "js-lib": "📦 JS Library",
        "analytics": "📊 Analytics",
        "monitoring": "🔍 Monitoring",
        "auth": "🔐 Auth",
        "cloud": "☁️  Cloud",
        "database": "🗄️  Database",
        "security": "🛡️  Security",
        "payment": "💳 Payment",
        "api": "🔌 API",
        "protocol": "📡 Protocol",
        "config": "⚙️  Config",
        "cache": "💾 Cache",
        "header": "📋 Header",
    }
    
    total = 0
    for t in sorted(by_type.keys()):
        if args.type and args.type.lower() not in t:
            continue
        label = type_labels.get(t, t)
        print(f"\n{label}:")
        for tech, info in by_type[t]:
            total += 1
            version = f" v{info['version']}" if "version" in info else ""
            print(f"  \033[92m✓\033[0m {tech}{version}")
            if args.json:
                for e in info["evidence"]:
                    print(f"      {e}")
    
    # Show raw headers
    for key, info in results.items():
        if key.startswith("_header_"):
            hname = key.replace("_header_", "")
            print(f"\n  \033[94m{hname}:\033[0m {info['evidence'][0]}")
    
    print(f"\n{'=' * 60}")
    print(f"Total: {total} technologies detected")
    
    # Save JSON
    out = {"url": url, "technologies": {k: v for k, v in results.items() if not k.startswith("_header_")}, "total": total}
    with open("output/tech_detect.json", "w") as f:
        json.dump(out, f, indent=2)
    print(f"[*] Results saved to output/tech_detect.json")


if __name__ == "__main__":
    main()
