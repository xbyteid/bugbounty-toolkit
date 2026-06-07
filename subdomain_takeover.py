#!/usr/bin/env python3
"""
Subdomain Takeover Checker — Find dangling CNAME records
Usage: python3 subdomain_takeover.py <domain>
"""

import sys
import json
import socket
import requests
import dns.resolver
from concurrent.futures import ThreadPoolExecutor

requests.packages.urllib3.disable_warnings()

# Known vulnerable services with fingerprints
FINGERPRINTS = {
    "GitHub Pages": {
        "cname": ["github.io", "github.map.fastly.net"],
        "body": ["There isn't a GitHub Pages site here.", "For root URLs (like http://example.com/) you must provide an index.html file"],
        "status": [404]
    },
    "Heroku": {
        "cname": ["herokudns.com", "herokussl.com", "herokuapp.com", "herokuspace.com"],
        "body": ["No such app", "no-hierarchical-name"],
        "status": [404]
    },
    "Shopify": {
        "cname": ["myshopify.com"],
        "body": ["Sorry, this shop is currently unavailable.", "Only one step left!"],
        "status": [404]
    },
    "Fastly": {
        "cname": ["fastly.net", "global.ssl.fastly.net", "a]global-ssl.fastly.net"],
        "body": ["Fastly error: unknown domain"],
        "status": [404]
    },
    "Pantheon": {
        "cname": ["pantheonsite.io"],
        "body": ["404 error unknown site!", "The gods are wise"],
        "status": [404]
    },
    "Tumblr": {
        "cname": ["domains.tumblr.com"],
        "body": ["Whatever you were looking for doesn't currently exist at this address"],
        "status": [404]
    },
    "WordPress.com": {
        "cname": ["wordpress.com"],
        "body": ["Do you want to register"],
        "status": [404]
    },
    "Zendesk": {
        "cname": ["zendesk.com"],
        "body": ["Help Center Closed", "This help center no longer exists"],
        "status": [404]
    },
    "Teamwork": {
        "cname": ["teamwork.com"],
        "body": ["Oops - We didn't find your site."],
        "status": [404]
    },
    "Helpjuice": {
        "cname": ["helpjuice.com"],
        "body": ["We could not find what you're looking for."],
        "status": [404]
    },
    "Helpscout": {
        "cname": ["helpscoutdocs.com"],
        "body": ["No settings were found for this company:"],
        "status": [404]
    },
    "Cargo": {
        "cname": ["cargocollective.com"],
        "body": ["If you're moving your domain away from Cargo you must make this configuration change"],
        "status": [404]
    },
    "Statuspage": {
        "cname": ["statuspage.io"],
        "body": ["Better StatusPage", "You are being redirected"],
        "status": [404]
    },
    "UserVoice": {
        "cname": ["uservoice.com"],
        "body": ["This UserVoice subdomain is currently available!"],
        "status": [404]
    },
    "Surge.sh": {
        "cname": ["surge.sh"],
        "body": ["project not found"],
        "status": [404]
    },
    "Intercom": {
        "cname": ["custom.intercom.help"],
        "body": ["This page is reserved for artistic dogs", "Uh oh. That page doesn't exist."],
        "status": [404]
    },
    "Webflow": {
        "cname": ["proxy.webflow.com", "proxy-ssl.webflow.com"],
        "body": ["The page you are looking for doesn't exist or has been moved."],
        "status": [404]
    },
    "Kajabi": {
        "cname": ["endpoint.mykajabi.com"],
        "body": ["The page you were looking for doesn't exist."],
        "status": [404]
    },
    "Thinkific": {
        "cname": ["thinkific.com"],
        "body": ["You may have typed the address incorrectly or you may have used an outdated link."],
        "status": [404]
    },
    "Tave": {
        "cname": ["clientaccess.tave.com"],
        "body": ["<h1>Error 404: Page Not Found</h1>"],
        "status": [404]
    },
    "Wishpond": {
        "cname": ["wishpond.com"],
        "body": ["https://www.wishpond.com/404?campaign=true"],
        "status": [404]
    },
    "Aftership": {
        "cname": ["aftership.com"],
        "body": ["Oops.</h2><p class=\"text-muted text-tight\">The page you're looking for doesn't exist."],
        "status": [404]
    },
    "Aha!": {
        "cname": ["ideas.aha.io"],
        "body": ["There is no portal here ... check portal URL"],
        "status": [404]
    },
    "Brightcove": {
        "cname": ["bcvp03al.o.brightcove.com"],
        "body": ["<h1>Error 404: Page Not Found</h1>"],
        "status": [404]
    },
    "BigCartel": {
        "cname": ["bigcartel.com"],
        "body": ["<h1>Oops! We couldn&#8217;t find that page.</h1>"],
        "status": [404]
    },
    "Campaignmonitor": {
        "cname": ["createsend.com", "name.createsend.com"],
        "body": ["Double check the URL", "Trying to access your account?"],
        "status": [404]
    },
    "Acquia": {
        "cname": ["acquia-test.co"],
        "body": ["Web Site Not Found", "If you are an Acquia Cloud customer"],
        "status": [404]
    },
    "Proposify": {
        "cname": ["proposify.biz"],
        "body": ["If you need immediate assistance, please contact <a href=\"mailto:support@proposify.biz\""],
        "status": [404]
    },
    "Simplebooklet": {
        "cname": ["simplebooklet.com"],
        "body": ["We can't find this <a href=\"https://simplebooklet.com\""],
        "status": [404]
    },
    "GetResponse": {
        "cname": [".gr8.com"],
        "body": ["With GetResponse Landing Pages, lead generation has never been easier"],
        "status": [404]
    },
    "Vend": {
        "cname": ["vendecommerce.com"],
        "body": ["Looks like you've followed a broken link or entered a URL that doesn't exist on this site."],
        "status": [404]
    },
    "Netlify": {
        "cname": ["netlify.app", "netlify.com"],
        "body": ["Not Found - Request ID"],
        "status": [404]
    },
    "Fly.io": {
        "cname": ["fly.dev", "edgeapp.net"],
        "body": ["404 Not Found"],
        "status": [404]
    },
    "Vercel": {
        "cname": ["vercel.app", "now.sh", "zeit.co"],
        "body": ["The deployment could not be found"],
        "status": [404]
    },
    "Render": {
        "cname": ["onrender.com"],
        "body": ["404 Not Found"],
        "status": [404]
    },
    "Azure": {
        "cname": ["azurewebsites.net", "cloudapp.net", "cloudapp.azure.com", "trafficmanager.net", "blob.core.windows.net"],
        "body": ["404 Web Site not found", "Azure Web App - Your web app is running and waiting for your content"],
        "status": [404]
    },
    "AWS S3": {
        "cname": ["s3.amazonaws.com", "s3-website"],
        "body": ["NoSuchBucket", "The specified bucket does not exist"],
        "status": [404]
    },
    "Google Cloud": {
        "cname": ["c.storage.googleapis.com", "storage.googleapis.com"],
        "body": ["NoSuchBucket", "The specified bucket does not exist"],
        "status": [404]
    },
    "Elastic Beanstalk": {
        "cname": ["elasticbeanstalk.com"],
        "body": [],
        "status": [404]
    },
}

# Additional CNAME patterns that indicate potential takeover
DANGEROUS_CNAME_PATTERNS = [
    "amazonaws.com", "azurewebsites.net", "cloudapp.net",
    "herokuapp.com", "herokudns.com", "github.io",
    "pantheonsite.io", "myshopify.com", "ghost.io",
    "surge.sh", "bitbucket.io", "netlify.app",
    "vercel.app", "now.sh", "fly.dev", "onrender.com",
    "pages.wixsites.com", "firebaseapp.com",
    "web.app", "blogspot.com", "wordpress.com",
    "domains.tumblr.com", "zendesk.com", "helpscoutdocs.com",
    "readme.io", "readthedocs.io", "gitbook.io",
    "canny.io", "intercom.help", "freshdesk.com",
    "statuspage.io", "tawk.to", "cargocollective.com",
    "launchrock.com", "hatena.ne.jp", "feedpress.me",
    "ghost.io", "cname.vercel-dns.com",
]

def get_cname(domain):
    """Get CNAME record for domain"""
    try:
        answers = dns.resolver.resolve(domain, 'CNAME')
        for rdata in answers:
            return str(rdata.target).rstrip('.')
    except:
        return None

def get_ips(domain):
    """Get A/AAAA records"""
    ips = []
    try:
        answers = dns.resolver.resolve(domain, 'A')
        for rdata in answers:
            ips.append(str(rdata))
    except:
        pass
    return ips

def check_takeover(subdomain):
    """Check if a subdomain is vulnerable to takeover"""
    result = {
        "subdomain": subdomain,
        "cname": None,
        "ips": [],
        "vulnerable": False,
        "service": None,
        "evidence": ""
    }
    
    # Get CNAME
    cname = get_cname(subdomain)
    result["cname"] = cname
    
    # Get IPs
    ips = get_ips(subdomain)
    result["ips"] = ips
    
    if not cname and not ips:
        return result
    
    # Check if CNAME points to known vulnerable service
    check_domain = cname if cname else subdomain
    
    for service, fp in FINGERPRINTS.items():
        cname_match = any(c in (check_domain or "").lower() for c in fp["cname"])
        
        if cname_match:
            # Try HTTP request
            try:
                r = requests.get(f"https://{subdomain}", timeout=10, verify=False, allow_redirects=True,
                               headers={"User-Agent": "Mozilla/5.0"})
                
                body_match = any(b in r.text for b in fp["body"])
                status_match = r.status_code in fp["status"]
                
                if body_match or status_match:
                    result["vulnerable"] = True
                    result["service"] = service
                    result["evidence"] = f"Status: {r.status_code}, CNAME: {cname}, Body match: {body_match}"
                    return result
            except:
                pass
            
            # Even without HTTP match, flag dangling CNAME
            result["vulnerable"] = True
            result["service"] = service
            result["evidence"] = f"Dangling CNAME: {cname} (service: {service})"
            return result
    
    # Check if CNAME points to dangerous pattern without active service
    if cname:
        for pattern in DANGEROUS_CNAME_PATTERNS:
            if pattern in cname.lower():
                try:
                    r = requests.get(f"https://{subdomain}", timeout=8, verify=False)
                    if r.status_code in [404, 500, 502, 503]:
                        result["vulnerable"] = True
                        result["service"] = f"Unknown ({pattern})"
                        result["evidence"] = f"CNAME: {cname}, Status: {r.status_code}"
                except socket.gaierror:
                    # DNS resolves but no server — classic takeover
                    result["vulnerable"] = True
                    result["service"] = f"Dead service ({pattern})"
                    result["evidence"] = f"CNAME: {cname}, DNS resolves but no HTTP response"
                except:
                    pass
                break
    
    return result

def load_subdomains(domain):
    """Load subdomains from previous scan or generate"""
    import os
    import glob
    
    # Check for existing subdomain scan results
    pattern = f"output/subdomains_{domain.replace('.', '_')}*.json"
    files = glob.glob(pattern)
    
    if files:
        # Use most recent
        latest = max(files, key=os.path.getmtime)
        with open(latest) as f:
            data = json.load(f)
        subs = [item.get("subdomain", item.get("domain", "")) for item in data]
        subs = [s for s in subs if s]
        if subs:
            return subs
    
    # Generate basic list
    common = ["www", "api", "mail", "dev", "staging", "test", "admin", "portal",
              "app", "beta", "cdn", "assets", "static", "media", "images",
              "docs", "support", "help", "blog", "status", "monitoring",
              "jenkins", "ci", "git", "gitlab", "grafana", "kibana",
              "vpn", "remote", "gateway", "proxy", "load", "lb"]
    return [f"{s}.{domain}" for s in common]

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 subdomain_takeover.py <domain>")
        print("Example: python3 subdomain_takeover.py example.com")
        print("\nOr: python3 subdomain_takeover.py -f subdomains.txt")
        sys.exit(1)
    
    if sys.argv[1] == "-f":
        with open(sys.argv[2]) as f:
            subdomains = [line.strip() for line in f if line.strip()]
        domain = subdomains[0].split(".")[-2] + "." + subdomains[0].split(".")[-1]
    else:
        domain = sys.argv[1]
        subdomains = load_subdomains(domain)
    
    print(f"\n{'='*60}")
    print(f"🏴‍☠️ Subdomain Takeover Checker")
    print(f"Target: {domain}")
    print(f"Subdomains: {len(subdomains)}")
    print(f"{'='*60}\n")
    
    results = []
    vulnerable = []
    
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(check_takeover, sub): sub for sub in subdomains}
        
        for i, future in enumerate(futures, 1):
            result = future.result()
            results.append(result)
            
            sub = result["subdomain"]
            cname = result["cname"] or "-"
            
            if result["vulnerable"]:
                vulnerable.append(result)
                print(f"  🔴 [{i}/{len(subdomains)}] {sub}")
                print(f"     CNAME: {cname}")
                print(f"     Service: {result['service']}")
                print(f"     Evidence: {result['evidence']}")
            elif result["cname"]:
                print(f"  🟡 [{i}/{len(subdomains)}] {sub} → {cname}")
            else:
                if i % 50 == 0:
                    print(f"  ⏳ [{i}/{len(subdomains)}] scanning...")
    
    # Summary
    print(f"\n{'='*60}")
    print(f"📊 RESULTS")
    print(f"{'='*60}")
    print(f"Total scanned: {len(subdomains)}")
    print(f"With CNAME: {len([r for r in results if r['cname']])}")
    print(f"Vulnerable: {len(vulnerable)}")
    
    if vulnerable:
        print(f"\n🔴 VULNERABLE TO SUBDOMAIN TAKEOVER:")
        for v in vulnerable:
            print(f"\n  {v['subdomain']}")
            print(f"  CNAME: {v['cname']}")
            print(f"  Service: {v['service']}")
            print(f"  Evidence: {v['evidence']}")
    
    # Save
    import os
    os.makedirs("output", exist_ok=True)
    outfile = f"output/takeover_{domain.replace('.', '_')}.json"
    with open(outfile, "w") as f:
        json.dump(vulnerable, f, indent=2)
    print(f"\n💾 Saved to {outfile}")

if __name__ == "__main__":
    main()
