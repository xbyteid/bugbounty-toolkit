#!/usr/bin/env python3
"""Favicon Hash Scanner (Shodan/Censys)
Computes favicon hash for Shodan/Censys queries to discover related infrastructure.
Uses mmh3 hash (Shodan format) and MurmurHash3.

Usage:
    python3 favicon_hash.py https://target.com
    python3 favicon_hash.py https://target.com --shodan-query  # Auto-generate Shodan query
    python3 favicon_hash.py https://target.com --check-virustotal
"""

import argparse
import base64
import hashlib
import json
import re
import struct
import requests
import urllib3
urllib3.disable_warnings()


def mmh3_hash(data):
    """Compute MurmurHash3 (32-bit, x86) — same as Shodan's favicon hash."""
    # MurmurHash3 implementation (simplified for 32-bit x86)
    c1 = 0xcc9e2d51
    c2 = 0x1b873593
    length = len(data)
    h1 = 0  # seed = 0
    
    # Body
    nblocks = length // 4
    for i in range(nblocks):
        k1 = struct.unpack('<I', data[i*4:(i+1)*4])[0]
        k1 = (k1 * c1) & 0xffffffff
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xffffffff
        k1 = (k1 * c2) & 0xffffffff
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xffffffff
        h1 = (h1 * 5 + 0xe6546b64) & 0xffffffff
    
    # Tail
    k1 = 0
    tail = length - nblocks * 4
    if tail == 3:
        k1 ^= (data[nblocks*4 + 2] & 0xff) << 16
    if tail >= 2:
        k1 ^= (data[nblocks*4 + 1] & 0xff) << 8
    if tail >= 1:
        k1 ^= (data[nblocks*4] & 0xff)
        k1 = (k1 * c1) & 0xffffffff
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xffffffff
        k1 = (k1 * c2) & 0xffffffff
        h1 ^= k1
    
    # Finalization
    h1 ^= length
    h1 ^= (h1 >> 16)
    h1 = (h1 * 0x85ebca6b) & 0xffffffff
    h1 ^= (h1 >> 13)
    h1 = (h1 * 0xc2b2ae35) & 0xffffffff
    h1 ^= (h1 >> 16)
    
    # Convert to signed 32-bit
    if h1 >= 0x80000000:
        h1 -= 0x100000000
    
    return h1


def get_favicon_urls(url):
    """Extract favicon URLs from page HTML."""
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    favicons = []
    parsed = re.match(r'(https?://[^/]+)', url)
    base = parsed.group(1) if parsed else url.rstrip("/")
    
    try:
        r = requests.get(url, headers=headers, timeout=10, verify=False)
        body = r.text
        
        # Find favicon in HTML
        icon_patterns = [
            r'<link[^>]*rel=["\'](?:icon|shortcut icon)["\'][^>]*href=["\']([^"\']+)["\']',
            r'<link[^>]*href=["\']([^"\']+)["\'][^>]*rel=["\'](?:icon|shortcut icon)["\']',
        ]
        
        for pat in icon_patterns:
            matches = re.findall(pat, body, re.I)
            for m in matches:
                if m.startswith("//"):
                    m = "https:" + m
                elif m.startswith("/"):
                    m = base + m
                elif not m.startswith("http"):
                    m = base + "/" + m
                favicons.append(m)
        
    except:
        pass
    
    # Common favicon paths
    common_paths = [
        "/favicon.ico",
        "/favicon.png",
        "/apple-touch-icon.png",
        "/apple-touch-icon-precomposed.png",
        "/apple-touch-icon-120x120.png",
        "/apple-touch-icon-152x152.png",
        "/android-chrome-192x192.png",
        "/android-chrome-512x512.png",
        "/mstile-150x150.png",
        "/safari-pinned-tab.svg",
        "/browserconfig.xml",
    ]
    
    for path in common_paths:
        favicons.append(base + path)
    
    return list(dict.fromkeys(favicons))  # Dedupe preserving order


def fetch_and_hash(url):
    """Fetch favicon and compute hashes."""
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    
    try:
        r = requests.get(url, headers=headers, timeout=10, verify=False)
        if r.status_code != 200:
            return None
        
        data = r.content
        if len(data) < 10:
            return None
        
        # Compute hashes
        mmh3 = mmh3_hash(data)
        md5 = hashlib.md5(data).hexdigest()
        sha256 = hashlib.sha256(data).hexdigest()
        b64 = base64.b64encode(data).decode()
        
        return {
            "url": url,
            "size": len(data),
            "mmh3": mmh3,
            "md5": md5,
            "sha256": sha256[:16] + "...",
            "base64": b64[:60] + "..." if len(b64) > 60 else b64,
            "content_type": r.headers.get("content-type", "unknown"),
        }
    except:
        return None


def main():
    parser = argparse.ArgumentParser(description="Favicon Hash Scanner (Shodan/Censys)")
    parser.add_argument("url", help="Target URL")
    parser.add_argument("--shodan-query", action="store_true", help="Generate Shodan search query")
    parser.add_argument("--check-virustotal", action="store_true", help="Check hash on VirusTotal")
    parser.add_argument("--json", action="store_true", help="JSON output")
    args = parser.parse_args()
    
    url = args.url.rstrip("/")
    if not url.startswith("http"):
        url = "https://" + url
    
    print(f"\033[95m[+]\033[0m Favicon Hash Scanner — {url}")
    print("=" * 60)
    
    # Get favicon URLs
    print(f"\033[94m[*]\033[0m Discovering favicon URLs...")
    favicon_urls = get_favicon_urls(url)
    print(f"\033[94m[*]\033[0m Found {len(favicon_urls)} potential favicon URLs")
    
    # Fetch and hash
    results = []
    for fav_url in favicon_urls:
        result = fetch_and_hash(fav_url)
        if result:
            results.append(result)
            print(f"\n\033[92m[✓]\033[0m {fav_url}")
            print(f"    Size: {result['size']} bytes | Type: {result['content_type']}")
            print(f"    MMH3 (Shodan): {result['mmh3']}")
            print(f"    MD5:           {result['md5']}")
            print(f"    SHA256:        {result['sha256']}")
            
            if args.shodan_query:
                print(f"\n    \033[93mShodan query:\033[0m")
                print(f"    http.favicon.hash:{result['mmh3']}")
                print(f"    \033[94mhttps://www.shodan.io/search?query=http.favicon.hash%3A{result['mmh3']}\033[0m")
            
            if args.check_virustotal:
                print(f"\n    \033[94mVirusTotal:\033[0m")
                print(f"    https://www.virustotal.com/gui/file/{result['md5']}")
            
            break  # Use first successful favicon
    
    if not results:
        print(f"\n\033[91m[-]\033[0m No favicons found")
        
        # Try direct /favicon.ico as last resort
        base = re.match(r'(https?://[^/]+)', url)
        if base:
            fav = base.group(1) + "/favicon.ico"
            print(f"\033[94m[*]\033[0m Trying direct: {fav}")
            result = fetch_and_hash(fav)
            if result:
                results.append(result)
                print(f"\033[92m[✓]\033[0m {fav}")
                print(f"    MMH3 (Shodan): {result['mmh3']}")
                print(f"    MD5:           {result['md5']}")
    
    if results:
        print(f"\n{'=' * 60}")
        print(f"\033[93m[!]\033[0m Use these queries to find related infrastructure:")
        for r in results:
            print(f"  Shodan:  http.favicon.hash:{r['mmh3']}")
            print(f"  Censys:  AND services.http.response.favicons.md5_hash={r['md5']}")
            break
        
        print(f"\n\033[94m[*]\033[0m Related infrastructure = same company/deployment (IPs, ASNs)")
    
    out = {"url": url, "favicons": results, "total_found": len(results)}
    with open("output/favicon_hash.json", "w") as f:
        json.dump(out, f, indent=2)
    print(f"\n[*] Results saved to output/favicon_hash.json")


if __name__ == "__main__":
    main()
