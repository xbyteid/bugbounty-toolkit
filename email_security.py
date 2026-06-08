#!/usr/bin/env python3
"""Email Security Checker — SPF, DKIM, DMARC
Validates email security configurations for a domain.
Critical for phishing/social engineering attack surface assessment.
"""

import argparse
import json
import re
import dns.resolver

def check_spf(domain):
    """Check SPF record."""
    result = {"status": "missing", "record": None, "issues": []}
    try:
        answers = dns.resolver.resolve(domain, "TXT")
        for r in answers:
            txt = str(r).strip('"')
            if txt.startswith("v=spf1"):
                result["record"] = txt
                result["status"] = "found"
                
                # Analyze SPF
                if "+all" in txt:
                    result["issues"].append("CRITICAL: +all allows ANY server to send (completely insecure)")
                elif "~all" in txt:
                    result["issues"].append("WARNING: ~all is softfail (emails pass but marked)")
                elif "-all" not in txt:
                    result["issues"].append("WARNING: No -all directive (default is neutral)")
                
                if "include:" in txt:
                    includes = re.findall(r'include:(\S+)', txt)
                    result["includes"] = includes
                
                # Check for too many DNS lookups
                mechanisms = re.findall(r'(include:|redirect=|a:|mx:|exists:)', txt)
                if len(mechanisms) > 10:
                    result["issues"].append(f"WARNING: {len(mechanisms)} DNS lookups (max 10, will cause permerror)")
                
                # Check IP ranges
                ip4 = re.findall(r'ip4:(\S+)', txt)
                ip6 = re.findall(r'ip6:(\S+)', txt)
                if ip4 or ip6:
                    result["ip_ranges"] = ip4 + ip6
                
                break
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        pass
    except Exception as e:
        result["error"] = str(e)
    
    return result


def check_dmarc(domain):
    """Check DMARC record."""
    result = {"status": "missing", "record": None, "policy": None, "issues": []}
    try:
        dmarc_domain = f"_dmarc.{domain}"
        answers = dns.resolver.resolve(dmarc_domain, "TXT")
        for r in answers:
            txt = str(r).strip('"')
            if "v=DMARC1" in txt:
                result["record"] = txt
                result["status"] = "found"
                
                # Extract policy
                policy_match = re.search(r'p=(\w+)', txt)
                if policy_match:
                    result["policy"] = policy_match.group(1)
                
                # Check policy
                if result["policy"] == "none":
                    result["issues"].append("WARNING: p=none (monitor only, no enforcement)")
                elif result["policy"] == "quarantine":
                    result["issues"].append("INFO: p=quarantine (suspicious emails quarantined)")
                elif result["policy"] == "reject":
                    result["issues"].append("GOOD: p=reject (strictest policy)")
                
                # Check rua/ruf
                rua = re.findall(r'rua=([^;\s]+)', txt)
                ruf = re.findall(r'ruf=([^;\s]+)', txt)
                if rua:
                    result["aggregate_reports"] = rua
                if ruf:
                    result["forensic_reports"] = ruf
                
                # Check subdomain policy
                sp = re.search(r'sp=(\w+)', txt)
                if sp:
                    result["subdomain_policy"] = sp.group(1)
                
                # Check alignment
                aspf = re.search(r'aspf=(\w+)', txt)
                adkim = re.search(r'adkim=(\w+)', txt)
                if aspf:
                    result["spf_alignment"] = aspf.group(1)
                if adkim:
                    result["dkim_alignment"] = adkim.group(1)
                
                # pct
                pct = re.search(r'pct=(\d+)', txt)
                if pct and int(pct.group(1)) < 100:
                    result["issues"].append(f"WARNING: pct={pct.group(1)} (only {pct.group(1)}% of emails checked)")
                
                break
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        pass
    except Exception as e:
        result["error"] = str(e)
    
    return result


def check_dkim(domain, selectors=None):
    """Check DKIM records with common selectors."""
    if selectors is None:
        selectors = [
            "default", "google", "selector1", "selector2", "k1", "k2",
            "mail", "email", "dkim", "s1", "s2", "smtp", "mandrill",
            "amazonses", "mailchimp", "sendgrid", "protonmail",
            "zoho", "yandex", "mxvault", "cm", "everlytickey1", "everlytickey2",
            "dkim1", "dkim2", "mx", "sig1", "smtpapi",
        ]
    
    results = []
    for sel in selectors:
        try:
            dkim_domain = f"{sel}._domainkey.{domain}"
            answers = dns.resolver.resolve(dkim_domain, "TXT")
            for r in answers:
                txt = str(r).strip('"')
                if "v=DKIM1" in txt or "k=rsa" in txt or "p=" in txt:
                    entry = {"selector": sel, "record": txt, "status": "found", "issues": []}
                    
                    # Check for revoked key
                    if "p=" in txt and txt.split("p=")[1].split(";")[0].strip() == "":
                        entry["issues"].append("CRITICAL: Empty p= means revoked key (no signing)")
                    
                    # Check key length
                    if "p=MIIB" in txt or "p=MIGf" in txt:
                        entry["issues"].append("INFO: RSA key present")
                    
                    # Check for weak hash
                    if "h=sha1" in txt.lower():
                        entry["issues"].append("WARNING: SHA-1 hash (consider SHA-256)")
                    
                    results.append(entry)
                    break
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            continue
        except:
            continue
    
    return results


def check_mx(domain):
    """Check MX records."""
    results = []
    try:
        answers = dns.resolver.resolve(domain, "MX")
        for r in answers:
            results.append({"priority": r.preference, "exchange": str(r.exchange).rstrip(".")})
        results.sort(key=lambda x: x["priority"])
    except:
        pass
    return results


def check_dane(domain):
    """Check DANE/TLSA records."""
    result = {"status": "missing"}
    try:
        answers = dns.resolver.resolve(f"_25._tcp.{domain}", "TLSA")
        records = []
        for r in answers:
            records.append(str(r))
        if records:
            result["status"] = "found"
            result["records"] = records
    except:
        pass
    return result


def check_mta_sts(domain):
    """Check MTA-STS policy."""
    result = {"status": "missing"}
    try:
        answers = dns.resolver.resolve(f"_mta-sts.{domain}", "TXT")
        for r in answers:
            txt = str(r).strip('"')
            if "v=STSv1" in txt:
                result["status"] = "found"
                result["record"] = txt
                # Try to fetch policy
                try:
                    import requests
                    policy = requests.get(f"https://mta-sts.{domain}/.well-known/mta-sts.txt", timeout=5)
                    if policy.status_code == 200:
                        result["policy"] = policy.text
                except:
                    pass
                break
    except:
        pass
    return result


def main():
    parser = argparse.ArgumentParser(description="Email Security Checker (SPF/DKIM/DMARC)")
    parser.add_argument("domain", help="Target domain")
    parser.add_argument("--dkim-selectors", help="Comma-separated DKIM selectors to check")
    parser.add_argument("--json", action="store_true", help="JSON output")
    args = parser.parse_args()
    
    domain = args.domain.lower().replace("http://", "").replace("https://", "").split("/")[0]
    
    selectors = None
    if args.dkim_selectors:
        selectors = [s.strip() for s in args.dkim_selectors.split(",")]
    
    print(f"\033[95m[+]\033[0m Email Security Check — {domain}")
    print("=" * 60)
    
    output = {"domain": domain}
    
    # MX Records
    mx = check_mx(domain)
    print(f"\n\033[94m[*] MX Records:\033[0m")
    if mx:
        for m in mx:
            print(f"    {m['priority']:5d}  {m['exchange']}")
        output["mx"] = mx
    else:
        print("    No MX records found")
        output["mx"] = []
    
    # SPF
    spf = check_spf(domain)
    print(f"\n\033[94m[*] SPF:\033[0m")
    if spf["status"] == "found":
        print(f"    \033[92m✓\033[0m {spf['record']}")
        for issue in spf["issues"]:
            color = "\033[91m" if "CRITICAL" in issue else "\033[93m" if "WARNING" in issue else "\033[92m"
            print(f"    {color}• {issue}\033[0m")
    else:
        print(f"    \033[91m✗ No SPF record found (anyone can spoof this domain!)\033[0m")
    output["spf"] = spf
    
    # DMARC
    dmarc = check_dmarc(domain)
    print(f"\n\033[94m[*] DMARC:\033[0m")
    if dmarc["status"] == "found":
        print(f"    \033[92m✓\033[0m {dmarc['record']}")
        for issue in dmarc["issues"]:
            color = "\033[91m" if "CRITICAL" in issue else "\033[93m" if "WARNING" in issue else "\033[92m"
            print(f"    {color}• {issue}\033[0m")
    else:
        print(f"    \033[91m✗ No DMARC record found (no email authentication policy!)\033[0m")
    output["dmarc"] = dmarc
    
    # DKIM
    dkim = check_dkim(domain, selectors)
    print(f"\n\033[94m[*] DKIM:\033[0m")
    if dkim:
        for d in dkim:
            masked = d['record'][:60] + "..." if len(d['record']) > 60 else d['record']
            print(f"    \033[92m✓\033[0m selector={d['selector']}  {masked}")
            for issue in d["issues"]:
                print(f"      • {issue}")
    else:
        print(f"    \033[93m⚠ No DKIM records found with common selectors\033[0m")
        print(f"      (try --dkim-selectors=custom1,custom2)")
    output["dkim"] = dkim
    
    # MTA-STS
    mta_sts = check_mta_sts(domain)
    print(f"\n\033[94m[*] MTA-STS:\033[0m")
    if mta_sts["status"] == "found":
        print(f"    \033[92m✓\033[0m {mta_sts['record']}")
    else:
        print(f"    \033[93m⚠ No MTA-STS (no forced TLS for inbound email)\033[0m")
    output["mta_sts"] = mta_sts
    
    # DANE
    dane = check_dane(domain)
    print(f"\n\033[94m[*] DANE/TLSA:\033[0m")
    if dane["status"] == "found":
        print(f"    \033[92m✓\033[0m TLSA records present")
    else:
        print(f"    \033[93m⚠ No DANE/TLSA records\033[0m")
    output["dane"] = dane
    
    # Summary
    print(f"\n{'=' * 60}")
    score = 0
    max_score = 5
    if spf["status"] == "found": score += 1
    if dmarc["status"] == "found": score += 1
    if dmarc.get("policy") in ["quarantine", "reject"]: score += 1
    if dkim: score += 1
    if mta_sts["status"] == "found": score += 1
    
    color = "\033[92m" if score >= 4 else "\033[93m" if score >= 2 else "\033[91m"
    print(f"{color}Email Security Score: {score}/{max_score}\033[0m")
    
    if score < 3:
        print(f"\n\033[91m[!] This domain is VULNERABLE to email spoofing!\033[0m")
        print(f"    Attackers can send emails as @{domain}")
    
    output["score"] = f"{score}/{max_score}"
    
    with open("output/email_security.json", "w") as f:
        json.dump(output, f, indent=2)
    print(f"\n[*] Results saved to output/email_security.json")


if __name__ == "__main__":
    main()
