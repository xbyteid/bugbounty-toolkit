#!/usr/bin/env python3
"""
Sensitive File Scanner — Find exposed .env, .git, backups, configs
Usage: python3 sensitive_scanner.py <url>
"""

import sys
import json
import requests
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin

requests.packages.urllib3.disable_warnings()

SENSITIVE_PATHS = [
    # Git
    ("/.git/HEAD", "Git repository exposed", "CRITICAL"),
    ("/.git/config", "Git config exposed", "CRITICAL"),
    ("/.gitignore", "Gitignore exposed", "MEDIUM"),
    ("/.git/logs/HEAD", "Git logs exposed", "HIGH"),
    
    # Environment files
    ("/.env", "Environment file exposed", "CRITICAL"),
    ("/.env.local", "Local env exposed", "CRITICAL"),
    ("/.env.production", "Production env exposed", "CRITICAL"),
    ("/.env.staging", "Staging env exposed", "CRITICAL"),
    ("/.env.development", "Development env exposed", "CRITICAL"),
    ("/.env.backup", "Backup env exposed", "CRITICAL"),
    ("/.env.old", "Old env exposed", "CRITICAL"),
    ("/.env.save", "Saved env exposed", "CRITICAL"),
    ("/.env.example", "Example env exposed", "HIGH"),
    ("/env", "Env endpoint", "HIGH"),
    ("/env.js", "Env JS file", "HIGH"),
    ("/config.js", "Config JS file", "HIGH"),
    ("/config.json", "Config JSON", "HIGH"),
    ("/config.yaml", "Config YAML", "HIGH"),
    ("/config.yml", "Config YAML", "HIGH"),
    ("/configuration.json", "Configuration file", "HIGH"),
    ("/settings.json", "Settings file", "HIGH"),
    
    # Backup files
    ("/backup", "Backup directory", "HIGH"),
    ("/backup.zip", "Backup ZIP", "CRITICAL"),
    ("/backup.tar.gz", "Backup tarball", "CRITICAL"),
    ("/backup.sql", "SQL backup", "CRITICAL"),
    ("/dump.sql", "SQL dump", "CRITICAL"),
    ("/database.sql", "Database dump", "CRITICAL"),
    ("/db.sql", "DB dump", "CRITICAL"),
    ("/backup.bak", "Backup file", "HIGH"),
    ("/site.zip", "Site backup", "CRITICAL"),
    ("/www.zip", "WWW backup", "CRITICAL"),
    ("/public.zip", "Public backup", "HIGH"),
    ("/source.zip", "Source backup", "CRITICAL"),
    ("/archive.zip", "Archive", "HIGH"),
    ("/old.zip", "Old backup", "HIGH"),
    
    # Docker
    ("/Dockerfile", "Dockerfile exposed", "HIGH"),
    ("/docker-compose.yml", "Docker Compose exposed", "HIGH"),
    ("/docker-compose.yaml", "Docker Compose exposed", "HIGH"),
    ("/.dockerignore", "Docker ignore exposed", "MEDIUM"),
    
    # CI/CD
    ("/.github/workflows", "GitHub Actions exposed", "HIGH"),
    ("/.gitlab-ci.yml", "GitLab CI exposed", "HIGH"),
    ("/Jenkinsfile", "Jenkins file exposed", "HIGH"),
    ("/.travis.yml", "Travis CI exposed", "MEDIUM"),
    ("/.circleci/config.yml", "CircleCI exposed", "MEDIUM"),
    ("/bitbucket-pipelines.yml", "Bitbucket Pipelines exposed", "MEDIUM"),
    
    # API docs
    ("/swagger.json", "Swagger JSON exposed", "HIGH"),
    ("/swagger.yaml", "Swagger YAML exposed", "HIGH"),
    ("/swagger-ui.html", "Swagger UI exposed", "HIGH"),
    ("/swagger-ui/", "Swagger UI exposed", "HIGH"),
    ("/api-docs", "API docs exposed", "HIGH"),
    ("/api-docs.json", "API docs JSON exposed", "HIGH"),
    ("/openapi.json", "OpenAPI spec exposed", "HIGH"),
    ("/openapi.yaml", "OpenAPI spec exposed", "HIGH"),
    ("/api/swagger.json", "API Swagger exposed", "HIGH"),
    ("/api/v1/swagger.json", "API v1 Swagger exposed", "HIGH"),
    ("/graphql", "GraphQL endpoint", "HIGH"),
    ("/graphiql", "GraphiQL exposed", "HIGH"),
    ("/playground", "GraphQL Playground exposed", "HIGH"),
    
    # Debug/Admin
    ("/debug", "Debug endpoint", "HIGH"),
    ("/debug/vars", "Debug vars exposed", "CRITICAL"),
    ("/debug/pprof", "Debug profiling exposed", "HIGH"),
    ("/debug/requests", "Debug requests exposed", "HIGH"),
    ("/trace", "Trace endpoint", "HIGH"),
    ("/actuator", "Spring Actuator exposed", "CRITICAL"),
    ("/actuator/env", "Spring env exposed", "CRITICAL"),
    ("/actuator/health", "Spring health exposed", "HIGH"),
    ("/actuator/info", "Spring info exposed", "HIGH"),
    ("/actuator/beans", "Spring beans exposed", "HIGH"),
    ("/actuator/configprops", "Spring config exposed", "CRITICAL"),
    ("/actuator/mappings", "Spring mappings exposed", "HIGH"),
    ("/actuator/heapdump", "Heap dump exposed", "CRITICAL"),
    ("/actuator/logfile", "Log file exposed", "HIGH"),
    ("/console", "Console exposed", "HIGH"),
    ("/admin", "Admin panel", "HIGH"),
    ("/admin/", "Admin panel", "HIGH"),
    ("/phpinfo", "PHP info exposed", "HIGH"),
    ("/phpinfo.php", "PHP info file", "HIGH"),
    ("/info.php", "Info PHP file", "HIGH"),
    ("/test.php", "Test PHP file", "MEDIUM"),
    ("/server-status", "Server status exposed", "HIGH"),
    ("/server-info", "Server info exposed", "HIGH"),
    ("/.htaccess", "htaccess exposed", "HIGH"),
    ("/nginx.conf", "Nginx config exposed", "HIGH"),
    ("/web.config", "Web config exposed", "HIGH"),
    
    # Monitoring
    ("/prometheus", "Prometheus exposed", "HIGH"),
    ("/metrics", "Metrics endpoint", "MEDIUM"),
    ("/grafana", "Grafana exposed", "HIGH"),
    ("/kibana", "Kibana exposed", "HIGH"),
    ("/elasticsearch", "Elasticsearch exposed", "CRITICAL"),
    ("/_cat/indices", "ES indices exposed", "CRITICAL"),
    ("/_cluster/health", "ES cluster health", "HIGH"),
    
    # Common files
    ("/robots.txt", "Robots.txt", "INFO"),
    ("/sitemap.xml", "Sitemap", "INFO"),
    ("/crossdomain.xml", "Cross-domain policy", "MEDIUM"),
    ("/clientaccesspolicy.xml", "Client access policy", "MEDIUM"),
    ("/security.txt", "Security.txt", "INFO"),
    ("/humans.txt", "Humans.txt", "INFO"),
    ("/readme.html", "Readme exposed", "LOW"),
    ("/readme.txt", "Readme exposed", "LOW"),
    ("/README.md", "README exposed", "LOW"),
    ("/CHANGELOG.md", "Changelog exposed", "MEDIUM"),
    ("/LICENSE", "License file", "INFO"),
    ("/package.json", "Package.json exposed", "MEDIUM"),
    ("/composer.json", "Composer.json exposed", "MEDIUM"),
    ("/Gemfile", "Gemfile exposed", "MEDIUM"),
    ("/requirements.txt", "Requirements exposed", "MEDIUM"),
    ("/yarn.lock", "Yarn lock exposed", "LOW"),
    ("/package-lock.json", "Package lock exposed", "LOW"),
    
    # WordPress
    ("/wp-admin", "WordPress admin", "HIGH"),
    ("/wp-login.php", "WordPress login", "MEDIUM"),
    ("/wp-json", "WordPress REST API", "HIGH"),
    ("/wp-json/wp/v2/users", "WordPress users API", "HIGH"),
    ("/xmlrpc.php", "XML-RPC exposed", "HIGH"),
    ("/wp-config.php.bak", "WP config backup", "CRITICAL"),
    ("/wp-config.php.old", "WP config old", "CRITICAL"),
    ("/wp-config.php.save", "WP config save", "CRITICAL"),
    ("/wp-config.php~", "WP config backup", "CRITICAL"),
    ("/wp-content/debug.log", "WP debug log", "HIGH"),
    
    # Laravel
    ("/storage/logs/laravel.log", "Laravel log exposed", "CRITICAL"),
    ("/_ignition/execute-solution", "Ignition RCE", "CRITICAL"),
    
    # Spring
    ("/jolokia", "Jolokia exposed", "CRITICAL"),
    ("/jmx-console", "JMX console exposed", "CRITICAL"),
    ("/web-console", "Web console exposed", "HIGH"),
    
    # Tomcat
    ("/manager/html", "Tomcat manager", "HIGH"),
    ("/host-manager/html", "Tomcat host manager", "HIGH"),
    
    # Misc
    ("/.ssh", "SSH directory exposed", "CRITICAL"),
    ("/.ssh/id_rsa", "SSH private key exposed", "CRITICAL"),
    ("/id_rsa", "SSH private key exposed", "CRITICAL"),
    ("/authorized_keys", "Authorized keys exposed", "HIGH"),
    ("/.bash_history", "Bash history exposed", "HIGH"),
    ("/.bashrc", "Bashrc exposed", "MEDIUM"),
    ("/.profile", "Profile exposed", "MEDIUM"),
    ("/.aws/credentials", "AWS credentials exposed", "CRITICAL"),
    ("/.aws/config", "AWS config exposed", "HIGH"),
    ("/credentials", "Credentials file exposed", "CRITICAL"),
    ("/secrets.json", "Secrets file exposed", "CRITICAL"),
    ("/secrets.yaml", "Secrets YAML exposed", "CRITICAL"),
    ("/tokens.json", "Tokens file exposed", "CRITICAL"),
    ("/keys.json", "Keys file exposed", "CRITICAL"),
    
    # Logs
    ("/logs", "Log directory", "HIGH"),
    ("/log", "Log directory", "HIGH"),
    ("/access.log", "Access log exposed", "HIGH"),
    ("/error.log", "Error log exposed", "HIGH"),
    ("/app.log", "App log exposed", "HIGH"),
    ("/debug.log", "Debug log exposed", "HIGH"),
    
    # Database
    ("/db", "Database endpoint", "HIGH"),
    ("/database", "Database endpoint", "HIGH"),
    ("/phpmyadmin", "phpMyAdmin exposed", "CRITICAL"),
    ("/adminer.php", "Adminer exposed", "CRITICAL"),
    ("/pgadmin", "pgAdmin exposed", "HIGH"),
    ("/mongo-express", "Mongo Express exposed", "CRITICAL"),
    
    # Cache/Queue
    ("/redis", "Redis exposed", "CRITICAL"),
    ("/memcached", "Memcached exposed", "HIGH"),
    ("/rabbitmq", "RabbitMQ exposed", "HIGH"),
    ("/celery", "Celery exposed", "HIGH"),
    
    # Cloud metadata
    ("/metadata", "Cloud metadata", "CRITICAL"),
    ("/latest/meta-data", "AWS metadata", "CRITICAL"),
]

def check_path(base_url, path_info):
    """Check if a sensitive path is accessible"""
    path, description, severity = path_info
    url = urljoin(base_url, path)
    
    try:
        r = requests.get(url, timeout=8, verify=False,
                        headers={"User-Agent": "Mozilla/5.0"},
                        allow_redirects=False)
        
        # Skip if redirected to login
        if r.status_code in [301, 302]:
            location = r.headers.get("Location", "").lower()
            if any(x in location for x in ["login", "signin", "auth", "sso"]):
                return None
        
        if r.status_code == 200 and len(r.text) > 10:
            body = r.text.lower()
            
            # Filter false positives
            if any(x in body for x in ["page not found", "404 not found", "not found",
                                         "does not exist", "error occurred"]):
                return None
            
            # Check for interesting content
            interesting = False
            if path.endswith((".env", ".git/HEAD", ".git/config")):
                interesting = True
            elif "password" in body or "secret" in body or "key" in body:
                interesting = True
            elif len(r.text) > 100:
                interesting = True
            
            if interesting:
                return {
                    "path": path,
                    "url": url,
                    "status": r.status_code,
                    "size": len(r.text),
                    "severity": severity,
                    "description": description,
                    "body_preview": r.text[:300]
                }
        
        elif r.status_code == 403:
            return {
                "path": path,
                "url": url,
                "status": 403,
                "severity": "INFO",
                "description": f"{description} (403 Forbidden)",
                "body_preview": ""
            }
    except:
        pass
    
    return None

def scan_url(url):
    """Scan URL for sensitive files"""
    base = url.rstrip('/') + '/'
    if not base.startswith("http"):
        base = "https://" + base
    
    print(f"\n{'='*60}")
    print(f"📁 Sensitive File Scanner")
    print(f"Target: {base}")
    print(f"Paths: {len(SENSITIVE_PATHS)}")
    print(f"{'='*60}\n")
    
    findings = []
    
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(check_path, base, p): p for p in SENSITIVE_PATHS}
        
        for i, future in enumerate(futures, 1):
            result = future.result()
            if result:
                findings.append(result)
                sev = result["severity"]
                icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "INFO": "⚪"}
                print(f"  {icon.get(sev, '⚪')} [{sev}] {result['path']}")
                print(f"     {result['description']} ({result['size']} bytes)")
            
            if i % 100 == 0:
                print(f"  ⏳ [{i}/{len(SENSITIVE_PATHS)}] scanning...")
    
    # Summary
    print(f"\n{'='*60}")
    print(f"📊 SENSITIVE FILE RESULTS")
    print(f"{'='*60}")
    
    critical = [f for f in findings if f["severity"] == "CRITICAL"]
    high = [f for f in findings if f["severity"] == "HIGH"]
    medium = [f for f in findings if f["severity"] == "MEDIUM"]
    low = [f for f in findings if f["severity"] in ["LOW", "INFO"]]
    
    print(f"🔴 Critical: {len(critical)}")
    print(f"🟠 High: {len(high)}")
    print(f"🟡 Medium: {len(medium)}")
    print(f"🟢 Low/Info: {len(low)}")
    
    if critical:
        print(f"\n🔴 CRITICAL FINDINGS:")
        for f in critical:
            print(f"  {f['path']}")
            print(f"    {f['description']}")
            if f['body_preview']:
                print(f"    Preview: {f['body_preview'][:100]}")
    
    # Save
    import os
    os.makedirs("output", exist_ok=True)
    from urllib.parse import urlparse
    domain = urlparse(base).netloc.replace(".", "_")
    outfile = f"output/sensitive_{domain}.json"
    with open(outfile, "w") as f:
        json.dump(findings, f, indent=2)
    print(f"\n💾 Saved to {outfile}")
    
    return findings

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 sensitive_scanner.py <url>")
        print("Example: python3 sensitive_scanner.py https://example.com")
        sys.exit(1)
    scan_url(sys.argv[1])
