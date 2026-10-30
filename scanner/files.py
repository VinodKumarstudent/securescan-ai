from urllib.parse import urljoin, urlparse
import requests
from config import Config

SENSITIVE_PATHS = [
    {
        "path": "/.env",
        "title": "Sensitive Environment File (.env) Exposed",
        "severity": "Critical",
        "cvss": 9.1,
        "indicator": lambda text: any(k in text for k in ["DB_PASSWORD", "SECRET_KEY", "AWS_ACCESS", "API_KEY", "APP_ENV="])
    },
    {
        "path": "/.git/HEAD",
        "title": "Git Repository Metadata Exposed (.git/HEAD)",
        "severity": "High",
        "cvss": 7.5,
        "indicator": lambda text: "ref: refs/" in text
    },
    {
        "path": "/robots.txt",
        "title": "Robots.txt Information Disclosure",
        "severity": "Info",
        "cvss": 2.0,
        "indicator": lambda text: "user-agent:" in text.lower() and "disallow:" in text.lower()
    },
    {
        "path": "/sitemap.xml",
        "title": "Sitemap File Exposed",
        "severity": "Info",
        "cvss": 1.0,
        "indicator": lambda text: "<urlset" in text.lower() or "<sitemapindex" in text.lower()
    },
    {
        "path": "/backup.sql",
        "title": "Database SQL Backup File Exposed",
        "severity": "Critical",
        "cvss": 8.9,
        "indicator": lambda text: any(k in text.lower() for k in ["create table", "insert into", "mysqldump", "pg_dump"])
    },
    {
        "path": "/admin",
        "title": "Administrative Interface Exposed (/admin)",
        "severity": "Low",
        "cvss": 3.5,
        "indicator": lambda text: any(k in text.lower() for k in ["admin", "login", "dashboard", "control panel"])
    }
]

def check_sensitive_files(base_url, session=None, rate_limiter=None, stop_checker=None):
    """
    Checks for exposed sensitive directories and configuration files.
    """
    findings = []
    headers = {"User-Agent": Config.USER_AGENT}
    parsed = urlparse(base_url)
    root_url = f"{parsed.scheme}://{parsed.netloc}"
    req = session if session else requests

    for item in SENSITIVE_PATHS:
        if stop_checker and stop_checker():
            break

        if rate_limiter:
            rate_limiter()

        target_path = item["path"]
        probe_url = urljoin(root_url, target_path)

        try:
            resp = req.get(probe_url, headers=headers, timeout=Config.DEFAULT_TIMEOUT, verify=False, allow_redirects=False)
            
            # Check 200 OK or 302/301 for admin
            if resp.status_code == 200:
                body = resp.text
                if item["indicator"](body):
                    findings.append({
                        "title": item["title"],
                        "severity": item["severity"],
                        "cvss_score": item["cvss"],
                        "affected_url": probe_url,
                        "parameter": f"Path: {target_path}",
                        "evidence": f"Path '{target_path}' returned HTTP 200 OK with matching diagnostic signature (Sample: {body[:150].strip()}).",
                        "owasp_category": "A05:2021-Security Misconfiguration",
                        "remediation": f"Restrict public web server access to '{target_path}' or remove sensitive files from document root."
                    })
            elif resp.status_code in (301, 302) and target_path == "/admin":
                findings.append({
                    "title": "Potential Administrative Portal Discovered (/admin)",
                    "severity": "Info",
                    "cvss_score": 2.0,
                    "affected_url": probe_url,
                    "parameter": "Path: /admin",
                    "evidence": f"Request to /admin redirected to: {resp.headers.get('Location', '')}",
                    "owasp_category": "A05:2021-Security Misconfiguration",
                    "remediation": "Ensure administrative endpoints are protected by multi-factor authentication and IP whitelisting."
                })
        except Exception:
            continue

    return findings
