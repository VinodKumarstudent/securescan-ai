from urllib.parse import urljoin
import requests
from config import Config

STACK_TRACE_PATTERNS = [
    "traceback (most recent call last):",
    "at org.apache.catalina.",
    "microsoft .net framework version:",
    "stack trace:",
    "laravel\\framework",
    "django.core.exceptions",
    "rails application's trace",
    "ignition: error page"
]

def check_info_disclosure(target_url, session=None):
    """
    Checks for Server / X-Powered-By banners and detailed stack trace disclosures.
    """
    findings = []
    headers = {"User-Agent": Config.USER_AGENT}
    req = session if session else requests

    try:
        resp = req.get(target_url, headers=headers, timeout=Config.DEFAULT_TIMEOUT, verify=False)
        resp_headers = {k.lower(): v for k, v in resp.headers.items()}

        # 1. Server Header Disclosure
        server_val = resp_headers.get("server", "")
        if server_val:
            # Check if detailed version numbers are present
            has_version = any(char.isdigit() for char in server_val)
            findings.append({
                "title": "Web Server Information Disclosure (Server Header)",
                "severity": "Low" if has_version else "Info",
                "cvss_score": 3.4 if has_version else 1.5,
                "affected_url": target_url,
                "parameter": "Header: Server",
                "evidence": f"Server header banner reveals underlying platform details: '{server_val}'.",
                "owasp_category": "A05:2021-Security Misconfiguration",
                "remediation": "Configure web server configuration (e.g. 'ServerTokens Prod' in Apache or 'server_tokens off' in Nginx) to suppress banner details."
            })

        # 2. X-Powered-By Header Disclosure
        if "x-powered-by" in resp_headers:
            pw_val = resp_headers["x-powered-by"]
            findings.append({
                "title": "Technology Stack Disclosure (X-Powered-By Header)",
                "severity": "Low",
                "cvss_score": 3.2,
                "affected_url": target_url,
                "parameter": "Header: X-Powered-By",
                "evidence": f"X-Powered-By header reveals backend engine: '{pw_val}'.",
                "owasp_category": "A05:2021-Security Misconfiguration",
                "remediation": "Remove the 'X-Powered-By' header in application or proxy settings."
            })

        # 3. Verbose Error Page / Stack Trace Check
        probe_404 = urljoin(target_url, f"/securescan_nonexistent_probe_{12345}")
        try:
            err_resp = req.get(probe_404, headers=headers, timeout=Config.DEFAULT_TIMEOUT, verify=False)
            err_text_lower = err_resp.text.lower()
            for pattern in STACK_TRACE_PATTERNS:
                if pattern in err_text_lower:
                    findings.append({
                        "title": "Verbose Error Page / Stack Trace Disclosure",
                        "severity": "Medium",
                        "cvss_score": 5.3,
                        "affected_url": probe_404,
                        "parameter": "Error Handling",
                        "evidence": f"Server exposed technical internal stack trace signature: '{pattern}'.",
                        "owasp_category": "A05:2021-Security Misconfiguration",
                        "remediation": "Disable debug mode in production. Ensure custom generic 404/500 error pages are shown to end users."
                    })
                    break
        except Exception:
            pass

    except Exception:
        pass

    return findings
