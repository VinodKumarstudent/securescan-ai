import requests
from config import Config

def check_security_headers(target_url, session=None):
    """
    Examines HTTP response headers for missing or misconfigured security headers.
    Returns a list of finding dictionaries.
    """
    findings = []
    headers = {"User-Agent": Config.USER_AGENT}
    
    try:
        req = session.get if session else requests.get
        resp = req(target_url, headers=headers, timeout=Config.DEFAULT_TIMEOUT, verify=False, allow_redirects=True)
        resp_headers = {k.lower(): v for k, v in resp.headers.items()}

        # 1. Content-Security-Policy (CSP)
        if "content-security-policy" not in resp_headers:
            findings.append({
                "title": "Missing Content-Security-Policy (CSP) Header",
                "severity": "Medium",
                "cvss_score": 5.4,
                "affected_url": target_url,
                "parameter": "Header: Content-Security-Policy",
                "evidence": "Header 'Content-Security-Policy' is absent from the HTTP response.",
                "owasp_category": "A05:2021-Security Misconfiguration",
                "remediation": "Implement a strong Content-Security-Policy to restrict scripts, stylesheets, and object sources (e.g., default-src 'self')."
            })
        else:
            csp_val = resp_headers["content-security-policy"]
            if "'unsafe-inline'" in csp_val or "'unsafe-eval'" in csp_val:
                findings.append({
                    "title": "Weak Content-Security-Policy Configuration",
                    "severity": "Low",
                    "cvss_score": 3.7,
                    "affected_url": target_url,
                    "parameter": "Header: Content-Security-Policy",
                    "evidence": f"CSP directive contains unsafe keywords: {csp_val[:120]}...",
                    "owasp_category": "A05:2021-Security Misconfiguration",
                    "remediation": "Avoid using 'unsafe-inline' or 'unsafe-eval' directives. Use nonces or hashes for inline scripts."
                })

        # 2. Strict-Transport-Security (HSTS)
        if target_url.startswith("https://"):
            if "strict-transport-security" not in resp_headers:
                findings.append({
                    "title": "Missing HTTP Strict-Transport-Security (HSTS) Header",
                    "severity": "Medium",
                    "cvss_score": 4.8,
                    "affected_url": target_url,
                    "parameter": "Header: Strict-Transport-Security",
                    "evidence": "HTTPS response does not enforce HSTS header.",
                    "owasp_category": "A05:2021-Security Misconfiguration",
                    "remediation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' to prevent SSL-stripping attacks."
                })

        # 3. X-Frame-Options (Clickjacking protection)
        if "x-frame-options" not in resp_headers and "frame-ancestors" not in resp_headers.get("content-security-policy", ""):
            findings.append({
                "title": "Missing Clickjacking Protection (X-Frame-Options)",
                "severity": "Medium",
                "cvss_score": 5.0,
                "affected_url": target_url,
                "parameter": "Header: X-Frame-Options",
                "evidence": "Neither X-Frame-Options nor CSP frame-ancestors header was provided.",
                "owasp_category": "A05:2021-Security Misconfiguration",
                "remediation": "Set 'X-Frame-Options: DENY' or 'SAMEORIGIN', or use CSP 'frame-ancestors' to protect against UI redressing/clickjacking."
            })

        # 4. X-Content-Type-Options
        if resp_headers.get("x-content-type-options", "").lower() != "nosniff":
            findings.append({
                "title": "Missing X-Content-Type-Options: nosniff Header",
                "severity": "Low",
                "cvss_score": 3.1,
                "affected_url": target_url,
                "parameter": "Header: X-Content-Type-Options",
                "evidence": f"X-Content-Type-Options header value: '{resp_headers.get('x-content-type-options', 'None')}'",
                "owasp_category": "A05:2021-Security Misconfiguration",
                "remediation": "Set 'X-Content-Type-Options: nosniff' to instruct browsers not to override MIME content types."
            })

        # 5. Referrer-Policy
        if "referrer-policy" not in resp_headers:
            findings.append({
                "title": "Missing Referrer-Policy Header",
                "severity": "Low",
                "cvss_score": 2.5,
                "affected_url": target_url,
                "parameter": "Header: Referrer-Policy",
                "evidence": "Referrer-Policy header is missing; browser may leak sensitive paths via Referer header.",
                "owasp_category": "A05:2021-Security Misconfiguration",
                "remediation": "Add 'Referrer-Policy: strict-origin-when-cross-origin' or 'no-referrer'."
            })

        # 6. Permissions-Policy
        if "permissions-policy" not in resp_headers and "feature-policy" not in resp_headers:
            findings.append({
                "title": "Missing Permissions-Policy Header",
                "severity": "Info",
                "cvss_score": 1.5,
                "affected_url": target_url,
                "parameter": "Header: Permissions-Policy",
                "evidence": "Permissions-Policy header is absent.",
                "owasp_category": "A05:2021-Security Misconfiguration",
                "remediation": "Define a Permissions-Policy header to control browser features like geolocation, microphone, and camera."
            })

    except Exception as e:
        pass

    return findings
