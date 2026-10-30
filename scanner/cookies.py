import requests
from config import Config

def check_cookie_security(target_url, session=None):
    """
    Analyzes cookies sent by the server for Secure, HttpOnly, and SameSite flags.
    Returns a list of security findings.
    """
    findings = []
    headers = {"User-Agent": Config.USER_AGENT}

    try:
        req = session.get if session else requests.get
        resp = req(target_url, headers=headers, timeout=Config.DEFAULT_TIMEOUT, verify=False, allow_redirects=True)
        
        # Parse Set-Cookie headers
        raw_cookies = resp.headers.get("Set-Cookie", "")
        # Requests stores cookies in resp.cookies
        for cookie in resp.cookies:
            name = cookie.name
            is_secure = cookie.secure
            is_httponly = cookie.has_nonstandard_attr('HttpOnly') or cookie.has_nonstandard_attr('httponly')
            samesite = cookie._rest.get('SameSite') or cookie._rest.get('samesite')

            # 1. HttpOnly flag check
            if not is_httponly:
                findings.append({
                    "title": f"Cookie '{name}' Missing HttpOnly Flag",
                    "severity": "Medium",
                    "cvss_score": 5.0,
                    "affected_url": target_url,
                    "parameter": f"Cookie: {name}",
                    "evidence": f"The cookie '{name}' does not specify the 'HttpOnly' directive, making it vulnerable to client-side script theft (XSS).",
                    "owasp_category": "A05:2021-Security Misconfiguration",
                    "remediation": f"Append '; HttpOnly' to the Set-Cookie directive for '{name}' so browsers block access from document.cookie."
                })

            # 2. Secure flag check
            if target_url.startswith("https://") and not is_secure:
                findings.append({
                    "title": f"Cookie '{name}' Missing Secure Flag over HTTPS",
                    "severity": "Medium",
                    "cvss_score": 4.9,
                    "affected_url": target_url,
                    "parameter": f"Cookie: {name}",
                    "evidence": f"Cookie '{name}' was set over HTTPS without the 'Secure' attribute.",
                    "owasp_category": "A05:2021-Security Misconfiguration",
                    "remediation": f"Append '; Secure' to the Set-Cookie directive for '{name}' to ensure transmission occurs exclusively over TLS."
                })

            # 3. SameSite flag check
            if not samesite:
                findings.append({
                    "title": f"Cookie '{name}' Missing SameSite Attribute",
                    "severity": "Low",
                    "cvss_score": 3.8,
                    "affected_url": target_url,
                    "parameter": f"Cookie: {name}",
                    "evidence": f"Cookie '{name}' does not declare a SameSite attribute (Lax/Strict).",
                    "owasp_category": "A01:2021-Broken Access Control",
                    "remediation": f"Set '; SameSite=Lax' or '; SameSite=Strict' on cookie '{name}' to defend against Cross-Site Request Forgery (CSRF)."
                })
            elif samesite.lower() == "none" and not is_secure:
                findings.append({
                    "title": f"Insecure Cookie SameSite=None without Secure flag",
                    "severity": "Medium",
                    "cvss_score": 5.3,
                    "affected_url": target_url,
                    "parameter": f"Cookie: {name}",
                    "evidence": f"Cookie '{name}' has SameSite=None but lacks the Secure attribute.",
                    "owasp_category": "A01:2021-Broken Access Control",
                    "remediation": "Modern browsers reject SameSite=None cookies unless the Secure attribute is also present."
                })

    except Exception:
        pass

    return findings
