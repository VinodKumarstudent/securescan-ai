from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import requests
from config import Config

REDIRECT_PARAMS = ["url", "redirect", "redirect_to", "next", "dest", "destination", "target", "return", "return_to", "r"]
BENIGN_TARGET = "https://example.com/securescan-test"

def check_open_redirect(endpoints, session=None, rate_limiter=None, stop_checker=None):
    """
    Detects unvalidated redirects and forwards by injecting a harmless external target.
    """
    findings = []
    headers = {"User-Agent": Config.USER_AGENT}
    tested_params = set()
    req = session if session else requests

    for url in endpoints:
        if stop_checker and stop_checker():
            break

        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        # Check existing parameters that match known redirect names
        matched_params = [p for p in params.keys() if p.lower() in REDIRECT_PARAMS]
        
        # If no explicit redirect parameter exists, optionally probe top candidates
        if not matched_params and parsed.path.endswith(("/login", "/logout", "/auth", "/redirect", "/goto")):
            matched_params = ["next", "redirect_to", "url"]

        for param in matched_params:
            param_key = f"{parsed.netloc}{parsed.path}?{param}"
            if param_key in tested_params:
                continue
            tested_params.add(param_key)

            if rate_limiter:
                rate_limiter()

            modified_params = dict(params)
            modified_params[param] = BENIGN_TARGET
            new_query = urlencode(modified_params, doseq=True)
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

            try:
                # Do not follow redirects automatically so we can inspect Location header
                resp = req.get(test_url, headers=headers, timeout=Config.DEFAULT_TIMEOUT, verify=False, allow_redirects=False)
                
                if resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get("Location", "")
                    if "example.com" in location:
                        findings.append({
                            "title": f"Open Redirect Vulnerability via '{param}'",
                            "severity": "Medium",
                            "cvss_score": 6.1,
                            "affected_url": test_url,
                            "parameter": param,
                            "evidence": f"HTTP {resp.status_code} redirection header 'Location: {location}' allows arbitrary external redirection.",
                            "owasp_category": "A01:2021-Broken Access Control",
                            "remediation": "Validate redirect targets against a strict whitelist of relative paths or authorized internal domains."
                        })
            except Exception:
                continue

    return findings
