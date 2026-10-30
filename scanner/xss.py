from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import requests
from config import Config

BENIGN_XSS_MARKER = "<securescan_test_marker_x78>"

def test_reflected_xss(endpoints, forms=None, session=None, rate_limiter=None, stop_checker=None):
    """
    Non-destructive Reflected XSS detection using benign HTML marker reflection.
    Inspects URL query parameters and forms.
    """
    findings = []
    headers = {"User-Agent": Config.USER_AGENT}
    tested_params = set()

    req = session if session else requests

    # 1. Test Query Parameters on Discovered Endpoints
    for url in endpoints:
        if stop_checker and stop_checker():
            break

        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if not params:
            continue

        for param in params.keys():
            param_key = f"{parsed.netloc}{parsed.path}?{param}"
            if param_key in tested_params:
                continue
            tested_params.add(param_key)

            if rate_limiter:
                rate_limiter()

            # Create test URL with benign payload
            modified_params = dict(params)
            modified_params[param] = BENIGN_XSS_MARKER
            new_query = urlencode(modified_params, doseq=True)
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

            try:
                resp = req.get(test_url, headers=headers, timeout=Config.DEFAULT_TIMEOUT, verify=False)
                
                # Check for unescaped reflection
                if BENIGN_XSS_MARKER in resp.text:
                    findings.append({
                        "title": f"Reflected Cross-Site Scripting (XSS) in Parameter '{param}'",
                        "severity": "High",
                        "cvss_score": 7.5,
                        "affected_url": test_url,
                        "parameter": param,
                        "evidence": f"Benign marker payload '{BENIGN_XSS_MARKER}' was reflected verbatim in the response body without HTML sanitization or entity encoding.",
                        "owasp_category": "A03:2021-Injection",
                        "remediation": f"Sanitize and HTML-encode user input '{param}' before rendering it in responses (e.g., using htmlspecialchars() in PHP or templating auto-escaping)."
                    })
            except Exception:
                continue

    # 2. Test Discovered Forms
    if forms:
        for form in forms:
            if stop_checker and stop_checker():
                break

            action_url = form.get("url")
            method = form.get("method", "GET").upper()
            inputs = form.get("inputs", [])
            
            for field in inputs:
                fname = field.get("name")
                if not fname:
                    continue

                if rate_limiter:
                    rate_limiter()

                payload_data = {}
                for f in inputs:
                    payload_data[f["name"]] = BENIGN_XSS_MARKER if f["name"] == fname else "test"

                try:
                    if method == "POST":
                        resp = req.post(action_url, data=payload_data, headers=headers, timeout=Config.DEFAULT_TIMEOUT, verify=False)
                    else:
                        resp = req.get(action_url, params=payload_data, headers=headers, timeout=Config.DEFAULT_TIMEOUT, verify=False)

                    if BENIGN_XSS_MARKER in resp.text:
                        findings.append({
                            "title": f"Reflected XSS in Form Input '{fname}'",
                            "severity": "High",
                            "cvss_score": 7.3,
                            "affected_url": action_url,
                            "parameter": f"Form input: {fname}",
                            "evidence": f"Payload reflected in form submission response without context-aware output encoding.",
                            "owasp_category": "A03:2021-Injection",
                            "remediation": f"Ensure all form values in '{fname}' are properly encoded before display in the DOM."
                        })
                except Exception:
                    continue

    return findings
