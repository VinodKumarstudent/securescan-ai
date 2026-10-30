CSRF_TOKEN_NAMES = [
    "csrf", "xsrf", "csrf_token", "_csrf", "authenticity_token", 
    "csrfmiddlewaretoken", "__requestverificationtoken", "_token", "csrf-token"
]

def check_csrf_tokens(forms):
    """
    Analyzes discovered HTML forms for absence of anti-CSRF protection tokens.
    """
    findings = []
    
    for form in forms:
        method = form.get("method", "GET").upper()
        # CSRF is relevant to state-changing methods (primarily POST)
        if method != "POST":
            continue

        inputs = form.get("inputs", [])
        has_csrf_token = False
        
        for field in inputs:
            fname = field.get("name", "").lower()
            if any(token_pattern in fname for token_pattern in CSRF_TOKEN_NAMES):
                has_csrf_token = True
                break

        if not has_csrf_token:
            action_url = form.get("url")
            page_url = form.get("page_url", action_url)
            findings.append({
                "title": "Missing Anti-CSRF Token on Form",
                "severity": "Medium",
                "cvss_score": 6.5,
                "affected_url": page_url,
                "parameter": f"Form Action: {action_url}",
                "evidence": f"POST form submitting to '{action_url}' contains {len(inputs)} fields but lacks an anti-CSRF token parameter.",
                "owasp_category": "A01:2021-Broken Access Control",
                "remediation": "Embed a unique, cryptographically random CSRF token in state-changing forms and validate it on submission."
            })

    return findings
