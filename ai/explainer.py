import os
import requests
from config import Config

STATIC_KNOWLEDGE_BASE = {
    "sql injection": {
        "summary": "SQL Injection occurs when untrusted input containing SQL metacontrol characters is concatenated directly into a database command, allowing attackers to manipulate queries, bypass authentication, read sensitive records, or modify the database.",
        "attack_vector": "An adversary supplies SQL syntactic characters (such as single quotes ', semicolons, or comments --) in input fields. If queries are unparameterized, the database parser misinterprets user data as executable query logic.",
        "impact": "Complete loss of confidentiality (database dumps), breach of data integrity (unauthorized updates/deletions), and potential remote code execution via database file write primitives or system commands.",
        "remediation_code": """# Python (SQLite / psycopg2 / SQLAlchemy):
# INSECURE: cursor.execute(f"SELECT * FROM users WHERE username = '{user_input}'")
# SECURE (Parameterized query):
cursor.execute("SELECT * FROM users WHERE username = ?", (user_input,))"""
    },
    "cross-site scripting": {
        "summary": "Reflected Cross-Site Scripting (XSS) occurs when an application receives user data in an HTTP request and echoes it back into the immediate response without adequate validation, HTML entity encoding, or contextual sanitization.",
        "attack_vector": "Attackers craft links containing script payloads or HTML markup. When a victim clicks the link, their browser renders and executes the script within the origin context of the vulnerable application.",
        "impact": "Session hijacking (cookie theft via document.cookie), keystroke logging, credential harvesting via fraudulent login forms, and arbitrary actions performed on behalf of the victim.",
        "remediation_code": """# Python (Flask / Jinja2):
# Jinja2 auto-escapes HTML variables by default. Never mark untrusted data with '| safe'.
# For raw Python string output:
import html
safe_output = html.escape(user_input)"""
    },
    "content-security-policy": {
        "summary": "Content Security Policy (CSP) is an HTTP response header that restricts where resources (scripts, styles, images, iframes) can be loaded from and controls frame ancestors, serving as defense-in-depth against XSS and clickjacking.",
        "attack_vector": "Without a restrictive CSP, if an injection vulnerability exists anywhere on the site, malicious JavaScript can execute without hindrance and exfiltrate data to attacker-controlled origins.",
        "impact": "Unrestricted script execution, inline script injection, iframe embedding for clickjacking, and unauthorized resource fetching.",
        "remediation_code": """# HTTP Header Configuration:
Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none';"""
    },
    "httponly": {
        "summary": "The HttpOnly cookie directive prevents client-side scripts (such as JavaScript) from accessing the cookie via document.cookie, mitigating session hijacking in the event of XSS vulnerabilities.",
        "attack_vector": "If an XSS flaw exists on any page on the domain, an attacker's script can read document.cookie and transmit active session tokens to an external server.",
        "impact": "Direct session takeover allowing attackers to impersonate authenticated users.",
        "remediation_code": """# Flask Session Cookie Configuration:
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE='Lax'
)"""
    },
    "csrf": {
        "summary": "Cross-Site Request Forgery (CSRF) tricks an authenticated user into unknowingly submitting an unauthorized request to a trusted web application.",
        "attack_vector": "A malicious third-party site contains an automatic form submission to your app. Because the user's browser automatically sends cookies with requests, the server processes the request as legitimate.",
        "impact": "Unauthorized account modification, password resets, financial transactions, or privilege escalation.",
        "remediation_code": """# Flask-WTF CSRF Protection:
from flask_wtf.csrf import CSRFProtect
csrf = CSRFProtect(app)

# In HTML template forms:
<form method="post">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
</form>"""
    },
    "open redirect": {
        "summary": "An Open Redirect takes a user-supplied parameter and uses it in an HTTP redirection without validating whether the destination URL points to a trusted domain.",
        "attack_vector": "Phishing attackers abuse legitimate domain trust (e.g. https://trusted.com/login?next=https://evil.com) to deceive victims into entering credentials on lookalike phishing pages.",
        "impact": "Facilitates highly believable spear phishing and credential harvesting attacks abusing domain reputation.",
        "remediation_code": """from urllib.parse import urlparse

def is_safe_url(target, host):
    parsed = urlparse(target)
    return not parsed.netloc or parsed.netloc == host"""
    }
}

def explain_finding(title, severity, affected_url, parameter, evidence, owasp_category):
    """
    Generates a structured, educational AI explanation of a vulnerability.
    Uses OpenAI if API key is provided; otherwise uses built-in static knowledge base.
    """
    api_key = Config.OPENAI_API_KEY or os.getenv("OPENAI_API_KEY")

    if api_key:
        try:
            prompt = f"""
You are an expert application security engineer. Provide an insightful, structured vulnerability analysis and remediation guide for the following security finding:

Title: {title}
Severity: {severity}
Affected URL: {affected_url}
Parameter: {parameter}
OWASP Category: {owasp_category}
Evidence: {evidence}

Return your explanation with the following sections formatted in clean markdown:
### 1. Executive Summary
### 2. Technical Vulnerability Analysis & Attack Mechanism
### 3. Business & Security Impact
### 4. Step-by-Step Developer Remediation (including code examples)
"""
            resp = requests.post(
                "https://api.openai.com/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json"
                },
                json={
                    "model": "gpt-4o-mini",
                    "messages": [
                        {"role": "system", "content": "You are a senior cybersecurity expert explaining web vulnerabilities clearly and constructively."},
                        {"role": "user", "content": prompt}
                    ],
                    "temperature": 0.2,
                    "max_tokens": 800
                },
                timeout=12
            )
            if resp.status_code == 200:
                data = resp.json()
                return data["choices"][0]["message"]["content"]
        except Exception:
            pass  # Fall back to static knowledge base

    # Fallback to local cybersecurity knowledge base
    title_lower = title.lower()
    matched_kb = None
    for key, val in STATIC_KNOWLEDGE_BASE.items():
        if key in title_lower:
            matched_kb = val
            break

    if not matched_kb:
        matched_kb = {
            "summary": f"The security scanner identified a potential issue regarding '{title}' on '{affected_url}'. This falls under the {owasp_category} category.",
            "attack_vector": f"Attackers may leverage this condition ({evidence}) to alter intended security behavior or harvest reconnaissance intelligence about the target application.",
            "impact": f"Risk level assessed as {severity}. If exploited in conjunction with other flaws, it may weaken defense-in-depth controls.",
            "remediation_code": "# Verify secure server configuration and consult the latest OWASP cheat sheet guidelines for this category."
        }

    explanation = f"""### 🛡️ AI Security Advisory: {title}

**Severity Rating:** `{severity}` | **OWASP Category:** `{owasp_category}`

#### 1. Executive Summary
{matched_kb['summary']}

#### 2. Technical Mechanism & Attack Scenario
{matched_kb['attack_vector']}

**Observed Evidence:**
> {evidence}

#### 3. Potential Impact
{matched_kb['impact']}

#### 4. Remediation & Code Sample
Follow standard defensive development practices to address this issue:

```
{matched_kb['remediation_code']}
```
"""
    return explanation
