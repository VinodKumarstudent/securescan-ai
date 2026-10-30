from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import requests
from config import Config

SQL_ERROR_PATTERNS = [
    # MySQL / MariaDB
    "you have an error in your sql syntax",
    "warning: mysql_",
    "valid mysql result",
    "check the manual that corresponds to your mysql server version",
    "mysql_fetch_array()",
    # PostgreSQL
    "postgresql query failed: error",
    "warning: pg_",
    "valid postgresql result",
    "pg_query() [",
    "syntax error at or near",
    # Microsoft SQL Server
    "driver][odbc sql server driver]",
    "microsoft ole db provider for sql server",
    "unclosed quotation mark after the character string",
    "syntax error in string in query expression",
    # Oracle
    "ora-01756: quoted string not properly terminated",
    "ora-00933: sql command not properly ended",
    "oracle error",
    # SQLite
    "sqlite3::sqlexception",
    "near \")\": syntax error",
    "unrecognized token:",
    "sqlite error 1:",
    "sql error: unrecognized token",
]

BENIGN_SQLI_PAYLOADS = ["'", "''", "\"", "\\"]

def test_sql_injection(endpoints, forms=None, session=None, rate_limiter=None, stop_checker=None):
    """
    Error-based SQL injection detection using benign syntax-breaking characters.
    Detection only; strictly non-destructive.
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
        if not params:
            continue

        # Baseline request
        baseline_text = ""
        try:
            if rate_limiter:
                rate_limiter()
            base_resp = req.get(url, headers=headers, timeout=Config.DEFAULT_TIMEOUT, verify=False)
            baseline_text = base_resp.text.lower()
        except Exception:
            continue

        for param, values in params.items():
            param_key = f"{parsed.netloc}{parsed.path}?{param}"
            if param_key in tested_params:
                continue
            tested_params.add(param_key)

            original_val = values[0] if values else ""

            for probe in BENIGN_SQLI_PAYLOADS:
                if stop_checker and stop_checker():
                    break

                if rate_limiter:
                    rate_limiter()

                modified_params = dict(params)
                modified_params[param] = f"{original_val}{probe}"
                new_query = urlencode(modified_params, doseq=True)
                test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

                try:
                    resp = req.get(test_url, headers=headers, timeout=Config.DEFAULT_TIMEOUT, verify=False)
                    resp_lower = resp.text.lower()

                    for pattern in SQL_ERROR_PATTERNS:
                        if pattern in resp_lower and pattern not in baseline_text:
                            findings.append({
                                "title": f"SQL Injection Vulnerability in Parameter '{param}'",
                                "severity": "Critical",
                                "cvss_score": 9.3,
                                "affected_url": test_url,
                                "parameter": param,
                                "evidence": f"Injected benign syntax probe '{probe}'. Server responded with database diagnostic error signature: '{pattern}'.",
                                "owasp_category": "A03:2021-Injection",
                                "remediation": "Use parameterized queries (prepared statements) or Object-Relational Mapping (ORM) to decouple SQL instructions from untrusted user data."
                            })
                            break
                    if any(f["parameter"] == param for f in findings):
                        break  # Found for this param, move to next
                except Exception:
                    continue

    return findings
