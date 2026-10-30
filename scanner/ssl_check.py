import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse
import requests
from config import Config

def check_ssl_tls(target_url):
    """
    Evaluates SSL/TLS certificate validity, expiration, and HTTP-to-HTTPS redirect.
    """
    findings = []
    parsed = urlparse(target_url)
    hostname = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    # 1. Check HTTP to HTTPS redirection
    if parsed.scheme == "http":
        try:
            http_url = f"http://{parsed.netloc}{parsed.path}"
            r = requests.get(http_url, headers={"User-Agent": Config.USER_AGENT}, timeout=Config.DEFAULT_TIMEOUT, allow_redirects=False)
            if r.status_code in (301, 302, 308):
                loc = r.headers.get("Location", "")
                if not loc.startswith("https://"):
                    findings.append({
                        "title": "Insecure HTTP Redirection",
                        "severity": "Medium",
                        "cvss_score": 4.8,
                        "affected_url": http_url,
                        "parameter": "Header: Location",
                        "evidence": f"HTTP endpoint redirects to non-HTTPS destination: {loc}",
                        "owasp_category": "A02:2021-Cryptographic Failures",
                        "remediation": "Configure permanent 301 redirection from HTTP to HTTPS."
                    })
            else:
                findings.append({
                    "title": "Plaintext HTTP Not Redirected to HTTPS",
                    "severity": "Medium",
                    "cvss_score": 5.3,
                    "affected_url": http_url,
                    "parameter": "Protocol: HTTP",
                    "evidence": "Web server accepts unencrypted HTTP connections without redirecting to HTTPS.",
                    "owasp_category": "A02:2021-Cryptographic Failures",
                    "remediation": "Enforce HTTPS by automatically redirecting all plaintext HTTP traffic to HTTPS."
                })
        except Exception:
            pass

    # 2. Check TLS certificate details if HTTPS
    if parsed.scheme == "https":
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # Check cert info even if self-signed in lab

        try:
            with socket.create_connection((hostname, port or 443), timeout=Config.DEFAULT_TIMEOUT) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    tls_version = ssock.version()
                    
                    if not cert:
                        # Fetch binary der
                        der = ssock.getpeercert(binary_form=True)

                    if tls_version in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
                        findings.append({
                            "title": f"Deprecated TLS Protocol In Use ({tls_version})",
                            "severity": "High",
                            "cvss_score": 7.4,
                            "affected_url": target_url,
                            "parameter": "Protocol Negotiation",
                            "evidence": f"Server negotiated obsolete and cryptographically vulnerable protocol {tls_version}.",
                            "owasp_category": "A02:2021-Cryptographic Failures",
                            "remediation": "Disable TLS 1.0, 1.1, and SSLv3. Require TLS 1.2 or TLS 1.3 exclusively."
                        })

                    if cert and "notAfter" in cert:
                        not_after_str = cert["notAfter"]
                        # format e.g. May 15 12:00:00 2026 GMT
                        try:
                            exp_date = datetime.strptime(not_after_str, '%b %d %H:%M:%S %Y %Z')
                            remaining_days = (exp_date - datetime.now(timezone.utc).replace(tzinfo=None)).days
                            if remaining_days < 0:
                                findings.append({
                                    "title": "Expired SSL/TLS Certificate",
                                    "severity": "Critical",
                                    "cvss_score": 8.1,
                                    "affected_url": target_url,
                                    "parameter": "Certificate Validity",
                                    "evidence": f"SSL certificate expired on {exp_date.strftime('%Y-%m-%d')} ({abs(remaining_days)} days ago).",
                                    "owasp_category": "A02:2021-Cryptographic Failures",
                                    "remediation": "Renew and install a valid SSL/TLS certificate immediately."
                                })
                            elif remaining_days < 15:
                                findings.append({
                                    "title": "SSL/TLS Certificate Expiring Soon",
                                    "severity": "Low",
                                    "cvss_score": 3.0,
                                    "affected_url": target_url,
                                    "parameter": "Certificate Validity",
                                    "evidence": f"SSL certificate expires in {remaining_days} days ({exp_date.strftime('%Y-%m-%d')}).",
                                    "owasp_category": "A02:2021-Cryptographic Failures",
                                    "remediation": "Plan certificate renewal prior to expiration."
                                })
                        except Exception:
                            pass
        except Exception as e:
            # If not an HTTPS server or connection fails
            pass

    return findings
