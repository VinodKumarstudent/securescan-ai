import secrets
import socket
from datetime import datetime, timedelta
import requests
from bs4 import BeautifulSoup
import dns.resolver

from config import Config
from database.db import get_db_connection, log_audit, utcnow, utcnow_str
from target_manager.scope_enforcer import normalize_domain, resolve_and_check_ssrf

def generate_verification_token():
    """Generate a cryptographically secure 32-character hexadecimal token."""
    return secrets.token_hex(16)

def check_token_expiry(token_created_at_str):
    """Check if token is older than the configured expiry days."""
    if not token_created_at_str:
        return True
    try:
        dt = datetime.strptime(token_created_at_str, '%Y-%m-%d %H:%M:%S')
        return utcnow() > (dt + timedelta(days=Config.TOKEN_EXPIRY_DAYS))
    except ValueError:
        return True

def verify_dns_txt(domain, token):
    """
    Verify ownership via DNS TXT record.
    Expected record: securescan-verify=<token>
    """
    clean_domain = normalize_domain(domain)
    expected_entry = f"securescan-verify={token}"
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5.0
        resolver.lifetime = 5.0
        answers = resolver.resolve(clean_domain, 'TXT')
        for rdata in answers:
            for txt_string in rdata.strings:
                decoded = txt_string.decode('utf-8', errors='ignore').strip()
                if decoded == expected_entry or token in decoded:
                    return True, f"Found matching TXT record: {decoded}"
        return False, f"No matching TXT record found for '{expected_entry}' on domain {clean_domain}."
    except dns.resolver.NXDOMAIN:
        return False, f"Domain {clean_domain} does not exist (NXDOMAIN)."
    except dns.resolver.NoAnswer:
        return False, f"No TXT records configured on {clean_domain}."
    except Exception as e:
        return False, f"DNS TXT resolution failed: {str(e)}"

def verify_html_meta(domain, token):
    """
    Verify ownership via HTML meta tag on homepage.
    Expected: <meta name="securescan-verification" content="<token>">
    """
    clean_domain = normalize_domain(domain)
    
    # Try HTTPS then HTTP
    protocols = ["https", "http"]
    last_err = ""
    for proto in protocols:
        url = f"{proto}://{clean_domain}/"
        try:
            # Check SSRF before making outbound request
            is_lab = clean_domain in Config.PREAPPROVED_LAB_TARGETS
            ok, ssrf_reason = resolve_and_check_ssrf(url, is_lab_target=is_lab)
            if not ok:
                return False, f"SSRF check failed: {ssrf_reason}"

            resp = requests.get(
                url,
                headers={"User-Agent": Config.USER_AGENT},
                timeout=Config.DEFAULT_TIMEOUT,
                verify=False
            )
            if resp.status_code == 200:
                soup = BeautifulSoup(resp.text, "html.parser")
                meta_tag = soup.find("meta", attrs={"name": "securescan-verification"})
                if meta_tag and meta_tag.get("content") == token:
                    return True, f"Found verification meta tag with matching token on {url}"
                # Also check case-insensitive attribute names
                for meta in soup.find_all("meta"):
                    if meta.get("name", "").lower() == "securescan-verification":
                        if meta.get("content", "").strip() == token:
                            return True, f"Found verification meta tag on {url}"
                last_err = f"Meta tag 'securescan-verification' not found or content did not match on {url}"
        except Exception as e:
            last_err = f"Failed to fetch {url}: {str(e)}"

    return False, last_err or "Verification meta tag could not be located on homepage."

def verify_file_upload(domain, token):
    """
    Verify ownership via well-known file upload.
    Expected URL: http[s]://<domain>/.well-known/securescan-verify.txt
    Content: <token>
    """
    clean_domain = normalize_domain(domain)
    protocols = ["https", "http"]
    last_err = ""
    for proto in protocols:
        url = f"{proto}://{clean_domain}/.well-known/securescan-verify.txt"
        try:
            is_lab = clean_domain in Config.PREAPPROVED_LAB_TARGETS
            ok, ssrf_reason = resolve_and_check_ssrf(url, is_lab_target=is_lab)
            if not ok:
                return False, f"SSRF check failed: {ssrf_reason}"

            resp = requests.get(
                url,
                headers={"User-Agent": Config.USER_AGENT},
                timeout=Config.DEFAULT_TIMEOUT,
                verify=False
            )
            if resp.status_code == 200:
                content = resp.text.strip()
                if token in content:
                    return True, f"Found valid token in verification file at {url}"
                else:
                    last_err = f"File found at {url} but content '{content[:40]}' did not match token."
            else:
                last_err = f"Verification file at {url} returned HTTP {resp.status_code}"
        except Exception as e:
            last_err = f"Failed to fetch verification file at {url}: {str(e)}"

    return False, last_err or "Verification file could not be read."

def execute_verification(target_id, ip_address="127.0.0.1"):
    """
    Orchestrate verification process for a target based on its configured method.
    Returns (success: bool, message: str)
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM targets WHERE id = ?", (target_id,))
    target = cursor.fetchone()
    
    if not target:
        conn.close()
        return False, "Target not found"

    domain = target["domain"]
    method = target["verification_method"]
    token = target["verification_token"]
    created_at = target["token_created_at"]

    # Check token expiration
    if check_token_expiry(created_at):
        cursor.execute("UPDATE targets SET status = 'expired' WHERE id = ?", (target_id,))
        conn.commit()
        conn.close()
        log_audit("VERIFICATION_FAILED", domain, "Token has expired (> 7 days). Generate a new token.", ip_address, status="EXPIRED")
        return False, "Verification token has expired (valid for 7 days). Please request a new token."

    # Preapproved / Lab
    if target["target_type"] == "lab" or method == "preapproved":
        now_str = utcnow_str()
        exp_str = (utcnow() + timedelta(days=365)).strftime('%Y-%m-%d %H:%M:%S')
        cursor.execute("""
            UPDATE targets 
            SET status = 'verified', verified_at = ?, expires_at = ?
            WHERE id = ?
        """, (now_str, exp_str, target_id))
        conn.commit()
        conn.close()
        log_audit("VERIFICATION_SUCCESS", domain, "Pre-approved educational lab target verified.", ip_address)
        return True, "Educational lab target verified automatically."

    # Dispatch verification method
    success = False
    details = ""
    
    if method == "dns_txt":
        success, details = verify_dns_txt(domain, token)
    elif method == "html_meta":
        success, details = verify_html_meta(domain, token)
    elif method == "file_upload":
        success, details = verify_file_upload(domain, token)
    else:
        success, details = False, f"Unknown verification method '{method}'"

    now_str = utcnow_str()
    
    # Record verification attempt
    cursor.execute("""
        INSERT INTO verifications (target_id, method, status, details, checked_at)
        VALUES (?, ?, ?, ?, ?)
    """, (target_id, method, "success" if success else "failed", details, now_str))

    if success:
        exp_str = (utcnow() + timedelta(days=90)).strftime('%Y-%m-%d %H:%M:%S')
        cursor.execute("""
            UPDATE targets 
            SET status = 'verified', verified_at = ?, expires_at = ?
            WHERE id = ?
        """, (now_str, exp_str, target_id))
        log_audit("VERIFICATION_SUCCESS", domain, f"Ownership verified via {method}: {details}", ip_address)
    else:
        cursor.execute("UPDATE targets SET status = 'failed' WHERE id = ?", (target_id,))
        log_audit("VERIFICATION_FAILED", domain, f"Ownership verification failed via {method}: {details}", ip_address, status="FAILED")

    conn.commit()
    conn.close()
    return success, details
