import socket
import ipaddress
from urllib.parse import urlparse
from datetime import datetime
from config import Config
from database.db import get_db_connection, utcnow

def normalize_domain(domain_or_url):
    """Extract clean lowercase domain or hostname from URL or string."""
    if not domain_or_url:
        return ""
    if not (domain_or_url.startswith("http://") or domain_or_url.startswith("https://")):
        domain_or_url = "http://" + domain_or_url
    parsed = urlparse(domain_or_url)
    netloc = parsed.netloc.split(":")[0].strip().lower()
    return netloc

def is_ip_restricted(ip_str):
    """Check if an IP address belongs to private, loopback, link-local, or cloud metadata ranges."""
    try:
        ip = ipaddress.ip_address(ip_str)
        # Check cloud metadata endpoint 169.254.169.254 explicitly
        if str(ip) == "169.254.169.254":
            return True, "Cloud metadata IP (169.254.169.254) blocked (SSRF Protection)"
        if ip.is_loopback:
            return True, f"Loopback address ({ip}) blocked (SSRF Protection)"
        if ip.is_link_local:
            return True, f"Link-local address ({ip}) blocked (SSRF Protection)"
        if ip.is_private:
            return True, f"Private network address ({ip}) blocked (SSRF Protection)"
        if ip.is_reserved:
            return True, f"Reserved address ({ip}) blocked (SSRF Protection)"
        return False, ""
    except ValueError:
        return True, "Invalid IP address structure"

def resolve_and_check_ssrf(url, is_lab_target=False):
    """
    Resolve target hostname to IP and verify SSRF safety.
    Lab targets are permitted to access local addresses (localhost / 127.0.0.1).
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return False, "Only HTTP and HTTPS protocols are permitted."
    
    hostname = parsed.hostname
    if not hostname:
        return False, "Invalid URL: hostname missing."
        
    hostname = hostname.lower()

    # Pre-approved lab targets exemption
    if is_lab_target or hostname in Config.PREAPPROVED_LAB_TARGETS:
        return True, "Lab target authorized."

    # Prevent direct numeric IP bypass for local addresses
    try:
        # Resolve hostname via DNS
        addr_info = socket.getaddrinfo(hostname, None)
        resolved_ips = set(info[4][0] for info in addr_info)
        
        for ip in resolved_ips:
            restricted, reason = is_ip_restricted(ip)
            if restricted:
                return False, f"Target '{hostname}' resolves to restricted IP {ip}: {reason}"
                
        return True, "IP resolution and SSRF check passed."
    except socket.gaierror as e:
        return False, f"DNS resolution failed for '{hostname}': {str(e)}"
    except Exception as e:
        return False, f"SSRF security check error: {str(e)}"

def is_path_in_scope(path, in_scope_str, out_of_scope_str):
    """
    Verify if a URL path conforms to authorized in-scope rules and does NOT match out-of-scope paths.
    """
    if not path:
        path = "/"
        
    # Clean up patterns
    out_patterns = [p.strip().rstrip("/") for p in (out_of_scope_str or "").split(",") if p.strip()]
    in_patterns = [p.strip().rstrip("/") for p in (in_scope_str or "/*").split(",") if p.strip()]

    # 1. Out-of-scope check (strict block)
    norm_path = path.rstrip("/")
    if not norm_path:
        norm_path = "/"
        
    for out_p in out_patterns:
        if out_p == "/*":
            return False, "Target configured to exclude all paths"
        out_p_clean = out_p.replace("/*", "")
        if norm_path == out_p_clean or norm_path.startswith(out_p_clean + "/") or norm_path.startswith(out_p):
            return False, f"Path '{path}' is explicitly out-of-scope ('{out_p}')"

    # 2. In-scope check
    if not in_patterns or "/*" in in_patterns or "*" in in_patterns or "/" in in_patterns:
        return True, "Path within root scope"

    for in_p in in_patterns:
        in_p_clean = in_p.replace("/*", "")
        if norm_path == in_p_clean or norm_path.startswith(in_p_clean + "/") or norm_path.startswith(in_p):
            return True, f"Path matches in-scope rule '{in_p}'"

    return False, f"Path '{path}' is not within authorized in-scope paths ({in_scope_str})"

def check_target_authorization_for_scan(target_id, target_url):
    """
    Core backend security enforcement:
    Validates target existence, verified/approved status, expiry, testing window, and scope.
    Returns (authorized: bool, message: str, target_row: sqlite3.Row)
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM targets WHERE id = ?", (target_id,))
    target = cursor.fetchone()
    
    if not target:
        conn.close()
        return False, f"Target ID #{target_id} does not exist in authorized targets database.", None

    target_dict = dict(target)
    status = target_dict.get("status", "").lower()
    target_type = target_dict.get("target_type", "")
    domain = target_dict.get("domain", "")

    # 1. Status verification check
    if status not in ("verified", "approved"):
        conn.close()
        return False, f"Unauthorized: Target '{domain}' has status '{status}'. Only 'Verified' or 'Approved' targets may be scanned.", target

    # 2. Expiry check
    now = utcnow()
    expires_at_str = target_dict.get("expires_at")
    if expires_at_str:
        try:
            exp_dt = datetime.strptime(expires_at_str, '%Y-%m-%d %H:%M:%S')
            if now > exp_dt:
                cursor.execute("UPDATE targets SET status = 'expired' WHERE id = ?", (target_id,))
                conn.commit()
                conn.close()
                return False, f"Unauthorized: Target authorization for '{domain}' expired on {expires_at_str}.", target
        except ValueError:
            pass

    # 3. Third-party testing window check
    if target_type == "third_party":
        cursor.execute("SELECT * FROM authorizations WHERE target_id = ? ORDER BY id DESC LIMIT 1", (target_id,))
        auth = cursor.fetchone()
        if auth:
            try:
                win_start = datetime.strptime(auth["testing_window_start"], '%Y-%m-%d %H:%M:%S')
                win_end = datetime.strptime(auth["testing_window_end"], '%Y-%m-%d %H:%M:%S')
                if now < win_start:
                    conn.close()
                    return False, f"Unauthorized: Authorized testing window for '{domain}' has not started yet (Starts: {auth['testing_window_start']}).", target
                if now > win_end:
                    cursor.execute("UPDATE targets SET status = 'expired' WHERE id = ?", (target_id,))
                    conn.commit()
                    conn.close()
                    return False, f"Unauthorized: Authorized testing window for '{domain}' expired on {auth['testing_window_end']}.", target
            except (ValueError, TypeError):
                pass

    conn.close()

    # 4. Domain matching check
    parsed_url = urlparse(target_url)
    req_host = parsed_url.netloc.split(":")[0].strip().lower()
    auth_host = normalize_domain(domain)
    
    if req_host != auth_host and not req_host.endswith("." + auth_host):
        return False, f"Unauthorized: Requested URL host '{req_host}' does not match authorized target domain '{auth_host}'.", target

    # 5. Path Scope check
    in_scope = target_dict.get("in_scope_paths", "/*")
    out_scope = target_dict.get("out_of_scope_paths", "")
    path_allowed, path_msg = is_path_in_scope(parsed_url.path or "/", in_scope, out_scope)
    if not path_allowed:
        return False, f"Scope Violation: {path_msg}", target

    # 6. SSRF / IP resolution check
    is_lab = target_type == "lab" or auth_host in Config.PREAPPROVED_LAB_TARGETS
    ssrf_ok, ssrf_msg = resolve_and_check_ssrf(target_url, is_lab_target=is_lab)
    if not ssrf_ok:
        return False, f"SSRF Security Violation: {ssrf_msg}", target

    return True, "Target verified and scan request authorized within scope.", target
