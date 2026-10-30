import time
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

from config import Config
from database.db import get_db_connection, log_audit, utcnow_str
from target_manager.scope_enforcer import normalize_domain, resolve_and_check_ssrf
from scanner.crawler import Crawler
from scanner.headers import check_security_headers
from scanner.cookies import check_cookie_security
from scanner.xss import test_reflected_xss
from scanner.sqli import test_sql_injection
from scanner.redirect import check_open_redirect
from scanner.files import check_sensitive_files
from scanner.ssl_check import check_ssl_tls
from scanner.info_disclosure import check_info_disclosure
from scanner.csrf import check_csrf_tokens

# Map of active scans to stop events
_active_scan_events = {}
_scan_lock = threading.Lock()

def stop_scan(scan_id):
    """Signal an active scan to terminate immediately."""
    with _scan_lock:
        if scan_id in _active_scan_events:
            _active_scan_events[scan_id].set()
            return True
    return False

def calculate_overall_risk_score(findings):
    """Calculate overall risk score (0.0 to 10.0) based on finding severities and CVSS scores."""
    if not findings:
        return 0.0
    highest_cvss = max((f.get("cvss_score", 0.0) for f in findings), default=0.0)
    # Severity weighting count
    crit = sum(1 for f in findings if f["severity"] == "Critical")
    high = sum(1 for f in findings if f["severity"] == "High")
    med = sum(1 for f in findings if f["severity"] == "Medium")
    
    score = highest_cvss + (crit * 0.4) + (high * 0.2) + (med * 0.1)
    return round(min(10.0, score), 1)

def run_scan_thread(scan_id, target_id, target_url, scan_type, intensity):
    """
    Background worker executing all authorized security detection modules.
    """
    stop_event = threading.Event()
    with _scan_lock:
        _active_scan_events[scan_id] = stop_event

    conn = get_db_connection()
    cursor = conn.cursor()

    def is_stopped():
        return stop_event.is_set() or Config.GLOBAL_KILL_SWITCH

    def append_log(message, level="INFO"):
        try:
            c = get_db_connection()
            cur = c.cursor()
            cur.execute("""
                INSERT INTO scan_logs (scan_id, level, message, timestamp)
                VALUES (?, ?, ?, ?)
            """, (scan_id, level, message, utcnow_str()))
            c.commit()
            c.close()
        except Exception:
            pass

    def update_progress(progress, module_name):
        try:
            c = get_db_connection()
            cur = c.cursor()
            cur.execute("UPDATE scans SET progress = ?, current_module = ? WHERE id = ?", (progress, module_name, scan_id))
            c.commit()
            c.close()
        except Exception:
            pass

    # Fetch target details for scope and rate limits
    cursor.execute("SELECT * FROM targets WHERE id = ?", (target_id,))
    target = cursor.fetchone()
    if not target:
        conn.close()
        return

    domain = target["domain"]
    in_scope = target["in_scope_paths"] or "/*"
    out_of_scope = target["out_of_scope_paths"] or ""
    max_req_sec = target["max_requests_per_sec"] or Config.DEFAULT_MAX_REQUESTS_PER_SEC
    is_lab = (target["target_type"] == "lab") or (normalize_domain(domain) in Config.PREAPPROVED_LAB_TARGETS)
    
    start_time = time.time()
    all_findings = []
    pages_crawled_count = 1

    append_log(f"Starting authorized scan on {target_url} (Target ID #{target_id}, Intensity: {intensity}).")
    update_progress(5, "Environment & Scope Validation")

    # Rate limiter closure
    min_interval = 1.0 / max(1, max_req_sec)
    last_req = [0.0]
    def rate_limiter():
        now = time.time()
        elapsed = now - last_req[0]
        if elapsed < min_interval:
            time.sleep(min_interval - elapsed)
        last_req[0] = time.time()

    try:
        # Step 1: Pre-scan SSRF & DNS validation
        if is_stopped():
            raise KeyboardInterrupt("Stopped by user or kill switch")

        append_log("Performing real-time DNS resolution and SSRF defense check...")
        ssrf_ok, ssrf_msg = resolve_and_check_ssrf(target_url, is_lab_target=is_lab)
        if not ssrf_ok:
            raise PermissionError(f"SSRF Safety block: {ssrf_msg}")
        append_log(f"Scope verification passed: {ssrf_msg}")

        # Step 2: SSL / TLS checks
        if not is_stopped():
            update_progress(15, "SSL/TLS Security Analysis")
            append_log("Checking SSL/TLS certificate validity, protocols, and HTTP redirection...")
            ssl_res = check_ssl_tls(target_url)
            all_findings.extend(ssl_res)
            append_log(f"SSL/TLS check completed. Identified {len(ssl_res)} findings.")

        # Step 3: Security headers
        if not is_stopped():
            update_progress(25, "Security Headers Verification")
            append_log("Inspecting response headers (CSP, HSTS, X-Frame-Options, etc.)...")
            headers_res = check_security_headers(target_url)
            all_findings.extend(headers_res)
            append_log(f"Security headers module completed. Identified {len(headers_res)} findings.")

        # Step 4: Cookie security
        if not is_stopped():
            update_progress(35, "Cookie Security Verification")
            append_log("Auditing cookie security flags (Secure, HttpOnly, SameSite)...")
            cookie_res = check_cookie_security(target_url)
            all_findings.extend(cookie_res)
            append_log(f"Cookie audit completed. Identified {len(cookie_res)} findings.")

        # Step 5: Server information disclosure
        if not is_stopped():
            update_progress(45, "Server Information Disclosure")
            append_log("Checking for Server banner, technology headers, and debug stack traces...")
            info_res = check_info_disclosure(target_url)
            all_findings.extend(info_res)
            append_log(f"Info disclosure module completed. Identified {len(info_res)} findings.")

        # If intensity is Light or Standard, proceed with crawling and active detection
        discovered_endpoints = [target_url]
        discovered_forms = []

        if intensity in ("Light", "Standard") and not is_stopped():
            update_progress(55, "Scope-Bound Web Crawler")
            append_log(f"Crawling target within allowed scope '{in_scope}' (skipping: '{out_of_scope}')...")
            max_p = 10 if intensity == "Light" else 25
            crawler = Crawler(
                target_url=target_url,
                in_scope=in_scope,
                out_of_scope=out_of_scope,
                max_pages=max_p,
                max_depth=2,
                max_req_per_sec=max_req_sec,
                is_lab=is_lab,
                stop_checker=is_stopped
            )
            crawl_res = crawler.crawl(log_callback=append_log)
            discovered_endpoints = crawl_res.get("endpoints", [target_url])
            discovered_forms = crawl_res.get("forms", [])
            pages_crawled_count = len(discovered_endpoints)
            append_log(f"Crawling complete: {len(discovered_endpoints)} in-scope pages, {len(discovered_forms)} forms discovered.")

            # CSRF Token Verification on discovered forms
            if not is_stopped():
                update_progress(65, "CSRF Form Token Audit")
                append_log("Checking discovered forms for anti-CSRF token presence...")
                csrf_res = check_csrf_tokens(discovered_forms)
                all_findings.extend(csrf_res)
                append_log(f"CSRF check completed. Identified {len(csrf_res)} findings.")

            # Sensitive Files and Directories Exposure
            if not is_stopped():
                update_progress(75, "Sensitive Files & Exposure Audit")
                append_log("Auditing for exposed sensitive paths (/.env, /.git, /admin, robots.txt)...")
                files_res = check_sensitive_files(target_url, rate_limiter=rate_limiter, stop_checker=is_stopped)
                all_findings.extend(files_res)
                append_log(f"Sensitive files check completed. Identified {len(files_res)} findings.")

        # If intensity is Standard, proceed with injection detection
        if intensity == "Standard" and not is_stopped():
            # Reflected XSS
            update_progress(82, "Benign Reflected XSS Detection")
            append_log("Testing parameters for unescaped benign reflection (Reflected XSS)...")
            xss_res = test_reflected_xss(discovered_endpoints, forms=discovered_forms, rate_limiter=rate_limiter, stop_checker=is_stopped)
            all_findings.extend(xss_res)
            append_log(f"XSS detection completed. Identified {len(xss_res)} findings.")

            # SQL Injection
            if not is_stopped():
                update_progress(90, "Error-Based SQL Injection Detection")
                append_log("Testing parameters with non-destructive probes for database syntax errors...")
                sqli_res = test_sql_injection(discovered_endpoints, forms=discovered_forms, rate_limiter=rate_limiter, stop_checker=is_stopped)
                all_findings.extend(sqli_res)
                append_log(f"SQLi detection completed. Identified {len(sqli_res)} findings.")

            # Open Redirect
            if not is_stopped():
                update_progress(95, "Open Redirect Audit")
                append_log("Checking for unvalidated redirects...")
                redirect_res = check_open_redirect(discovered_endpoints, rate_limiter=rate_limiter, stop_checker=is_stopped)
                all_findings.extend(redirect_res)
                append_log(f"Open redirect audit completed. Identified {len(redirect_res)} findings.")

        # Finalize Scan
        end_time = time.time()
        duration = round(end_time - start_time, 2)
        final_risk = calculate_overall_risk_score(all_findings)
        final_status = "stopped" if is_stopped() else "completed"

        # Save findings to DB
        c = get_db_connection()
        cur = c.cursor()
        for f in all_findings:
            cur.execute("""
                INSERT INTO findings (
                    scan_id, title, severity, cvss_score, affected_url, parameter,
                    evidence, owasp_category, remediation, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                scan_id, f["title"], f["severity"], f.get("cvss_score", 0.0),
                f["affected_url"], f.get("parameter", "N/A"), f.get("evidence", ""),
                f.get("owasp_category", "N/A"), f.get("remediation", ""),
                utcnow_str()
            ))

        cur.execute("""
            UPDATE scans SET 
                status = ?, progress = 100, current_module = 'Scan Finished',
                risk_score = ?, pages_crawled = ?, duration_seconds = ?,
                completed_at = ?
            WHERE id = ?
        """, (final_status, final_risk, pages_crawled_count, duration, utcnow_str(), scan_id))
        c.commit()
        c.close()

        append_log(f"Scan {final_status} in {duration}s. Total findings: {len(all_findings)}. Final Risk Score: {final_risk}/10.0")
        log_audit("SCAN_COMPLETED" if final_status == "completed" else "SCAN_STOPPED", 
                  domain, f"Scan #{scan_id} {final_status}. Findings: {len(all_findings)}, Score: {final_risk}")

    except KeyboardInterrupt:
        append_log("Scan halted by operator command or emergency kill switch.", level="WARN")
        c = get_db_connection()
        cur = c.cursor()
        cur.execute("UPDATE scans SET status = 'stopped', current_module = 'Halted' WHERE id = ?", (scan_id,))
        c.commit()
        c.close()
        log_audit("SCAN_STOPPED", domain, f"Scan #{scan_id} manually stopped.")
    except Exception as e:
        append_log(f"Scan aborted with error: {str(e)}", level="ERROR")
        c = get_db_connection()
        cur = c.cursor()
        cur.execute("UPDATE scans SET status = 'failed', current_module = 'Error Encountered' WHERE id = ?", (scan_id,))
        c.commit()
        c.close()
        log_audit("SCAN_FAILED", domain, f"Scan #{scan_id} failed: {str(e)}", status="FAILED")
    finally:
        with _scan_lock:
            _active_scan_events.pop(scan_id, None)

def start_scan_async(scan_id, target_id, target_url, scan_type, intensity):
    """Launch scan in an asynchronous background daemon thread."""
    t = threading.Thread(
        target=run_scan_thread,
        args=(scan_id, target_id, target_url, scan_type, intensity),
        daemon=True
    )
    t.start()
    return t
