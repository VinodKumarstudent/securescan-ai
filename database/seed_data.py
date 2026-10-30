import os
from datetime import datetime, timedelta
from database.db import get_db_connection, init_db
from config import Config

def seed_demo_data():
    """
    Seeds database with initial educational lab targets, pending third-party authorizations,
    and a sample completed scan to ensure the dashboard looks populated on first launch.
    """
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()

    # Check if data already exists
    cursor.execute("SELECT COUNT(*) as count FROM targets")
    if cursor.fetchone()["count"] > 0:
        conn.close()
        return

    now = datetime.utcnow()
    now_str = now.strftime('%Y-%m-%d %H:%M:%S')
    one_year_later = (now + timedelta(days=365)).strftime('%Y-%m-%d %H:%M:%S')
    thirty_days_later = (now + timedelta(days=30)).strftime('%Y-%m-%d %H:%M:%S')

    # 1. Seed Targets
    # Pre-approved Lab Target: testphp.vulnweb.com
    cursor.execute("""
        INSERT INTO targets (
            domain, target_type, status, verification_method, in_scope_paths, 
            out_of_scope_paths, allowed_intensity, max_requests_per_sec, verified_at, expires_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        "testphp.vulnweb.com", "lab", "verified", "preapproved", "/*",
        "/admin,/logout", "Standard", 5, now_str, one_year_later
    ))
    target1_id = cursor.lastrowid

    # Pre-approved Lab Target: localhost
    cursor.execute("""
        INSERT INTO targets (
            domain, target_type, status, verification_method, in_scope_paths, 
            out_of_scope_paths, allowed_intensity, max_requests_per_sec, verified_at, expires_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        "localhost:5001", "lab", "verified", "preapproved", "/*",
        "", "Standard", 10, now_str, one_year_later
    ))
    target2_id = cursor.lastrowid

    # Own Website Verified Target: my-cloud-app.com
    cursor.execute("""
        INSERT INTO targets (
            domain, target_type, status, verification_method, verification_token,
            in_scope_paths, out_of_scope_paths, allowed_intensity, max_requests_per_sec, verified_at, expires_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        "my-cloud-app.com", "own", "verified", "dns_txt", "securescan_token_9a8b7c6d5e4f",
        "/*", "/payment,/admin", "Standard", 5, now_str, thirty_days_later
    ))
    target3_id = cursor.lastrowid

    # Pending Third-Party Target: client-portal.acmefinance.com
    cursor.execute("""
        INSERT INTO targets (
            domain, target_type, status, verification_method, in_scope_paths, 
            out_of_scope_paths, allowed_intensity, max_requests_per_sec, expires_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        "client-portal.acmefinance.com", "third_party", "pending", "written_auth",
        "/api/v1/*,/dashboard/*", "/admin,/payment,/auth/logout", "Standard", 4, thirty_days_later
    ))
    target4_id = cursor.lastrowid

    # Seed Written Authorization for Acme Finance
    sample_token = "demo_signed_approval_token_acme_839120"
    os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)
    mock_pdf_path = os.path.join(Config.UPLOAD_FOLDER, "auth_proof_acme_sample.pdf")
    if not os.path.exists(mock_pdf_path):
        with open(mock_pdf_path, "wb") as f:
            f.write(b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF")

    cursor.execute("""
        INSERT INTO authorizations (
            target_id, authorizer_name, authorizer_designation, authorizer_org,
            authorizer_email, authorizer_phone, testing_window_start, testing_window_end,
            allowed_intensity, max_requests_per_sec, proof_filename, proof_original_name,
            decl_written_permission, decl_legal_responsibility, decl_no_exploitation,
            approval_token
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        target4_id, "Sarah Jenkins", "VP of Information Security", "Acme Financial Services LLC",
        "s.jenkins@acmefinance.com", "+1-555-019-2834", now_str, thirty_days_later,
        "Standard", 4, "auth_proof_acme_sample.pdf", "Acme_Security_Testing_Agreement_2026.pdf",
        1, 1, 1, sample_token
    ))

    # 2. Seed Sample Scans
    # Scan on testphp.vulnweb.com
    cursor.execute("""
        INSERT INTO scans (
            target_id, target_url, scan_type, intensity, status, progress, current_module,
            risk_score, pages_crawled, duration_seconds, started_at, completed_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        target1_id, "http://testphp.vulnweb.com", "full", "Standard", "completed", 100, "Scan Finished",
        9.3, 14, 8.42, 
        (now - timedelta(hours=2)).strftime('%Y-%m-%d %H:%M:%S'),
        (now - timedelta(hours=1, minutes=59)).strftime('%Y-%m-%d %H:%M:%S')
    ))
    scan1_id = cursor.lastrowid

    # Seed Findings for Scan 1
    sample_findings = [
        (
            scan1_id,
            "SQL Injection Vulnerability in Parameter 'artist'",
            "Critical",
            9.3,
            "http://testphp.vulnweb.com/artists.php?artist=1",
            "artist",
            "Injected benign syntax probe '''. Server responded with database diagnostic error signature: 'you have an error in your sql syntax'.",
            "A03:2021-Injection",
            "Use parameterized queries (prepared statements) with PDO or mysqli to bind user input parameters safely."
        ),
        (
            scan1_id,
            "Reflected Cross-Site Scripting (XSS) in Parameter 'searchFor'",
            "High",
            7.5,
            "http://testphp.vulnweb.com/search.php?test=query",
            "searchFor",
            "Benign marker payload '<securescan_test_marker_x78>' was reflected verbatim in the response body without HTML sanitization or entity encoding.",
            "A03:2021-Injection",
            "Ensure input is sanitized and HTML-encoded (e.g. htmlspecialchars) before being output in HTML templates."
        ),
        (
            scan1_id,
            "Missing Content-Security-Policy (CSP) Header",
            "Medium",
            5.4,
            "http://testphp.vulnweb.com/",
            "Header: Content-Security-Policy",
            "Header 'Content-Security-Policy' is absent from the HTTP response.",
            "A05:2021-Security Misconfiguration",
            "Implement a strict Content-Security-Policy to restrict scripts, stylesheets, and frame sources."
        ),
        (
            scan1_id,
            "Missing Anti-CSRF Token on Form",
            "Medium",
            6.5,
            "http://testphp.vulnweb.com/login.php",
            "Form Action: http://testphp.vulnweb.com/userinfo.php",
            "POST form submitting to userinfo.php contains 2 fields but lacks an anti-CSRF token parameter.",
            "A01:2021-Broken Access Control",
            "Embed unique, cryptographically random CSRF tokens in all POST forms."
        ),
        (
            scan1_id,
            "Web Server Information Disclosure (Server Header)",
            "Low",
            3.4,
            "http://testphp.vulnweb.com/",
            "Header: Server",
            "Server header banner reveals underlying platform details: 'nginx/1.19.0'.",
            "A05:2021-Security Misconfiguration",
            "Configure 'server_tokens off' in Nginx configuration to minimize attack surface disclosure."
        ),
        (
            scan1_id,
            "Robots.txt Information Disclosure",
            "Info",
            2.0,
            "http://testphp.vulnweb.com/robots.txt",
            "Path: /robots.txt",
            "Path '/robots.txt' returned HTTP 200 OK disclosing crawler disallow rules.",
            "A05:2021-Security Misconfiguration",
            "Review robots.txt to ensure sensitive administrator endpoints are not advertised to search crawlers."
        )
    ]

    for f in sample_findings:
        cursor.execute("""
            INSERT INTO findings (
                scan_id, title, severity, cvss_score, affected_url, parameter,
                evidence, owasp_category, remediation, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (*f, now_str))

    # Sample Logs for Scan 1
    sample_logs = [
        (scan1_id, "INFO", "Starting authorized scan on http://testphp.vulnweb.com (Target ID #1, Intensity: Standard)."),
        (scan1_id, "INFO", "Performing real-time DNS resolution and SSRF defense check..."),
        (scan1_id, "INFO", "Scope verification passed: Lab target authorized."),
        (scan1_id, "INFO", "Checking SSL/TLS certificate validity, protocols, and HTTP redirection..."),
        (scan1_id, "INFO", "Security headers module completed. Identified 1 findings."),
        (scan1_id, "INFO", "Crawling target within allowed scope '/*' (skipping: '/admin,/logout')..."),
        (scan1_id, "INFO", "Crawling complete: 14 in-scope pages, 3 forms discovered."),
        (scan1_id, "INFO", "Testing parameters for unescaped benign reflection (Reflected XSS)..."),
        (scan1_id, "INFO", "Testing parameters with non-destructive probes for database syntax errors..."),
        (scan1_id, "INFO", "Scan completed in 8.42s. Total findings: 6. Final Risk Score: 9.3/10.0")
    ]
    for log in sample_logs:
        cursor.execute("INSERT INTO scan_logs (scan_id, level, message, timestamp) VALUES (?, ?, ?, ?)", (*log, now_str))

    # 3. Seed Audit Logs
    audit_entries = [
        ("TARGET_ADDED", "testphp.vulnweb.com", "Registered pre-approved educational lab target.", "127.0.0.1"),
        ("VERIFICATION_SUCCESS", "testphp.vulnweb.com", "Pre-approved educational lab target verified.", "127.0.0.1"),
        ("TARGET_ADDED", "localhost:5000", "Registered local sandbox environment.", "127.0.0.1"),
        ("VERIFICATION_SUCCESS", "localhost:5000", "Educational lab target verified automatically.", "127.0.0.1"),
        ("TARGET_ADDED", "my-cloud-app.com", "Registered own organization website.", "127.0.0.1"),
        ("VERIFICATION_SUCCESS", "my-cloud-app.com", "Ownership verified via dns_txt: Found matching TXT record.", "127.0.0.1"),
        ("TARGET_ADDED", "client-portal.acmefinance.com", "Added third-party client target with scope restrictions.", "127.0.0.1"),
        ("AUTHORIZATION_SUBMITTED", "client-portal.acmefinance.com", "Submitted for authorizer Sarah Jenkins (s.jenkins@acmefinance.com)", "127.0.0.1"),
        ("SCAN_STARTED", "testphp.vulnweb.com", "Scan #1 launched with Standard intensity.", "127.0.0.1"),
        ("SCAN_COMPLETED", "testphp.vulnweb.com", "Scan #1 completed. Findings: 6, Score: 9.3", "127.0.0.1")
    ]

    for a in audit_entries:
        cursor.execute("""
            INSERT INTO audit_logs (action, target_domain, details, ip_address, created_at)
            VALUES (?, ?, ?, ?, ?)
        """, (*a, now_str))

    conn.commit()
    conn.close()
