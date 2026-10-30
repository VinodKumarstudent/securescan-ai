import os
import unittest
import json
from datetime import datetime, timedelta
from app import app
from config import Config
from database.db import get_db_connection, init_db, utcnow, utcnow_str
from target_manager.scope_enforcer import is_ip_restricted, is_path_in_scope, check_target_authorization_for_scan
from target_manager.authorization import approve_authorization_by_token
from target_manager.verifier import generate_verification_token

class TestSecureScanSecurityEnforcement(unittest.TestCase):
    def setUp(self):
        self.app = app
        self.client = self.app.test_client()
        init_db()

    def test_unverified_target_blocked(self):
        """Ensure scanning an unverified target returns HTTP 403 Forbidden."""
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            INSERT OR REPLACE INTO targets (domain, target_type, status, verification_method, in_scope_paths)
            VALUES (?, ?, ?, ?, ?)
        """, ("unverified-site.org", "own", "pending", "dns_txt", "/*"))
        target_id = cur.lastrowid
        conn.commit()
        conn.close()

        resp = self.client.post("/api/scan", json={
            "target_id": target_id,
            "target_url": "https://unverified-site.org",
            "authorized_declaration": True
        })
        self.assertEqual(resp.status_code, 403)
        data = resp.get_json()
        self.assertIn("Unauthorized", data.get("error", ""))
        print("[✓] Passed: Unverified target scan blocked with HTTP 403.")

    def test_out_of_scope_url_blocked(self):
        """Ensure scanning an out-of-scope URL path returns HTTP 403 Forbidden."""
        conn = get_db_connection()
        cur = conn.cursor()
        now_str = utcnow_str()
        exp_str = (utcnow() + timedelta(days=30)).strftime('%Y-%m-%d %H:%M:%S')
        cur.execute("""
            INSERT OR REPLACE INTO targets (
                domain, target_type, status, verification_method, in_scope_paths, 
                out_of_scope_paths, verified_at, expires_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            "testphp.vulnweb.com", "lab", "verified", "preapproved", 
            "/*", "/admin,/payment,/logout", now_str, exp_str
        ))
        target_id = cur.lastrowid
        conn.commit()
        conn.close()

        # Attempt to scan explicitly out-of-scope path /admin/login
        resp = self.client.post("/api/scan", json={
            "target_id": target_id,
            "target_url": "http://testphp.vulnweb.com/admin/login",
            "authorized_declaration": True
        })
        self.assertEqual(resp.status_code, 403)
        data = resp.get_json()
        self.assertIn("out-of-scope", data.get("error", "").lower())
        print("[✓] Passed: Out-of-scope URL blocked with HTTP 403.")

    def test_expired_authorization_blocked(self):
        """Ensure expired target authorizations reject scan launches with HTTP 403."""
        conn = get_db_connection()
        cur = conn.cursor()
        yesterday = (utcnow() - timedelta(days=1)).strftime('%Y-%m-%d %H:%M:%S')
        cur.execute("""
            INSERT OR REPLACE INTO targets (
                domain, target_type, status, verification_method, in_scope_paths, expires_at
            ) VALUES (?, ?, ?, ?, ?, ?)
        """, ("expired-client.com", "third_party", "approved", "written_auth", "/*", yesterday))
        target_id = cur.lastrowid
        conn.commit()
        conn.close()

        resp = self.client.post("/api/scan", json={
            "target_id": target_id,
            "target_url": "https://expired-client.com",
            "authorized_declaration": True
        })
        self.assertEqual(resp.status_code, 403)
        data = resp.get_json()
        self.assertIn("expired", data.get("error", "").lower())
        print("[✓] Passed: Expired authorization blocked with HTTP 403.")

    def test_private_ip_ssrf_blocked(self):
        """Ensure private IP ranges and cloud metadata IPs are rejected by SSRF protection."""
        restricted, reason = is_ip_restricted("192.168.1.1")
        self.assertTrue(restricted)
        self.assertIn("Private network", reason)

        restricted, reason = is_ip_restricted("10.0.0.5")
        self.assertTrue(restricted)

        restricted, reason = is_ip_restricted("127.0.0.1")
        self.assertTrue(restricted)
        self.assertIn("Loopback", reason)

        # Cloud metadata address
        restricted, reason = is_ip_restricted("169.254.169.254")
        self.assertTrue(restricted)
        self.assertIn("Cloud metadata", reason)
        print("[✓] Passed: Private and cloud metadata IP ranges blocked by SSRF defense.")

    def test_scope_path_matcher(self):
        """Test in-scope and out-of-scope path rules."""
        in_scope = "/api/*, /portal/*"
        out_scope = "/admin, /api/internal"

        # In-scope path
        allowed, msg = is_path_in_scope("/api/v1/users", in_scope, out_scope)
        self.assertTrue(allowed)

        # Out-of-scope path
        allowed, msg = is_path_in_scope("/admin/dashboard", in_scope, out_scope)
        self.assertFalse(allowed)

        # Out-of-scope subpath
        allowed, msg = is_path_in_scope("/api/internal/secrets", in_scope, out_scope)
        self.assertFalse(allowed)

        # Path not in in-scope list
        allowed, msg = is_path_in_scope("/other/page", in_scope, out_scope)
        self.assertFalse(allowed)
        print("[✓] Passed: Granular path scope engine evaluated accurately.")

    def test_written_authorization_approval_flow(self):
        """Test authorizer link approval updates target status to approved."""
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            INSERT OR REPLACE INTO targets (domain, target_type, status, verification_method)
            VALUES (?, ?, ?, ?)
        """, ("bank-client.com", "third_party", "pending", "written_auth"))
        target_id = cur.lastrowid

        token = "test_signed_approval_token_xyz123"
        now_str = utcnow_str()
        exp_str = (utcnow() + timedelta(days=14)).strftime('%Y-%m-%d %H:%M:%S')
        cur.execute("""
            INSERT INTO authorizations (
                target_id, authorizer_name, authorizer_designation, authorizer_org,
                authorizer_email, testing_window_start, testing_window_end, approval_token
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (target_id, "Alice Smith", "Head of Security", "Bank Corp", "alice@bankcorp.com", now_str, exp_str, token))
        conn.commit()
        conn.close()

        # Authorizer clicks approval link
        success, msg = approve_authorization_by_token(token)
        self.assertTrue(success)

        # Check DB status is now 'approved'
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT status FROM targets WHERE id = ?", (target_id,))
        row = cur.fetchone()
        conn.close()
        self.assertEqual(row["status"], "approved")
        print("[✓] Passed: Third-party written authorization approval flow succeeded.")

    def test_pdf_report_generation(self):
        """Ensure ReportLab builds professional PDF reports for completed scans."""
        from reports.pdf_generator import generate_pdf_report
        conn = get_db_connection()
        cur = conn.cursor()
        now_str = utcnow_str()
        cur.execute("""
            INSERT OR REPLACE INTO targets (id, domain, target_type, status, verification_method, verified_at)
            VALUES (999, 'report-test.com', 'lab', 'verified', 'preapproved', ?)
        """, (now_str,))
        cur.execute("""
            INSERT INTO scans (id, target_id, target_url, status, progress, risk_score, pages_crawled, duration_seconds)
            VALUES (999, 999, 'https://report-test.com', 'completed', 100, 7.5, 5, 2.3)
        """)
        cur.execute("""
            INSERT INTO findings (scan_id, title, severity, cvss_score, affected_url, parameter, evidence, owasp_category, remediation)
            VALUES (999, 'Test High Finding', 'High', 7.5, 'https://report-test.com/login', 'user', 'Insecure reflection', 'A03:2021-Injection', 'Encode output')
        """)
        conn.commit()
        conn.close()

        pdf_bytes = generate_pdf_report(999)
        self.assertIsNotNone(pdf_bytes)
        self.assertTrue(len(pdf_bytes) > 500)
        self.assertTrue(pdf_bytes.startswith(b"%PDF"))
        print(f"[✓] Passed: PDF report generated successfully ({len(pdf_bytes)} bytes).")

    def test_json_report_generation(self):
        """Ensure JSON reports include metadata, authorization compliance, and findings."""
        from reports.json_generator import generate_json_report
        conn = get_db_connection()
        cur = conn.cursor()
        now_str = utcnow_str()
        cur.execute("""
            INSERT OR REPLACE INTO targets (id, domain, target_type, status, verification_method, verified_at)
            VALUES (998, 'json-test.com', 'lab', 'verified', 'preapproved', ?)
        """, (now_str,))
        cur.execute("""
            INSERT INTO scans (id, target_id, target_url, status, progress, risk_score, pages_crawled, duration_seconds)
            VALUES (998, 998, 'https://json-test.com', 'completed', 100, 5.0, 3, 1.1)
        """)
        cur.execute("""
            INSERT INTO findings (scan_id, title, severity, cvss_score, affected_url, parameter, evidence, owasp_category, remediation)
            VALUES (998, 'Test Med Finding', 'Medium', 5.0, 'https://json-test.com/app', 'Header', 'Missing HSTS', 'A05:2021-Security Misconfiguration', 'Set HSTS')
        """)
        conn.commit()
        conn.close()

        report = generate_json_report(998)
        self.assertIsNotNone(report)
        self.assertIn("scan_metadata", report)
        self.assertIn("authorization_compliance", report)
        self.assertIn("statistics", report)
        self.assertIn("findings", report)
        self.assertEqual(len(report["findings"]), 1)
        print(f"[✓] Passed: JSON report export generated with {len(report['findings'])} findings.")

    def test_ai_explainer_fallback(self):
        """Ensure AI explainer provides rich advisory via static knowledge base when no API key is set."""
        from ai.explainer import explain_finding
        exp = explain_finding(
            title="SQL Injection Vulnerability in Parameter 'id'",
            severity="Critical",
            affected_url="https://example.com/items?id=1",
            parameter="id",
            evidence="MySQL syntax error returned",
            owasp_category="A03:2021-Injection"
        )
        self.assertIn("Executive Summary", exp)
        self.assertIn("Remediation", exp)
        self.assertIn("Attack", exp)
        print("[✓] Passed: AI Explainer returned structured technical advisory.")

if __name__ == "__main__":
    unittest.main()
