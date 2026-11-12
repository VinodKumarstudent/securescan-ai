import sqlite3
import os
import threading
from datetime import datetime, timezone
from config import Config

def utcnow():
    """Return current naive UTC datetime."""
    return datetime.now(timezone.utc).replace(tzinfo=None)

def utcnow_str():
    """Return formatted UTC timestamp string."""
    return utcnow().strftime('%Y-%m-%d %H:%M:%S')

_db_lock = threading.Lock()

def get_db_connection():
    """Create a thread-safe connection to the SQLite database."""
    conn = sqlite3.connect(Config.DB_PATH, check_same_thread=False, timeout=20.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn

def init_db():
    """Initialize all required tables for SecureScan AI."""
    os.makedirs(os.path.dirname(Config.DB_PATH), exist_ok=True)
    with _db_lock:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Targets table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS targets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL UNIQUE,
            target_type TEXT NOT NULL, /* 'lab', 'own', 'third_party' */
            status TEXT NOT NULL DEFAULT 'pending', /* 'pending', 'verified', 'approved', 'failed', 'expired', 'revoked' */
            verification_method TEXT, /* 'dns_txt', 'html_meta', 'file_upload', 'written_auth', 'preapproved' */
            verification_token TEXT,
            token_created_at TIMESTAMP,
            verified_at TIMESTAMP,
            expires_at TIMESTAMP,
            in_scope_paths TEXT DEFAULT '/*',
            out_of_scope_paths TEXT DEFAULT '/admin,/payment,/logout',
            allowed_intensity TEXT DEFAULT 'Standard', /* 'Passive', 'Light', 'Standard' */
            max_requests_per_sec INTEGER DEFAULT 5,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)

        # Authorizations table for third-party written permission
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS authorizations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id INTEGER NOT NULL,
            authorizer_name TEXT NOT NULL,
            authorizer_designation TEXT NOT NULL,
            authorizer_org TEXT NOT NULL,
            authorizer_email TEXT NOT NULL,
            authorizer_phone TEXT,
            testing_window_start TIMESTAMP NOT NULL,
            testing_window_end TIMESTAMP NOT NULL,
            allowed_intensity TEXT DEFAULT 'Standard',
            max_requests_per_sec INTEGER DEFAULT 5,
            proof_filename TEXT,
            proof_original_name TEXT,
            decl_written_permission INTEGER DEFAULT 1,
            decl_legal_responsibility INTEGER DEFAULT 1,
            decl_no_exploitation INTEGER DEFAULT 1,
            approval_token TEXT,
            approved_at TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (target_id) REFERENCES targets (id) ON DELETE CASCADE
        )
        """)

        # Verifications attempts history
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS verifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id INTEGER NOT NULL,
            method TEXT NOT NULL,
            status TEXT NOT NULL, /* 'attempted', 'success', 'failed' */
            details TEXT,
            checked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (target_id) REFERENCES targets (id) ON DELETE CASCADE
        )
        """)

        # Audit logs table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT NOT NULL,
            target_domain TEXT,
            details TEXT,
            ip_address TEXT,
            user_identifier TEXT DEFAULT 'admin',
            status TEXT DEFAULT 'SUCCESS',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)

        # Scans table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id INTEGER NOT NULL,
            target_url TEXT NOT NULL,
            scan_type TEXT DEFAULT 'full',
            intensity TEXT DEFAULT 'Standard',
            status TEXT DEFAULT 'pending', /* 'pending', 'running', 'completed', 'stopped', 'failed' */
            progress INTEGER DEFAULT 0,
            current_module TEXT DEFAULT '',
            risk_score REAL DEFAULT 0.0,
            pages_crawled INTEGER DEFAULT 0,
            duration_seconds REAL DEFAULT 0.0,
            started_at TIMESTAMP,
            completed_at TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (target_id) REFERENCES targets (id) ON DELETE CASCADE
        )
        """)

        # Findings table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            severity TEXT NOT NULL, /* 'Critical', 'High', 'Medium', 'Low', 'Info' */
            cvss_score REAL DEFAULT 0.0,
            affected_url TEXT NOT NULL,
            parameter TEXT DEFAULT 'N/A',
            evidence TEXT,
            owasp_category TEXT,
            remediation TEXT,
            ai_explanation TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
        )
        """)

        # Scan logs table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            level TEXT DEFAULT 'INFO',
            message TEXT NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
        )
        """)

        # Ensure default lab and demo targets exist
        from datetime import timedelta
        now_dt = utcnow()
        now_s = now_dt.strftime('%Y-%m-%d %H:%M:%S')
        exp_s = (now_dt + timedelta(days=365)).strftime('%Y-%m-%d %H:%M:%S')
        default_targets = [
            ("localhost:5001", "lab", "/*", "", 10),
            ("localhost:5000", "lab", "/*", "", 10),
            ("testphp.vulnweb.com", "lab", "/*", "/admin,/logout", 5),
            ("weather-app-a7f3.onrender.com", "lab", "/*", "", 5),
            ("bank-client.com", "lab", "/*", "/admin,/payment", 5),
        ]
        for dom, ttype, in_s, out_s, max_rps in default_targets:
            cursor.execute("SELECT id FROM targets WHERE domain = ?", (dom,))
            if not cursor.fetchone():
                cursor.execute("""
                    INSERT INTO targets (domain, target_type, status, verification_method, in_scope_paths, out_of_scope_paths, allowed_intensity, max_requests_per_sec, verified_at, expires_at)
                    VALUES (?, ?, 'verified', 'preapproved', ?, ?, 'Standard', ?, ?, ?)
                """, (dom, ttype, in_s, out_s, max_rps, now_s, exp_s))

        conn.commit()
        conn.close()

def log_audit(action, target_domain="", details="", ip_address="127.0.0.1", user="admin", status="SUCCESS"):
    """Insert an entry into the audit_logs table."""
    with _db_lock:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO audit_logs (action, target_domain, details, ip_address, user_identifier, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (action, target_domain, details, ip_address, user, status, utcnow_str()))
        conn.commit()
        conn.close()
