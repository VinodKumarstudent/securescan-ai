import json
from database.db import get_db_connection

def generate_json_report(scan_id):
    """
    Generates a structured JSON export of the scan results and compliance metadata.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT s.*, t.domain, t.target_type, t.in_scope_paths, t.out_of_scope_paths, 
               t.verification_method, t.verified_at
        FROM scans s
        JOIN targets t ON s.target_id = t.id
        WHERE s.id = ?
    """, (scan_id,))
    scan = cursor.fetchone()

    if not scan:
        conn.close()
        return None

    cursor.execute("SELECT * FROM authorizations WHERE target_id = ? ORDER BY id DESC LIMIT 1", (scan["target_id"],))
    auth = cursor.fetchone()

    cursor.execute("SELECT * FROM findings WHERE scan_id = ? ORDER BY cvss_score DESC", (scan_id,))
    findings = [dict(f) for f in cursor.fetchall()]

    cursor.execute("SELECT * FROM scan_logs WHERE scan_id = ? ORDER BY id ASC", (scan_id,))
    logs = [dict(l) for l in cursor.fetchall()]

    conn.close()

    report = {
        "report_type": "SecureScan AI Assessment Report",
        "version": "1.0",
        "scan_metadata": dict(scan),
        "authorization_compliance": dict(auth) if auth else {
            "type": "Educational Lab or Pre-Approved Host",
            "compliance_verified": True
        },
        "statistics": {
            "total_findings": len(findings),
            "critical": sum(1 for f in findings if f["severity"] == "Critical"),
            "high": sum(1 for f in findings if f["severity"] == "High"),
            "medium": sum(1 for f in findings if f["severity"] == "Medium"),
            "low": sum(1 for f in findings if f["severity"] == "Low"),
            "info": sum(1 for f in findings if f["severity"] == "Info"),
            "pages_crawled": scan["pages_crawled"],
            "duration_seconds": scan["duration_seconds"],
            "risk_score": scan["risk_score"]
        },
        "findings": findings,
        "execution_logs": logs
    }
    return report
