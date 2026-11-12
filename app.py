import os
import csv
import io
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, render_template, send_file, Response, send_from_directory, abort
from flask_cors import CORS

from config import Config
from database.db import get_db_connection, init_db, log_audit, utcnow, utcnow_str
from database.seed_data import seed_demo_data
from target_manager.scope_enforcer import (
    normalize_domain,
    check_target_authorization_for_scan,
    resolve_and_check_ssrf
)
from target_manager.verifier import (
    generate_verification_token,
    execute_verification
)
from target_manager.authorization import (
    create_written_authorization,
    approve_authorization_by_token
)
from scanner.engine import start_scan_async, stop_scan
from ai.explainer import explain_finding
from reports.pdf_generator import generate_pdf_report
from reports.json_generator import generate_json_report

app = Flask(__name__, static_folder="static", template_folder="templates")
app.config.from_object(Config)
CORS(app)

# Initialize Database and Demo Data on startup
with app.app_context():
    init_db()
    seed_demo_data()

# -------------------------------------------------------------
# Frontend Page Routes
# -------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/presentation")
def presentation_page():
    """Interactive HTML5 slide presentation deck for project defense and seminar."""
    return render_template("presentation.html")

@app.route("/presentation/download")
def download_presentation_pptx():
    """Download the 14-slide master PowerPoint file (.pptx)."""
    pptx_path = os.path.join(os.path.dirname(__file__), "securescan_ai_presentation.pptx")
    if not os.path.exists(pptx_path):
        from generate_ppt import create_presentation
        create_presentation()
    return send_file(
        pptx_path,
        mimetype="application/vnd.openxmlformats-officedocument.presentationml.presentation",
        as_attachment=True,
        download_name="SecureScan_AI_Presentation.pptx"
    )

@app.route("/research-papers/pdf")
def download_research_papers_pdf():
    """Download the compiled academic literature review PDF document."""
    pdf_path = os.path.join(os.path.dirname(__file__), "securescan_ai_research_papers.pdf")
    if not os.path.exists(pdf_path):
        from generate_research_pdf import build_research_pdf
        build_research_pdf(pdf_path)
    return send_file(
        pdf_path,
        mimetype="application/pdf",
        as_attachment=True,
        download_name="SecureScan_AI_Academic_Research_Papers.pdf"
    )

@app.route("/docs/pdf/<filename>")
def download_package_pdf(filename):
    """Download any PDF from the PDF_Documentation_Package."""
    package_dir = os.path.join(os.path.dirname(__file__), "PDF_Documentation_Package")
    file_path = os.path.join(package_dir, filename)
    if not os.path.exists(file_path):
        return jsonify({"error": f"Document {filename} not found"}), 404
    return send_file(
        file_path,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=filename
    )

@app.route("/lab/test-page", methods=["GET", "POST"])
def educational_lab_page():
    """
    Built-in educational vulnerable sandbox endpoint for localhost testing.
    Demonstrates benign reflection and security header auditing.
    """
    param_name = request.args.get("name", "Student")
    response_html = f"""
    <!DOCTYPE html>
    <html>
    <head><title>SecureScan AI - Educational Lab Sandbox</title></head>
    <body style="font-family: sans-serif; padding: 2rem;">
        <h2>🎓 SecureScan AI Local Vulnerability Test Page</h2>
        <p>Welcome, {param_name}!</p>
        <p>This test endpoint simulates a legacy educational lab environment.</p>
        <form method="POST" action="/lab/test-page">
            <label>Comment: <input type="text" name="comment" value="Test feedback"></label>
            <button type="submit">Submit Feedback</button>
        </form>
        <p><a href="/lab/test-page?name=probe">Self Link</a></p>
    </body>
    </html>
    """
    resp = Response(response_html, mimetype="text/html")
    resp.headers["Server"] = "DemoServer/2.4.49"
    resp.headers["X-Powered-By"] = "Python/EducationalLab"
    # Note: Intentionally omitting CSP, HSTS, and X-Frame-Options to test detection
    return resp

@app.route("/approve/<token>")
def approve_token_page(token):
    """Authorizer verification link landing page."""
    success, msg = approve_authorization_by_token(token, ip_address=request.remote_addr)
    return render_template("index.html", approval_status=success, approval_msg=msg)

@app.route("/uploads/authorizations/<filename>")
def serve_authorization_file(filename):
    """Safely serve authorization proof files."""
    return send_from_directory(Config.UPLOAD_FOLDER, filename)

# -------------------------------------------------------------
# Authorized Targets API
# -------------------------------------------------------------
@app.route("/api/targets", methods=["GET"])
def list_targets():
    """Return all authorized targets with verification and authorization status."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT t.*, 
               a.authorizer_name, a.authorizer_email, a.authorizer_org, 
               a.testing_window_start, a.testing_window_end, a.proof_filename, a.approval_token
        FROM targets t
        LEFT JOIN authorizations a ON t.id = a.target_id
        ORDER BY t.id DESC
    """)
    rows = cursor.fetchall()
    
    targets = []
    now = utcnow()

    for r in rows:
        t = dict(r)
        # Compute expiry status & countdown
        is_expired = False
        exp_countdown = "No Expiry"
        if t.get("expires_at"):
            try:
                exp_dt = datetime.strptime(t["expires_at"], '%Y-%m-%d %H:%M:%S')
                if now > exp_dt:
                    is_expired = True
                    t["status"] = "expired"
                    exp_countdown = "Expired"
                else:
                    diff = exp_dt - now
                    exp_countdown = f"{diff.days}d {diff.seconds // 3600}h remaining"
            except ValueError:
                pass
        t["is_expired"] = is_expired
        t["expiry_countdown"] = exp_countdown
        targets.append(t)

    conn.close()
    return jsonify({"targets": targets})

@app.route("/api/targets", methods=["POST"])
def add_target():
    """Register a new target with ownership token or educational lab status."""
    data = request.get_json() or {}
    raw_domain = data.get("domain", "").strip()
    target_type = data.get("target_type", "own")
    method = data.get("verification_method", "dns_txt")
    in_scope = data.get("in_scope_paths", "/*").strip()
    out_of_scope = data.get("out_of_scope_paths", "/admin,/payment,/logout").strip()
    allowed_intensity = data.get("allowed_intensity", "Standard")
    max_req_sec = int(data.get("max_requests_per_sec", 5))

    clean_domain = normalize_domain(raw_domain)
    if not clean_domain:
        return jsonify({"error": "Invalid domain or host provided."}), 400

    now = utcnow()
    now_str = utcnow_str()
    
    # Lab target auto-approval
    is_lab = target_type == "lab" or clean_domain in Config.PREAPPROVED_LAB_TARGETS
    if is_lab:
        status = "verified"
        method = "preapproved"
        token = None
        exp_str = (now + timedelta(days=365)).strftime('%Y-%m-%d %H:%M:%S')
    else:
        status = "pending"
        token = generate_verification_token() if target_type == "own" else None
        exp_str = (now + timedelta(days=Config.TOKEN_EXPIRY_DAYS)).strftime('%Y-%m-%d %H:%M:%S')

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT INTO targets (
                domain, target_type, status, verification_method, verification_token,
                token_created_at, verified_at, expires_at, in_scope_paths, 
                out_of_scope_paths, allowed_intensity, max_requests_per_sec
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            clean_domain, target_type, status, method, token,
            now_str, now_str if is_lab else None, exp_str,
            in_scope, out_of_scope, allowed_intensity, max_req_sec
        ))
        target_id = cursor.lastrowid
        conn.commit()

        log_audit("TARGET_ADDED", clean_domain, f"Added target '{clean_domain}' (Type: {target_type})", request.remote_addr)
        
        return jsonify({
            "message": f"Target '{clean_domain}' registered successfully.",
            "target_id": target_id,
            "verification_token": token,
            "status": status
        }), 201
    except Exception as e:
        conn.rollback()
        return jsonify({"error": f"Failed to register target: {str(e)}"}), 400
    finally:
        conn.close()

@app.route("/api/targets/<int:target_id>/verify", methods=["POST"])
def verify_target(target_id):
    """Trigger real-time ownership verification for an owned target."""
    success, msg = execute_verification(target_id, ip_address=request.remote_addr)
    status_code = 200 if success else 400
    return jsonify({
        "success": success,
        "message": msg
    }), status_code

@app.route("/api/targets/<int:target_id>/authorization", methods=["POST"])
def submit_written_authorization(target_id):
    """Submit written authorization form and upload proof document for a third-party target."""
    form_data = request.form.to_dict()
    proof_file = request.files.get("proof_document")

    # Validate declarations
    if not form_data.get("decl_written_permission") or not form_data.get("decl_legal_responsibility") or not form_data.get("decl_no_exploitation"):
        return jsonify({"error": "You must check and agree to all legal declarations before submitting authorization."}), 400

    try:
        approval_token = create_written_authorization(
            target_id=target_id,
            data=form_data,
            file_storage=proof_file,
            ip_address=request.remote_addr
        )
        approval_url = f"{request.host_url.rstrip('/')}/approve/{approval_token}"
        return jsonify({
            "message": "Written authorization submitted successfully. Authorizer approval link generated.",
            "approval_token": approval_token,
            "approval_url": approval_url
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route("/api/targets/<int:target_id>/manual-approve", methods=["POST"])
def manual_approve_target(target_id):
    """Quick approval helper for demo and testing environments."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM targets WHERE id = ?", (target_id,))
    target = cursor.fetchone()
    if not target:
        conn.close()
        return jsonify({"error": "Target not found"}), 404

    now_str = utcnow_str()
    exp_str = (utcnow() + timedelta(days=30)).strftime('%Y-%m-%d %H:%M:%S')
    cursor.execute("""
        UPDATE targets 
        SET status = 'approved', verified_at = ?, expires_at = ?
        WHERE id = ?
    """, (now_str, exp_str, target_id))
    
    cursor.execute("UPDATE authorizations SET approved_at = ? WHERE target_id = ?", (now_str, target_id))
    conn.commit()
    conn.close()

    log_audit("AUTHORIZATION_APPROVED", target["domain"], "Target manually approved in test/demo mode.", request.remote_addr)
    return jsonify({"message": f"Target '{target['domain']}' marked as approved."})

@app.route("/api/targets/<int:target_id>", methods=["PATCH"])
def update_target(target_id):
    """Update scope rules, intensity, or revoke a target."""
    data = request.get_json() or {}
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Check if revoking
    if data.get("action") == "revoke":
        cursor.execute("UPDATE targets SET status = 'revoked', updated_at = CURRENT_TIMESTAMP WHERE id = ?", (target_id,))
        conn.commit()
        cursor.execute("SELECT domain FROM targets WHERE id = ?", (target_id,))
        dom = cursor.fetchone()["domain"]
        conn.close()
        log_audit("TARGET_REVOKED", dom, "Target authorization revoked by operator.", request.remote_addr)
        return jsonify({"message": f"Authorization for target revoked successfully."})

    in_scope = data.get("in_scope_paths")
    out_scope = data.get("out_of_scope_paths")
    intensity = data.get("allowed_intensity")
    max_req = data.get("max_requests_per_sec")

    cursor.execute("""
        UPDATE targets SET 
            in_scope_paths = COALESCE(?, in_scope_paths),
            out_of_scope_paths = COALESCE(?, out_of_scope_paths),
            allowed_intensity = COALESCE(?, allowed_intensity),
            max_requests_per_sec = COALESCE(?, max_requests_per_sec),
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
    """, (in_scope, out_scope, intensity, max_req, target_id))
    conn.commit()
    conn.close()
    return jsonify({"message": "Target settings updated successfully."})

@app.route("/api/targets/<int:target_id>", methods=["DELETE"])
def delete_target(target_id):
    """Delete a target and its associated scan records."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT domain FROM targets WHERE id = ?", (target_id,))
    target = cursor.fetchone()
    if not target:
        conn.close()
        return jsonify({"error": "Target not found"}), 404

    domain = target["domain"]
    cursor.execute("DELETE FROM targets WHERE id = ?", (target_id,))
    conn.commit()
    conn.close()

    log_audit("TARGET_DELETED", domain, f"Target '{domain}' removed from system.", request.remote_addr)
    return jsonify({"message": f"Target '{domain}' and associated data removed."})

# -------------------------------------------------------------
# Scans API (Mandatory Authorization Enforced)
# -------------------------------------------------------------
@app.route("/api/scan", methods=["POST"])
def start_scan():
    """
    Launch a new security scan.
    MANDATORY SECURITY ENFORCEMENT:
    Enforces that target is verified/approved, within scope, and inside testing window.
    Returns HTTP 403 on authorization failure.
    """
    data = request.get_json() or {}
    target_id = data.get("target_id")
    target_url = (data.get("target_url") or "").strip()
    scan_type = data.get("scan_type", "full")
    intensity = data.get("intensity", "Standard")
    is_authorized_declared = data.get("authorized_declaration", False)

    if not is_authorized_declared:
        return jsonify({
            "error": "You must check the authorization declaration affirming you have legal permission to test this target.",
            "status": 403
        }), 403

    if not target_id:
        return jsonify({
            "error": "Missing target_id. Scans may only be initiated against registered and verified targets.",
            "status": 403
        }), 403

    if not target_url:
        return jsonify({"error": "Missing target_url parameter."}), 400

    # Ensure target_url has scheme
    if not (target_url.startswith("http://") or target_url.startswith("https://")):
        target_url = "http://" + target_url

    # CORE BACKEND AUTHORIZATION & SCOPE CHECK
    authorized, reason, target_row = check_target_authorization_for_scan(target_id, target_url)
    if not authorized:
        log_audit("SCAN_BLOCKED", target_url, f"Scan request blocked: {reason}", request.remote_addr, status="BLOCKED")
        return jsonify({
            "error": reason,
            "status": 403,
            "target_id": target_id,
            "target_url": target_url
        }), 403

    # Respect intensity upper bound set by authorization
    max_allowed_intensity = target_row["allowed_intensity"] or "Standard"
    intensity_order = {"Passive": 1, "Light": 2, "Standard": 3}
    if intensity_order.get(intensity, 3) > intensity_order.get(max_allowed_intensity, 3):
        intensity = max_allowed_intensity

    # Insert scan record
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO scans (
            target_id, target_url, scan_type, intensity, status, progress, current_module,
            started_at, created_at
        ) VALUES (?, ?, ?, ?, 'running', 5, 'Initialization', ?, ?)
    """, (
        target_id, target_url, scan_type, intensity,
        utcnow_str(),
        utcnow_str()
    ))
    scan_id = cursor.lastrowid
    conn.commit()
    conn.close()

    # Launch scan in background thread
    start_scan_async(scan_id, target_id, target_url, scan_type, intensity)

    log_audit("SCAN_STARTED", target_row["domain"], f"Scan #{scan_id} launched on {target_url} (Intensity: {intensity})", request.remote_addr)

    return jsonify({
        "message": "Scan initiated successfully.",
        "scan_id": scan_id,
        "target_id": target_id,
        "target_url": target_url,
        "intensity": intensity
    }), 201

@app.route("/api/scans", methods=["GET"])
def list_scans():
    """List all scans with target domain and metrics."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT s.*, t.domain, t.target_type,
               (SELECT COUNT(*) FROM findings WHERE scan_id = s.id) as findings_count,
               (SELECT COUNT(*) FROM findings WHERE scan_id = s.id AND severity = 'Critical') as critical_count
        FROM scans s
        JOIN targets t ON s.target_id = t.id
        ORDER BY s.id DESC
    """)
    scans = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify({"scans": scans})

@app.route("/api/scan/<int:scan_id>", methods=["GET"])
def get_scan(scan_id):
    """Fetch complete details, findings, and logs for a scan."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT s.*, t.domain, t.target_type, t.in_scope_paths, t.out_of_scope_paths,
               t.verification_method, t.verified_at
        FROM scans s
        JOIN targets t ON s.target_id = t.id
        WHERE s.id = ?
    """, (scan_id,))
    scan_row = cursor.fetchone()
    if not scan_row:
        conn.close()
        return jsonify({"error": "Scan not found"}), 404

    scan = dict(scan_row)

    cursor.execute("SELECT * FROM findings WHERE scan_id = ? ORDER BY cvss_score DESC", (scan_id,))
    findings = [dict(f) for f in cursor.fetchall()]

    cursor.execute("SELECT * FROM scan_logs WHERE scan_id = ? ORDER BY id ASC", (scan_id,))
    logs = [dict(l) for l in cursor.fetchall()]

    conn.close()
    scan["findings"] = findings
    scan["logs"] = logs
    return jsonify({"scan": scan})

@app.route("/api/scan/<int:scan_id>/status", methods=["GET"])
def get_scan_status(scan_id):
    """Fast polling endpoint for live scan progress, latest logs, and findings."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, status, progress, current_module, risk_score, pages_crawled, duration_seconds FROM scans WHERE id = ?", (scan_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "Scan not found"}), 404

    res = dict(row)

    # Fetch latest 20 logs
    cursor.execute("SELECT level, message, timestamp FROM scan_logs WHERE scan_id = ? ORDER BY id DESC LIMIT 20", (scan_id,))
    res["logs"] = [dict(l) for l in reversed(cursor.fetchall())]

    # Fetch findings count and list
    cursor.execute("SELECT id, title, severity, cvss_score, affected_url, parameter, owasp_category FROM findings WHERE scan_id = ? ORDER BY id DESC", (scan_id,))
    res["findings"] = [dict(f) for f in cursor.fetchall()]
    res["findings_count"] = len(res["findings"])

    conn.close()
    return jsonify(res)

@app.route("/api/scan/<int:scan_id>/stop", methods=["POST"])
def stop_scan_route(scan_id):
    """Stop an active scan."""
    stopped = stop_scan(scan_id)
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE scans SET status = 'stopped', current_module = 'Manually Stopped' WHERE id = ? AND status = 'running'", (scan_id,))
    conn.commit()
    conn.close()
    return jsonify({"message": f"Scan #{scan_id} stop signal delivered."})

@app.route("/api/scan/<int:scan_id>", methods=["DELETE"])
def delete_scan(scan_id):
    """Delete a scan record and its findings."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    conn.commit()
    conn.close()
    return jsonify({"message": f"Scan #{scan_id} deleted."})

# -------------------------------------------------------------
# AI Explainer API
# -------------------------------------------------------------
@app.route("/api/explain", methods=["POST"])
def explain_finding_route():
    """Generate an in-depth AI vulnerability explanation with remediation guidance."""
    data = request.get_json() or {}
    finding_id = data.get("finding_id")

    title = data.get("title", "")
    severity = data.get("severity", "Medium")
    affected_url = data.get("affected_url", "")
    parameter = data.get("parameter", "")
    evidence = data.get("evidence", "")
    owasp_category = data.get("owasp_category", "")

    if finding_id:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM findings WHERE id = ?", (finding_id,))
        f = cursor.fetchone()
        conn.close()
        if f:
            title = f["title"]
            severity = f["severity"]
            affected_url = f["affected_url"]
            parameter = f["parameter"]
            evidence = f["evidence"]
            owasp_category = f["owasp_category"]

    explanation = explain_finding(
        title=title,
        severity=severity,
        affected_url=affected_url,
        parameter=parameter,
        evidence=evidence,
        owasp_category=owasp_category
    )

    if finding_id:
        # Cache explanation in DB
        c = get_db_connection()
        cur = c.cursor()
        cur.execute("UPDATE findings SET ai_explanation = ? WHERE id = ?", (explanation, finding_id))
        c.commit()
        c.close()

    return jsonify({"explanation": explanation})

# -------------------------------------------------------------
# Reports API
# -------------------------------------------------------------
@app.route("/api/scan/<int:scan_id>/report.pdf", methods=["GET"])
def download_pdf_report(scan_id):
    """Download executive PDF assessment report."""
    pdf_bytes = generate_pdf_report(scan_id)
    if not pdf_bytes:
        return jsonify({"error": "Scan not found or report failed to build."}), 404

    log_audit("REPORT_DOWNLOAD", f"Scan #{scan_id}", "Executive PDF report downloaded.", request.remote_addr)

    return send_file(
        io.BytesIO(pdf_bytes),
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"securescan_audit_report_scan_{scan_id}.pdf"
    )

@app.route("/api/scan/<int:scan_id>/report.json", methods=["GET"])
def download_json_report(scan_id):
    """Download comprehensive JSON assessment export."""
    report_dict = generate_json_report(scan_id)
    if not report_dict:
        return jsonify({"error": "Scan not found."}), 404

    log_audit("REPORT_DOWNLOAD", f"Scan #{scan_id}", "JSON report exported.", request.remote_addr)

    return jsonify(report_dict)

# -------------------------------------------------------------
# Dashboard Statistics API
# -------------------------------------------------------------
@app.route("/api/stats", methods=["GET"])
def get_dashboard_stats():
    """Aggregate statistics for dashboard metrics and charts."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # 1. Total Scans
    cursor.execute("SELECT COUNT(*) as cnt FROM scans")
    total_scans = cursor.fetchone()["cnt"]

    # 2. Total Vulnerabilities
    cursor.execute("SELECT COUNT(*) as cnt FROM findings")
    total_vulns = cursor.fetchone()["cnt"]

    # 3. Critical Issues
    cursor.execute("SELECT COUNT(*) as cnt FROM findings WHERE severity = 'Critical'")
    critical_issues = cursor.fetchone()["cnt"]

    # 4. Average Risk Score
    cursor.execute("SELECT AVG(risk_score) as avg_score FROM scans WHERE status = 'completed'")
    avg_score_row = cursor.fetchone()
    avg_risk_score = round(avg_score_row["avg_score"] or 0.0, 1)

    # 5. Severity Distribution
    cursor.execute("""
        SELECT severity, COUNT(*) as cnt 
        FROM findings 
        GROUP BY severity
    """)
    sev_map = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for r in cursor.fetchall():
        if r["severity"] in sev_map:
            sev_map[r["severity"]] = r["cnt"]

    # 6. OWASP Categories Distribution
    cursor.execute("""
        SELECT owasp_category, COUNT(*) as cnt 
        FROM findings 
        WHERE owasp_category IS NOT NULL AND owasp_category != ''
        GROUP BY owasp_category 
        ORDER BY cnt DESC 
        LIMIT 6
    """)
    owasp_labels = []
    owasp_counts = []
    for r in cursor.fetchall():
        # Shorten label for clean chart presentation
        cat_short = r["owasp_category"].split("-")[-1] if "-" in r["owasp_category"] else r["owasp_category"]
        owasp_labels.append(cat_short[:22])
        owasp_counts.append(r["cnt"])

    # 7. Vulnerabilities Over Time (Recent 7 completed scans)
    cursor.execute("""
        SELECT s.id, s.target_url, s.completed_at, COUNT(f.id) as finding_count
        FROM scans s
        LEFT JOIN findings f ON s.id = f.scan_id
        WHERE s.status = 'completed'
        GROUP BY s.id
        ORDER BY s.id ASC
        LIMIT 7
    """)
    timeline_labels = []
    timeline_counts = []
    for r in cursor.fetchall():
        timeline_labels.append(f"Scan #{r['id']}")
        timeline_counts.append(r["finding_count"])

    # 8. Recent Scans
    cursor.execute("""
        SELECT s.*, t.domain,
               (SELECT COUNT(*) FROM findings WHERE scan_id = s.id) as findings_count
        FROM scans s
        JOIN targets t ON s.target_id = t.id
        ORDER BY s.id DESC
        LIMIT 5
    """)
    recent_scans = [dict(r) for r in cursor.fetchall()]

    conn.close()

    return jsonify({
        "total_scans": total_scans,
        "total_vulnerabilities": total_vulns,
        "critical_issues": critical_issues,
        "avg_risk_score": avg_risk_score,
        "severity_distribution": sev_map,
        "owasp_distribution": {
            "labels": owasp_labels,
            "counts": owasp_counts
        },
        "timeline": {
            "labels": timeline_labels,
            "counts": timeline_counts
        },
        "recent_scans": recent_scans
    })

# -------------------------------------------------------------
# Compliance & Audit Logs API
# -------------------------------------------------------------
@app.route("/api/audit-logs", methods=["GET"])
def get_audit_logs():
    """Retrieve filtered audit trail of system operations."""
    action_filter = request.args.get("action", "")
    domain_filter = request.args.get("domain", "")

    query = "SELECT * FROM audit_logs WHERE 1=1"
    params = []

    if action_filter:
        query += " AND action LIKE ?"
        params.append(f"%{action_filter}%")
    if domain_filter:
        query += " AND target_domain LIKE ?"
        params.append(f"%{domain_filter}%")

    query += " ORDER BY id DESC LIMIT 200"

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(query, params)
    logs = [dict(r) for r in cursor.fetchall()]
    conn.close()

    return jsonify({"logs": logs})

@app.route("/api/audit-logs.csv", methods=["GET"])
def export_audit_logs_csv():
    """Export compliance audit logs as CSV."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, action, target_domain, details, ip_address, user_identifier, status, created_at FROM audit_logs ORDER BY id DESC")
    rows = cursor.fetchall()
    conn.close()

    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(["ID", "Action", "Target Domain", "Details", "IP Address", "User", "Status", "Timestamp"])
    for r in rows:
        cw.writerow(list(r))

    output = si.getvalue()
    log_audit("AUDIT_EXPORT_CSV", "", "Exported compliance audit logs in CSV format.", request.remote_addr)

    return Response(
        output,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment;filename=securescan_audit_trail_{utcnow().strftime('%Y%m%d')}.csv"}
    )

# -------------------------------------------------------------
# Settings API
# -------------------------------------------------------------
@app.route("/api/settings", methods=["GET", "POST"])
def settings_api():
    """Manage global settings and emergency kill switch."""
    if request.method == "POST":
        data = request.get_json() or {}
        if "kill_switch" in data:
            Config.GLOBAL_KILL_SWITCH = bool(data["kill_switch"])
            action_desc = "ACTIVATED" if Config.GLOBAL_KILL_SWITCH else "DEACTIVATED"
            log_audit("KILL_SWITCH_TOGGLE", "", f"Emergency kill switch was {action_desc}.", request.remote_addr)
        if "contact_email" in data:
            Config.CONTACT_EMAIL = data["contact_email"]
            Config.USER_AGENT = f"SecureScanAI/1.0 (authorized security scan; contact: {Config.CONTACT_EMAIL})"
        if "openai_api_key" in data:
            Config.OPENAI_API_KEY = data["openai_api_key"]

        return jsonify({"message": "Settings updated successfully."})

    return jsonify({
        "contact_email": Config.CONTACT_EMAIL,
        "user_agent": Config.USER_AGENT,
        "openai_configured": bool(Config.OPENAI_API_KEY),
        "kill_switch": Config.GLOBAL_KILL_SWITCH,
        "preapproved_targets": Config.PREAPPROVED_LAB_TARGETS
    })

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5001))
    print(f"[*] SecureScan AI starting on http://localhost:{port} (http://127.0.0.1:{port})")
    app.run(host="0.0.0.0", port=port, debug=False)
