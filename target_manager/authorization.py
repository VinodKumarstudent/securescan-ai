import os
import secrets
import uuid
from datetime import datetime
from werkzeug.utils import secure_filename
from config import Config
from database.db import get_db_connection, log_audit, utcnow_str

def is_allowed_file(filename):
    """Check if the uploaded authorization proof has an allowed extension."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in Config.ALLOWED_EXTENSIONS

def save_proof_file(file_storage):
    """Save authorization proof file safely with randomized UUID filename."""
    if not file_storage or not file_storage.filename:
        return None, None
        
    ext = file_storage.filename.rsplit('.', 1)[1].lower() if '.' in file_storage.filename else ''
    if ext not in Config.ALLOWED_EXTENSIONS:
        raise ValueError(f"Invalid file extension '.{ext}'. Allowed: {', '.join(Config.ALLOWED_EXTENSIONS)}")

    os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)
    random_filename = f"auth_proof_{uuid.uuid4().hex[:16]}.{ext}"
    dest_path = os.path.join(Config.UPLOAD_FOLDER, random_filename)
    
    file_storage.save(dest_path)
    return random_filename, file_storage.filename

def generate_approval_token():
    """Generate a high-entropy URL-safe approval token."""
    return secrets.token_urlsafe(32)

def create_written_authorization(target_id, data, file_storage=None, ip_address="127.0.0.1"):
    """
    Store written authorization record and generate verification link.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM targets WHERE id = ?", (target_id,))
    target = cursor.fetchone()
    if not target:
        conn.close()
        raise ValueError("Target not found.")

    proof_filename, proof_orig = None, None
    if file_storage:
        proof_filename, proof_orig = save_proof_file(file_storage)

    approval_token = generate_approval_token()
    
    cursor.execute("""
        INSERT INTO authorizations (
            target_id, authorizer_name, authorizer_designation, authorizer_org,
            authorizer_email, authorizer_phone, testing_window_start, testing_window_end,
            allowed_intensity, max_requests_per_sec, proof_filename, proof_original_name,
            decl_written_permission, decl_legal_responsibility, decl_no_exploitation,
            approval_token
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        target_id,
        data.get("authorizer_name", "").strip(),
        data.get("authorizer_designation", "").strip(),
        data.get("authorizer_org", "").strip(),
        data.get("authorizer_email", "").strip(),
        data.get("authorizer_phone", "").strip(),
        data.get("testing_window_start"),
        data.get("testing_window_end"),
        data.get("allowed_intensity", "Standard"),
        int(data.get("max_requests_per_sec", 5)),
        proof_filename,
        proof_orig,
        1 if data.get("decl_written_permission") else 0,
        1 if data.get("decl_legal_responsibility") else 0,
        1 if data.get("decl_no_exploitation") else 0,
        approval_token
    ))

    # Update target record with authorization parameters
    cursor.execute("""
        UPDATE targets SET 
            in_scope_paths = ?,
            out_of_scope_paths = ?,
            allowed_intensity = ?,
            max_requests_per_sec = ?,
            expires_at = ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
    """, (
        data.get("in_scope_paths", "/*"),
        data.get("out_of_scope_paths", "/admin,/payment,/logout"),
        data.get("allowed_intensity", "Standard"),
        int(data.get("max_requests_per_sec", 5)),
        data.get("testing_window_end"),
        target_id
    ))

    conn.commit()
    conn.close()

    log_audit("AUTHORIZATION_SUBMITTED", target["domain"], 
              f"Submitted for authorizer {data.get('authorizer_name')} ({data.get('authorizer_email')})", 
              ip_address)

    return approval_token

def approve_authorization_by_token(token, ip_address="127.0.0.1"):
    """
    Called when an authorizer clicks the verification approval link or when manually approved.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT a.*, t.domain, t.id as tid 
        FROM authorizations a 
        JOIN targets t ON a.target_id = t.id 
        WHERE a.approval_token = ?
    """, (token,))
    row = cursor.fetchone()
    
    if not row:
        conn.close()
        return False, "Invalid or expired authorization approval token."

    target_id = row["tid"]
    domain = row["domain"]
    now_str = utcnow_str()

    cursor.execute("UPDATE authorizations SET approved_at = ? WHERE id = ?", (now_str, row["id"]))
    cursor.execute("""
        UPDATE targets 
        SET status = 'approved', verified_at = ?, expires_at = ?
        WHERE id = ?
    """, (now_str, row["testing_window_end"], target_id))

    conn.commit()
    conn.close()

    log_audit("AUTHORIZATION_APPROVED", domain, f"Authorized by {row['authorizer_name']} ({row['authorizer_email']})", ip_address)
    return True, f"Target '{domain}' successfully authorized for penetration testing within window."
