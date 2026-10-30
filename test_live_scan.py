import time
from app import app
from database.db import get_db_connection

def test_live_scan_run():
    print("=" * 60)
    print("Testing Live Scan Execution against Local Lab Page")
    print("=" * 60)
    
    client = app.test_client()

    # Fetch localhost target ID from seed
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT id FROM targets WHERE domain LIKE '%localhost%' LIMIT 1")
    target_row = cur.fetchone()
    conn.close()

    if not target_row:
        print("[!] No localhost target found. Aborting.")
        return False

    target_id = target_row["id"]
    print(f"[*] Found pre-approved lab target ID: {target_id}")

    # Launch scan
    launch_resp = client.post("/api/scan", json={
        "target_id": target_id,
        "target_url": "http://localhost:5000/lab/test-page",
        "scan_type": "full",
        "intensity": "Standard",
        "authorized_declaration": True
    })

    print(f"[*] Launch response status: {launch_resp.status_code}")
    data = launch_resp.get_json()
    scan_id = data.get("scan_id")
    print(f"[*] Scan ID: {scan_id}")

    # Wait for background thread to execute
    max_wait = 15
    start = time.time()
    status = "running"
    
    while time.time() - start < max_wait:
        st_resp = client.get(f"/api/scan/{scan_id}/status")
        st_data = st_resp.get_json()
        status = st_data.get("status")
        progress = st_data.get("progress")
        current_mod = st_data.get("current_module")
        print(f"[*] Progress: {progress}% | Module: {current_mod} | Status: {status}")
        
        if status in ("completed", "stopped", "failed"):
            break
        time.sleep(1)

    print(f"[+] Final scan status: {status}")

    # Inspect results
    res_resp = client.get(f"/api/scan/{scan_id}")
    res_data = res_resp.get_json()
    findings = res_data["scan"]["findings"]
    print(f"[+] Total findings discovered on /lab/test-page: {len(findings)}")
    for f in findings:
        print(f"    - [{f['severity']}] {f['title']} ({f['parameter']})")

    assert len(findings) > 0, "Expected at least 1 security finding on vulnerable test page"
    print("[✓] Live scan successfully identified expected vulnerabilities on local lab page!")
    return True

if __name__ == "__main__":
    test_live_scan_run()
