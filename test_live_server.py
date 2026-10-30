import time
import threading
import requests
from app import app
from database.db import get_db_connection, utcnow_str

TEST_PORT = 5055

def run_test_server():
    app.run(host="127.0.0.1", port=TEST_PORT, debug=False, use_reloader=False)

def main():
    print("=" * 60)
    print("Starting Flask Test Server on 127.0.0.1:5055")
    print("=" * 60)

    server_thread = threading.Thread(target=run_test_server, daemon=True)
    server_thread.start()

    # Wait for server to be responsive
    time.sleep(1.5)
    base_url = f"http://127.0.0.1:{TEST_PORT}"
    
    # Check server availability
    try:
        r = requests.get(f"{base_url}/lab/test-page")
        print(f"[+] Local lab page reachable: HTTP {r.status_code}")
    except Exception as e:
        print(f"[!] Server unreachable: {e}")
        return False

    # Ensure 127.0.0.1:5055 target is registered and verified
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        INSERT OR REPLACE INTO targets (domain, target_type, status, verification_method, in_scope_paths, out_of_scope_paths, verified_at)
        VALUES (?, 'lab', 'verified', 'preapproved', '/*', '', ?)
    """, (f"127.0.0.1:{TEST_PORT}", utcnow_str()))
    target_id = cur.lastrowid
    conn.commit()
    conn.close()

    print(f"[+] Registered lab target ID #{target_id} for 127.0.0.1:{TEST_PORT}")

    # Launch scan via API
    scan_resp = requests.post(f"{base_url}/api/scan", json={
        "target_id": target_id,
        "target_url": f"{base_url}/lab/test-page",
        "scan_type": "full",
        "intensity": "Standard",
        "authorized_declaration": True
    })

    print(f"[+] Scan start response: {scan_resp.status_code}")
    scan_data = scan_resp.json()
    scan_id = scan_data["scan_id"]
    print(f"[+] Scan ID #{scan_id} initiated.")

    # Poll status
    for _ in range(20):
        time.sleep(1)
        st = requests.get(f"{base_url}/api/scan/{scan_id}/status").json()
        print(f"    Progress: {st['progress']}% | Module: {st['current_module']} | Status: {st['status']}")
        if st["status"] in ("completed", "stopped", "failed"):
            break

    # Get results
    results = requests.get(f"{base_url}/api/scan/{scan_id}").json()
    findings = results["scan"]["findings"]
    print("=" * 60)
    print(f"[✓] Scan Completed! Identified {len(findings)} findings on local test page:")
    for f in findings:
        print(f"    - [{f['severity']}] {f['title']} (Component: {f['parameter']})")
    print("=" * 60)

    # Test PDF download endpoint
    pdf_resp = requests.get(f"{base_url}/api/scan/{scan_id}/report.pdf")
    assert pdf_resp.status_code == 200
    assert len(pdf_resp.content) > 1000
    print(f"[✓] Downloaded PDF Report ({len(pdf_resp.content)} bytes)")

    # Test JSON download endpoint
    json_resp = requests.get(f"{base_url}/api/scan/{scan_id}/report.json")
    assert json_resp.status_code == 200
    print(f"[✓] Downloaded JSON Report ({len(json_resp.json()['findings'])} findings)")

    assert len(findings) >= 3, "Expected multiple findings from header and vulnerability checks"
    print("\n[🎉] FULL END-TO-END TEST PASSED SUCCESSFULLY!")
    return True

if __name__ == "__main__":
    main()
