import os
from config import Config
from database.db import init_db
from database.seed_data import seed_demo_data

def run_migrations():
    """Ensure database schema is up-to-date and seed initial demo data."""
    print("=" * 60)
    print("SecureScan AI — Database Schema Migration & Initialization")
    print("=" * 60)
    
    os.makedirs(os.path.dirname(Config.DB_PATH), exist_ok=True)
    os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)
    
    print(f"[*] Initializing database at: {Config.DB_PATH}")
    init_db()
    print("[+] Database tables verified/created successfully.")
    
    print("[*] Seeding demo data (pre-approved targets, pending authorizations, sample scan)...")
    seed_demo_data()
    print("[+] Demo data loaded successfully.")
    print("=" * 60)

if __name__ == "__main__":
    run_migrations()
