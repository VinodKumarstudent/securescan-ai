import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env if present
BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "securescan-ai-super-secret-key-2026")
    
    # Serverless (Vercel) / Cloud environment compatibility
    IS_VERCEL = bool(os.getenv("VERCEL"))
    if IS_VERCEL:
        DB_PATH = os.getenv("DB_PATH", "/tmp/securescan.db")
        UPLOAD_FOLDER = os.getenv("UPLOAD_FOLDER", "/tmp/uploads/authorizations")
    else:
        DB_PATH = os.getenv("DB_PATH", str(BASE_DIR / "database" / "securescan.db"))
        UPLOAD_FOLDER = os.getenv("UPLOAD_FOLDER", str(BASE_DIR / "uploads" / "authorizations"))

    MAX_CONTENT_LENGTH = 5 * 1024 * 1024  # 5 MB max
    ALLOWED_EXTENSIONS = {"pdf", "png", "jpg", "jpeg"}
    
    # Contact email included in scanner User-Agent
    CONTACT_EMAIL = os.getenv("CONTACT_EMAIL", "security-team@securescan.local")
    USER_AGENT = f"SecureScanAI/1.0 (authorized security scan; contact: {CONTACT_EMAIL})"
    
    # OpenAI key (optional; fallback to knowledge base if missing)
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
    
    # Pre-approved educational and lab targets
    PREAPPROVED_LAB_TARGETS = [
        "localhost",
        "127.0.0.1",
        "0.0.0.0",
        "localhost:5000",
        "localhost:5001",
        "127.0.0.1:5000",
        "127.0.0.1:5001",
        "testphp.vulnweb.com",
        "testasp.vulnweb.com",
        "juice-shop.herokuapp.com",
        "dvwa.local"
    ]
    
    # Scanner rate limits and timeouts
    DEFAULT_TIMEOUT = 7  # seconds
    DEFAULT_MAX_REQUESTS_PER_SEC = 5
    TOKEN_EXPIRY_DAYS = 7
    
    # Global Kill Switch (can be toggled at runtime)
    GLOBAL_KILL_SWITCH = False
