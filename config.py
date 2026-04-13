import os
import secrets

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class Config:
    SECRET_KEY = secrets.token_hex(32)

    DATA_DIR = os.path.join(BASE_DIR, "data")
    LOG_DIR = os.path.join(BASE_DIR, "logs")
    UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
    TEMPLATE_DIR = os.path.join(BASE_DIR, "templates")
    STATIC_DIR = os.path.join(BASE_DIR, "static")

    USERS_FILE = os.path.join(DATA_DIR, "users.json")
    SESSIONS_FILE = os.path.join(DATA_DIR, "sessions.json")
    DOCUMENTS_FILE = os.path.join(DATA_DIR, "documents.json")
    SHARES_FILE = os.path.join(DATA_DIR, "shares.json")
    AUDIT_FILE = os.path.join(DATA_DIR, "audit.json")

    MAX_CONTENT_LENGTH = 10 * 1024 * 1024
    ALLOWED_EXTENSIONS = {"txt", "pdf", "docx"}