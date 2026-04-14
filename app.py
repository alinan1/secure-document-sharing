from flask import Flask, render_template, request, redirect, url_for, make_response, g, send_file, abort
import os
import json
import re
import time
import bcrypt
import secrets
import io
import logging
from cryptography.fernet import Fernet
from werkzeug.utils import secure_filename
from config import Config

app = Flask(__name__)
app.config.from_object(Config)


def ensure_directories():
    folders = [
        app.config["DATA_DIR"],
        app.config["LOG_DIR"],
        app.config["UPLOAD_DIR"],
        app.config["TEMPLATE_DIR"],
        app.config["STATIC_DIR"],
    ]

    for folder in folders:
        os.makedirs(folder, exist_ok=True)


def ensure_json_files():
    files_with_defaults = {
        app.config["USERS_FILE"]: {},
        app.config["SESSIONS_FILE"]: {},
        app.config["DOCUMENTS_FILE"]: {},
        app.config["SHARES_FILE"]: {},
        app.config["AUDIT_FILE"]: [],
        os.path.join(app.config["DATA_DIR"], "login_attempts.json"): {}
    }

    for file_path, default_data in files_with_defaults.items():
        if not os.path.exists(file_path):
            with open(file_path, "w", encoding="utf-8") as file:
                json.dump(default_data, file, indent=4)


def setup_loggers():
    security_logger = logging.getLogger("security")
    access_logger = logging.getLogger("access")

    if not security_logger.handlers:
        security_logger.setLevel(logging.INFO)
        security_handler = logging.FileHandler(os.path.join(app.config["LOG_DIR"], "security.log"))
        security_formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
        security_handler.setFormatter(security_formatter)
        security_logger.addHandler(security_handler)

    if not access_logger.handlers:
        access_logger.setLevel(logging.INFO)
        access_handler = logging.FileHandler(os.path.join(app.config["LOG_DIR"], "access.log"))
        access_formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
        access_handler.setFormatter(access_formatter)
        access_logger.addHandler(access_handler)

    return security_logger, access_logger


def log_security_event(event_type, username=None, document_id=None, details=None, severity="INFO"):
    entry = {
        "timestamp": time.time(),
        "event_type": event_type,
        "username": username,
        "document_id": document_id,
        "ip_address": request.remote_addr if request else None,
        "user_agent": request.headers.get("User-Agent") if request else None,
        "details": details or {}
    }

    message = json.dumps(entry)

    if severity == "WARNING":
        security_logger.warning(message)
    elif severity == "ERROR":
        security_logger.error(message)
    else:
        security_logger.info(message)


def log_access_event():
    entry = {
        "timestamp": time.time(),
        "username": g.user,
        "method": request.method,
        "path": request.path,
        "status": getattr(g, "response_status", None),
        "ip_address": request.remote_addr,
        "user_agent": request.headers.get("User-Agent")
    }
    access_logger.info(json.dumps(entry))


def load_json(file_path, default_data):
    if not os.path.exists(file_path):
        return default_data
    with open(file_path, "r", encoding="utf-8") as file:
        try:
            return json.load(file)
        except json.JSONDecodeError:
            return default_data


def save_json(file_path, data):
    with open(file_path, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=4)


def validate_username(username):
    return re.fullmatch(r"^[A-Za-z0-9_]{3,20}$", username) is not None


def validate_email(email):
    return re.fullmatch(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email) is not None


def validate_password(password):
    if len(password) < 12:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"[0-9]", password):
        return False
    if not re.search(r"[!@#$%^&*]", password):
        return False
    return True


def allowed_file(filename):
    if "." not in filename:
        return False
    extension = filename.rsplit(".", 1)[1].lower()
    return extension in app.config["ALLOWED_EXTENSIONS"]


def get_key_file_path():
    return os.path.join(app.config["DATA_DIR"], "secret.key")


def get_login_attempts_file():
    return os.path.join(app.config["DATA_DIR"], "login_attempts.json")


def load_or_create_encryption_key():
    key_file = get_key_file_path()

    if os.path.exists(key_file):
        with open(key_file, "rb") as file:
            return file.read()

    key = Fernet.generate_key()
    with open(key_file, "wb") as file:
        file.write(key)

    return key


def get_cipher():
    key = load_or_create_encryption_key()
    return Fernet(key)


def is_rate_limited(ip_address):
    attempts_file = get_login_attempts_file()
    attempts = load_json(attempts_file, {})
    current_time = time.time()
    window_seconds = 60
    max_attempts = 10

    if ip_address not in attempts:
        attempts[ip_address] = []

    recent_attempts = [
        timestamp for timestamp in attempts[ip_address]
        if current_time - timestamp < window_seconds
    ]
    attempts[ip_address] = recent_attempts
    save_json(attempts_file, attempts)

    return len(recent_attempts) >= max_attempts


def record_login_attempt(ip_address):
    attempts_file = get_login_attempts_file()
    attempts = load_json(attempts_file, {})
    current_time = time.time()

    if ip_address not in attempts:
        attempts[ip_address] = []

    attempts[ip_address].append(current_time)
    attempts[ip_address] = [
        timestamp for timestamp in attempts[ip_address]
        if current_time - timestamp < 60
    ]

    save_json(attempts_file, attempts)


def create_session(username):
    sessions = load_json(app.config["SESSIONS_FILE"], {})
    token = secrets.token_urlsafe(32)

    sessions[token] = {
        "username": username,
        "created_at": time.time(),
        "last_activity": time.time()
    }

    save_json(app.config["SESSIONS_FILE"], sessions)
    log_security_event("SESSION_CREATED", username=username, details={"token_created": True})
    return token


def validate_session(token):
    sessions = load_json(app.config["SESSIONS_FILE"], {})

    if token not in sessions:
        return None

    session_data = sessions[token]
    current_time = time.time()
    session_timeout = 1800

    if current_time - session_data["last_activity"] > session_timeout:
        del sessions[token]
        save_json(app.config["SESSIONS_FILE"], sessions)
        log_security_event("SESSION_EXPIRED", username=session_data["username"])
        return None

    session_data["last_activity"] = current_time
    sessions[token] = session_data
    save_json(app.config["SESSIONS_FILE"], sessions)

    return session_data


def destroy_session(token):
    sessions = load_json(app.config["SESSIONS_FILE"], {})
    if token in sessions:
        username = sessions[token]["username"]
        del sessions[token]
        save_json(app.config["SESSIONS_FILE"], sessions)
        log_security_event("SESSION_DESTROYED", username=username)


def log_audit_event(username, action, document_id=None, details=None):
    audit_log = load_json(app.config["AUDIT_FILE"], [])
    audit_log.append({
        "timestamp": time.time(),
        "username": username,
        "action": action,
        "document_id": document_id,
        "details": details or {}
    })
    save_json(app.config["AUDIT_FILE"], audit_log)


def get_document_audit_events(document_id):
    audit_log = load_json(app.config["AUDIT_FILE"], [])
    return [event for event in audit_log if event.get("document_id") == document_id]


def get_user_owned_documents(username):
    documents = load_json(app.config["DOCUMENTS_FILE"], {})
    return [doc for doc in documents.values() if doc["owner"] == username]


def get_user_shared_documents(username):
    documents = load_json(app.config["DOCUMENTS_FILE"], {})
    shared_docs = []

    for doc in documents.values():
        shared_with = doc.get("shared_with", {})
        if username in shared_with and doc["owner"] != username:
            shared_docs.append(doc)

    return shared_docs


def can_user_access_document(document, username):
    if document["owner"] == username:
        return True

    shared_with = document.get("shared_with", {})
    return username in shared_with


def get_user_document_role(document, username):
    if document["owner"] == username:
        return "owner"

    shared_with = document.get("shared_with", {})
    return shared_with.get(username)


def can_user_edit_document(document, username):
    role = get_user_document_role(document, username)
    return role in ["owner", "editor"]


ensure_directories()
ensure_json_files()
load_or_create_encryption_key()
security_logger, access_logger = setup_loggers()


@app.before_request
def load_logged_in_user():
    g.user = None
    token = request.cookies.get("session_token")

    if token:
        session_data = validate_session(token)
        if session_data:
            g.user = session_data["username"]


@app.after_request
def apply_security_headers(response):
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "frame-ancestors 'none'"
    )
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

    g.response_status = response.status_code
    log_access_event()

    return response


@app.route("/")
def home():
    return render_template("home.html", current_user=g.user)


@app.route("/register", methods=["GET", "POST"])
def register():
    message = ""
    success = False
    username = ""
    email = ""

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        users = load_json(app.config["USERS_FILE"], {})

        if not validate_username(username):
            message = "Username must be 3-20 characters and only contain letters, numbers, and underscores."
            log_security_event("REGISTER_FAILED", username=username, details={"reason": "invalid_username"}, severity="WARNING")
        elif not validate_email(email):
            message = "Please enter a valid email address."
            log_security_event("REGISTER_FAILED", username=username, details={"reason": "invalid_email"}, severity="WARNING")
        elif not validate_password(password):
            message = "Password must be at least 12 characters and include uppercase, lowercase, number, and special character."
            log_security_event("REGISTER_FAILED", username=username, details={"reason": "weak_password"}, severity="WARNING")
        elif password != confirm_password:
            message = "Passwords do not match."
            log_security_event("REGISTER_FAILED", username=username, details={"reason": "password_mismatch"}, severity="WARNING")
        elif username in users:
            message = "That username is already taken."
            log_security_event("REGISTER_FAILED", username=username, details={"reason": "duplicate_username"}, severity="WARNING")
        elif any(user["email"] == email for user in users.values()):
            message = "That email is already registered."
            log_security_event("REGISTER_FAILED", username=username, details={"reason": "duplicate_email"}, severity="WARNING")
        else:
            hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12))

            users[username] = {
                "username": username,
                "email": email,
                "password_hash": hashed_password.decode("utf-8"),
                "created_at": time.time(),
                "role": "user",
                "failed_attempts": 0,
                "locked_until": None
            }

            save_json(app.config["USERS_FILE"], users)
            message = "Registration successful."
            success = True
            log_security_event("REGISTER_SUCCESS", username=username)

    return render_template(
        "register.html",
        message=message,
        success=success,
        username=username,
        email=email
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    message = ""
    username = ""

    if request.method == "POST":
        ip_address = request.remote_addr
        record_login_attempt(ip_address)

        if is_rate_limited(ip_address):
            message = "Too many login attempts from this IP. Please wait a minute and try again."
            log_security_event("RATE_LIMIT_TRIGGERED", details={"ip_address": ip_address}, severity="WARNING")
            return render_template("login.html", message=message, username=username)

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        users = load_json(app.config["USERS_FILE"], {})

        if username not in users:
            message = "Invalid username or password."
            log_security_event("LOGIN_FAILED", username=username, details={"reason": "unknown_user"}, severity="WARNING")
        else:
            user = users[username]
            current_time = time.time()

            if user["locked_until"] is not None and current_time < user["locked_until"]:
                remaining_seconds = int(user["locked_until"] - current_time)
                message = f"Account is locked. Try again in {remaining_seconds} seconds."
                log_security_event("LOGIN_BLOCKED_LOCKED_ACCOUNT", username=username, severity="WARNING")
            else:
                stored_hash = user["password_hash"].encode("utf-8")

                if bcrypt.checkpw(password.encode("utf-8"), stored_hash):
                    user["failed_attempts"] = 0
                    user["locked_until"] = None
                    users[username] = user
                    save_json(app.config["USERS_FILE"], users)

                    token = create_session(username)
                    log_audit_event(username, "LOGIN_SUCCESS", details={"ip": request.remote_addr})
                    log_security_event("LOGIN_SUCCESS", username=username)

                    response = make_response(redirect(url_for("dashboard")))
                    response.set_cookie(
                        "session_token",
                        token,
                        httponly=True,
                        samesite="Strict",
                        secure=False,
                        max_age=1800
                    )
                    return response
                else:
                    user["failed_attempts"] += 1

                    if user["failed_attempts"] >= 5:
                        user["locked_until"] = current_time + (15 * 60)
                        message = "Account locked for 15 minutes after 5 failed attempts."
                        log_audit_event(username, "ACCOUNT_LOCKED", details={"reason": "5 failed attempts"})
                        log_security_event("ACCOUNT_LOCKED", username=username, severity="ERROR")
                    else:
                        remaining_attempts = 5 - user["failed_attempts"]
                        message = f"Invalid username or password. {remaining_attempts} attempt(s) remaining before lockout."

                    users[username] = user
                    save_json(app.config["USERS_FILE"], users)
                    log_audit_event(username, "LOGIN_FAILED", details={"ip": request.remote_addr})
                    log_security_event("LOGIN_FAILED", username=username, details={"failed_attempts": user["failed_attempts"]}, severity="WARNING")

    return render_template(
        "login.html",
        message=message,
        username=username
    )


@app.route("/dashboard")
def dashboard():
    if not g.user:
        log_security_event("ACCESS_DENIED", details={"resource": "/dashboard", "reason": "not_logged_in"}, severity="WARNING")
        return redirect(url_for("login"))

    users = load_json(app.config["USERS_FILE"], {})
    user_data = users.get(g.user)

    owned_documents = get_user_owned_documents(g.user)
    shared_documents = get_user_shared_documents(g.user)

    return render_template(
        "dashboard.html",
        current_user=g.user,
        user_data=user_data,
        owned_documents=owned_documents,
        shared_documents=shared_documents
    )


@app.route("/upload", methods=["GET", "POST"])
def upload():
    if not g.user:
        log_security_event("ACCESS_DENIED", details={"resource": "/upload", "reason": "not_logged_in"}, severity="WARNING")
        return redirect(url_for("login"))

    message = ""

    if request.method == "POST":
        if "document" not in request.files:
            message = "No file part found."
            log_security_event("UPLOAD_FAILED", username=g.user, details={"reason": "no_file_part"}, severity="WARNING")
            return render_template("upload.html", message=message)

        file = request.files["document"]

        if file.filename == "":
            message = "Please choose a file."
            log_security_event("UPLOAD_FAILED", username=g.user, details={"reason": "empty_filename"}, severity="WARNING")
            return render_template("upload.html", message=message)

        if not allowed_file(file.filename):
            message = "File type not allowed. Only txt, pdf, and docx are allowed."
            log_security_event("UPLOAD_FAILED", username=g.user, details={"reason": "disallowed_file_type", "filename": file.filename}, severity="WARNING")
            return render_template("upload.html", message=message)

        original_filename = secure_filename(file.filename)
        document_id = secrets.token_hex(8)
        stored_filename = f"{document_id}_v1.enc"
        file_path = os.path.join(app.config["UPLOAD_DIR"], stored_filename)

        file_bytes = file.read()
        cipher = get_cipher()
        encrypted_data = cipher.encrypt(file_bytes)

        with open(file_path, "wb") as encrypted_file:
            encrypted_file.write(encrypted_data)

        uploaded_at = time.time()

        documents = load_json(app.config["DOCUMENTS_FILE"], {})
        documents[document_id] = {
            "document_id": document_id,
            "owner": g.user,
            "original_filename": original_filename,
            "stored_filename": stored_filename,
            "uploaded_at": uploaded_at,
            "version": 1,
            "shared_with": {},
            "versions": [
                {
                    "version_number": 1,
                    "stored_filename": stored_filename,
                    "uploaded_at": uploaded_at,
                    "uploaded_by": g.user,
                    "original_filename": original_filename
                }
            ]
        }

        save_json(app.config["DOCUMENTS_FILE"], documents)
        log_audit_event(g.user, "UPLOAD_DOCUMENT", document_id=document_id, details={"filename": original_filename, "version": 1})
        log_security_event("UPLOAD_SUCCESS", username=g.user, document_id=document_id, details={"filename": original_filename})
        message = "File uploaded and encrypted successfully."

    return render_template("upload.html", message=message)


@app.route("/share/<document_id>", methods=["GET", "POST"])
def share(document_id):
    if not g.user:
        log_security_event("ACCESS_DENIED", details={"resource": f"/share/{document_id}", "reason": "not_logged_in"}, severity="WARNING")
        return redirect(url_for("login"))

    documents = load_json(app.config["DOCUMENTS_FILE"], {})
    users = load_json(app.config["USERS_FILE"], {})

    if document_id not in documents:
        abort(404)

    document = documents[document_id]

    if document["owner"] != g.user:
        log_security_event("ACCESS_DENIED", username=g.user, document_id=document_id, details={"resource": "share", "reason": "not_owner"}, severity="WARNING")
        abort(403)

    message = ""

    if request.method == "POST":
        target_username = request.form.get("target_username", "").strip()
        permission = request.form.get("permission", "").strip().lower()

        if target_username == "":
            message = "Please enter a username."
        elif target_username not in users:
            message = "That user does not exist."
        elif target_username == g.user:
            message = "You cannot share a document with yourself."
        elif permission not in ["viewer", "editor"]:
            message = "Invalid permission selected."
        else:
            document["shared_with"][target_username] = permission
            documents[document_id] = document
            save_json(app.config["DOCUMENTS_FILE"], documents)
            log_audit_event(g.user, "SHARE_DOCUMENT", document_id=document_id, details={"shared_with": target_username, "permission": permission})
            log_security_event("SHARE_SUCCESS", username=g.user, document_id=document_id, details={"shared_with": target_username, "permission": permission})
            message = f"Document shared with {target_username} as {permission}."

    return render_template(
        "share.html",
        current_user=g.user,
        document=document,
        message=message
    )


@app.route("/new-version/<document_id>", methods=["GET", "POST"])
def new_version(document_id):
    if not g.user:
        log_security_event("ACCESS_DENIED", details={"resource": f"/new-version/{document_id}", "reason": "not_logged_in"}, severity="WARNING")
        return redirect(url_for("login"))

    documents = load_json(app.config["DOCUMENTS_FILE"], {})

    if document_id not in documents:
        abort(404)

    document = documents[document_id]

    if not can_user_edit_document(document, g.user):
        log_security_event("ACCESS_DENIED", username=g.user, document_id=document_id, details={"resource": "new_version", "reason": "insufficient_permission"}, severity="WARNING")
        abort(403)

    message = ""

    if request.method == "POST":
        if "document" not in request.files:
            message = "No file part found."
            return render_template("new_version.html", document=document, message=message)

        file = request.files["document"]

        if file.filename == "":
            message = "Please choose a file."
            return render_template("new_version.html", document=document, message=message)

        if not allowed_file(file.filename):
            message = "File type not allowed. Only txt, pdf, and docx are allowed."
            return render_template("new_version.html", document=document, message=message)

        original_filename = secure_filename(file.filename)
        new_version_number = document["version"] + 1
        stored_filename = f"{document_id}_v{new_version_number}.enc"
        file_path = os.path.join(app.config["UPLOAD_DIR"], stored_filename)

        file_bytes = file.read()
        cipher = get_cipher()
        encrypted_data = cipher.encrypt(file_bytes)

        with open(file_path, "wb") as encrypted_file:
            encrypted_file.write(encrypted_data)

        uploaded_at = time.time()

        document["version"] = new_version_number
        document["stored_filename"] = stored_filename
        document["original_filename"] = original_filename
        document["uploaded_at"] = uploaded_at

        if "versions" not in document:
            document["versions"] = []

        document["versions"].append({
            "version_number": new_version_number,
            "stored_filename": stored_filename,
            "uploaded_at": uploaded_at,
            "uploaded_by": g.user,
            "original_filename": original_filename
        })

        documents[document_id] = document
        save_json(app.config["DOCUMENTS_FILE"], documents)
        log_audit_event(g.user, "UPLOAD_NEW_VERSION", document_id=document_id, details={"version": new_version_number, "filename": original_filename})
        log_security_event("NEW_VERSION_UPLOADED", username=g.user, document_id=document_id, details={"version": new_version_number, "filename": original_filename})

        message = f"Version {new_version_number} uploaded successfully."

    return render_template("new_version.html", document=document, message=message)


@app.route("/audit/<document_id>")
def audit(document_id):
    if not g.user:
        log_security_event("ACCESS_DENIED", details={"resource": f"/audit/{document_id}", "reason": "not_logged_in"}, severity="WARNING")
        return redirect(url_for("login"))

    documents = load_json(app.config["DOCUMENTS_FILE"], {})

    if document_id not in documents:
        abort(404)

    document = documents[document_id]

    if not can_user_access_document(document, g.user):
        log_security_event("ACCESS_DENIED", username=g.user, document_id=document_id, details={"resource": "audit", "reason": "insufficient_permission"}, severity="WARNING")
        abort(403)

    events = get_document_audit_events(document_id)

    return render_template(
        "audit.html",
        document=document,
        events=events,
        current_user=g.user
    )


@app.route("/download/<document_id>")
def download(document_id):
    if not g.user:
        log_security_event("ACCESS_DENIED", details={"resource": f"/download/{document_id}", "reason": "not_logged_in"}, severity="WARNING")
        return redirect(url_for("login"))

    documents = load_json(app.config["DOCUMENTS_FILE"], {})

    if document_id not in documents:
        abort(404)

    document = documents[document_id]

    if not can_user_access_document(document, g.user):
        log_security_event("ACCESS_DENIED", username=g.user, document_id=document_id, details={"resource": "download", "reason": "insufficient_permission"}, severity="WARNING")
        abort(403)

    file_path = os.path.join(app.config["UPLOAD_DIR"], document["stored_filename"])

    if not os.path.exists(file_path):
        abort(404)

    with open(file_path, "rb") as encrypted_file:
        encrypted_data = encrypted_file.read()

    cipher = get_cipher()
    decrypted_data = cipher.decrypt(encrypted_data)

    log_audit_event(g.user, "DOWNLOAD_DOCUMENT", document_id=document_id, details={"filename": document["original_filename"], "version": document["version"]})
    log_security_event("DOWNLOAD_SUCCESS", username=g.user, document_id=document_id, details={"filename": document["original_filename"], "version": document["version"]})

    return send_file(
        io.BytesIO(decrypted_data),
        as_attachment=True,
        download_name=document["original_filename"]
    )


@app.route("/logout")
def logout():
    token = request.cookies.get("session_token")

    if token:
        destroy_session(token)
        log_audit_event(g.user if g.user else "unknown", "LOGOUT")
        log_security_event("LOGOUT", username=g.user if g.user else "unknown")

    response = make_response(redirect(url_for("home")))
    response.set_cookie("session_token", "", expires=0)
    return response


if __name__ == "__main__":
    app.run(debug=True)