from flask import Flask, render_template, request, redirect, url_for, make_response, g, send_file, abort
import os
import json
import re
import time
import bcrypt
import secrets
import io
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
    }

    for file_path, default_data in files_with_defaults.items():
        if not os.path.exists(file_path):
            with open(file_path, "w", encoding="utf-8") as file:
                json.dump(default_data, file, indent=4)


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


def create_session(username):
    sessions = load_json(app.config["SESSIONS_FILE"], {})
    token = secrets.token_urlsafe(32)

    sessions[token] = {
        "username": username,
        "created_at": time.time(),
        "last_activity": time.time()
    }

    save_json(app.config["SESSIONS_FILE"], sessions)
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
        return None

    session_data["last_activity"] = current_time
    sessions[token] = session_data
    save_json(app.config["SESSIONS_FILE"], sessions)

    return session_data


def destroy_session(token):
    sessions = load_json(app.config["SESSIONS_FILE"], {})
    if token in sessions:
        del sessions[token]
        save_json(app.config["SESSIONS_FILE"], sessions)


ensure_directories()
ensure_json_files()
load_or_create_encryption_key()


@app.before_request
def load_logged_in_user():
    g.user = None
    token = request.cookies.get("session_token")

    if token:
        session_data = validate_session(token)
        if session_data:
            g.user = session_data["username"]


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
        elif not validate_email(email):
            message = "Please enter a valid email address."
        elif not validate_password(password):
            message = "Password must be at least 12 characters and include uppercase, lowercase, number, and special character."
        elif password != confirm_password:
            message = "Passwords do not match."
        elif username in users:
            message = "That username is already taken."
        elif any(user["email"] == email for user in users.values()):
            message = "That email is already registered."
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
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        users = load_json(app.config["USERS_FILE"], {})

        if username not in users:
            message = "Invalid username or password."
        else:
            user = users[username]
            current_time = time.time()

            if user["locked_until"] is not None and current_time < user["locked_until"]:
                remaining_seconds = int(user["locked_until"] - current_time)
                message = f"Account is locked. Try again in {remaining_seconds} seconds."
            else:
                stored_hash = user["password_hash"].encode("utf-8")

                if bcrypt.checkpw(password.encode("utf-8"), stored_hash):
                    user["failed_attempts"] = 0
                    user["locked_until"] = None
                    users[username] = user
                    save_json(app.config["USERS_FILE"], users)

                    token = create_session(username)

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
                    else:
                        remaining_attempts = 5 - user["failed_attempts"]
                        message = f"Invalid username or password. {remaining_attempts} attempt(s) remaining before lockout."

                    users[username] = user
                    save_json(app.config["USERS_FILE"], users)

    return render_template(
        "login.html",
        message=message,
        username=username
    )


@app.route("/dashboard")
def dashboard():
    if not g.user:
        return redirect(url_for("login"))

    users = load_json(app.config["USERS_FILE"], {})
    documents = load_json(app.config["DOCUMENTS_FILE"], {})
    user_documents = [doc for doc in documents.values() if doc["owner"] == g.user]

    user_data = users.get(g.user)

    return render_template(
        "dashboard.html",
        current_user=g.user,
        user_data=user_data,
        documents=user_documents
    )


@app.route("/upload", methods=["GET", "POST"])
def upload():
    if not g.user:
        return redirect(url_for("login"))

    message = ""

    if request.method == "POST":
        if "document" not in request.files:
            message = "No file part found."
            return render_template("upload.html", message=message)

        file = request.files["document"]

        if file.filename == "":
            message = "Please choose a file."
            return render_template("upload.html", message=message)

        if not allowed_file(file.filename):
            message = "File type not allowed. Only txt, pdf, and docx are allowed."
            return render_template("upload.html", message=message)

        original_filename = secure_filename(file.filename)
        document_id = secrets.token_hex(8)
        stored_filename = f"{document_id}.enc"
        file_path = os.path.join(app.config["UPLOAD_DIR"], stored_filename)

        file_bytes = file.read()
        cipher = get_cipher()
        encrypted_data = cipher.encrypt(file_bytes)

        with open(file_path, "wb") as encrypted_file:
            encrypted_file.write(encrypted_data)

        documents = load_json(app.config["DOCUMENTS_FILE"], {})
        documents[document_id] = {
            "document_id": document_id,
            "owner": g.user,
            "original_filename": original_filename,
            "stored_filename": stored_filename,
            "uploaded_at": time.time(),
            "version": 1,
            "shared_with": {}
        }

        save_json(app.config["DOCUMENTS_FILE"], documents)
        message = "File uploaded and encrypted successfully."

    return render_template("upload.html", message=message)


@app.route("/download/<document_id>")
def download(document_id):
    if not g.user:
        return redirect(url_for("login"))

    documents = load_json(app.config["DOCUMENTS_FILE"], {})

    if document_id not in documents:
        abort(404)

    document = documents[document_id]

    if document["owner"] != g.user:
        abort(403)

    file_path = os.path.join(app.config["UPLOAD_DIR"], document["stored_filename"])

    if not os.path.exists(file_path):
        abort(404)

    with open(file_path, "rb") as encrypted_file:
        encrypted_data = encrypted_file.read()

    cipher = get_cipher()
    decrypted_data = cipher.decrypt(encrypted_data)

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

    response = make_response(redirect(url_for("home")))
    response.set_cookie("session_token", "", expires=0)
    return response


if __name__ == "__main__":
    app.run(debug=True)