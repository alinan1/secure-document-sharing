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
from functools import wraps

app = Flask(__name__)
app.config.from_object(Config)

def is_admin(username):
    users = load_json(app.config["USERS_FILE"], {})
    user = users.get(username)
    return user is not None and user.get("role") == "admin"

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not g.user:
            log_security_event(
                "ACCESS_DENIED",
                details={"resource": request.path, "reason": "not_logged_in"},
                severity="WARNING"
            )
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

def require_role(role):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            users = load_json(app.config["USERS_FILE"], {})
            user = users.get(g.user, {})

            if user.get("role") != role:
                log_security_event(
                    "ACCESS_DENIED",
                    username=g.user,
                    details={"resource": request.path, "reason": f"requires_role:{role}"},
                    severity="WARNING"
                )
                abort(403)
            return f(*args, **kwargs)
        return decorated
    return decorator

# creates folders and files if they don't exist
def ensure_directories():
    folders = [
        app.config["TEMPLATE_DIR"],
        app.config["STATIC_DIR"],
        app.config["DATA_DIR"],
        app.config["LOG_DIR"],
        app.config["UPLOAD_DIR"],
    ]
    # The function iterates through each folder path in the folders list and creates the directory if it doesn't already exist using os.makedirs with exist_ok=True to avoid errors if the directory already exists.
    for folder in folders:
        os.makedirs(folder, exist_ok=True)

# creates json files if they don't exist.
# files_defaults that maps file paths to their default data structures (empty dicts or lists). 
# The function iterates through each file path and default data pair, checks if the file exists, 
# If not, creates it and writes the default data to it in JSON 
def ensure_json_files():
    files_defaults = {
        app.config["USERS_FILE"]: {},
        app.config["SESSIONS_FILE"]: {},
        app.config["DOCUMENTS_FILE"]: {},
        app.config["SHARES_FILE"]: {},
        app.config["AUDIT_FILE"]: [],
        os.path.join(app.config["DATA_DIR"], "login_attempts.json"): {}
    }

    for filepath, defaultdata in files_defaults.items():
        if not os.path.exists(filepath):
            with open(filepath, "w", encoding="utf-8") as file:
                json.dump(defaultdata, file, indent=4)

# This function sets up two loggers: one for security-related events and another for access-related events.
def setup_loggers():
    sec_logger = logging.getLogger("security") #This line creates a logger named "security" using the logging module. This logger will be used to log security-related events in the application.
    access_logger = logging.getLogger("access") #This line creates another logger named "access" which will be used to log access-related events, such as user logins and page visits.

   #sec logger -> logs security events (logins, attacks, etc) to security.log
    if not sec_logger.handlers:
        sec_logger.setLevel(logging.INFO)   #INFO means normal events like successful logins, WARNING is for suspicious activities like failed logins, and ERROR is for critical issues like account lockouts. Each log entry includes a timestamp, the severity level, and a message describing the event.
        sec_handler = logging.FileHandler(os.path.join(app.config["LOG_DIR"], "security.log")) # This line creates a file handler that writes log messages to a file named "security.log" located in the directory specified by app.config["LOG_DIR"]. This handler will be responsible for writing security-related log entries to the file.
        sec_formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s") # defines how logs look like. It includes the timestamp of the log entry, the severity level (INFO, WARNING, ERROR), and the log message itself.
        sec_handler.setFormatter(sec_formatter) #set format for the handler
        sec_logger.addHandler(sec_handler) #connects logger to file

    #access logger -> logs access events (page visits, requests etc) to access.log
    if not access_logger.handlers:
        access_logger.setLevel(logging.INFO)
        access_handler = logging.FileHandler(os.path.join(app.config["LOG_DIR"], "access.log"))
        access_formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
        access_handler.setFormatter(access_formatter)
        access_logger.addHandler(access_handler)

    return sec_logger, access_logger

# This function is responsible for logging security-related events in the application.
def log_security_event(event_type, username=None, document_id=None, details=None, severity="INFO"):
    entry = {
        "timestamp": time.time(),
        "event_type": event_type,
        "username": username,
        "document_id": document_id,
        "ip_address": request.remote_addr if request else None,
        "user_agent": request.headers.get("User-Agent") if request else None,
        "details": details or {}  # if no additional details use empty dict
    }

    message = json.dumps(entry) # The json.dumps function is used to convert the entry dictionary into a JSON-formatted string, which can then be easily logged to the security log file in a structured format.
    
    # event logged as whatever severity level it is
    if severity == "WARNING":
        security_logger.warning(message)
    elif severity == "ERROR":
        security_logger.error(message)
    else:
        security_logger.info(message)

# logs access related events
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

# This function is a utility function for READING JSON data from a file safely
# It takes two parameters: file_path, which is the path to the JSON file & default_data, which is the data to return if the file does not exist or error decoding the JSON.
def load_json(file_path, default_data):
    if not os.path.exists(file_path):
        return default_data
    with open(file_path, "r", encoding="utf-8") as file:
        try:
            return json.load(file)
        except json.JSONDecodeError:
            return default_data

# safely WRITES data to a JSON file safely
def save_json(file_path, data):
    with open(file_path, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=4)

# This function makes sure username is 3-20 characters long and only contains letters, numbers, and underscores
def validate_username(username):
    if len(username) > 20:  # length check
        return False
    return re.fullmatch(r"^[A-Za-z0-9_]{3,20}$", username) is not None # is not None means function returns true if username matches regex pattern false otherwise

# makes sure email is in a valid format (basic check for presence of @ and .)
def validate_email(email):
    if len(email) > 254: # lenght check
        return False
    return re.fullmatch(r"^[^@]+@[^@]+\.[^@]+$", email) is not None

# makes sure password is at least 12 characters long and includes uppercase, lowercase, special character, and number
def validate_password(password):
    if len(password) > 128: # length check
        return False
    length = len(password) >= 12
    uppercase = re.search(r"[A-Z]", password) 
    lowercase = re.search(r"[a-z]", password) 
    special = re.search(r"[@$!%*?&]", password) 
    number = re.search(r"\d", password)
    return all([length, uppercase, lowercase, special, number])

# This function checks if the uploaded file has an allowed extension (txt, pdf, docx)
# first checking if the filename contains a period (.) to separate the name from the extension.
def allowed_file(filename):
    if "." not in filename:
        return False
    extension = filename.rsplit(".", 1)[1].lower()
    return extension in app.config["ALLOWED_EXTENSIONS"]

# magic bytes are specific byte sequences at the beginning of a file that indicate its format.
MAGIC_BYTES = {
    "pdf": [(0, b"%PDF")],
    "docx": [(0, b"PK\x03\x04")],
    "txt": []
}
# This function checks the MIME type of the uploaded file by reading its initial bytes and comparing them to known magic byte signatures for allowed file types.
def allowed_mime(file_stream, filename):
    if "." not in filename:
        return False

    sig = MAGIC_BYTES.get(filename.rsplit(".", 1)[1].lower()) # signature is
    if sig is None or len(sig) == 0:
        return True

    header = file_stream.read(16)
    file_stream.seek(0)
    for offset, magic in sig:
        if header[offset:offset + len(magic)] == magic:
            return True
    return False

#loads encryption key from file if it exists, otherwise creates a new key and saves it to file. 
# This key is used for encrypting and decrypting uploaded documents 
def create_encryption_key():
    key_file = os.path.join(app.config["DATA_DIR"], "secret.key") #get path to key file in data directory

    if os.path.exists(key_file):
        with open(key_file, "rb") as file:
            return file.read()
        
    #if doesnt exist generate new key using Fernet.generate_key() which creates a secure random key suitable for encryption and decryption.
    # The generated key is then saved to the specified file in binary mode for future use.
    key = Fernet.generate_key()
    with open(key_file, "wb") as file: #secrets.key file
        file.write(key)

    return key

# This function creates and returns a Fernet cipher object using the encryption key loaded or created by the load_or_create_encryption_key function.
def get_cipher():
    key = create_encryption_key()
    return Fernet(key)

# records EVERY login attempts from a given IP address along with their timestamps. 
# used for future refrence when checking for rate limits 
def num_login_attempt(ip_address):
    attempts_file = os.path.join(app.config["DATA_DIR"], "login_attempts.json")
    attempts = load_json(attempts_file, {})
    current_time = time.time()

    #if ip not in attempt dict set empty list for said ip addr
    if ip_address not in attempts:
        attempts[ip_address] = []
    # add current timestamp to list of attempts for that IP address, 
    # then filter out any attempts that are older than the defined time window (60 seconds) 
    # Then ave the updated attempts back to the JSON file for future reference when checking for rate limits.
    attempts[ip_address].append(current_time)
    attempts[ip_address] = [
        timestamp for timestamp in attempts[ip_address]
        if current_time - timestamp < 60
    ]

    save_json(attempts_file, attempts)

#This function checks if the number of login attempts from a given IP address exceeds a defined threshold (10 attempts) within a specified time window (60 seconds).
#redundant 60 second check ensures data is consistently cleaned up and that the rate limit is based on the most recent login attempts within the defined time window.
def rate_limit(ip_address):
    attempts_file = os.path.join(app.config["DATA_DIR"], "login_attempts.json")
    attempts = load_json(attempts_file, {})
    current_time = time.time()
    window = 60
    max_attempts = 10 #required 10 attempts within 60 seconds to trigger rate limit

    if ip_address not in attempts: #if ip_address not in attempts dict
        attempts[ip_address] = [] #initialize new entry for that IP address with empty list

    # create list of recent in order to filter
    recent_attempts = []  # hold timestamp of recent (60 seconds) login attempts from that IP address
    for timestamp in attempts[ip_address]:
        if current_time - timestamp < window: #check if current time minus the time the attempt was made (timestamp) is less than the defined window (60 seconds)
            recent_attempts.append(timestamp) 

    attempts[ip_address] = recent_attempts #update the attempts dict with only the recent attempts for that IP address
    save_json(attempts_file, attempts)  #save to json

    return len(recent_attempts) >= max_attempts # count # of attempts in recent_attempts list and check if it exceeds the defined max_attempts (10). If it does, return True to indicate that the IP address is rate limited; otherwise, return False.

# logs user in
def create_session(username):
    sessions = load_json(app.config["SESSIONS_FILE"], {}) # loads existing sessions from the JSON file. If the file doesn't exist or is empty, it initializes an empty dictionary to hold session data.
    token = secrets.token_urlsafe(32) # gen random unique token to be used as session identifier and is 32 bytes long, which provides a high level of entropy to prevent session hijacking or guessing attacks. The token is URL-safe, meaning it can be safely included in URLs without encoding issues.

    #defines a new session entry in the sessions dictionary using the generated token as the key. 
    # The session data includes the username of the logged-in user, the timestamp when the session was created, and the timestamp of the last activity (initially set to the creation time).
    sessions[token] = {
        "username": username,
        "created_at": time.time(),
        "last_activity": time.time()
    }

    save_json(app.config["SESSIONS_FILE"], sessions)
    log_security_event("SESSION_CREATED", username=username, details={"token_created": True})
    return token # sends token to browser as a cookie to maintain the user's logged-in state across requests. 

#checks if user is still logged in and if session is still valid. 
def validate_session(token):
    sessions = load_json(app.config["SESSIONS_FILE"], {})

    #if token not found then session is invalid and return none (user not logged in)
    if token not in sessions:
        return None

    session_data = sessions[token]
    current_time = time.time()
    timeout = 1800

    # if time since last activity is greater them session timeout (30 minutes), then session is expired.
    # Remove session from sessions dict, save updated sessions to JSON file, 
    # log security event for session expiration
    # return None bc session is no longer valid.
    if current_time - session_data["last_activity"] > timeout:
        del sessions[token]
        save_json(app.config["SESSIONS_FILE"], sessions)
        log_security_event("SESSION_EXPIRED", username=session_data["username"])
        return None
    
    # IF session is VALID then update last activity timestamp to current time, 
    # save updated sessions to JSON file, 
    # and return session data for use in the application (e.g., to identify the logged-in user).
    session_data["last_activity"] = current_time
    sessions[token] = session_data 
    save_json(app.config["SESSIONS_FILE"], sessions)

    return session_data

# This function is responsible for destroying a user session, effectively logging the user out.
def destroy_session(token):
    sessions = load_json(app.config["SESSIONS_FILE"], {})
    # if token exists retrieve username associated with session for logging purposes
    # Then remove the session entry from the sessions dictionary, 
    # save the updated sessions back to the JSON file,
    # Log a security event indicating that the session has been destroyed.
    if token in sessions:
        username = sessions[token]["username"]
        del sessions[token]
        save_json(app.config["SESSIONS_FILE"], sessions)
        log_security_event("SESSION_DESTROYED", username=username)

# logs actions related to documents (uploading, sharing, downloading, etc) for auditing purposes.
def log_audit_event(username, action, document_id=None, details=None):
    # load audit entries
    # append new entry with timestamp, username, action performed, document ID (if applicable), and any additional details provided.
    audit_log = load_json(app.config["AUDIT_FILE"], [])
    audit_log.append({
        "timestamp": time.time(),
        "username": username,
        "action": action,
        "document_id": document_id,
        "details": details or {}
    })
    save_json(app.config["AUDIT_FILE"], audit_log)

# returns audit events for a specific document by filtering the audit log based on the provided document ID.
def get_document_audit_events(document_id):
    audit_log = load_json(app.config["AUDIT_FILE"], [])
    return [event for event in audit_log if event.get("document_id") == document_id]

#returns list of documents owned by a specific user by filtering the documents data based on the owner field matching the provided username.
def get_user_owned_documents(username):
    documents = load_json(app.config["DOCUMENTS_FILE"], {})
    return [doc for doc in documents.values() if doc["owner"] == username]

# returns the role of a user for a specific document by first checking if the user is the owner of the document. If the user is the owner, it returns "owner".
# If not, it checks the shared_with field of the document to see if the user's username is listed and retrieves the associated permission level
def get_user_document_role(document, username):
    if document["owner"] == username:
        return "owner"

    shared_with = document.get("shared_with", {})
    return shared_with.get(username)

# returns list of docs shared with specific user
# iterates through all documents and checks if the provided username is listed in the shared_with field of each document. 
# If the user is found in the shared_with list and is not the owner of the document, it adds that document to the shared_docs list, which is then returned.
def get_user_shared_documents(username):
    documents = load_json(app.config["DOCUMENTS_FILE"], {})
    shared_docs = []

    for doc in documents.values():
        shared_with = doc.get("shared_with", {})
        if username in shared_with and doc["owner"] != username:
            shared_docs.append(doc)

    return shared_docs

# checks if a user has access to a specific document by first checking if the user is the owner of the document
# If the user is not the owner, it then checks if the user's username is listed in the shared_with field of the document indicating the doc was shared with that user. 
# If either condition is true, the function returns True --> indicating that the user has access to the document otherwise, it returns False.
def can_user_access_document(document, username):
    if is_admin(username):
        return True

    if document["owner"] == username:
        return True

    shared_with = document.get("shared_with", {})
    return username in shared_with

#checks if uder as edit permission 
# first checks if the user is the owner of the document, if so returns True. 
# If not, it checks the shared_with field of the document to see if the user's username is listed and retrieves the associated permission level.
def can_user_edit_document(document, username):
    if is_admin(username):
        return True

    role = get_user_document_role(document, username)
    return role in ["owner", "editor"]


#--------------- FLASK APP LOGIC ----------------

ensure_directories() #creates necessary directories for templates, static files, data storage, logs, and uploads if they don't already exist. This ensures that the application has the required folder structure to operate correctly.
ensure_json_files() # creates necessary JSON files with default data if they don't already exist (user info, sessions, documents, shares, audit logs, login attempts).
create_encryption_key() # create encryption key for encrypting docs, consisten key
security_logger, access_logger = setup_loggers() # sets up loggers for security and access events, configuring them to write to separate log files with appropriate formatting and severity levels.

#enforce HTTPS by redirecting HTTP requests to HTTPS in production environments. 
# checks if the application is not in debug mode (indicating it's running in production) and if the incoming request is not secure (i.e., using HTTP instead of HTTPS).
@app.before_request
def require_https():
    if not request.is_secure and not app.debug:
        #if not request.issecure and app.env != "development":
        url = request.url.replace("http://", "https://", 1)
        log_security_event("HTTP_TO_HTTPS_REDIRECT", details={"original_url": request.url})
        return redirect(url, code=301)

# Run before every request
@app.before_request
def load_logged_in_user():
    g.user = None
    token = request.cookies.get("session_token") #get session token from cookie sent by browser to identify the user's session and determine if they are logged in.

    # if token is true validate session using validate_session function.
    # If session is valid:...
    # set g.user to the username associated with the session. 
    if token:
        session_data = validate_session(token)
        if session_data:
            g.user = session_data["username"]

# Run after every request to apply security headers and log access events.
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

# --------SSET UP HOMEPAGE--------S
@app.route("/")
def home():
    return render_template("home.html", current_user=g.user) # pass user info to template

# --------SSET UP REGISTRATION PAGE--------S
@app.route("/register", methods=["GET", "POST"])
#variables to hold form data and messages to be displayed to user. 
# These variables are initialized to empty strings or False at the beginning of the function and will be updated based on the form submission and validation results.
def register():
    msg = "" 
    username = ""
    email = ""
    success = False #used in HTML

    # get input from post request and validate it. 
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        users = load_json(app.config["USERS_FILE"], {})

    # validate input and provide specific error messages for different validation failures.
        if not validate_username(username):
            msg = "Username must be 3-20 characters and only contain letters, numbers, and underscores."
            log_security_event("REGISTER_FAILED", username=username, details={"reason": "invalid_username"}, severity="WARNING")
        elif not validate_email(email):
            msg = "Please enter valid email address."
            log_security_event("REGISTER_FAILED", username=username, details={"reason": "invalid_email"}, severity="WARNING")
        elif not validate_password(password):
            msg = "Password must be at least 12 characters and include uppercase, lowercase, special character, and number"
            log_security_event("REGISTER_FAILED", username=username, details={"reason": "weak_password"}, severity="WARNING")
        elif password != confirm_password:
            msg = "Passwords do not match."
            log_security_event("REGISTER_FAILED", username=username, details={"reason": "password_mismatch"}, severity="WARNING")
        elif username in users:
            msg = "Username is already taken."
            log_security_event("REGISTER_FAILED", username=username, details={"reason": "duplicate_username"}, severity="WARNING")
        elif any(user["email"] == email for user in users.values()):
            msg = "Email is already registered."
            log_security_event("REGISTER_FAILED", username=username, details={"reason": "duplicate_email"}, severity="WARNING")
        else:
            #else --> if all validation checks pass, hash the password using bcrypt with a strong work factor (12 rounds) to protect
            salt = bcrypt.gensalt(rounds=12)
            
            hashed_password = bcrypt.hashpw(password.encode("utf-8"), salt)

            #create new user entry in users dict
            users[username] = {
                "username": username,
                "email": email,
                "password_hash": hashed_password.decode("utf-8"),
                "created_at": time.time(),
                "role": "user",
                "failed_attempts": 0,
                "locked_until": None
            }

            # save iser to json file
            save_json(app.config["USERS_FILE"], users)
            success = True
            msg = "Registration successful."
            log_security_event("REGISTER_SUCCESS", username=username) # log as succesful

    return render_template(
        "register.html",
        message=msg,
        success=success, #used in HTML page
        username=username,
        email=email
    )
# --------SET UP LOGIN PAGE--------
@app.route("/login", methods=["GET", "POST"])
def login():
    message = ""
    username = ""

    # if the request method is POST, it means the user has submitted the login form. 
    # The function then retrieves the user's IP address and calls num_login_attempt to record the login attempt for that IP address.
    if request.method == "POST":
        ip_address = request.remote_addr
        num_login_attempt(ip_address)

        #check if login attempts exceed limit
        if rate_limit(ip_address):
            log_security_event("RATE_LIMIT_TRIGGERED", details={"ip_address": ip_address}, severity="WARNING")
            return render_template("login.html", message="Too many attempted LOGINS from this IP. Wait a minute and try again.", username=username)

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        users = load_json(app.config["USERS_FILE"], {})

        #using not in first provides cleaner code to reaf
        # check if username does not exists in dictionary --> log in fail
        if username not in users:
            message = "Invalid username or password."
            log_security_event("LOGIN_FAILED", username=username, details={"reason": "unknown_user"}, severity="WARNING")
        else:
        # if it exists retrieve user data and check if account is locked by comparing current time to locked_until timestamp.
        # If account is locked, calculate remaining lockout time and display message to user. 
        # Log security event for blocked login attempt bc of locked account
            user = users[username]
            current_time = time.time()
            locked_until = user.get("locked_until")

            if locked_until and current_time < locked_until:
                remaining_seconds = int(locked_until - current_time)
                message = f"Account is locked. Try again in {remaining_seconds} seconds."
                log_security_event("LOGIN_BLOCKED_LOCKED_ACCOUNT", username=username, severity="WARNING")
            else:
                # IF ACCOUNT NOT LOCKED:
                stored_hash = user["password_hash"].encode("utf-8") # get stored pass hash and encode it to bytes for bcrypt check

                # IF PASSWORD MATCHES STORED HASH...
                if bcrypt.checkpw(password.encode("utf-8"), stored_hash):
                    user["failed_attempts"] = 0
                    users[username] = user
                    save_json(app.config["USERS_FILE"], users)
                    locked_until = None #locked_until = None

                    #log the user in by creating a session --> generating a session token using the create_session function.
                    token = create_session(username)
                    log_audit_event(username, "LOGIN_SUCCESS", details={"ip": request.remote_addr})
                    log_security_event("LOGIN_SUCCESS", username=username)

                    # Create a response object and set the session cookie
                    res = make_response(redirect(url_for("dashboard")))
                    res.set_cookie(
                        "session_token",
                        token,
                        httponly=True,
                        samesite="Strict",
                        secure=not app.debug, #THIS ENSURES COOKIE IS ONLY SENT OVER HTTPS IN PRODUCTION ENVIRONMENTS, BUT ALLOWS IT IN DEBUG MODE FOR LOCAL TESTING
                        max_age=1800
                    )
                    return res # logs user in and redirects to dashboard page
                else:
                    #IF PASSWORDS DONT MATCH...
                    user["failed_attempts"] += 1 # increment failed attmpt everytime 

                    #check if failed attempt pash threshold
                    if user["failed_attempts"] >= 5:
                        user["locked_until"] = current_time + 900
                        message = "You have 5 failed attempts therefore account locked for 15 minutes."

                        log_audit_event(username, "ACCOUNT_LOCKED", details={"reason": "5 failed attempts"})
                        log_security_event("ACCOUNT_LOCKED", username=username, severity="ERROR")
                    else:
                        #if user hasnt reach thresh continue to decrement
                        remaining_attempts = 5 - user["failed_attempts"]
                        message = f"Invalid username or password. {remaining_attempts} attempt(s) remaining before lockout."
                    
                    #update user info
                    users[username] = user
                    save_json(app.config["USERS_FILE"], users)

                    log_audit_event(username, "LOGIN_FAILED", details={"ip": request.remote_addr})
                    log_security_event("LOGIN_FAILED", username=username, details={"failed_attempts": user["failed_attempts"]}, severity="WARNING")

    return render_template(
        "login.html",
        message=message,
        username=username
    )

# --------SET UP DASHBOARD PAGE--------S
@app.route("/dashboard")
@require_auth
def dashboard():
    # load user data
    users = load_json(app.config["USERS_FILE"], {})
    data = users.get(g.user)
    # return dashboard template with user data, owned documents, and shared documents for the loggedin user
    return render_template(
        "dashboard.html",
        current_user=g.user,
        user_data=data,
        owned_documents=get_user_owned_documents(g.user),
        shared_documents=get_user_shared_documents(g.user)
    )

# --------SET UP UPLOAD PAGE--------
@app.route("/upload", methods=["GET", "POST"])
@require_auth
def upload():
    
    message = ""
    # if user submits upload form, validate file and save it to server if valid.
    if request.method == "POST":
        if "document" not in request.files:
            message = "No file found."
            log_security_event("UPLOAD_FAILED", username=g.user, details={"reason": "no_file_part"}, severity="WARNING")
            return render_template("upload.html", message=message)

        file = request.files["document"] # get uploaded file from form data

        #check if file was uploaded with a filename. 
        # If filename is empty, it means upload failed
        if file.filename == "":
            message = "Please choose a file."
            log_security_event("UPLOAD_FAILED", username=g.user, details={"reason": "empty_filename"}, severity="WARNING")
            return render_template("upload.html", message=message)
        
        if not allowed_file(file.filename):
            message = "File type not allowed. Only txt, pdf, and docx are allowed."
            log_security_event(
                "UPLOAD_FAILED",
                username=g.user,
                details={"reason": "disallowed_file_type", "filename": file.filename},
                severity="WARNING"
            )
            return render_template("upload.html", message=message)

        #checks if file type is allowed
        if not allowed_mime(file, file.filename):
            message = "File content does not match its extension. Upload rejected."
            log_security_event(
                "UPLOAD_FAILED",
                username=g.user,
                details={"reason": "mime_mismatch", "filename": file.filename},
                severity="WARNING"
            )
            return render_template("upload.html", message=message)

        original_filename = secure_filename(file.filename) # remove dangerous characters from filename--> prevents dict traversal attacks and other security issues related to file handling.
        id = secrets.token_hex(8) # gen random id for document
        stored_filename = f"{id}_v1.enc" # save file with .enc extension to indicate it's encrypted and include version number for future versioning support ---> prevent filename collisions and makes it easier to manage document versions.
        file_path = os.path.join(app.config["UPLOAD_DIR"], stored_filename)

        #read file, encrypt then save 
        encrypted_data = get_cipher().encrypt(file.read())
        with open(file_path, "wb") as encrypted_file:
            encrypted_file.write(encrypted_data)
        
        #save all info about document to json file including owner, original filename, stored filename, upload timestamp, version number, and shared_with list 
        upload = time.time()
        documents = load_json(app.config["DOCUMENTS_FILE"], {})
        documents[id] = {
            "document_id": id,
            "owner": g.user,
            "original_filename": original_filename,
            "stored_filename": stored_filename,
            "uploaded_at": upload,
            "version": 1,
            "shared_with": {},
            "versions": [
                {
                    "version_number": 1,
                    "stored_filename": stored_filename,
                    "uploaded_at": upload,
                    "uploaded_by": g.user,
                    "original_filename": original_filename
                }
            ]
        }
        #save to json and log
        save_json(app.config["DOCUMENTS_FILE"], documents)

        log_audit_event(g.user, "UPLOAD_DOCUMENT", document_id=id, details={"filename": original_filename, "version": 1})
        log_security_event("UPLOAD_SUCCESS", username=g.user, document_id=id, details={"filename": original_filename})
        message = "File uploaded and encrypted successfully."

    return render_template("upload.html", message=message)


#--------SET UP SHARING PAGE--------
@app.route("/share/<document_id>", methods=["GET", "POST"])
@require_auth
def share(document_id):
    
    # load data
    documents = load_json(app.config["DOCUMENTS_FILE"], {})
    users = load_json(app.config["USERS_FILE"], {})
    #check doc exists
    if document_id not in documents:
        abort(404)

    # check if user or admin and if not then denied
    doc = documents[document_id]
    if doc["owner"] != g.user and not is_admin(g.user): 
        log_security_event(
        "ACCESS_DENIED",
        username=g.user,
        document_id=document_id,
        details={"resource": "share", "reason": "not_owner_or_admin"},
        severity="WARNING"
        )
        abort(403)

    #if submits share form then process input and update document sharing settings if valid.
    message = ""
    if request.method == "POST":
        target_username = request.form.get("target_username", "").strip()
        permission = request.form.get("permission", "").strip().lower()

        if target_username == "":
            message = "Enter a username."
        elif target_username not in users:
            message = "User does not exist."
        elif target_username == g.user:
            message = "You cant share a document with yourself."
        elif permission not in ["viewer", "editor"]:
            message = "Invalid permission selected."
        else:
            # if all validation checks pass, update the shared_with field of the document to include the target username and their assigned permission level (viewer or editor).
            doc["shared_with"][target_username] = permission
            documents[document_id] = doc
            save_json(app.config["DOCUMENTS_FILE"], documents)

            log_audit_event(g.user, "SHARE_DOCUMENT", document_id=document_id, details={"shared_with": target_username, "permission": permission})
            log_security_event("SHARE_SUCCESS", username=g.user, document_id=document_id, details={"shared_with": target_username, "permission": permission})
            message = f"Document shared with {target_username} as {permission}."

    return render_template(
        "share.html",
        current_user=g.user,
        document=doc,
        message=message
    )


##--------SET UP NEW VERSION UPLOAD PAGE--------
@app.route("/newversion/<document_id>", methods=["GET", "POST"])
@require_auth
def new_version(document_id):
    
    # load documents and check if document exists
    documents = load_json(app.config["DOCUMENTS_FILE"], {})
    if document_id not in documents:
        abort(404)

    doc = documents[document_id]
    #check if has edit permissions
    if not can_user_edit_document(doc, g.user):
        log_security_event(
            "ACCESS_DENIED",
            username=g.user,
            document_id=document_id,
            details={"resource": "new_version", "reason": "insufficient_permission"},
            severity="WARNING"
        )
        abort(403)

    message = ""
    if request.method == "POST":
        if "document" not in request.files:
            return render_template("newversion.html", document=doc, message="No file part found.")

        file = request.files["document"]
        if file.filename == "":
            return render_template("newversion.html", document=doc, message="Choose a file.")

        if not allowed_file(file.filename):
            
            return render_template("newversion.html", document=doc, message="File type not allowed. Only txt, pdf, and docx are allowed.")

        if not allowed_mime(file, file.filename):
            log_security_event(
                "UPLOAD_FAILED",
                username=g.user,
                document_id=document_id,
                details={"reason": "mime_mismatch", "filename": file.filename},
                severity="WARNING"
            )
            return render_template("newversion.html", document=doc, message="File content does not match its extension. Upload rejected.")

        og_filename = secure_filename(file.filename)
        newversion_number = doc["version"] + 1
        stored_filename = f"{document_id}_v{newversion_number}.enc"
        file_path = os.path.join(app.config["UPLOAD_DIR"], stored_filename)

        file_bytes = file.read()
        encrypted_data = get_cipher().encrypt(file_bytes)

        with open(file_path, "wb") as encrypted_file:
            encrypted_file.write(encrypted_data)

        if "versions" not in doc:
            doc["versions"] = []

        upload = time.time()
        doc["version"] = newversion_number
        doc["stored_filename"] = stored_filename
        doc["original_filename"] = og_filename
        doc["uploaded_at"] = upload

        doc["versions"].append({
            "version_number": newversion_number,
            "stored_filename": stored_filename,
            "uploaded_at": upload,
            "uploaded_by": g.user,
            "original_filename": og_filename
        })

        documents[document_id] = doc
        save_json(app.config["DOCUMENTS_FILE"], documents)

        log_audit_event(g.user, "UPLOAD_NEW_VERSION", document_id=document_id,details={"version": newversion_number, "filename": og_filename})
        log_security_event("NEW_VERSION_UPLOADED",username=g.user, document_id=document_id, details={"version": newversion_number, "filename": og_filename})

        message = f"Version {newversion_number} uploaded successfully."

    return render_template("newversion.html", document=doc, message=message)

# --------SET UP AUDIT LOG --------
@app.route("/audit/<document_id>")
@require_auth
def audit(document_id):
    
    #load documents and check if document exists
    documents = load_json(app.config["DOCUMENTS_FILE"], {})
    if document_id not in documents:
        abort(404)

    document = documents[document_id] # get document info for specified document ID

    # check if user has access to document
    if not can_user_access_document(document, g.user):
        log_security_event("ACCESS_DENIED", username=g.user, document_id=document_id, details={"resource": "audit", "reason": "insufficient_permission"}, severity="WARNING")
        abort(403)

    events = get_document_audit_events(document_id) # get audit events for said doc ID
    #render audit template HTML 
    return render_template(
        "audit.html",
        document=document,
        events=events,
        current_user=g.user
    )

#--------SET UP DOWNLOAD --------
@app.route("/download/<document_id>")
@require_auth
def download(document_id):
    
    #load documents
    documents = load_json(app.config["DOCUMENTS_FILE"], {})
    if document_id not in documents: #check document exists
        abort(404)

    document = documents[document_id] #get specific document data (document_id)

    #check access permissions for user. 
    if not can_user_access_document(document, g.user):
        log_security_event("ACCESS_DENIED", username=g.user, document_id=document_id, details={"resource": "download", "reason": "insufficient_permission"}, severity="WARNING")
        abort(403)

    #get file path n check if exists 
    file_path = os.path.join(app.config["UPLOAD_DIR"], document["stored_filename"])
    if not os.path.exists(file_path):
        abort(404)
    #read encrypyed file
    with open(file_path, "rb") as encrypted_file:
        read_encrypted_data = encrypted_file.read()

    #decrypt the file
    decrypted_data = get_cipher().decrypt(read_encrypted_data)

    #LOG events
    log_audit_event(g.user, "DOWNLOAD_DOCUMENT", document_id=document_id, details={"filename": document["original_filename"], "version": document["version"]})
    log_security_event("DOWNLOAD_SUCCESS", username=g.user, document_id=document_id, details={"filename": document["original_filename"], "version": document["version"]})

    # send decrypted file to user
    # attachment --> forces browser to download file instead of trying to open it.
    # download_name --> specifies the original filename that will be suggested to the user when they download the file, rather than the stored filename on the server. T
    # ***better user experience by providing a familiar filename instead of encrypted /versioned name
    return send_file(
        io.BytesIO(decrypted_data),
        as_attachment=True,
        download_name=document["original_filename"]
    )
#---- DELETE OPTION ---------
@app.route("/delete/<document_id>", methods=["POST"])
@require_auth
def delete_document(document_id):
    documents = load_json(app.config["DOCUMENTS_FILE"], {})
    if document_id not in documents:
        abort(404)

    document = documents[document_id]

    if document["owner"] != g.user and not is_admin(g.user):
        log_security_event(
            "ACCESS_DENIED",
            username=g.user,
            document_id=document_id,
            details={"resource": "delete", "reason": "not_owner_or_admin"},
            severity="WARNING"
        )
        abort(403)

    file_path = os.path.join(app.config["UPLOAD_DIR"], document["stored_filename"])
    if os.path.exists(file_path):
        os.remove(file_path)

    del documents[document_id]
    save_json(app.config["DOCUMENTS_FILE"], documents)

    log_audit_event(g.user, "DELETE_DOCUMENT", document_id=document_id, details={"filename": document["original_filename"]})
    log_security_event("DELETE_DOCUMENT", username=g.user, document_id=document_id, details={"filename": document["original_filename"]})

    return redirect(url_for("dashboard"))

#----ADMIN ROLES AND DASHBOARD--------
# Route to dashboard
#can see all users and documents
@app.route("/admin")
@require_auth
@require_role("admin")
def admin_dashboard():
    users = load_json(app.config["USERS_FILE"], {})
    documents = load_json(app.config["DOCUMENTS_FILE"], {})
    log_audit_event(g.user, "ADMIN_DASH_ACCESS")
    return render_template("admin.html", current_user=g.user, users=users, documents=documents)

#-----ADMIN USER PAGE ----------
# Loads all users from json file
# this page is where admin can choose who to lock/unlock from account
@app.route("/admin/manage-users")
@require_auth
@require_role("admin")
def admin_manageusers():
    users = load_json(app.config["USERS_FILE"], {})

    log_audit_event(g.user, "ADMIN_VIEW_MANAGE_USERS")
    return render_template("admin_manageusers.html", current_user=g.user, users=users)

#------ADMIN LOCK USER------
# Used for when LOCK button pressed / route
@app.route("/admin/manage-users/<username>/lock", methods=["POST"])
@require_auth
@require_role("admin")
# load all users and check if matches username
def admin_lock_user(username):
    users = load_json(app.config["USERS_FILE"], {})
    if username not in users:
        abort(404)
    # if it is <username> then lock account for 15 min
    users[username]["locked_until"] = time.time() + 900
    #save updayed user info
    save_json(app.config["USERS_FILE"], users)

    log_audit_event(g.user, "ADMIN_LOCK_USER", details={"target": username})
    log_security_event("ADMIN_LOCK_USER", username=g.user, details={"target": username}, severity="WARNING")
    return redirect(url_for("admin_manageusers"))

#----ADMINN UNLOCK------
#Used for when unlocked buton press
@app.route("/admin/manage-users/<username>/unlock", methods=["POST"])
@require_auth
@require_role("admin")
def admin_unlock_user(username):
    users = load_json(app.config["USERS_FILE"], {})
    if username not in users:
        abort(404)

    # similair to lock for unlock set locked until to none and failed attempts to 0 so user can log in again.
    users[username]["locked_until"] = None
    users[username]["failed_attempts"] = 0
    save_json(app.config["USERS_FILE"], users)

    log_audit_event(g.user, "ADMIN_UNLOCK_USER", details={"target": username})
    log_security_event("ADMIN_UNLOCK_USER", username=g.user, details={"target": username})
    return redirect(url_for("admin_manageusers"))

#--------ADMIN RESET PASSWORD--------
@app.route("/admin/manage-users/<username>/resetpassword", methods=["POST"])
@require_auth
@require_role("admin")
def admin_reset_password(username):
    allusers = load_json(app.config["USERS_FILE"], {})
    #check if user exists
    if username not in allusers:
        abort(404)

    #new password is name of input field 
    #.get retrieves from html form
    #strip is just so no whitespace
    newpassword = request.form.get("newpassword", "").strip()

    #kis password empy then bad req
    if not newpassword:
        abort(400)

    #otherwise hash passwors and store ...
    # hash the new password same way done before
    salt = bcrypt.gensalt(rounds=12)
    hashed_password = bcrypt.hashpw(newpassword.encode("utf-8"), salt)

    allusers[username]["password_hash"] = hashed_password.decode("utf-8") #store newpassowrd, decode turns bytes into string for json file
    allusers[username]["failed_attempts"] = 0 #resets login attempts --> so user isnt locked out anymore after reset
    allusers[username]["locked_until"] = None #unlocks account by removing time limit

    save_json(app.config["USERS_FILE"],allusers) #save updated user

    log_audit_event(g.user, "ADMIN_RESET_PASSWORD", details={"target": username})
    log_security_event("ADMIN_RESET_PASSWORD", username=g.user, details={"target": username})

    return redirect(url_for("admin_users"))

#-------- VIEW FOR GUEST USERS--------
# THIS IS FOR GUEST USERS TO VIEW DOCUMENTS THAT HAVE BEEN SHARED WITH THE "GUEST" USERNAME WITHOUT REQUIRING LOGIN.
@app.route("/view/<document_id>")
def public_view(document_id):
    #load all doc n check if doc id exists
    documents = load_json(app.config["DOCUMENTS_FILE"], {})
    if document_id not in documents:
        abort(404)

    document = documents[document_id]

    #if logged in user is asccesing and already has permission then load that doc and render view page
    if g.user and can_user_access_document(document, g.user):
        events = get_document_audit_events(document_id)
        return render_template("view.html", document=document, events=events, current_user=g.user)

    #if "guest" is in the share with dictionary log event and render to the view page since guests are ONLY able to VIEW
    shared_with = document.get("shared_with", {})
    if "guest" in shared_with:
        log_security_event("GUEST_VIEW", document_id=document_id, details={"ip": request.remote_addr})
        return render_template("view.html", document=document, events=[], current_user=None)

    log_security_event( "ACCESS_DENIED", username=g.user, document_id=document_id, details={"resource": "public_view", "reason": "not_shared_with_guest"}, severity="WARNING"
    )
    abort(403)

#--------SET UP LOGOUT --------
@app.route("/logout")
def logout():
    # get session token from cookie to identify which session to destroy
    token = request.cookies.get("session_token")

    #if token exists, call destroy_session function to remove session from server and log audit and security events for logout action.
    if token:
        destroy_session(token)
        log_audit_event(g.user if g.user else "unknown", "LOGOUT")
        log_security_event("LOGOUT", username=g.user if g.user else "unknown")

    # redirect user to homepage after logout
    # AND clear cookie removing logged in state from browser
    response = make_response(redirect(url_for("home")))
    response.set_cookie("session_token", "", expires=0)
    return response 

if __name__ == "__main__":
    app.run(
        debug=True,
        ssl_context=("cert.pem", "key.pem"),
        host="0.0.0.0",
        port=5001
    )

    #debug true - allow http for development
    #debug flase-force https for real users n apps online
    # self-signed certificate was generated using OpenSSL to enable HTTPS locally
    # self assigned will give error bc certificate was not issued by a trusted public certificate authority
    # This allows the application to support TLS encryption for secure communication during development