"""
Information Security Fall 2025 Lab - Flask Application
-----------------------------------------------------
Short description: Minimal course-branded web app that supports registration
(Name, Andrew ID, Password), login, session-based greeting, and logout.
Includes a landing page and CMU-themed styling.

Routes:
- GET /          : Landing page with welcome message + Login/Register buttons.
- GET/POST /register : Register with name, Andrew ID, and password; on success redirect to /login.
- GET/POST /login    : Login with Andrew ID + password; on success redirect to /dashboard.
- GET /dashboard     : Greets authenticated user: "Hello {Name}, Welcome to Lab 2 of Information Security course."
- GET /logout        : Clear session and return to landing page.
"""
from flask import Flask, request, redirect, render_template, session, url_for, flash, send_file, abort
import sqlite3, os
from werkzeug.utils import secure_filename
# Import the necessary functions from werkzeug.security
from werkzeug.security import generate_password_hash, check_password_hash

from functools import wraps
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import io
import datetime
import hashlib

# --- Role Constants ---
ROLE_BASIC = "basic"
ROLE_USER_ADMIN = "user_admin"
ROLE_DATA_ADMIN = "data_admin"

# --- Policy Dictionary ---
policy = {
    "upload_own_file": ROLE_BASIC,
    "download_own_file": ROLE_BASIC,
    "delete_own_file": ROLE_BASIC,
    "change_password": ROLE_BASIC,
    "create_user": ROLE_USER_ADMIN,
    "delete_user": ROLE_USER_ADMIN,
    "assign_role": ROLE_USER_ADMIN,
    "change_username": ROLE_USER_ADMIN,
    "download_any_file": ROLE_DATA_ADMIN,
    "delete_any_file": ROLE_DATA_ADMIN,
    "read_log_file": ROLE_USER_ADMIN,
}

# --- Configuration ---
DATABASE = "infosec_lab.db"
UPLOAD_FOLDER = "uploads"
ALLOWED_EXTENSIONS = {"txt", "pdf", "png", "jpg", "jpeg", "gif"}
SECRET_KEY = "supersecretkey"
AES_KEY_FILE = "secret_aes.key"

app = Flask(__name__)
app.secret_key = os.environ.get("APP_SECRET_KEY", "change-me-in-production")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(BASE_DIR, "infosec_lab.db")
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


# ---------------- Database Helpers ----------------
def get_db():
    """Open a connection to SQLite with Row access."""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize the database by executing schema.sql (single source of truth)."""
    schema_path = os.path.join(BASE_DIR, "schema.sql")
    with open(schema_path, "r", encoding="utf-8") as f:
        schema_sql = f.read()
    conn = get_db()
    try:
        conn.executescript(schema_sql)
        conn.commit()
    finally:
        conn.close()

# Ensure database is initialized at import time
os.makedirs(BASE_DIR, exist_ok=True)
init_db()

# --- AES Encryption/Decryption Helper Functions ---

def load_key():
    """Loads the AES key from the key file."""
    if not os.path.exists(AES_KEY_FILE):
        # Generate key if it doesn't exist
        key = get_random_bytes(32)
        with open(AES_KEY_FILE, "wb") as f:
            f.write(key)
    with open(AES_KEY_FILE, "rb") as f:
        return f.read()

def encrypt_file(file_data, key):
    """Encrypts file data using AES."""
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(file_data, AES.block_size))
    return cipher.iv + ciphertext

def decrypt_file(encrypted_data, key):
    """Decrypts file data using AES."""
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return decrypted_data

# ---------------- Utility ----------------
def current_user():
    """Return the current logged-in user row or None."""
    uid = session.get("user_id")
    if not uid:
        return None
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
    conn.close()
    return user

def generate_otp_chain(user_id):
    """Generates a chain of OTPs for a user."""
    conn = get_db()
    # Start with a secret seed
    seed = f"user-{user_id}-{os.urandom(16).hex()}".encode('utf-8')
    
    # Generate OTPs for the next 24 hours
    now = datetime.datetime.utcnow()
    for i in range(1440): # 24 hours * 60 minutes
        timestamp = (now + datetime.timedelta(minutes=i)).strftime("%Y%m%d%H%M")
        
        # Create a hash chain
        otp_hash = hashlib.sha256(seed).hexdigest()
        otp_code = str(int(otp_hash, 16))[-6:]
        
        # Insert into the database
        conn.execute(
            "INSERT INTO otp_chain (user_id, timestamp, otp_code) VALUES (?, ?, ?)",
            (user_id, timestamp, otp_code)
        )
        
        # Update the seed for the next iteration
        seed = otp_hash.encode('utf-8')
        
    conn.commit()
    conn.close()

# ---------------- Decorators ----------------
def require_login_and_2fa(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = current_user()
        if not user or not session.get("verified_2fa"):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def require_admin(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = current_user()
        if not user or user['role'] == ROLE_BASIC:
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

# ---------------- Guard Function ----------------
def guard(action, target=None, forbid_self_delete=True):
    user = current_user()
    if not user or not session.get("verified_2fa"):
        return False, "Login and 2FA required."

    required_role = policy.get(action)
    if not required_role:
        return False, "Invalid action."

    user_role = user['role']
    
    # Role hierarchy
    role_hierarchy = {ROLE_BASIC: 1, ROLE_USER_ADMIN: 2, ROLE_DATA_ADMIN: 2}

    if role_hierarchy.get(user_role, 0) < role_hierarchy.get(required_role, 0):
        outcome = "denied"
        if user_role in [ROLE_USER_ADMIN, ROLE_DATA_ADMIN]:
            audit_log(action, target, outcome)
        return False, "Permission denied."

    if action == 'delete_user' and forbid_self_delete and str(user['id']) == str(target):
        outcome = "denied"
        audit_log(action, target, outcome)
        return False, "You cannot delete yourself."

    outcome = "allowed"
    if user_role in [ROLE_USER_ADMIN, ROLE_DATA_ADMIN]:
        audit_log(action, target, outcome)

    return True, "Allowed"

def audit_log(action, target_pretty, outcome):
    user = current_user()
    conn = get_db()
    conn.execute(
        "INSERT INTO audit_logs (actor_id, actor_andrew_id, action, target_pretty, outcome) VALUES (?, ?, ?, ?, ?)",
        (user['id'], user['andrew_id'], action, target_pretty, outcome)
    )
    conn.commit()
    conn.close()

# ---------------- Routes ----------------
@app.route("/")
def index():
    """Landing page with CMU-themed welcome and CTA buttons."""
    if current_user():
        return redirect(url_for('dashboard'))
    return render_template("index.html", title="Information Security Fall 2025 Lab", user=current_user())

@app.route("/register", methods=["GET", "POST"])
def register():
    """Register: capture name, Andrew ID, and password; redirect to login on success."""
    if current_user():
        return redirect(url_for('dashboard'))
        
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        andrew_id = request.form.get("andrew_id", "").strip().lower()
        password = request.form.get("password", "")

        # Basic validation
        if not name or not andrew_id or not password:
            flash("All fields are required.", "error")
            return render_template("register.html", title="Register")

        hashed_password = generate_password_hash(password)

        conn = get_db()
        try:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO users (name, andrew_id, password, role) VALUES (?, ?, ?, ?)",
                (name, andrew_id, hashed_password, ROLE_BASIC)
            )
            user_id = cursor.lastrowid
            conn.commit()
            
            # Generate OTP chain for the new user
            generate_otp_chain(user_id)
            
            flash("Registration successful! Please log in.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("That Andrew ID is already registered.", "error")
            return render_template("register.html", title="Register", name=name, andrew_id=andrew_id)
        finally:
            conn.close()
    return render_template("register.html", title="Register")

@app.route("/login", methods=["GET", "POST"])
def login():
    """Login with Andrew ID and password; redirect to 2FA on success."""
    if current_user():
        return redirect(url_for('dashboard'))

    if request.method == "POST":
        andrew_id = request.form.get("andrew_id", "").strip().lower()
        password = request.form.get("password", "")

        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE andrew_id = ?", (andrew_id,)).fetchone()
        conn.close()

        if user and check_password_hash(user["password"], password):
            session["user_id"] = user["id"]
            session["user_name"] = user["name"]
            session["user_andrew_id"] = user["andrew_id"]
            session["user_role"] = user["role"]
            return redirect(url_for("two_fa"))
        
        flash("Invalid Andrew ID or password.", "error")
    return render_template("login.html", title="Login")

@app.route("/2fa", methods=["GET", "POST"])
def two_fa():
    """2FA verification page."""
    user = current_user()
    if not user:
        return redirect(url_for("login"))

    if request.method == "POST":
        otp_code = request.form.get("otp_code", "").strip()
        now = datetime.datetime.utcnow()
        
        conn = get_db()
        
        # Check OTPs for the current minute and ±2 minutes
        for i in range(-2, 3):
            timestamp = (now + datetime.timedelta(minutes=i)).strftime("%Y%m%d%H%M")
            stored_otp = conn.execute(
                "SELECT * FROM otp_chain WHERE user_id = ? AND timestamp = ?",
                (user["id"], timestamp)
            ).fetchone()
            
            if stored_otp and stored_otp["otp_code"] == otp_code:
                session["verified_2fa"] = True
                conn.close()
                return redirect(url_for("dashboard"))

        conn.close()
        flash("Invalid OTP.", "error")

    return render_template("2fa.html", title="2FA Verification")

@app.route("/show-otp")
def show_otp():
    """Debug route to show the current OTP."""
    user = current_user()
    if not user:
        return redirect(url_for("login"))

    now = datetime.datetime.utcnow()
    timestamp = now.strftime("%Y%m%d%H%M")
    
    conn = get_db()
    otp = conn.execute(
        "SELECT * FROM otp_chain WHERE user_id = ? AND timestamp = ?",
        (user["id"], timestamp)
    ).fetchone()
    conn.close()

    return render_template("show_otp.html", title="Show OTP", otp=otp)

@app.route("/dashboard", methods=["GET", "POST"])
@require_login_and_2fa
def dashboard():
    """Authenticated page greeting the user and handling file uploads."""
    user = current_user()

    if request.method == "POST":
        allowed, message = guard("upload_own_file")
        if not allowed:
            flash(message, "error")
            return redirect(url_for('dashboard'))

        if 'file' not in request.files:
            flash('No file part', 'error')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No selected file', 'error')
            return redirect(request.url)
        if file:
            filename = secure_filename(file.filename)
            file_data = file.read()

            key = load_key()
            encrypted_data = encrypt_file(file_data, key)
            
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            with open(filepath, 'wb') as f:
                f.write(encrypted_data)
            
            conn = get_db()
            conn.execute(
                "INSERT INTO files (filename, uploader_andrew_id) VALUES (?, ?)",
                (filename, user['andrew_id'])
            )
            conn.commit()
            conn.close()
            flash("File successfully uploaded", "success")
            return redirect(url_for('dashboard'))

    conn = get_db()
    files = conn.execute("SELECT * FROM files WHERE uploader_andrew_id = ? ORDER BY upload_timestamp DESC", (user['andrew_id'],)).fetchall()
    conn.close()
    greeting = f"Hello {user['name']}, Welcome to Lab 6 of Information Security course."
    return render_template("dashboard.html", title="Dashboard", greeting=greeting, user=user, files=files)

@app.route('/uploads/<filename>')
@require_login_and_2fa
def download_file(filename):
    user = current_user()
    conn = get_db()
    file = conn.execute("SELECT * FROM files WHERE filename = ?", (filename,)).fetchone()
    conn.close()

    if not file:
        abort(404)

    if file['uploader_andrew_id'] == user['andrew_id']:
        allowed, message = guard("download_own_file", filename)
    else:
        allowed, message = guard("download_any_file", filename)

    if not allowed:
        flash(message, "error")
        return redirect(url_for('dashboard'))

    try:
        key = load_key()
        encrypted_filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        with open(encrypted_filepath, 'rb') as f:
            encrypted_data = f.read()

        decrypted_data = decrypt_file(encrypted_data, key)
        
        return send_file(
            io.BytesIO(decrypted_data),
            as_attachment=True,
            download_name=filename
        )

    except Exception as e:
        flash(f"Error decrypting file: {e}", "error")
        return redirect(url_for('dashboard'))

@app.route('/delete/<int:file_id>')
@require_login_and_2fa
def delete_file(file_id):
    user = current_user()
    conn = get_db()
    file = conn.execute("SELECT * FROM files WHERE id = ?", (file_id,)).fetchone()
    conn.close()

    if not file:
        flash('File not found', 'error')
        return redirect(url_for('dashboard'))

    if file['uploader_andrew_id'] == user['andrew_id']:
        allowed, message = guard("delete_own_file", file['filename'])
    else:
        allowed, message = guard("delete_any_file", file['filename'])
    
    if not allowed:
        flash(message, 'error')
        return redirect(url_for('dashboard'))
        
    os.remove(os.path.join(app.config['UPLOAD_FOLDER'], file['filename']))
    conn = get_db()
    conn.execute("DELETE FROM files WHERE id = ?", (file_id,))
    conn.commit()
    conn.close()
    flash('File deleted successfully', 'success')
    return redirect(url_for('dashboard'))

# ---------------- Admin Routes ----------------
@app.route('/admin/users')
@require_login_and_2fa
@require_admin
def admin_users():
    user = current_user()
    conn = get_db()
    if user['role'] == ROLE_USER_ADMIN:
        users = conn.execute("SELECT * FROM users").fetchall()
        return render_template('admin_users.html', users=users, user=user)
    elif user['role'] == ROLE_DATA_ADMIN:
        files = conn.execute("SELECT * FROM files").fetchall()
        return render_template('admin_users.html', files=files, user=user)
    conn.close()
    return "Invalid admin role", 400
    
@app.route('/admin/create-user', methods=['POST'])
@require_login_and_2fa
@require_admin
def create_user():
    name = request.form.get('name')
    andrew_id = request.form.get('andrew_id')
    password = request.form.get('password')
    role = request.form.get('role')

    allowed, message = guard('create_user', target=andrew_id)
    if not allowed:
        flash(message, 'error')
        return redirect(url_for('admin_users'))
    
    hashed_password = generate_password_hash(password)
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (name, andrew_id, password, role) VALUES (?, ?, ?, ?)",
            (name, andrew_id, hashed_password, role)
        )
        user_id = cursor.lastrowid
        conn.commit()
        generate_otp_chain(user_id)
        flash(f'User {andrew_id} created successfully!', 'success')
    except sqlite3.IntegrityError:
        flash(f'Andrew ID {andrew_id} already exists.', 'error')
    finally:
        conn.close()
    
    return redirect(url_for('admin_users'))

@app.route('/admin/assign-role/<int:user_id>', methods=['POST'])
@require_login_and_2fa
@require_admin
def assign_role(user_id):
    role = request.form.get('role')
    
    conn = get_db()
    target_user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()

    allowed, message = guard('assign_role', target=target_user['andrew_id'])
    if not allowed:
        flash(message, 'error')
        return redirect(url_for('admin_users'))
        
    conn = get_db()
    conn.execute("UPDATE users SET role = ? WHERE id = ?", (role, user_id))
    conn.commit()
    conn.close()
    flash(f"Role for {target_user['andrew_id']} updated to {role}", 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/change-username/<int:user_id>', methods=['POST'])
@require_login_and_2fa
@require_admin
def change_username(user_id):
    new_name = request.form.get('new_name')

    conn = get_db()
    target_user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()

    allowed, message = guard('change_username', target=target_user['andrew_id'])
    if not allowed:
        flash(message, 'error')
        return redirect(url_for('admin_users'))

    conn = get_db()
    conn.execute("UPDATE users SET name = ? WHERE id = ?", (new_name, user_id))
    conn.commit()
    conn.close()
    flash(f"Username for {target_user['andrew_id']} changed to {new_name}", 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/delete-user/<int:user_id>')
@require_login_and_2fa
@require_admin
def delete_user(user_id):
    conn = get_db()
    target_user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()

    allowed, message = guard('delete_user', target=str(target_user['id']))
    if not allowed:
        flash(message, 'error')
        return redirect(url_for('admin_users'))

    conn = get_db()
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()

    flash(f"User {target_user['andrew_id']} has been deleted.", 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/logs')
@require_login_and_2fa
@require_admin
def admin_logs():
    allowed, message = guard('read_log_file')
    if not allowed:
        abort(403, description=message)
        
    conn = get_db()
    logs = conn.execute("SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 200").fetchall()
    conn.close()
    return render_template('admin_logs.html', logs=logs)

@app.route("/logout")
def logout():
    """Clear session and return to the landing page."""
    session.clear()
    return redirect(url_for("index"))

# Entrypoint for local dev
if __name__ == "__main__":
    if not os.path.exists(DB_FILE):
        print("[*] Initializing database...")
        init_db()
    else:
        print("[*] Database already exists, skipping init.")

    app.run(host="0.0.0.0", port=5000, debug=True)