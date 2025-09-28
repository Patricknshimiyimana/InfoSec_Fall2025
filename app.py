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
from flask import Flask, request, redirect, render_template, session, url_for, flash, send_file
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
                "INSERT INTO users (name, andrew_id, password) VALUES (?, ?, ?)",
                (name, andrew_id, hashed_password)
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
def dashboard():
    """Authenticated page greeting the user and handling file uploads."""
    user = current_user()
    if not user or not session.get("verified_2fa"):
        return redirect(url_for("two_fa"))

    if request.method == "POST":
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No selected file')
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
            flash("File successfully uploaded")
            return redirect(url_for('dashboard'))

    conn = get_db()
    files = conn.execute("SELECT * FROM files ORDER BY upload_timestamp DESC").fetchall()
    conn.close()
    greeting = f"Hello {user['name']}, Welcome to Lab 2 of Information Security course."
    return render_template("dashboard.html", title="Dashboard", greeting=greeting, user=user, files=files)

@app.route('/uploads/<filename>')
def download_file(filename):
    user = current_user()
    if not user or not session.get("verified_2fa"):
        return redirect(url_for("two_fa"))

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
        flash(f"Error decrypting file: {e}")
        return redirect(url_for('dashboard'))

@app.route('/delete/<int:file_id>')
def delete_file(file_id):
    user = current_user()
    if not user or not session.get("verified_2fa"):
        return redirect(url_for('two_fa'))

    conn = get_db()
    file = conn.execute("SELECT * FROM files WHERE id = ?", (file_id,)).fetchone()
    if file:
        os.remove(os.path.join(app.config['UPLOAD_FOLDER'], file['filename']))
        conn.execute("DELETE FROM files WHERE id = ?", (file_id,))
        conn.commit()
        flash('File deleted successfully')
    else:
        flash('File not found')
    conn.close()
    return redirect(url_for('dashboard'))

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