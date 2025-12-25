from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import secrets
import string
import hashlib
import base64

app = Flask(__name__)
app.secret_key = "change_this_secret_key"  # later: use env var in production
DB_NAME = "database.db"


def get_db():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            flash("Please login to continue.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


# ---------- Password Generator (unique each time) ----------
def generate_strong_password(phrase: str, email: str) -> str:
    salt = secrets.token_bytes(16)
    key = hashlib.pbkdf2_hmac(
        "sha256",
        (phrase + "|" + email).encode("utf-8"),
        salt,
        120_000
    )
    raw = base64.urlsafe_b64encode(key).decode("utf-8").rstrip("=")

    symbols = "!@#$%^&*_-+?"
    pwd = (
        raw[:10] +
        secrets.choice(string.ascii_uppercase) +
        secrets.choice(string.ascii_lowercase) +
        secrets.choice(string.digits) +
        secrets.choice(symbols)
    )
    pwd_list = list(pwd)
    secrets.SystemRandom().shuffle(pwd_list)
    return "".join(pwd_list)


# ✅ IMPORTANT: Public endpoint (works on Register page too)
@app.route("/generate_password", methods=["POST"])
def generate_password():
    phrase = request.form.get("phrase", "").strip()
    email = request.form.get("email", "").strip().lower()

    if not phrase or not email:
        return jsonify({"error": "Phrase and email are required"}), 400

    return jsonify({"password": generate_strong_password(phrase, email)})


# Optional: separate page (keep or remove)
@app.route("/password-generator")
@login_required
def password_generator_page():
    return render_template("password_generator.html")


@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        # Must match template input names: username/email/password
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not username or not email or not password:
            flash("All fields are required.", "danger")
            return redirect(url_for("register"))

        pw_hash = generate_password_hash(password)

        try:
            conn = get_db()
            conn.execute(
                "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
                (username, email, pw_hash),
            )
            conn.commit()
            conn.close()
            flash("Account created. Please login.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            # email UNIQUE -> same email cannot register twice
            flash("Email already registered. Try logging in.", "danger")
            return redirect(url_for("register"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        conn.close()

        # Generic message (good security practice)
        if not user or not check_password_hash(user["password_hash"], password):
            flash("Invalid email or password.", "danger")
            return redirect(url_for("login"))

        session.clear()
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        flash("Logged in successfully.", "success")
        return redirect(url_for("dashboard"))

    return render_template("login.html")


@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", username=session.get("username"))


@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.", "success")
    return redirect(url_for("login"))


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000, debug=True)
