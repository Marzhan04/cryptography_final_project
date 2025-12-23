import os
import re
import time
import base64
import hmac
import hashlib
import secrets
from io import BytesIO
from file_crypto_module import FileCryptoModule
files = FileCryptoModule()

from flask import Flask, request, render_template, redirect, url_for, session, flash
import bcrypt
import pyotp
import qrcode

app = Flask(__name__)

# ❗Не хардкодим ключ. Для дедлайна можно fallback, но лучше set ENV SECRET_KEY
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", secrets.token_hex(32))

# ----------------------------
# "DB" IN MEMORY (DICT)
# ----------------------------
USERS = {
    # username: {
    #   "pw_hash": b"...",
    #   "totp_secret": "...",
    #   "backup_hashes": [ "...sha256hex...", ... ],
    #   "created_at": int
    # }
}

RATE_LIMIT = {
    # key=username_or_ip : {"count": int, "reset_ts": int}
}

# HMAC secret for session token signing
HMAC_SECRET = os.environ.get("HMAC_SECRET")
if not HMAC_SECRET:
    # для дедлайна ок, но лучше тоже env
    HMAC_SECRET = secrets.token_hex(32)
HMAC_SECRET = HMAC_SECRET.encode()


# ----------------------------
# HELPERS
# ----------------------------
def password_is_strong(pw: str) -> bool:
    # минимум: 8+, 1 uppercase, 1 lowercase, 1 digit
    if len(pw) < 8:
        return False
    if not re.search(r"[a-z]", pw):
        return False
    if not re.search(r"[A-Z]", pw):
        return False
    if not re.search(r"\d", pw):
        return False
    return True


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def make_session_token(username: str) -> str:
    """
    Session token format:
    base64url(username|ts|nonce|hmac)
    where hmac = HMAC-SHA256(secret, username|ts|nonce)
    """
    ts = str(int(time.time()))
    nonce = secrets.token_hex(16)
    msg = f"{username}|{ts}|{nonce}".encode()
    sig = hmac.new(HMAC_SECRET, msg, hashlib.sha256).hexdigest()
    raw = f"{username}|{ts}|{nonce}|{sig}".encode()
    return base64.urlsafe_b64encode(raw).decode()


def verify_session_token(token: str) -> bool:
    try:
        raw = base64.urlsafe_b64decode(token.encode()).decode()
        username, ts, nonce, sig = raw.split("|")
        msg = f"{username}|{ts}|{nonce}".encode()
        expected = hmac.new(HMAC_SECRET, msg, hashlib.sha256).hexdigest()
        # constant-time compare
        return hmac.compare_digest(sig, expected)
    except Exception:
        return False


def rate_limited(key: str, limit: int = 5, window_sec: int = 60) -> bool:
    """
    Simple rate limit: max attempts per window per key (username or IP).
    """
    now = int(time.time())
    rec = RATE_LIMIT.get(key)

    if not rec or now >= rec["reset_ts"]:
        RATE_LIMIT[key] = {"count": 1, "reset_ts": now + window_sec}
        return False

    rec["count"] += 1
    RATE_LIMIT[key] = rec
    return rec["count"] > limit


def generate_backup_codes(n: int = 8):
    # показываем пользователю один раз, а храним хэши
    codes = [secrets.token_hex(4) for _ in range(n)]  # 8 hex chars
    hashes = [sha256_hex(c.encode()) for c in codes]
    return codes, hashes


def consume_backup_code(username: str, code: str) -> bool:
    """
    Check if backup code matches one of stored hashes; if yes, remove it (one-time use).
    """
    user = USERS.get(username)
    if not user:
        return False

    code_hash = sha256_hex(code.encode())
    # constant-time compare across list
    for i, h in enumerate(user["backup_hashes"]):
        if hmac.compare_digest(h, code_hash):
            # remove used code
            user["backup_hashes"].pop(i)
            USERS[username] = user
            return True
    return False


def totp_qr_data_url(username: str, secret: str) -> str:
    """
    Return QR as data URL PNG for embedding in <img src="...">
    """
    issuer = "CryptoVault"
    uri = pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer)

    qr = qrcode.make(uri)
    buf = BytesIO()
    qr.save(buf, format="PNG")
    b64 = base64.b64encode(buf.getvalue()).decode()
    return f"data:image/png;base64,{b64}"


# ----------------------------
# ROUTES (MODULE 1)
# ----------------------------
@app.route("/")
def home():
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            flash("Username and password are required.", "error")
            return redirect(url_for("register"))

        if username in USERS:
            flash("User already exists.", "error")
            return redirect(url_for("register"))

        if not password_is_strong(password):
            flash("Password is weak. Use 8+ chars, upper, lower, digit.", "error")
            return redirect(url_for("register"))

        pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
        totp_secret = pyotp.random_base32()

        backup_codes, backup_hashes = generate_backup_codes(8)

        USERS[username] = {
            "pw_hash": pw_hash,
            "totp_secret": totp_secret,
            "backup_hashes": backup_hashes,
            "created_at": int(time.time()),
        }

        # показываем backup codes один раз (в сессии для страницы)
        session["new_backup_codes"] = backup_codes

        flash("Registered успешно. Настрой TOTP через QR.", "success")
        return redirect(url_for("setup_totp", username=username))

    return render_template("register.html")


@app.route("/setup-totp/<username>")
def setup_totp(username):
    user = USERS.get(username)
    if not user:
        flash("User not found.", "error")
        return redirect(url_for("register"))

    qr_url = totp_qr_data_url(username, user["totp_secret"])
    backup_codes = session.pop("new_backup_codes", None)  # забираем 1 раз

    return render_template("setup_totp.html", username=username, qr_url=qr_url, backup_codes=backup_codes)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        totp_code = request.form.get("totp", "").strip()
        backup_code = request.form.get("backup", "").strip()

        # rate limit по username (или ip можно request.remote_addr)
        key = username if username else request.remote_addr
        if rate_limited(key):
            flash("Too many attempts. Try again later.", "error")
            return redirect(url_for("login"))

        user = USERS.get(username)
        if not user:
            flash("Invalid credentials.", "error")
            return redirect(url_for("login"))

        # bcrypt check (внутри безопасно)
        if not bcrypt.checkpw(password.encode(), user["pw_hash"]):
            flash("Invalid credentials.", "error")
            return redirect(url_for("login"))

        # MFA: either TOTP or backup code
        totp = pyotp.TOTP(user["totp_secret"])

        mfa_ok = False
        if totp_code:
            # tolerance window: +/- 1 step
            mfa_ok = totp.verify(totp_code, valid_window=1)
        elif backup_code:
            mfa_ok = consume_backup_code(username, backup_code)

        if not mfa_ok:
            flash("MFA failed. Provide TOTP or a valid backup code.", "error")
            return redirect(url_for("login"))

        token = make_session_token(username)
        session["user"] = username
        session["session_token"] = token

        flash("Login successful!", "success")
        return redirect(url_for("dashboard"))

    return render_template("login.html")


@app.route("/dashboard")
def dashboard():
    if "user" not in session or "session_token" not in session:
        return redirect(url_for("login"))

    if not verify_session_token(session["session_token"]):
        session.clear()
        flash("Session invalid. Login again.", "error")
        return redirect(url_for("login"))

    return render_template("dashboard.html", user=session["user"])


@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.", "success")
    return redirect(url_for("home"))


if __name__ == "__main__":
    app.run(debug=True)
import json
from flask import jsonify

@app.route("/encrypt-file", methods=["GET", "POST"])
def encrypt_file_page():
    if "user" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        f = request.files.get("file")
        password = request.form.get("password", "")
        if not f or not password:
            flash("File and password required.", "error")
            return redirect(url_for("encrypt_file_page"))

        data = files.encrypt_file(f.read(), password, f.filename)

        # если есть ledger у вас — логируйте:
        # ledger.log_event({"type": "FILE_ENCRYPT", "user": session["user"], "file_hash": data["file_hash"]})

        return render_template("encrypt_result.html", payload=json.dumps(data, indent=2))

    return render_template("encrypt.html")


@app.route("/decrypt-file", methods=["GET", "POST"])
def decrypt_file_page():
    if "user" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        password = request.form.get("password", "")
        payload_text = request.form.get("payload", "")

        try:
            payload = json.loads(payload_text)
            result = files.decrypt_file(payload, password)

            # ledger.log_event({"type": "FILE_DECRYPT", "user": session["user"], "file_hash": result["file_hash"]})

            return render_template("decrypt_result.html", result=result)
        except Exception as e:
            flash(str(e), "error")
            return redirect(url_for("decrypt_file_page"))

    return render_template("decrypt.html")
