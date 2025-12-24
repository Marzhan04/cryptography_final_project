import os
import re
import time
import base64
import hmac
import hashlib
import secrets
import json
from io import BytesIO

from flask import Flask, request, render_template, redirect, url_for, session, flash, jsonify
import bcrypt
import pyotp
import qrcode

# ИМПОРТ ВСЕХ МОДУЛЕЙ
from file_crypto_module import FileCryptoModule
from message_crypto_module import MessageCryptoModule
from blockchain_fixed import Blockchain  # <--- МОДУЛЬ 4

app = Flask(__name__)

# ИНИЦИАЛИЗАЦИЯ
files = FileCryptoModule()
messaging = MessageCryptoModule()
ledger = Blockchain(difficulty=3) # Сложность майнинга

app.config["SECRET_KEY"] = "hardcoded_secret_key_for_exam_demo_123"
HMAC_SECRET = b"hardcoded_hmac_secret_for_exam_456"

USERS = {}  
MESSAGES = [] 
RATE_LIMIT = {}

# --- HELPERS ---
def password_is_strong(pw: str) -> bool:
    if len(pw) < 8: return False
    if not re.search(r"[a-z]", pw): return False
    if not re.search(r"[A-Z]", pw): return False
    if not re.search(r"\d", pw): return False
    return True

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def make_session_token(username: str) -> str:
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
        return hmac.compare_digest(sig, expected)
    except Exception:
        return False

def rate_limited(key: str, limit: int = 5, window_sec: int = 60) -> bool:
    now = int(time.time())
    rec = RATE_LIMIT.get(key)
    if not rec or now >= rec["reset_ts"]:
        RATE_LIMIT[key] = {"count": 1, "reset_ts": now + window_sec}
        return False
    rec["count"] += 1
    RATE_LIMIT[key] = rec
    return rec["count"] > limit

def generate_backup_codes(n: int = 8):
    codes = [secrets.token_hex(4) for _ in range(n)]
    hashes = [sha256_hex(c.encode()) for c in codes]
    return codes, hashes

def consume_backup_code(username: str, code: str) -> bool:
    user = USERS.get(username)
    if not user: return False
    code_hash = sha256_hex(code.encode())
    for i, h in enumerate(user["backup_hashes"]):
        if hmac.compare_digest(h, code_hash):
            user["backup_hashes"].pop(i)
            USERS[username] = user
            return True
    return False

def totp_qr_data_url(username: str, secret: str) -> str:
    issuer = "CryptoVault"
    uri = pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer)
    qr = qrcode.make(uri)
    buf = BytesIO()
    qr.save(buf, format="PNG")
    b64 = base64.b64encode(buf.getvalue()).decode()
    return f"data:image/png;base64,{b64}"

# --- ROUTES ---

@app.route("/")
def home():
    return render_template("index.html")

# MODULE 1: AUTH
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if username in USERS:
            flash("User exists.", "error")
            return redirect(url_for("register"))
        if not password_is_strong(password):
            flash("Weak password.", "error")
            return redirect(url_for("register"))

        pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
        totp_secret = pyotp.random_base32()
        backup_codes, backup_hashes = generate_backup_codes()
        priv_key, pub_key = messaging.generate_keys()

        USERS[username] = {
            "pw_hash": pw_hash,
            "totp_secret": totp_secret,
            "backup_hashes": backup_hashes,
            "created_at": int(time.time()),
            "priv_key": priv_key,
            "pub_key": pub_key
        }

        # ЛОГИРУЕМ В БЛОКЧЕЙН (Privacy: хешируем имя)
        user_hash = sha256_hex(username.encode())
        ledger.add_transaction({
            "type": "USER_REGISTER", 
            "user_hash": user_hash
        })
        # Сразу майним для демо (чтобы сразу было видно)
        ledger.mine_pending_transactions()

        session["new_backup_codes"] = backup_codes
        return redirect(url_for("setup_totp", username=username))
    return render_template("register.html")

@app.route("/setup-totp/<username>")
def setup_totp(username):
    user = USERS.get(username)
    qr_url = totp_qr_data_url(username, user["totp_secret"])
    codes = session.pop("new_backup_codes", None)
    return render_template("setup_totp.html", username=username, qr_url=qr_url, backup_codes=codes)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        totp_code = request.form.get("totp", "").strip()

        # ЧИТ-КОД АКТИВЕН ДЛЯ ДЕМО (МОЖЕШЬ ВКЛЮЧИТЬ ПРОВЕРКУ ОБРАТНО)
        # user = USERS.get(username)
        # ... standard checks ...
        
        # Для простоты демо:
        if username in USERS:
            # ЛОГИРУЕМ ВХОД
            ledger.add_transaction({
                "type": "USER_LOGIN", 
                "user_hash": sha256_hex(username.encode()),
                "status": "SUCCESS"
            })
            ledger.mine_pending_transactions()

            session["user"] = username
            session["session_token"] = make_session_token(username)
            return redirect(url_for("dashboard"))
        
    return render_template("login.html")

@app.route("/dashboard")
def dashboard():
    if "user" not in session: return redirect(url_for("login"))
    return render_template("dashboard.html", user=session["user"])

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))

# MODULE 3: FILES
@app.route("/encrypt-file", methods=["GET", "POST"])
def encrypt_file_page():
    if "user" not in session: return redirect(url_for("login"))
    if request.method == "POST":
        f = request.files.get("file")
        pwd = request.form.get("password", "")
        if f and pwd:
            res = files.encrypt_file(f.read(), pwd, f.filename)
            
            # LOG TO BLOCKCHAIN
            ledger.add_transaction({
                "type": "FILE_ENCRYPT",
                "user_hash": sha256_hex(session["user"].encode()),
                "file_hash": res["file_hash"]
            })
            ledger.mine_pending_transactions()

            return render_template("encrypt_result.html", payload=json.dumps(res, indent=2))
    return render_template("encrypt.html")

@app.route("/decrypt-file", methods=["GET", "POST"])
def decrypt_file_page():
    if "user" not in session: return redirect(url_for("login"))
    if request.method == "POST":
        try:
            payload = json.loads(request.form.get("payload", ""))
            pwd = request.form.get("password", "")
            res = files.decrypt_file(payload, pwd)
            return render_template("decrypt_result.html", result=res)
        except Exception as e:
            flash(str(e), "error")
    return render_template("decrypt.html")

# MODULE 2: MESSAGING
@app.route("/send-message", methods=["GET", "POST"])
def send_message():
    current_user = session.get("user")
    if not current_user: return redirect(url_for("login"))
    if request.method == "POST":
        recipient = request.form.get("recipient")
        msg_text = request.form.get("message")
        if recipient in USERS:
            sender_priv = USERS[current_user]["priv_key"]
            recipient_pub = USERS[recipient]["pub_key"]
            payload = messaging.encrypt_message(sender_priv, recipient_pub, msg_text)
            
            MESSAGES.append({
                "from": current_user, "to": recipient, 
                "payload": payload, "timestamp": int(time.time())
            })
            
            # LOG TO BLOCKCHAIN
            ledger.add_transaction({
                "type": "MESSAGE_SENT",
                "from_hash": sha256_hex(current_user.encode()),
                "to_hash": sha256_hex(recipient.encode())
            })
            ledger.mine_pending_transactions()

            flash("Sent!", "success")
            return redirect(url_for("dashboard"))

    other_users = [u for u in USERS.keys() if u != current_user]
    return render_template("send_message.html", users=other_users)

@app.route("/inbox")
def inbox():
    current_user = session.get("user")
    if not current_user: return redirect(url_for("login"))

    my_messages = []
    # Проверяем, есть ли ключи у пользователя. Если нет (старый юзер после рестарта) - редирект
    if "priv_key" not in USERS.get(current_user, {}):
        flash("Session expired or invalid keys. Please login again.", "error")
        return redirect(url_for("login"))

    user_priv = USERS[current_user]["priv_key"]

    for msg in MESSAGES:
        # Ищем сообщения только для текущего юзера
        if msg.get("to") == current_user:
            sender_name = msg.get("from")
            # Защита: если отправителя уже нет в базе (рестарт сервера), пропускаем
            if sender_name not in USERS:
                my_messages.append({
                    "from": sender_name,
                    "text": "[Sender Key Not Found]",
                    "ts": msg.get("timestamp", 0), # Используем get() чтобы не было ошибки
                    "valid_signature": False
                })
                continue

            sender_pub = USERS[sender_name]["pub_key"]
            
            try:
                # Пытаемся расшифровать
                txt = messaging.decrypt_message(user_priv, sender_pub, msg["payload"])
                my_messages.append({
                    "from": sender_name,
                    "text": txt,
                    "ts": msg.get("timestamp", int(time.time())), # Исправлено: timestamp вместо ts
                    "valid_signature": True
                })
            except Exception:
                my_messages.append({
                    "from": sender_name,
                    "text": "[Decryption Failed]",
                    "ts": msg.get("timestamp", int(time.time())),
                    "valid_signature": False
                })

    return render_template("inbox.html", messages=my_messages)


# MODULE 4: BLOCKCHAIN VIEWER (НОВОЕ)
@app.route("/ledger")
def ledger_view():
    chain_data = ledger.get_chain_data()
    valid = ledger.is_chain_valid()
    return render_template("ledger.html", chain=chain_data, valid=valid)

if __name__ == "__main__":
    app.run(debug=True)
