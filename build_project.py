import os
import subprocess

print("🚀 ĐANG KHỞI TẠO DỰ ÁN TỰ ĐỘNG...")

# --- 1. ĐỊNH NGHĨA NỘI DUNG CÁC FILE ---
gitignore = """venv/
env/
.venv/
.env
__pycache__/
*.pyc
*.pyo
*.pyd
crack_lab/sample_md5_hashes.txt
crack_lab/sample_argon2_hashes.txt
"""

readme = """# Đề tài 7: Lưu trữ Mật khẩu An toàn & Phòng thủ Offline Cracking
**Mục tiêu:** Xây dựng hệ thống đăng nhập an toàn chống Credential Stuffing, Rate Limiting (Online) và chặn đứng nỗ lực bẻ khóa CSDL ngoại tuyến.

## 🛡️ Hướng dẫn Chạy Ứng dụng (App Login)
1. `cd app_login`
2. `pip install -r requirements.txt`
3. `python app.py`
4. Truy cập web tại: `http://localhost:5000`

## 🔨 Hướng dẫn Demo Bẻ Khóa (Offline Cracking)
1. `cd crack_lab`
2. `python generate_dataset.py`
3. `hashcat -m 0 -a 0 sample_md5_hashes.txt mini_wordlist.txt`
4. `hashcat -m 32300 -a 0 sample_argon2_hashes.txt mini_wordlist.txt`
"""

requirements = """flask==3.0.3
argon2-cffi==23.1.0
werkzeug==3.0.4
gunicorn==23.0.0
"""

env_example = """APP_PEPPER_SECRET=secret_server_pepper_key_2026
PORT=5000
"""

mini_wordlist = """123456
12345678
password
admin
admin123
qwerty
iloveyou
welcome
"""

generate_dataset = """import hashlib
import hmac
from argon2 import PasswordHasher, Type

ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2, hash_len=32, salt_len=16, type=Type.ID)
PEPPER_SECRET = b"secret_server_pepper_key_2026"
victims = [("user1", "123456"), ("user2", "password"), ("user3", "admin123"), ("user4", "iloveyou"), ("user5", "qwerty")]

with open("sample_md5_hashes.txt", "w") as f:
    for _, pwd in victims: f.write(hashlib.md5(pwd.encode()).hexdigest() + "\\n")
print("✅ Da tao sample_md5_hashes.txt")

with open("sample_argon2_hashes.txt", "w") as f:
    for _, pwd in victims:
        peppered = hmac.new(PEPPER_SECRET, pwd.encode(), hashlib.sha256).hexdigest()
        f.write(ph.hash(peppered) + "\\n")
print("✅ Da tao sample_argon2_hashes.txt")
"""

app_py = r'''import os, time, hmac, hashlib
from flask import Flask, request, jsonify, render_template_string
from werkzeug.middleware.proxy_fix import ProxyFix
from argon2 import PasswordHasher, Type
from argon2.exceptions import VerifyMismatchError

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
PEPPER_SECRET = os.environ.get("APP_PEPPER_SECRET", "secret_server_pepper_key_2026")
ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2, hash_len=32, salt_len=16, type=Type.ID)

def apply_pepper(pwd: str) -> str: return hmac.new(PEPPER_SECRET.encode("utf-8"), pwd.encode("utf-8"), hashlib.sha256).hexdigest()

MAX_FAILED_ATTEMPTS, RATE_LIMIT_WINDOW, FAILED_LOGIN_LOG = 5, 180, {}

def get_client_ip() -> str: return request.remote_addr or "127.0.0.1"

def clean_and_get_attempts(key: str, now: float) -> list:
    valid = [t for t in FAILED_LOGIN_LOG.get(key, []) if now - t < RATE_LIMIT_WINDOW]
    if valid: FAILED_LOGIN_LOG[key] = valid
    else: FAILED_LOGIN_LOG.pop(key, None)
    return valid

def check_rate_limit(ip: str, username: str) -> int:
    now = time.time()
    ip_att = clean_and_get_attempts(f"ip:{ip}", now)
    user_att = clean_and_get_attempts(f"user:{username.lower()}", now) if username else []
    w_ip = int(RATE_LIMIT_WINDOW - (now - ip_att[0])) + 1 if len(ip_att) >= MAX_FAILED_ATTEMPTS else 0
    w_u = int(RATE_LIMIT_WINDOW - (now - user_att[0])) + 1 if len(user_att) >= MAX_FAILED_ATTEMPTS else 0
    return max(w_ip, w_u)

def record_failed_attempt(ip: str, username: str):
    now = time.time()
    ip_att = clean_and_get_attempts(f"ip:{ip}", now)
    ip_att.append(now); FAILED_LOGIN_LOG[f"ip:{ip}"] = ip_att
    user_att = []
    if username:
        user_att = clean_and_get_attempts(f"user:{username.lower()}", now)
        user_att.append(now); FAILED_LOGIN_LOG[f"user:{username.lower()}"] = user_att
    used = max(len(ip_att), len(user_att))
    remaining = max(0, MAX_FAILED_ATTEMPTS - used)
    return remaining, check_rate_limit(ip, username) if remaining == 0 else 0

BREACHED_PASSWORDS = {"123456", "password", "12345678", "admin123", "qwerty"}
HIBP_INDEX = {}
for pwd in BREACHED_PASSWORDS:
    h = hashlib.sha1(pwd.encode("utf-8")).hexdigest().upper()
    HIBP_INDEX.setdefault(h[:5], set()).add(h[5:])

def is_password_pwned(pwd: str) -> bool:
    h = hashlib.sha1(pwd.encode("utf-8")).hexdigest().upper()
    return h[5:] in HIBP_INDEX.get(h[:5], set())

USERS_DB = {"admin": ph.hash(apply_pepper("AnToan@2026"))}
DUMMY_HASH = USERS_DB["admin"]

@app.route("/api/register", methods=["POST"])
def api_register():
    data = request.get_json() or {}
    u, p, c = data.get("username", "").strip(), data.get("password", ""), data.get("confirm_password", "")
    if not u or not p: return jsonify({"error": "Thieu thong tin."}), 400
    if u.lower() in (x.lower() for x in USERS_DB): return jsonify({"error": "Tai khoan da ton tai."}), 409
    if p != c: return jsonify({"error": "Mat khau khong khop."}), 400
    if is_password_pwned(p): return jsonify({"error": "Mat khau yeu/lo lot."}), 422
    USERS_DB[u] = ph.hash(apply_pepper(p))
    return jsonify({"message": "Dang ky thanh cong!"})

@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json() or {}
    u, p, ip = data.get("username", "").strip(), data.get("password", ""), get_client_ip()
    retry_after = check_rate_limit(ip, u)
    if retry_after > 0: return jsonify({"error": f"Bi khoa {retry_after}s.", "retry_after": retry_after}), 429
    matched = next((x for x in USERS_DB if x.lower() == u.lower()), None)
    if not matched:
        try: ph.verify(DUMMY_HASH, apply_pepper(p))
        except VerifyMismatchError: pass
        rem, lck = record_failed_attempt(ip, u)
        return jsonify({"error": "Sai tai khoan hoac mat khau."} if lck == 0 else {"error": f"Bi khoa {lck}s.", "retry_after": lck}), 401 if lck == 0 else 429
    try:
        ph.verify(USERS_DB[matched], apply_pepper(p))
        FAILED_LOGIN_LOG.pop(f"ip:{ip}", None); FAILED_LOGIN_LOG.pop(f"user:{u.lower()}", None)
        return jsonify({"message": "OK", "username": matched})
    except VerifyMismatchError:
        rem, lck = record_failed_attempt(ip, matched)
        return jsonify({"error": "Sai tai khoan hoac mat khau."} if lck == 0 else {"error": f"Bi khoa {lck}s.", "retry_after": lck}), 401 if lck == 0 else 429

HTML_UI = """
<!DOCTYPE html><html lang="vi"><head><meta charset="UTF-8"><title>Login</title>
<style>body{font-family:sans-serif;background:#0f172a;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;} .card{background:#fff;padding:30px;border-radius:10px;width:300px;} input{width:100%;padding:10px;margin:10px 0;box-sizing:border-box;} button{width:100%;padding:10px;background:#2563eb;color:#fff;border:none;border-radius:5px;cursor:pointer;}</style>
</head><body>
<div class="card"><h2 style="text-align:center">Đăng nhập Lab 7</h2>
<input id="u" placeholder="Username"><input type="password" id="p" placeholder="Password"><button onclick="login()">Đăng nhập</button>
<p id="msg" style="color:red;font-size:14px;text-align:center"></p></div>
<script>
async function login(){
  let btn = document.querySelector('button'); btn.disabled=true; document.getElementById('msg').innerText="Đang xử lý...";
  let r = await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:document.getElementById('u').value,password:document.getElementById('p').value})});
  let d = await r.json(); btn.disabled=false; document.getElementById('msg').innerText = d.error || d.message;
}
</script></body></html>
"""
@app.route("/")
def index(): return render_template_string(HTML_UI)
if __name__ == "__main__": app.run(host="0.0.0.0", port=5000, debug=True)
'''

# --- 2. HÀM TẠO FILE TỰ ĐỘNG ---
files = {
    ".gitignore": gitignore,
    "README.md": readme,
    "app_login/requirements.txt": requirements,
    "app_login/.env.example": env_example,
    "app_login/app.py": app_py,
    "crack_lab/mini_wordlist.txt": mini_wordlist,
    "crack_lab/generate_dataset.py": generate_dataset
}

for filepath, content in files.items():
    os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(content.strip() + "\n")
    print(f"📁 Đã tạo: {filepath}")

# --- 3. ĐẨY LÊN GITHUB TỰ ĐỘNG ---
print("\n🔥 ĐANG ĐẨY CODE LÊN GITHUB...")
commands = [
    "git init",
    "git add .",
    'git commit -m "Auto-build: App Login & Crack Lab"',
    "git branch -M main",
    "git remote add origin https://github.com/buibaolong02102007/DeTai7_SecurePassword.git",
    "git push -u origin main"
]

for cmd in commands:
    subprocess.run(cmd, shell=True)

print("\n🎉 XONG! BẠN VÀO LINK GITHUB KIỂM TRA ĐI!")