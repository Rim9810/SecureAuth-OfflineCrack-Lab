import os
import json
import time
import hmac
import hashlib
import secrets
from flask import Flask, request, jsonify, render_template_string, session
from argon2 import PasswordHasher, Type
from argon2.exceptions import VerifyMismatchError

app = Flask(__name__)
# Khóa bí mật dùng để ký cookie session của Flask
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)

# =====================================================================
# 1. CẤU HÌNH PEPPER (256-BIT CSPRNG) & ARGON2ID LOCAL
# =====================================================================
PEPPER_FILE = "pepper.secret"
DATASET_FILE = "users_dataset.json"
BREACHED_FILE = "breached_passwords.txt"


def load_or_create_pepper() -> str:
    env_pepper = os.environ.get("APP_PEPPER_SECRET")
    if env_pepper:
        return env_pepper

    if os.path.exists(PEPPER_FILE):
        with open(PEPPER_FILE, "r", encoding="utf-8") as f:
            return f.read().strip()

    new_pepper = secrets.token_hex(32)  # 32 bytes = 256-bit
    with open(PEPPER_FILE, "w", encoding="utf-8") as f:
        f.write(new_pepper)
    return new_pepper


PEPPER_SECRET = load_or_create_pepper()

ph = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=2,
    hash_len=32,
    salt_len=16,
    type=Type.ID
)


def apply_pepper(password: str) -> str:
    return hmac.new(
        PEPPER_SECRET.encode("utf-8"),
        password.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()


# =====================================================================
# 2. CƠ CHẾ DYNAMIC DATASET (LƯU TRONG RAM + FILE users_dataset.json)
# =====================================================================
DYNAMIC_DATASET = []


def save_dataset():
    with open(DATASET_FILE, "w", encoding="utf-8") as f:
        json.dump(DYNAMIC_DATASET, f, ensure_ascii=False, indent=2)


def load_dataset():
    global DYNAMIC_DATASET
    if os.path.exists(DATASET_FILE):
        try:
            with open(DATASET_FILE, "r", encoding="utf-8") as f:
                DYNAMIC_DATASET = json.load(f)
        except Exception:
            DYNAMIC_DATASET = []

    if not DYNAMIC_DATASET:
        DYNAMIC_DATASET.append({
            "id": 1,
            "username": "admin",
            "argon2_hash": ph.hash(apply_pepper("AnToan@2026")),
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S")
        })
        save_dataset()


def find_user(username: str):
    for user in DYNAMIC_DATASET:
        if user["username"].lower() == username.lower():
            return user
    return None


def add_user_to_dataset(username: str, password: str):
    new_record = {
        "id": len(DYNAMIC_DATASET) + 1,
        "username": username,
        "argon2_hash": ph.hash(apply_pepper(password)),
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S")
    }
    DYNAMIC_DATASET.append(new_record)
    save_dataset()
    return new_record


load_dataset()
DUMMY_HASH = DYNAMIC_DATASET[0]["argon2_hash"]


# =====================================================================
# 3. CƠ CHẾ RATE LIMIT: TỐI ĐA 5 LẦN SAI TRONG 3 PHÚT (180 GIÂY)
# =====================================================================
MAX_FAILED_ATTEMPTS = 5
RATE_LIMIT_WINDOW = 180
FAILED_LOGIN_LOG = {}


def get_client_ip() -> str:
    return request.remote_addr or "127.0.0.1"


def clean_and_get_attempts(key: str, now: float) -> list:
    attempts = FAILED_LOGIN_LOG.get(key, [])
    valid_attempts = [t for t in attempts if now - t < RATE_LIMIT_WINDOW]
    if valid_attempts:
        FAILED_LOGIN_LOG[key] = valid_attempts
    else:
        FAILED_LOGIN_LOG.pop(key, None)
    return valid_attempts


def check_rate_limit(ip: str, username: str) -> int:
    now = time.time()
    ip_attempts = clean_and_get_attempts(f"ip:{ip}", now)
    user_attempts = clean_and_get_attempts(f"user:{username.lower()}", now) if username else []

    wait_ip = int(RATE_LIMIT_WINDOW - (now - ip_attempts[0])) + 1 if len(ip_attempts) >= MAX_FAILED_ATTEMPTS else 0
    wait_user = int(RATE_LIMIT_WINDOW - (now - user_attempts[0])) + 1 if len(user_attempts) >= MAX_FAILED_ATTEMPTS else 0

    return max(wait_ip, wait_user)


def record_failed_attempt(ip: str, username: str) -> tuple[int, int]:
    now = time.time()
    ip_key = f"ip:{ip}"
    ip_attempts = clean_and_get_attempts(ip_key, now)
    ip_attempts.append(now)
    FAILED_LOGIN_LOG[ip_key] = ip_attempts

    user_attempts = []
    if username:
        user_key = f"user:{username.lower()}"
        user_attempts = clean_and_get_attempts(user_key, now)
        user_attempts.append(now)
        FAILED_LOGIN_LOG[user_key] = user_attempts

    used = max(len(ip_attempts), len(user_attempts))
    remaining = max(0, MAX_FAILED_ATTEMPTS - used)
    retry_after = check_rate_limit(ip, username) if remaining == 0 else 0
    return remaining, retry_after


def clear_failed_attempts(ip: str, username: str):
    FAILED_LOGIN_LOG.pop(f"ip:{ip}", None)
    if username:
        FAILED_LOGIN_LOG.pop(f"user:{username.lower()}", None)


# =====================================================================
# 4. KIỂM TRA MẬT KHẨU LỘ LỌT LOCAL (HIBP K-ANONYMITY OFFLINE)
# =====================================================================
DEFAULT_BREACHED = {
    "123456", "password", "password123", "password1!", "p@ssw0rd", "passw0rd",
    "12345678", "123456789", "1234567890", "12345", "11111111", "00000000",
    "qwerty", "qwerty123", "qwertyuiop", "1q2w3e4r", "1qaz2wsx", "asdfghjkl",
    "admin123", "admin@123", "root1234", "iloveyou", "iloveyou123", "welcome123",
    "abc12345", "abcd1234", "matkhau123", "anhyeuem", "0123456789", "superman123"
}

HIBP_INDEX = {}


def init_local_hibp_index():
    words = set(DEFAULT_BREACHED)
    if os.path.exists(BREACHED_FILE):
        try:
            with open(BREACHED_FILE, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    w = line.strip()
                    if w:
                        words.add(w)
                        words.add(w.lower())
        except OSError:
            pass

    for pwd in words:
        sha1_hex = hashlib.sha1(pwd.encode("utf-8")).hexdigest().upper()
        HIBP_INDEX.setdefault(sha1_hex[:5], set()).add(sha1_hex[5:])


init_local_hibp_index()


def check_k_anonymity_local(sha1_full: str) -> bool:
    prefix, suffix = sha1_full[:5], sha1_full[5:]
    return suffix in HIBP_INDEX.get(prefix, set())


def is_password_pwned(password: str) -> bool:
    sha1_exact = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    sha1_lower = hashlib.sha1(password.lower().encode("utf-8")).hexdigest().upper()
    return check_k_anonymity_local(sha1_exact) or check_k_anonymity_local(sha1_lower)


# =====================================================================
# 5. CÁC ENDPOINT API
# =====================================================================
@app.route("/api/register", methods=["POST"])
def api_register():
    data = request.get_json() or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")
    confirm = data.get("confirm_password", "")

    if not username or not password:
        return jsonify({"error": "Vui lòng nhập đầy đủ tên đăng nhập và mật khẩu."}), 400

    if len(username) < 3:
        return jsonify({"error": "Tên đăng nhập phải có ít nhất 3 ký tự."}), 400

    if find_user(username):
        return jsonify({"error": "Tên đăng nhập này đã được sử dụng."}), 409

    if len(password) < 8:
        return jsonify({"error": "Mật khẩu phải có ít nhất 8 ký tự."}), 400

    if password != confirm:
        return jsonify({"error": "Mật khẩu xác nhận không khớp."}), 400

    if is_password_pwned(password):
        return jsonify({
            "error": "Mật khẩu này quá phổ biến hoặc đã bị lộ trong các vụ rò rỉ dữ liệu. Vui lòng chọn mật khẩu khác an toàn hơn."
        }), 422

    add_user_to_dataset(username, password)
    return jsonify({"message": "Đăng ký tài khoản thành công! Bạn có thể đăng nhập ngay."})


@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json() or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")
    client_ip = get_client_ip()

    if not username or not password:
        return jsonify({"error": "Vui lòng nhập tên đăng nhập và mật khẩu."}), 400

    retry_after = check_rate_limit(client_ip, username)
    if retry_after > 0:
        return jsonify({
            "error": f"Bạn đã nhập sai quá {MAX_FAILED_ATTEMPTS} lần trong 3 phút. Vui lòng thử lại sau {retry_after} giây.",
            "retry_after": retry_after
        }), 429

    user_record = find_user(username)

    if not user_record:
        try:
            ph.verify(DUMMY_HASH, apply_pepper(password))
        except VerifyMismatchError:
            pass

        remaining, lock_sec = record_failed_attempt(client_ip, username)
        if lock_sec > 0:
            return jsonify({
                "error": f"Bạn đã nhập sai quá {MAX_FAILED_ATTEMPTS} lần trong 3 phút. Vui lòng thử lại sau {lock_sec} giây.",
                "retry_after": lock_sec
            }), 429

        return jsonify({
            "error": f"Tên đăng nhập hoặc mật khẩu không chính xác. (Còn {remaining} lần thử)"
        }), 401

    try:
        ph.verify(user_record["argon2_hash"], apply_pepper(password))
        clear_failed_attempts(client_ip, user_record["username"])

        # Lưu thông tin đăng nhập và quyền hạn vào Session
        is_admin = (user_record["username"].lower() == "admin")
        session["username"] = user_record["username"]
        session["is_admin"] = is_admin

        return jsonify({
            "message": "Đăng nhập thành công!",
            "username": user_record["username"],
            "is_admin": is_admin
        })
    except VerifyMismatchError:
        remaining, lock_sec = record_failed_attempt(client_ip, user_record["username"])
        if lock_sec > 0:
            return jsonify({
                "error": f"Bạn đã nhập sai quá {MAX_FAILED_ATTEMPTS} lần trong 3 phút. Vui lòng thử lại sau {lock_sec} giây.",
                "retry_after": lock_sec
            }), 429

        return jsonify({
            "error": f"Tên đăng nhập hoặc mật khẩu không chính xác. (Còn {remaining} lần thử)"
        }), 401


@app.route("/api/logout", methods=["POST"])
def api_logout():
    session.clear()
    return jsonify({"message": "Đã đăng xuất."})


@app.route("/api/dataset", methods=["GET"])
def api_view_dataset():
    # Chặn truy cập nếu chưa đăng nhập hoặc không phải tài khoản admin
    if not session.get("is_admin"):
        return jsonify({
            "error": "Truy cập bị từ chối! Chỉ tài khoản quản trị viên (admin) mới có quyền xem danh sách và mã hash."
        }), 403

    return jsonify({
        "storage_file": DATASET_FILE,
        "total_accounts": len(DYNAMIC_DATASET),
        "accounts": DYNAMIC_DATASET
    })


# =====================================================================
# 6. GIAO DIỆN ĐĂNG NHẬP / ĐĂNG KÝ / ADMIN DASHBOARD
# =====================================================================
HTML_UI = """
<!DOCTYPE html>
<html lang="vi">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Đăng nhập hệ thống</title>
  <style>
    * { box-sizing: border-box; font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; }
    body {
      margin: 0;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
      color: #1e293b;
      padding: 20px;
    }
    .auth-card {
      background: #ffffff;
      width: 100%;
      max-width: 400px;
      padding: 36px 32px;
      border-radius: 16px;
      box-shadow: 0 20px 40px rgba(0, 0, 0, 0.35);
      transition: max-width 0.3s ease;
    }
    /* Mở rộng card khi Admin xem bảng danh sách user & hash */
    .auth-card.admin-mode {
      max-width: 960px;
    }
    .auth-header {
      text-align: center;
      margin-bottom: 28px;
    }
    .auth-header h1 {
      margin: 0 0 8px 0;
      font-size: 24px;
      font-weight: 700;
      color: #0f172a;
    }
    .auth-header p {
      margin: 0;
      font-size: 14px;
      color: #64748b;
    }
    .form-group {
      margin-bottom: 18px;
    }
    label {
      display: block;
      font-size: 13.5px;
      font-weight: 600;
      color: #334155;
      margin-bottom: 6px;
    }
    input {
      width: 100%;
      padding: 11px 14px;
      font-size: 14.5px;
      border: 1px solid #cbd5e1;
      border-radius: 8px;
      outline: none;
      transition: border-color 0.2s, box-shadow 0.2s;
    }
    input:focus {
      border-color: #2563eb;
      box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.15);
    }
    .btn-primary {
      width: 100%;
      padding: 12px;
      font-size: 15px;
      font-weight: 600;
      color: #ffffff;
      background: #2563eb;
      border: none;
      border-radius: 8px;
      cursor: pointer;
      transition: background 0.2s;
      margin-top: 4px;
    }
    .btn-primary:hover {
      background: #1d4ed8;
    }
    .btn-primary:disabled {
      background: #94a3b8;
      cursor: not-allowed;
    }
    .switch-view {
      text-align: center;
      margin-top: 22px;
      padding-top: 18px;
      border-top: 1px solid #e2e8f0;
      font-size: 14px;
      color: #64748b;
    }
    .switch-view a {
      color: #2563eb;
      font-weight: 600;
      text-decoration: none;
      cursor: pointer;
      margin-left: 4px;
    }
    .switch-view a:hover {
      text-decoration: underline;
    }
    .alert {
      padding: 11px 14px;
      border-radius: 8px;
      font-size: 13.5px;
      margin-bottom: 18px;
      display: none;
      line-height: 1.4;
    }
    .alert-error {
      background: #fef2f2;
      color: #b91c1c;
      border: 1px solid #fecaca;
    }
    .alert-success {
      background: #f0fdf4;
      color: #15803d;
      border: 1px solid #bbf7d0;
    }
    .hidden {
      display: none !important;
    }
    .welcome-box {
      text-align: center;
      padding: 10px 0;
    }
    .avatar-circle {
      width: 64px;
      height: 64px;
      background: #dbeafe;
      color: #2563eb;
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 26px;
      font-weight: 700;
      margin: 0 auto 16px auto;
    }
    .role-badge {
      display: inline-block;
      margin-top: 8px;
      padding: 4px 12px;
      border-radius: 999px;
      font-size: 12px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    .role-admin {
      background: #fef3c7;
      color: #b45309;
      border: 1px solid #fde68a;
    }
    .role-user {
      background: #e0f2fe;
      color: #0369a1;
      border: 1px solid #bae6fd;
    }
    .btn-outline {
      width: 100%;
      max-width: 240px;
      padding: 11px;
      font-size: 14.5px;
      font-weight: 600;
      color: #475569;
      background: #f8fafc;
      border: 1px solid #cbd5e1;
      border-radius: 8px;
      cursor: pointer;
      margin-top: 22px;
    }
    .btn-outline:hover {
      background: #f1f5f9;
    }

    /* CSS cho bảng Admin Panel */
    .admin-panel {
      margin-top: 26px;
      padding-top: 22px;
      border-top: 1px solid #e2e8f0;
      text-align: left;
    }
    .admin-panel-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 10px;
      margin-bottom: 14px;
    }
    .admin-panel-header h3 {
      margin: 0;
      font-size: 16px;
      color: #0f172a;
    }
    .btn-refresh {
      padding: 6px 12px;
      font-size: 13px;
      font-weight: 600;
      color: #2563eb;
      background: #eff6ff;
      border: 1px solid #bfdbfe;
      border-radius: 6px;
      cursor: pointer;
    }
    .btn-refresh:hover {
      background: #dbeafe;
    }
    .table-wrapper {
      overflow-x: auto;
      border: 1px solid #e2e8f0;
      border-radius: 10px;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 13.5px;
    }
    th {
      background: #f8fafc;
      color: #475569;
      font-weight: 600;
      text-align: left;
      padding: 11px 14px;
      border-bottom: 1px solid #e2e8f0;
      white-space: nowrap;
    }
    td {
      padding: 11px 14px;
      border-bottom: 1px solid #f1f5f9;
      vertical-align: middle;
    }
    tr:last-child td {
      border-bottom: none;
    }
    tr:hover td {
      background: #f8fafc;
    }
    .hash-cell {
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .hash-code {
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 12px;
      background: #f1f5f9;
      color: #0f172a;
      padding: 5px 8px;
      border-radius: 6px;
      word-break: break-all;
      line-height: 1.4;
    }
    .btn-copy {
      flex-shrink: 0;
      padding: 5px 9px;
      font-size: 12px;
      font-weight: 600;
      color: #334155;
      background: #ffffff;
      border: 1px solid #cbd5e1;
      border-radius: 6px;
      cursor: pointer;
    }
    .btn-copy:hover {
      background: #f1f5f9;
      border-color: #94a3b8;
    }
  </style>
</head>
<body>

  <div id="main-card" class="auth-card">
    <div id="alert-box" class="alert"></div>

    <!-- VIEW: ĐĂNG NHẬP -->
    <div id="view-login">
      <div class="auth-header">
        <h1>Đăng nhập</h1>
        <p>Chào mừng bạn quay trở lại hệ thống</p>
      </div>

      <form onsubmit="handleLogin(event)">
        <div class="form-group">
          <label for="login-username">Tên đăng nhập</label>
          <input type="text" id="login-username" placeholder="Nhập tên đăng nhập" required autocomplete="username" />
        </div>
        <div class="form-group">
          <label for="login-password">Mật khẩu</label>
          <input type="password" id="login-password" placeholder="Nhập mật khẩu" required autocomplete="current-password" />
        </div>
        <button type="submit" id="btn-login" class="btn-primary">Đăng nhập</button>
      </form>

      <div class="switch-view">
        Chưa có tài khoản? <a onclick="switchTab('register')">Đăng ký tài khoản</a>
      </div>
    </div>

    <!-- VIEW: ĐĂNG KÝ -->
    <div id="view-register" class="hidden">
      <div class="auth-header">
        <h1>Tạo tài khoản mới</h1>
        <p>Điền thông tin bên dưới để đăng ký</p>
      </div>

      <form onsubmit="handleRegister(event)">
        <div class="form-group">
          <label for="reg-username">Tên đăng nhập</label>
          <input type="text" id="reg-username" placeholder="Tối thiểu 3 ký tự" required autocomplete="username" />
        </div>
        <div class="form-group">
          <label for="reg-password">Mật khẩu</label>
          <input type="password" id="reg-password" placeholder="Tối thiểu 8 ký tự" required autocomplete="new-password" />
        </div>
        <div class="form-group">
          <label for="reg-confirm">Xác nhận mật khẩu</label>
          <input type="password" id="reg-confirm" placeholder="Nhập lại mật khẩu" required autocomplete="new-password" />
        </div>
        <button type="submit" id="btn-register" class="btn-primary">Đăng ký</button>
      </form>

      <div class="switch-view">
        Đã có tài khoản? <a onclick="switchTab('login')">Đăng nhập ngay</a>
      </div>
    </div>

    <!-- VIEW: DASHBOARD SAU KHI ĐĂNG NHẬP -->
    <div id="view-dashboard" class="hidden">
      <div class="welcome-box">
        <div class="avatar-circle" id="user-avatar">U</div>
        <h2 style="margin:0 0 6px 0; color:#0f172a;">Xin chào, <span id="display-username"></span>!</h2>
        <p style="margin:0; font-size:14px; color:#64748b;">Bạn đã đăng nhập vào hệ thống thành công.</p>
        <div id="user-role-badge"></div>

        <!-- KHU VỰC CHỈ HIỂN THỊ CHO ADMIN -->
        <div id="admin-panel" class="admin-panel hidden">
          <div class="admin-panel-header">
            <h3>Danh sách tài khoản & Mã Hash Argon2id (<span id="total-users">0</span>)</h3>
            <button type="button" class="btn-refresh" onclick="loadAdminUsers()">↻ Làm mới</button>
          </div>
          <div class="table-wrapper">
            <table>
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Tên đăng nhập</th>
                  <th>Ngày tạo</th>
                  <th>Mã Hash (Argon2id + Pepper)</th>
                </tr>
              </thead>
              <tbody id="users-table-body">
                <!-- Dữ liệu được render bởi JS -->
              </tbody>
            </table>
          </div>
        </div>

        <button class="btn-outline" onclick="handleLogout()">Đăng xuất</button>
      </div>
    </div>
  </div>

<script>
  let lockTimer = null;

  function showAlert(message, type) {
    const box = document.getElementById("alert-box");
    box.textContent = message;
    box.className = "alert " + (type === "success" ? "alert-success" : "alert-error");
    box.style.display = "block";
  }

  function hideAlert() {
    document.getElementById("alert-box").style.display = "none";
  }

  function escapeHtml(str) {
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function copyHash(btn, hashText) {
    navigator.clipboard.writeText(hashText).then(() => {
      const original = btn.textContent;
      btn.textContent = "Đã chép!";
      btn.style.color = "#15803d";
      btn.style.borderColor = "#86efac";
      setTimeout(() => {
        btn.textContent = original;
        btn.style.color = "";
        btn.style.borderColor = "";
      }, 1500);
    });
  }

  async function loadAdminUsers() {
    const tbody = document.getElementById("users-table-body");
    tbody.innerHTML = '<tr><td colspan="4" style="text-align:center; color:#64748b;">Đang tải dữ liệu...</td></tr>';

    try {
      const res = await fetch("/api/dataset");
      const data = await res.json();

      if (!res.ok) {
        tbody.innerHTML = `<tr><td colspan="4" style="text-align:center; color:#b91c1c;">${escapeHtml(data.error || "Lỗi tải dữ liệu")}</td></tr>`;
        return;
      }

      document.getElementById("total-users").textContent = data.total_accounts;
      tbody.innerHTML = "";

      data.accounts.forEach(acc => {
        const tr = document.createElement("tr");
        const isAccAdmin = acc.username.toLowerCase() === "admin";
        const userLabel = isAccAdmin
          ? `<strong>${escapeHtml(acc.username)}</strong> <span style="font-size:11px; color:#b45309; background:#fef3c7; padding:2px 6px; border-radius:4px;">ADMIN</span>`
          : `<strong>${escapeHtml(acc.username)}</strong>`;

        tr.innerHTML = `
          <td>#${acc.id}</td>
          <td style="white-space:nowrap;">${userLabel}</td>
          <td style="white-space:nowrap; color:#64748b;">${escapeHtml(acc.created_at || "-")}</td>
          <td>
            <div class="hash-cell">
              <code class="hash-code">${escapeHtml(acc.argon2_hash)}</code>
              <button type="button" class="btn-copy" onclick="copyHash(this, '${escapeHtml(acc.argon2_hash)}')">Copy</button>
            </div>
          </td>
        `;
        tbody.appendChild(tr);
      });
    } catch (err) {
      tbody.innerHTML = '<tr><td colspan="4" style="text-align:center; color:#b91c1c;">Không thể kết nối đến máy chủ.</td></tr>';
    }
  }

  function startLockoutCountdown(seconds) {
    const btn = document.getElementById("btn-login");
    if (lockTimer) clearInterval(lockTimer);

    let remaining = seconds;
    btn.disabled = true;

    const updateText = () => {
      const mins = Math.floor(remaining / 60);
      const secs = remaining % 60;
      const timeStr = mins > 0 ? `${mins} phút ${secs} giây` : `${secs} giây`;
      btn.textContent = `Tạm khóa (${timeStr})`;
      showAlert(`Bạn đã nhập sai quá 5 lần trong 3 phút. Vui lòng thử lại sau ${timeStr}.`, "error");
    };

    updateText();
    lockTimer = setInterval(() => {
      remaining--;
      if (remaining <= 0) {
        clearInterval(lockTimer);
        lockTimer = null;
        btn.disabled = false;
        btn.textContent = "Đăng nhập";
        hideAlert();
      } else {
        updateText();
      }
    }, 1000);
  }

  function switchTab(tab) {
    if (!lockTimer) hideAlert();
    document.getElementById("view-login").classList.toggle("hidden", tab !== "login");
    document.getElementById("view-register").classList.toggle("hidden", tab !== "register");
    document.getElementById("view-dashboard").classList.toggle("hidden", tab !== "dashboard");

    if (tab !== "dashboard") {
      document.getElementById("main-card").classList.remove("admin-mode");
      document.getElementById("admin-panel").classList.add("hidden");
    }
  }

  async function handleLogin(e) {
    e.preventDefault();
    if (lockTimer) return;
    hideAlert();

    const btn = document.getElementById("btn-login");
    btn.disabled = true;
    btn.textContent = "Đang xử lý...";

    const username = document.getElementById("login-username").value;
    const password = document.getElementById("login-password").value;

    try {
      const res = await fetch("/api/login", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({ username, password })
      });
      const data = await res.json();

      if (res.status === 429 && data.retry_after) {
        startLockoutCountdown(data.retry_after);
        return;
      }

      if (!res.ok) {
        showAlert(data.error || "Đăng nhập thất bại.", "error");
      } else {
        document.getElementById("display-username").textContent = data.username;
        document.getElementById("user-avatar").textContent = data.username.charAt(0).toUpperCase();
        document.getElementById("login-password").value = "";

        const roleBadge = document.getElementById("user-role-badge");
        const adminPanel = document.getElementById("admin-panel");
        const mainCard = document.getElementById("main-card");

        if (data.is_admin) {
          roleBadge.innerHTML = '<span class="role-badge role-admin">Quản trị viên (Admin)</span>';
          mainCard.classList.add("admin-mode");
          adminPanel.classList.remove("hidden");
          loadAdminUsers();
        } else {
          roleBadge.innerHTML = '<span class="role-badge role-user">Người dùng (User)</span>';
          mainCard.classList.remove("admin-mode");
          adminPanel.classList.add("hidden");
        }

        switchTab("dashboard");
      }
    } catch (err) {
      showAlert("Không thể kết nối đến máy chủ.", "error");
    } finally {
      if (!lockTimer) {
        btn.disabled = false;
        btn.textContent = "Đăng nhập";
      }
    }
  }

  async function handleRegister(e) {
    e.preventDefault();
    hideAlert();
    const btn = document.getElementById("btn-register");
    btn.disabled = true;
    btn.textContent = "Đang tạo tài khoản...";

    const username = document.getElementById("reg-username").value;
    const password = document.getElementById("reg-password").value;
    const confirm_password = document.getElementById("reg-confirm").value;

    try {
      const res = await fetch("/api/register", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({ username, password, confirm_password })
      });
      const data = await res.json();

      if (!res.ok) {
        showAlert(data.error || "Đăng ký thất bại.", "error");
      } else {
        switchTab("login");
        document.getElementById("login-username").value = username;
        document.getElementById("reg-username").value = "";
        document.getElementById("reg-password").value = "";
        document.getElementById("reg-confirm").value = "";
        showAlert(data.message, "success");
      }
    } catch (err) {
      showAlert("Không thể kết nối đến máy chủ.", "error");
    } finally {
      btn.disabled = false;
      btn.textContent = "Đăng ký";
    }
  }

  async function handleLogout() {
    try {
      await fetch("/api/logout", { method: "POST" });
    } catch (err) {}
    document.getElementById("users-table-body").innerHTML = "";
    switchTab("login");
  }
</script>
</body>
</html>
"""


@app.route("/")
def index():
    return render_template_string(HTML_UI)


if __name__ == "__main__":
    print("====================================================")
    print(" Ứng dụng đang chạy Local tại: http://127.0.0.1:5000")
    print(" Tài khoản mặc định:           admin / AnToan@2026")
    print("====================================================")
    app.run(host="127.0.0.1", port=5000, debug=True)
