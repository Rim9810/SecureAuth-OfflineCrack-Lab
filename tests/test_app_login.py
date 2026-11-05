import sys
from pathlib import Path
import pytest

# Thêm đường dẫn src/app_login vào hệ thống để import được app.py
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR / "src" / "app_login"))

import app as login_app


@pytest.fixture(autouse=True)
def setup_isolated_env(tmp_path, monkeypatch):
    """
    Fixture tự động chạy trước mỗi hàm test:
    - Chuyển DATASET_FILE sang tệp tạm để không ảnh hưởng dữ liệu thật.
    - Reset lại DYNAMIC_DATASET và bộ đếm Rate Limit (FAILED_LOGIN_LOG).
    """
    temp_dataset = tmp_path / "test_users_dataset.json"
    monkeypatch.setattr(login_app, "DATASET_FILE", str(temp_dataset))
    
    login_app.DYNAMIC_DATASET.clear()
    login_app.FAILED_LOGIN_LOG.clear()
    login_app.load_dataset()
    
    yield


@pytest.fixture
def client():
    """Khởi tạo Flask test client."""
    login_app.app.config["TESTING"] = True
    with login_app.app.test_client() as client:
        yield client


# =====================================================================
# 1. KIỂM THỬ CÁC HÀM BẢO MẬT CỐT LÕI (PEPPER, ARGON2, HIBP)
# =====================================================================
def test_apply_pepper_and_argon2_verify():
    """Kiểm tra hàm apply_pepper và xác thực băm Argon2id."""
    raw_pwd = "MatKhauTest@2026"
    peppered_1 = login_app.apply_pepper(raw_pwd)
    peppered_2 = login_app.apply_pepper(raw_pwd)

    # Cùng mật khẩu phải cho ra cùng chuỗi HMAC-SHA256
    assert peppered_1 == peppered_2
    assert len(peppered_1) == 64

    # Băm bằng Argon2id và verify chính xác
    hashed = login_app.ph.hash(peppered_1)
    assert login_app.ph.verify(hashed, peppered_1) is True


def test_is_password_pwned():
    """Kiểm tra bộ lọc mật khẩu lộ lọt theo cơ chế k-Anonymity."""
    assert login_app.is_password_pwned("12345678") is True
    assert login_app.is_password_pwned("welcome123") is True
    assert login_app.is_password_pwned("admin123") is True
    assert login_app.is_password_pwned("AnToanTuyetDoi#2026") is False


# =====================================================================
# 2. KIỂM THỬ GIAO DIỆN & API DATASET
# =====================================================================
def test_index_ui(client):
    """Kiểm tra trang chủ trả về giao diện HTML thành công."""
    res = client.get("/")
    assert res.status_code == 200
    assert "Đăng nhập hệ thống".encode("utf-8") in res.data


def test_api_view_dataset(client):
    """Kiểm tra API /api/dataset khởi tạo sẵn tài khoản admin."""
    res = client.get("/api/dataset")
    assert res.status_code == 200
    data = res.get_json()
    assert data["total_accounts"] == 1
    assert data["accounts"][0]["username"] == "admin"


# =====================================================================
# 3. KIỂM THỬ API ĐĂNG KÝ (/api/register)
# =====================================================================
def test_register_success(client):
    """Kiểm tra đăng ký tài khoản mới hợp lệ."""
    res = client.post("/api/register", json={
        "username": "new_user",
        "password": "StrongPassword@123",
        "confirm_password": "StrongPassword@123"
    })
    assert res.status_code == 200
    assert "thành công" in res.get_json()["message"]
    assert login_app.find_user("new_user") is not None


@pytest.mark.parametrize("payload,expected_status", [
    ({"username": "", "password": "ValidPassword123", "confirm_password": "ValidPassword123"}, 400),
    ({"username": "ab", "password": "ValidPassword123", "confirm_password": "ValidPassword123"}, 400),
    ({"username": "ADMIN", "password": "ValidPassword123", "confirm_password": "ValidPassword123"}, 409),
    ({"username": "user1", "password": "short", "confirm_password": "short"}, 400),
    ({"username": "user1", "password": "ValidPassword123", "confirm_password": "DifferentPassword"}, 400),
    ({"username": "user1", "password": "12345678", "confirm_password": "12345678"}, 422),
])
def test_register_validation_errors(client, payload, expected_status):
    """Kiểm tra các trường hợp dữ liệu đăng ký không hợp lệ hoặc mật khẩu bị lộ."""
    res = client.post("/api/register", json=payload)
    assert res.status_code == expected_status
    assert "error" in res.get_json()


# =====================================================================
# 4. KIỂM THỬ API ĐĂNG NHẬP (/api/login) & RATE LIMIT
# =====================================================================
def test_login_admin_success(client):
    """Kiểm tra đăng nhập thành công với tài khoản admin mặc định."""
    res = client.post("/api/login", json={
        "username": "admin",
        "password": "AnToan@2026"
    })
    assert res.status_code == 200
    data = res.get_json()
    assert data["username"] == "admin"
    assert "thành công" in data["message"]


def test_login_missing_credentials(client):
    """Kiểm tra báo lỗi 400 khi bỏ trống thông tin đăng nhập."""
    res = client.post("/api/login", json={"username": "admin", "password": ""})
    assert res.status_code == 400


def test_login_wrong_password_and_nonexistent_user(client):
    """Kiểm tra đăng nhập sai mật khẩu hoặc tài khoản không tồn tại."""
    # Sai mật khẩu tài khoản có thật
    res1 = client.post("/api/login", json={"username": "admin", "password": "WrongPassword"})
    assert res1.status_code == 401
    assert "Còn 4 lần thử" in res1.get_json()["error"]

    # Tài khoản không tồn tại (chạy qua nhánh DUMMY_HASH)
    res2 = client.post("/api/login", json={"username": "ghost_user", "password": "WrongPassword"})
    assert res2.status_code == 401
    assert "Còn 3 lần thử" in res2.get_json()["error"]


def test_login_rate_limit_lockout(client):
    """Kiểm tra cơ chế khóa 3 phút (HTTP 429) khi đăng nhập sai 5 lần liên tiếp."""
    for i in range(4):
        res = client.post("/api/login", json={"username": "admin", "password": "WrongPassword"})
        assert res.status_code == 401

    # Lần sai thứ 5 sẽ kích hoạt khóa tạm thời (429)
    res_5th = client.post("/api/login", json={"username": "admin", "password": "WrongPassword"})
    assert res_5th.status_code == 429
    data_5th = res_5th.get_json()
    assert "retry_after" in data_5th
    assert data_5th["retry_after"] > 0

    # Khi đang bị khóa, nhập đúng mật khẩu vẫn phải trả về 429
    res_blocked = client.post("/api/login", json={"username": "admin", "password": "AnToan@2026"})
    assert res_blocked.status_code == 429


def test_login_success_resets_failed_attempts(client):
    """Kiểm tra đăng nhập thành công sẽ xóa lịch sử nhập sai trước đó."""
    # Nhập sai 2 lần
    client.post("/api/login", json={"username": "admin", "password": "WrongPassword"})
    client.post("/api/login", json={"username": "admin", "password": "WrongPassword"})

    # Nhập đúng ở lần thứ 3
    res_ok = client.post("/api/login", json={"username": "admin", "password": "AnToan@2026"})
    assert res_ok.status_code == 200

    # Nhập sai lại từ đầu phải báo còn 4 lần thử (đã reset bộ đếm)
    res_fail = client.post("/api/login", json={"username": "admin", "password": "WrongPassword"})
    assert res_fail.status_code == 401
    assert "Còn 4 lần thử" in res_fail.get_json()["error"]
