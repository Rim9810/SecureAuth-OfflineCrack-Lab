# Đề tài 7: Lưu trữ Mật khẩu An toàn & Phòng thủ Offline Cracking

**Mục tiêu:** Xây dựng hệ thống đăng nhập an toàn chống Credential Stuffing, Rate Limiting (Online) và mô phỏng các phương pháp tấn công bẻ khóa mật khẩu ngoại tuyến (Offline Cracking) bằng thuật toán tự xây dựng.

---

## 🛡️ Hướng dẫn Chạy Ứng dụng (App Login)

1. `cd app_login`
2. `pip install -r requirements.txt`
3. `python app.py`
4. Truy cập web tại: `http://localhost:5000`

---

## 🔨 Hướng dẫn Demo Bẻ Khóa (Offline Cracking Lab)

Nhóm triển khai 2 phương pháp tấn công mật khẩu ngoại tuyến tự xây dựng (không sử dụng công cụ bên thứ ba như Hashcat):

### 1. Phương pháp Brute Force (Tấn công vét cạn)
Thử tất cả các tổ hợp ký tự có thể dựa trên tập charset để tìm lại mật khẩu gốc từ chuỗi hash.
- `cd crack_lab`
- `python generate_dataset.py`
- `python brute_force.py`

### 2. Phương pháp Rainbow Table (Bảng cầu vồng)
Sử dụng bảng tra cứu được tính toán sẵn chứa ánh xạ giữa chuỗi hash và mật khẩu để tra cứu nhanh.
- `cd crack_lab`
- `python rainbow_table.py`