# Đề tài 7: Lưu trữ Mật khẩu An toàn & Phòng thủ Offline Cracking
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
