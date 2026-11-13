# Đề tài 7: Lưu trữ Mật khẩu An toàn & Phòng thủ Offline Cracking

**Mục tiêu:** Xây dựng hệ thống đăng nhập an toàn chống Credential Stuffing, Rate Limiting (Online) và mô phỏng các phương pháp tấn công bẻ khóa mật khẩu ngoại tuyến (Offline Cracking) bằng thuật toán tự xây dựng.

---

## 🛡️ Hướng dẫn Chạy Ứng dụng (App Login)

1. `cd app_login`
2. `pip install -r requirements.txt`
3. `python app.py`
4. Truy cập web tại: `http://localhost:5000`

---

## 🔨 Hướng dẫn Demo Bẻ Khóa Bằng Từ Điển (Offline Dictionary Cracking Lab)

Tạo từ điển mã băm (Precomputed Dictionary) bằng công cụ knotty (được viết bằng ngôn ngữ PHP). Sau đó, so sánh dataset có chứa các mã băm MD5 bị rò rỉ với từ điển mã băm vừa được tạo từ danh sách mật khẩu rõ để tìm ra mật khẩu gốc.

1. git clone https://github.com/prodigiousMind/knotty.git
2. cd knotty
3. Tạo file từ điển mã băm (chạy 1 trong 2 lệnh dưới đây):
   - Cách 1 (Sử dụng script knotty):
     for i in $(cat plaintext-wordlists.txt); do php knotty.php plaintext=$i salt1= salt2= format=2 algo=md5; done > hashed_wordlist.txt
   - Cách 2 (Sử dụng lệnh PHP thuần):
     php -r '$f=fopen("plaintext-wordlists.txt","r"); while(($p=fgets($f))!==false){ $p=rtrim($p,"\r\n"); echo md5($p).":md5:".$p."\n"; } fclose($f);' > hashed_wordlist.txt
4. grep -w -f database.txt hashed_wordlist.txt
