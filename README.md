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

Tạo bảng Rainbow_table bằng công cụ knotty ( được viết bằng ngôn ngữ php). Rồi so sánh dataset có chứa các mã băm thuật toán md5 bị rò rỉ với bảng rainbow_table được tạo từ hàng triệu mật khẩu đã được băm sang md5.

1. git clone https://github.com/prodigiousMind/knotty.git
2. cd knotty
3. for i in $(cat plaintext-wordlists.txt); do php knotty.php plaintext=$i salt1= salt2= format=2 algo=md5; done > rainbow_table.txt
   php -r '$f=fopen("plaintext-wordlists.txt","r"); while(($p=fgets($f))!==false){ $p=rtrim($p,"\r\n"); echo md5($p).":md5:".$p."\n"; } fclose($f);' > rainbow_table.txt
4. grep -f database.txt rainbowtable.txt
