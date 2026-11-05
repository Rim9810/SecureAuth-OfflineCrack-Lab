cat << 'EOF' > src/gen_dynamic_dataset.py
import hashlib
import random
import string
import csv
import os
import sys

FIRST_NAMES = ["An", "Binh", "Chi", "Dung", "Huy", "Linh", "Minh", "Nam", "Phuong", "Thao"]
WEAK_PASSWORDS = ["123456", "password", "qwerty", "admin123", "iloveyou", "12345678", "welcome1"]
SPECIAL_CHARS = ["@", "!", "#", "$", "_", "-"]

def generate_dynamic_dataset(num_users: int = 50, output_dir: str = "data", seed: int = 42):
    """
    Sinh dataset động phục vụ phân tích bảo mật (CLO2 & CLO3):
    - Đảm bảo tính tái lập (Reproducibility) qua tham số seed.
    - Chia thành 3 nhóm độ mạnh: weak (từ điển), alphanum_6 (khớp bảng 1-6 ký tự), strong (phức tạp).
    """
    random.seed(seed)
    os.makedirs(output_dir, exist_ok=True)
    users_data = []
    stats = {"weak": 0, "alphanum_6": 0, "strong": 0}

    alphanum_chars = string.ascii_letters + string.digits

    for i in range(1, num_users + 1):
        username = f"user_{FIRST_NAMES[i % len(FIRST_NAMES)].lower()}_{i:03d}"
        rand_val = random.random()

        if rand_val < 0.4:
            # 40%: Mật khẩu yếu phổ biến trong từ điển
            password = random.choice(WEAK_PASSWORDS)
            category = "weak"
        elif rand_val < 0.7:
            # 30%: Mật khẩu chữ và số dài đúng 6 ký tự (khớp tập mixalpha-numeric 1-6)
            password = "".join(random.choices(alphanum_chars, k=6))
            category = "alphanum_6"
        else:
            # 30%: Mật khẩu phức tạp có ký tự đặc biệt và độ dài lớn hơn 8
            name_part = random.choice(FIRST_NAMES)
            char_part = random.choice(SPECIAL_CHARS)
            num_part = random.randint(2020, 2099)
            password = f"{name_part}{char_part}{num_part}!"
            category = "strong"

        stats[category] += 1
        users_data.append((username, password, category))

    csv_path = os.path.join(output_dir, "users_dynamic_plain.csv")
    md5_path = os.path.join(output_dir, "md5_dynamic.txt")
    sha1_path = os.path.join(output_dir, "sha1_dynamic.txt")

    with open(csv_path, "w", newline="", encoding="utf-8") as f_plain, \
         open(md5_path, "w", encoding="utf-8") as f_md5, \
         open(sha1_path, "w", encoding="utf-8") as f_sha1:
        
        writer = csv.writer(f_plain)
        writer.writerow(["username", "password", "category"])
        
        for uname, pwd, category in users_data:
            writer.writerow([uname, pwd, category])
            f_md5.write(hashlib.md5(pwd.encode()).hexdigest() + "\n")
            f_sha1.write(hashlib.sha1(pwd.encode()).hexdigest() + "\n")

    print(f"[+] Đã sinh thành công dataset động gồm {num_users} tài khoản (Seed={seed})!")
    print(f"    - Phân bổ: {stats['weak']} weak | {stats['alphanum_6']} alphanum_6 | {stats['strong']} strong")
    print(f"    - File gốc:  {csv_path}")
    print(f"    - File MD5:  {md5_path}")
    print(f"    - File SHA1: {sha1_path}")
    return users_data

if __name__ == "__main__":
    count = int(sys.argv[1]) if len(sys.argv) > 1 else 50
    generate_dynamic_dataset(num_users=count)
EOF
