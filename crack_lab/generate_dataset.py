import hashlib
import hmac
from argon2 import PasswordHasher, Type

ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2, hash_len=32, salt_len=16, type=Type.ID)
PEPPER_SECRET = b"secret_server_pepper_key_2026"
victims = [("user1", "123456"), ("user2", "password"), ("user3", "admin123"), ("user4", "iloveyou"), ("user5", "qwerty")]

with open("sample_md5_hashes.txt", "w") as f:
    for _, pwd in victims: f.write(hashlib.md5(pwd.encode()).hexdigest() + "\n")
print("✅ Da tao sample_md5_hashes.txt")

with open("sample_argon2_hashes.txt", "w") as f:
    for _, pwd in victims:
        peppered = hmac.new(PEPPER_SECRET, pwd.encode(), hashlib.sha256).hexdigest()
        f.write(ph.hash(peppered) + "\n")
print("✅ Da tao sample_argon2_hashes.txt")
