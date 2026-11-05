cat << 'EOF' > src/hash_bench.py
import time
import hashlib
import bcrypt
from argon2 import PasswordHasher

TEST_PASSWORD = "Assignment7_Secure_Password_2026!"
ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)

def benchmark_algorithm(name, func, iterations=100):
    start_time = time.perf_counter()
    for _ in range(iterations):
        func()
    end_time = time.perf_counter()
    total_time = end_time - start_time
    time_per_hash_ms = (total_time / iterations) * 1000
    hashes_per_sec = iterations / total_time if total_time > 0 else 0
    print(f"| {name:<22} | {time_per_hash_ms:>12.4f} ms | {hashes_per_sec:>15,.2f} H/s |")

def main():
    print("=" * 65)
    print(" BẮT ĐẦU BENCHMARK 6 THUẬT TOÁN BĂM")
    print("=" * 65)
    print(f"| {'Thuật toán':<22} | {'Thời gian/hash':<15} | {'Tốc độ (H/s)':<17} |")
    print("|------------------------|-----------------|-------------------|")
    benchmark_algorithm("MD5 (Nhanh)", lambda: hashlib.md5(TEST_PASSWORD.encode()).hexdigest(), 10000)
    benchmark_algorithm("SHA-1 (Nhanh)", lambda: hashlib.sha1(TEST_PASSWORD.encode()).hexdigest(), 10000)
    benchmark_algorithm("PBKDF2-HMAC-SHA256", lambda: hashlib.pbkdf2_hmac('sha256', TEST_PASSWORD.encode(), b'salt_16', 600000), 10)
    benchmark_algorithm("scrypt", lambda: hashlib.scrypt(TEST_PASSWORD.encode(), salt=b'salt_16', n=16384, r=8, p=1, dklen=32), 5)
    benchmark_algorithm("bcrypt (rounds=12)", lambda: bcrypt.hashpw(TEST_PASSWORD.encode(), bcrypt.gensalt(rounds=12)), 5)
    benchmark_algorithm("Argon2id (OWASP)", lambda: ph.hash(TEST_PASSWORD), 5)
    print("=" * 65)

if __name__ == "__main__":
    main()
EOF
