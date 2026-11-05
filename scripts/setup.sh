#!/usr/bin/env bash
set -e

echo "=========================================================="
echo " [1/3] Cập nhật hệ thống và cài đặt gói cơ bản..."
echo "=========================================================="
sudo apt update
sudo apt install -y python3 python3-pip python3-venv git

echo "=========================================================="
echo " [2/3] Cài đặt các thư viện Python bảo mật & kiểm thử..."
echo "=========================================================="
pip install flask flask-sqlalchemy argon2-cffi bcrypt requests pytest flake8 --break-system-packages

echo "=========================================================="
echo " [3/3] Khởi tạo thư mục dữ liệu thực nghiệm..."
echo "=========================================================="
mkdir -p data

echo "[+] Hoàn tất cài đặt môi trường! Bạn có thể chạy: bash scripts/reproduce.sh"


sudo apt update && sudo apt install php-cli git -y
echo "=========================================================="
