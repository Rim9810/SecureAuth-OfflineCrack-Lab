import sys
from pathlib import Path
import pytest

# Lấy đường dẫn gốc của dự án
ROOT_DIR = Path(__file__).resolve().parent.parent

# Thêm src/app_login và scripts vào sys.path
sys.path.insert(0, str(ROOT_DIR / "src" / "app_login"))
sys.path.insert(0, str(ROOT_DIR / "scripts"))
