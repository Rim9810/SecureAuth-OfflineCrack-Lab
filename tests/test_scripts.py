from pathlib import Path
import gen_dynamic_dataset
import hash_bench

ROOT_DIR = Path(__file__).resolve().parent.parent

def test_scripts_imported():
    """Đảm bảo các script không có lỗi cú pháp khi import."""
    assert gen_dynamic_dataset is not None
    assert hash_bench is not None

def test_setup_script_exists():
    """Kiểm tra tệp setup.sh tồn tại trong thư mục scripts."""
    setup_file = ROOT_DIR / "scripts" / "setup.sh"
    assert setup_file.exists(), "Không tìm thấy scripts/setup.sh"
