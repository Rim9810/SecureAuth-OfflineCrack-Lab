from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
DEMO_DIR = ROOT_DIR / "src" / "democrackpwd"

def test_dataset_file_exists_and_not_empty():
    """Kiểm tra dataset.txt tồn tại và có dữ liệu."""
    dataset_path = DEMO_DIR / "dataset.txt"
    assert dataset_path.exists(), "Thiếu tệp dataset.txt"
    assert dataset_path.stat().st_size > 0, "Tệp dataset.txt đang trống"

def test_knotty_php_exists():
    """Kiểm tra tệp knotty.php tồn tại."""
    php_path = DEMO_DIR / "knotty.php"
    assert php_path.exists(), "Thiếu tệp knotty.php"
