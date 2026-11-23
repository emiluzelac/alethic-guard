from pathlib import Path
import subprocess
import sys
from zipfile import ZIP_DEFLATED, ZIP_STORED, ZipFile


def test_wheel_normalization_ignores_toolchain_archive_metadata(tmp_path):
    normalizer = Path(__file__).resolve().parents[2] / "scripts/normalize-kernel-wheel.py"
    first, second = tmp_path / "a.whl", tmp_path / "b.whl"
    with ZipFile(first, "w", compression=ZIP_DEFLATED) as wheel:
        wheel.writestr("alethic/kernel.py", b"kernel")
        wheel.writestr("alethic/__init__.py", b"init")
    with ZipFile(second, "w", compression=ZIP_STORED) as wheel:
        wheel.writestr("alethic/__init__.py", b"init")
        wheel.writestr("alethic/kernel.py", b"kernel")
    assert first.read_bytes() != second.read_bytes()
    for path in (first, second):
        subprocess.run([sys.executable, str(normalizer), str(path)], check=True)
    assert first.read_bytes() == second.read_bytes()
