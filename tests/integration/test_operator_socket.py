from pathlib import Path
import subprocess


def test_workload_status_uses_local_daemon(tmp_path: Path):
    result = subprocess.run(
        ["alethic-guard", "--socket", str(tmp_path / "missing.sock"), "workload",
         "status", "6c9cf14a-8226-41ea-8fa6-311abf2f6b6d"],
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 1
    assert "daemon" in result.stderr
