from pathlib import Path
import json
import subprocess

from alethic_guard_cli import main


WORKLOAD = "6c9cf14a-8226-41ea-8fa6-311abf2f6b6d"


def test_workload_status_uses_local_daemon(tmp_path: Path):
    result = subprocess.run(
        ["alethic-guard", "--socket", str(tmp_path / "missing.sock"), "workload",
         "status", WORKLOAD],
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 1
    assert "daemon" in result.stderr


def test_cutoff_reports_only_the_emergency_response(tmp_path, monkeypatch, capsys):
    calls = []

    def daemon_call(path, request, timeout):
        calls.append((path.name, request))
        return {"broker_cutoff": "VERIFIED", "admissions": "VERIFIED"}

    monkeypatch.setattr(main, "daemon_call", daemon_call)
    assert main.main(["--socket", str(tmp_path / "operator.sock"), "workload", "cutoff", WORKLOAD]) == 0
    assert calls == [("operator.sock.emergency", {"command": "cutoff", "id": WORKLOAD})]
    assert json.loads(capsys.readouterr().out) == {"broker_cutoff": "VERIFIED", "admissions": "VERIFIED"}


def test_terminate_runs_cleanup_when_emergency_socket_is_unavailable(tmp_path, monkeypatch, capsys):
    calls = []

    def daemon_call(path, request, timeout=None):
        calls.append((path.name, request["command"]))
        if path.name.endswith(".emergency"):
            raise ValueError("socket unavailable")
        return {"shutdown": "VERIFIED"}

    monkeypatch.setattr(main, "daemon_call", daemon_call)
    assert main.main(["--socket", str(tmp_path / "operator.sock"), "workload", "terminate", WORKLOAD]) == 0
    assert calls == [("operator.sock.emergency", "cutoff"), ("operator.sock", "terminate")]
    result = json.loads(capsys.readouterr().out)
    assert result["shutdown"] == "VERIFIED"
    assert result["emergency"] == {"broker_cutoff": "UNKNOWN", "error": "socket unavailable"}


def test_emergency_terminate_uses_only_the_emergency_socket(tmp_path, monkeypatch, capsys):
    calls = []

    def daemon_call(path, request, timeout):
        calls.append((path.name, request))
        return {"broker_cutoff": "VERIFIED", "shutdown": "UNKNOWN"}

    monkeypatch.setattr(main, "daemon_call", daemon_call)
    result = main.main(["--socket", str(tmp_path / "operator.sock"), "workload",
                        "emergency-terminate", WORKLOAD])
    assert result == 0
    assert calls == [("operator.sock.emergency", {"command": "terminate", "id": WORKLOAD})]
    assert json.loads(capsys.readouterr().out)["shutdown"] == "UNKNOWN"
