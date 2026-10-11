"""Launcher regressions: failed setup, service failure, and process cleanup."""

import subprocess
import sys

import pytest

import start


def test_failed_install_invalidates_stamp(tmp_path):
    stamp = tmp_path / "stamp"
    stamp.write_text("previous-success")
    with pytest.raises(RuntimeError, match="Command failed"):
        start.install_if_changed([sys.executable, "-c", "raise SystemExit(7)"],
                                 stamp, "new-dependencies")
    assert not stamp.exists()


def test_unchanged_dependencies_do_not_run_install(tmp_path):
    stamp = tmp_path / "stamp"
    stamp.write_text("current\n")
    start.install_if_changed(["this-command-must-not-run"], stamp, "current")


def test_readiness_detects_service_exit():
    child = subprocess.Popen([sys.executable, "-c", "raise SystemExit(7)"])
    child.wait()
    with pytest.raises(RuntimeError, match="API exited with code 7"):
        start.wait_ready("http://127.0.0.1:1", [("API", child)])


def test_cleanup_stops_running_services():
    children = [start.spawn([sys.executable, "-c", "import time; time.sleep(60)"])
                for _ in range(2)]
    try:
        start.stop_children()
        assert all(child.poll() is not None for child in children)
    finally:
        for child in children:
            if child.poll() is None:
                child.kill()
                child.wait()
        start.CHILDREN.clear()


def test_wrong_platform_venv_has_actionable_error(tmp_path, monkeypatch):
    monkeypatch.setattr(start, "VENV", tmp_path)
    monkeypatch.setattr(start, "PYTHON", tmp_path / "missing-python")
    monkeypatch.setattr(start.shutil, "which", lambda name: name)
    monkeypatch.setattr(start.subprocess, "check_output", lambda *a, **kw: "v22.0.0")
    with pytest.raises(RuntimeError, match="from another OS"):
        start.setup()
