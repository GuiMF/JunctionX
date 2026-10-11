#!/usr/bin/env python3
"""Set up and run the local API and dashboard on Windows, macOS, or Linux."""

import argparse
import hashlib
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import time
from urllib.error import URLError
from urllib.request import build_opener, ProxyHandler


ROOT = Path(__file__).resolve().parent
WEB = ROOT / "web"
VENV = ROOT / ".venv"
WINDOWS = os.name == "nt"
PYTHON = VENV / ("Scripts/python.exe" if WINDOWS else "bin/python")
CHILDREN = []


def say(message):
    print("[QuantumTrace] " + message, flush=True)


def spawn(command, cwd=ROOT, env=None):
    options = {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if WINDOWS else {
        "start_new_session": True,
    }
    child = subprocess.Popen([str(arg) for arg in command], cwd=cwd, env=env, **options)
    CHILDREN.append(child)
    return child


def run(command, cwd=ROOT):
    child = spawn(command, cwd=cwd)
    code = child.wait()
    CHILDREN.remove(child)
    if code:
        raise RuntimeError("Command failed (exit %s): %s" % (code, command[0]))


def stop_children():
    for child in reversed(CHILDREN):
        if WINDOWS:
            if child.poll() is None:
                # Kill the whole tree, including npm's shell and child processes.
                subprocess.run(["taskkill", "/PID", str(child.pid), "/T", "/F"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            try:
                os.killpg(child.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
    deadline = time.monotonic() + 5
    for child in reversed(CHILDREN):
        try:
            child.wait(timeout=max(0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            if not WINDOWS:
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            else:
                child.kill()
            child.wait()


def python_supported(command):
    try:
        return subprocess.run(
            command + ["-c", "import sys; sys.exit(sys.version_info < (3, 12))"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        ).returncode == 0
    except OSError:
        return False


def find_python():
    candidates = [[sys.executable]]
    if WINDOWS:
        candidates.append(["py", "-3"])
    candidates += [["python3.%s" % minor] for minor in range(15, 11, -1)]
    candidates += [["python3"], ["python"]]
    for command in candidates:
        if python_supported(command):
            return command
    raise RuntimeError("Install Python 3.12 or newer, reopen your terminal, and retry.")


def fingerprint(paths):
    digest = hashlib.sha256()
    for path in paths:
        digest.update(path.read_bytes())
    return digest.hexdigest()


def install_if_changed(command, stamp, digest, force=False, cwd=ROOT):
    if force or not stamp.exists() or stamp.read_text().strip() != digest:
        # Never retain a successful stamp after a failed or interrupted install.
        stamp.unlink(missing_ok=True)
        run(command, cwd=cwd)
        stamp.write_text(digest + "\n")


def setup(force=False):
    node = shutil.which("node")
    npm = shutil.which("npm.cmd" if WINDOWS else "npm")
    if not node or not npm:
        raise RuntimeError("Install Node.js 22+ (including npm), reopen your terminal, and retry.")
    version = subprocess.check_output([node, "--version"], text=True).strip()
    if int(version.lstrip("v").split(".")[0]) < 22:
        raise RuntimeError("Node.js 22+ is required; found " + version)
    if PYTHON.exists():
        if not python_supported([str(PYTHON)]):
            raise RuntimeError(".venv needs Python 3.12+. Rename or remove .venv, then retry.")
    elif VENV.exists():
        raise RuntimeError(".venv is incomplete or from another OS. Rename or remove it, then retry.")
    else:
        command = find_python()
        say("Creating .venv with " + " ".join(command))
        run(command + ["-m", "venv", str(VENV)])
    say("Checking Python dependencies...")
    install_if_changed(
        [PYTHON, "-m", "pip", "install", "-r", ROOT / "requirements.txt"],
        VENV / ".requirements.sha256", fingerprint([ROOT / "requirements.txt"]), force,
    )
    say("Checking dashboard dependencies...")
    vite = WEB / "node_modules/vite/bin/vite.js"
    install_if_changed(
        [npm, "ci"], WEB / "node_modules/.quantumtrace-dependencies.sha256",
        fingerprint([WEB / "package.json", WEB / "package-lock.json"]) + version,
        force or not vite.exists(), cwd=WEB,
    )
    if not shutil.which("tshark"):
        say("Optional: install Wireshark/TShark for capture scans. Source and AWS scans are ready.")
    return node, vite


def check_port(port):
    with socket.socket() as sock:
        try:
            sock.bind(("127.0.0.1", port))
        except OSError as error:
            raise RuntimeError("Cannot bind port %s: %s. If it is in use, stop that service and retry."
                               % (port, error)) from error


def wait_ready(url, services):
    # Local development traffic should not go through a system HTTP proxy.
    opener = build_opener(ProxyHandler({}))
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        for name, child in services:
            if child.poll() is not None:
                raise RuntimeError("%s exited with code %s. See its output above." % (name, child.returncode))
        try:
            with opener.open(url, timeout=1) as response:
                if response.status == 200:
                    return
        except (URLError, OSError):
            pass
        time.sleep(0.2)
    raise RuntimeError("Timed out waiting for " + url)


def api_port(value):
    port = int(value)
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("Choose a port from 1 to 65535.")
    return port


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=api_port, default=8000, help="API port (default: 8000)")
    parser.add_argument("--web-port", type=api_port, default=5173,
                        help="Dashboard port (default: 5173)")
    parser.add_argument("--reinstall", action="store_true", help="Reinstall both sets of dependencies")
    args = parser.parse_args()
    if args.port == args.web_port:
        parser.error("API and dashboard ports must be different.")
    check_port(args.port)
    check_port(args.web_port)
    node, vite = setup(args.reinstall)
    api_url = "http://127.0.0.1:%s" % args.port
    web_url = "http://127.0.0.1:%s" % args.web_port
    api_env = dict(os.environ, CORS_ORIGINS=web_url + ",http://localhost:%s" % args.web_port)
    say("Starting API...")
    api = spawn([PYTHON, "-m", "uvicorn", "api.main:app", "--host", "127.0.0.1",
                 "--port", str(args.port)], env=api_env)
    services = [("API", api)]
    wait_ready(api_url + "/openapi.json", services)
    env = dict(os.environ, VITE_API_BASE_URL=api_url)
    say("Starting dashboard...")
    # Run Vite directly so there is no npm shell between us and the server.
    dashboard = spawn([node, vite, "--host", "127.0.0.1", "--port", str(args.web_port), "--strictPort"],
                      cwd=WEB, env=env)
    services.append(("Dashboard", dashboard))
    wait_ready(web_url, services)
    say("Ready! Open " + web_url)
    say("API docs: " + api_url + "/docs | Ctrl-C stops both services.")
    while True:
        for name, child in services:
            if child.poll() is not None:
                raise RuntimeError("%s exited with code %s. Stopping both services." % (name, child.returncode))
        time.sleep(0.3)


def interrupt(signum, frame):
    raise KeyboardInterrupt


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, interrupt)
    try:
        main()
    except KeyboardInterrupt:
        say("Stopping...")
    except (RuntimeError, OSError, subprocess.SubprocessError) as error:
        say("ERROR: " + str(error))
        sys.exit(1)
    finally:
        # A second Ctrl-C must not interrupt cleanup and leave servers running.
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        stop_children()
