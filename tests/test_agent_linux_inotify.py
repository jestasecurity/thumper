"""Linux read sensor (#7, foundation for CI/CD #3): on Linux with inotifywait,
the agent watches bait via inotify IN_ACCESS and fires the signed callback.

Runs on any OS by faking `uname` (-> Linux) and `inotifywait` (emits the watched
path to simulate an access) on PATH, so it exercises the Linux dispatch branch +
the agent's parse/fire wiring without a real Linux kernel.
"""
import http.server
import os
import signal
import subprocess
import threading
import time
from pathlib import Path

import pytest

AGENT = Path(__file__).resolve().parents[1] / "agent" / "thumper_agent.sh"
BAIT_BODY = "BAIT-honeytoken-content"


class _Stub(http.server.BaseHTTPRequestHandler):
    seen = []
    bait_path = ""

    def log_message(self, *_a):
        pass

    def _text(self, body):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(body.encode())

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        _Stub.seen.append(self.path)
        self._text("agent_token=tok-123\nendpoint_id=ep_1\n"
                   if self.path == "/api/enroll" else "ok")

    def do_GET(self):
        if self.path == "/api/agent/deployments":
            base = f"http://{self.headers['Host']}"
            self._text("\t".join(["dep_0", _Stub.bait_path, "secret",
                                   f"{base}/content/dep_0", f"{base}/cb/dep_0"]) + "\n")
        elif self.path.startswith("/content/"):
            self._text(BAIT_BODY)
        else:
            self.send_response(404)
            self.end_headers()


def _write(path, body):
    path.write_text(body)
    path.chmod(0o755)


@pytest.fixture
def fakes(tmp_path):
    d = tmp_path / "fakebin"
    d.mkdir()
    _write(d / "uname", "#!/bin/sh\necho Linux\n")
    # Simulate an access: print the watched path(s) (args after --) then stay alive.
    _write(d / "inotifywait", "#!/bin/sh\npaths=\nwhile [ $# -gt 0 ]; do "
           "case \"$1\" in --) shift; paths=\"$*\"; break ;; *) shift ;; esac; done\n"
           "sleep 0.5\nfor p in $paths; do printf '%s\\n' \"$p\"; done\nsleep 30\n")
    return d


def test_inotify_read_fires_callback(tmp_path, fakes):
    httpd = http.server.HTTPServer(("127.0.0.1", 0), _Stub)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    bait = tmp_path / "bait"               # agent plants it (must not pre-exist)
    _Stub.bait_path = str(bait)
    _Stub.seen = []

    env = {**os.environ, "PATH": f"{fakes}:{os.environ['PATH']}"}
    proc = subprocess.Popen(
        ["sh", str(AGENT), "run", "--server", base, "--enroll-token", "dev-enroll-token",
         "--tripwire", "tw", "--state-file", str(tmp_path / "state" / "agent.json"),
         "--heartbeat", "0", "--sync-interval", "0"],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        deadline = time.time() + 12
        while time.time() < deadline:
            if "/cb/dep_0" in _Stub.seen:
                break
            time.sleep(0.2)
        assert "/cb/dep_0" in _Stub.seen, "inotify access did not fire the callback"
        assert bait.read_text() == BAIT_BODY  # bait was planted
    finally:
        proc.send_signal(signal.SIGTERM)
        proc.wait(timeout=10)
        httpd.shutdown()


def test_inotify_failure_degrades_to_atime(tmp_path, fakes):
    # inotifywait that dies immediately (e.g. fs.inotify watch-limit exhaustion)
    # must NOT leave a silently-dark sensor - the agent logs the failure (stderr
    # not swallowed) and falls back to the atime poll instead of going blind.
    _write(fakes / "inotifywait",
           "#!/bin/sh\necho 'inotifywait: failed to add watch (max_user_watches)' >&2\nexit 1\n")
    httpd = http.server.HTTPServer(("127.0.0.1", 0), _Stub)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    bait = tmp_path / "bait"
    _Stub.bait_path = str(bait)
    _Stub.seen = []

    env = {**os.environ, "PATH": f"{fakes}:{os.environ['PATH']}"}
    logf = (tmp_path / "agent.out").open("w+")
    proc = subprocess.Popen(
        ["sh", str(AGENT), "run", "--server", base, "--enroll-token", "dev-enroll-token",
         "--tripwire", "tw", "--state-file", str(tmp_path / "state" / "agent.json"),
         "--heartbeat", "0", "--sync-interval", "0", "--poll", "1"],
        env=env, stdout=logf, stderr=subprocess.STDOUT, text=True)
    try:
        deadline = time.time() + 10
        text = ""
        while time.time() < deadline:
            text = (tmp_path / "agent.out").read_text()
            if "degrading to atime poll" in text and "atime poll every" in text:
                break
            time.sleep(0.2)
        # The dead sensor is visible (not swallowed) AND we kept some coverage.
        assert "inotifywait: failed to add watch" in text, "inotifywait stderr was swallowed"
        assert "inotify watcher exited unexpectedly - degrading to atime poll" in text
        assert "atime poll every" in text, "did not fall back to the atime poll"
    finally:
        proc.send_signal(signal.SIGTERM)
        proc.wait(timeout=10)
        httpd.shutdown()
        logf.close()
