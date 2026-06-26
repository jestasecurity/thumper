"""Re-armable atime sensor (#28 / #100 layered design): `--sensor atime` plants
the bait as a NORMAL regular file whose atime is armed to the past; a read bumps
atime, the agent fires AND re-arms so the NEXT read is detectable too.

Reads are simulated by bumping atime via os.utime(), so the test is deterministic
regardless of the filesystem's relatime policy. Cross-platform (macOS + Linux):
atime is the primary regular-file detection layer on both."""
import http.server, subprocess, threading, os, time
from pathlib import Path
import pytest

AGENT = Path(__file__).resolve().parents[1] / "agent" / "thumper_agent.sh"
BAIT_BODY = "AKIA-BAIT\nsecret=shhh\n"
ARMED_MAX = 1_000_000_000   # armed atime (~year 2000, ~9.46e8) is well below "now" (~1.7e9)


class Stub(http.server.BaseHTTPRequestHandler):
    callbacks = []
    bait_path = ""
    def log_message(self, *a): pass
    def _t(self, body=""):
        self.send_response(200); self.send_header("Content-Type", "text/plain")
        self.end_headers(); self.wfile.write(body.encode())
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0)); body = self.rfile.read(n).decode()
        if self.path == "/api/enroll": return self._t("agent_token=tok-1\nendpoint_id=ep_1\n")
        if self.path.startswith("/cb/"): Stub.callbacks.append(body); return self._t("ok")
        if self.path.endswith("/state"): return self._t("ok")
        return self._t("ok")
    def do_GET(self):
        if self.path == "/api/agent/deployments":
            base = f"http://127.0.0.1:{self.server.server_port}"
            rec = "\t".join(["dep_1", Stub.bait_path, "sekret", f"{base}/content/dep_1", f"{base}/cb/dep_1"])
            return self._t(rec + "\n")
        if self.path.startswith("/content/"): return self._t(BAIT_BODY)
        return self._t("")


@pytest.fixture
def server():
    httpd = http.server.HTTPServer(("127.0.0.1", 0), Stub)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    Stub.callbacks = []
    yield httpd
    httpd.shutdown()


def _spawn(server, tmp_path, *extra):
    port = server.server_port
    state = tmp_path / "agent.json"
    return subprocess.Popen(
        ["sh", str(AGENT), "run", "--server", f"http://127.0.0.1:{port}",
         "--enroll-token", "e", "--tripwire", "tw_1", "--state-file", str(state),
         "--sensor", "atime", "--poll", "1", "--heartbeat", "0", "--sync-interval", "0", *extra],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def _wait(cond, t=12.0):
    end = time.time() + t
    while time.time() < end:
        if cond(): return True
        time.sleep(0.05)
    return False


def _atime(p): return os.stat(p).st_atime
def _atime_hits(): return sum("atime" in c for c in Stub.callbacks)


def test_atime_sensor_plants_a_regular_file_and_arms_it(server, tmp_path):
    bait = tmp_path / "credentials"; Stub.bait_path = str(bait)
    p = _spawn(server, tmp_path)
    try:
        assert _wait(lambda: bait.exists() and bait.is_file()), "bait was not planted as a regular file"
        assert _wait(lambda: _atime(bait) < ARMED_MAX), "atime sensor did not arm the bait to the past"
    finally:
        p.terminate(); p.wait(timeout=5)


def test_atime_sensor_is_rearmable(server, tmp_path):
    bait = tmp_path / "credentials"; Stub.bait_path = str(bait)
    p = _spawn(server, tmp_path)
    try:
        assert _wait(lambda: bait.exists() and _atime(bait) < ARMED_MAX), "bait not planted+armed"
        # simulate read #1: bump atime forward (what a real read does under relatime)
        os.utime(bait, (time.time(), os.stat(bait).st_mtime))
        assert _wait(lambda: _atime_hits() >= 1), "read #1 was not detected"
        # the agent MUST re-arm so the next read is detectable
        assert _wait(lambda: _atime(bait) < ARMED_MAX), "bait was not re-armed after detection"
        # simulate read #2
        os.utime(bait, (time.time(), os.stat(bait).st_mtime))
        assert _wait(lambda: _atime_hits() >= 2), "read #2 not detected (re-arm is broken)"
    finally:
        p.terminate(); p.wait(timeout=5)
