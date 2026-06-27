"""Per-deployment sensor (#100 dual-plant, increment 1): each deployment record
carries a 6th `sensor` field (fifo|atime). The agent plants and watches EACH
bait per its own sensor, so a FIFO bait (canonical, definitive pid) and an atime
bait (companion, normal-file detection) run side by side from one agent.

macOS-gated: the pair includes a FIFO bait. The atime 'read' is simulated by
os.utime() (deterministic); the FIFO read is a real open()."""
import http.server, subprocess, threading, os, stat, time
import platform as _platform
from pathlib import Path
import pytest

pytestmark = pytest.mark.skipif(_platform.system() != "Darwin", reason="pair includes a FIFO bait (macOS)")

AGENT = Path(__file__).resolve().parents[1] / "agent" / "thumper_agent.sh"
BAIT_BODY = "AKIA-BAIT\nsecret=shhh\n"
ARMED_MAX = 1_000_000_000


class Stub(http.server.BaseHTTPRequestHandler):
    callbacks = []           # (callback_path, body)
    deployments = []         # list of (id, path, sensor)
    def log_message(self, *a): pass
    def _t(self, body=""):
        self.send_response(200); self.send_header("Content-Type", "text/plain")
        self.end_headers(); self.wfile.write(body.encode())
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0)); body = self.rfile.read(n).decode()
        if self.path == "/api/enroll": return self._t("agent_token=tok-1\nendpoint_id=ep_1\n")
        if self.path.startswith("/cb/"): Stub.callbacks.append((self.path, body)); return self._t("ok")
        if self.path.endswith("/state"): return self._t("ok")
        return self._t("ok")
    def do_GET(self):
        if self.path == "/api/agent/deployments":
            base = f"http://127.0.0.1:{self.server.server_port}"
            lines = ["\t".join([did, path, "sekret", f"{base}/content/{did}", f"{base}/cb/{did}", sensor])
                     for did, path, sensor in Stub.deployments]
            return self._t("\n".join(lines) + "\n")
        if self.path.startswith("/content/"): return self._t(BAIT_BODY)
        return self._t("")


@pytest.fixture
def server():
    httpd = http.server.HTTPServer(("127.0.0.1", 0), Stub)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    Stub.callbacks = []
    yield httpd
    httpd.shutdown()


def _spawn(server, tmp_path):
    port = server.server_port
    state = tmp_path / "agent.json"
    # NO --sensor: the per-deployment field must govern, overriding the auto-probe.
    return subprocess.Popen(
        ["sh", str(AGENT), "run", "--server", f"http://127.0.0.1:{port}",
         "--enroll-token", "e", "--tripwire", "tw_1", "--state-file", str(state),
         "--poll", "1", "--heartbeat", "0", "--sync-interval", "0"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def _wait(cond, t=15.0):
    end = time.time() + t
    while time.time() < end:
        if cond(): return True
        time.sleep(0.05)
    return False


def _fired(cb_id): return any(cb_id in p for p, _ in Stub.callbacks)


def test_mixed_sensors_plant_and_fire_together(server, tmp_path):
    fifo = tmp_path / "credentials"   # canonical -> FIFO (pid)
    atin = tmp_path / "config"        # companion -> regular file (atime detect)
    Stub.deployments = [("dep_fifo", str(fifo), "fifo"), ("dep_atime", str(atin), "atime")]
    agent = _spawn(server, tmp_path)
    try:
        # planted per its OWN sensor, not the global auto-probe
        assert _wait(lambda: fifo.exists() and stat.S_ISFIFO(fifo.stat().st_mode)), \
            "fifo-sensor bait was not planted as a named pipe"
        assert _wait(lambda: atin.exists() and atin.is_file() and atin.stat().st_atime < ARMED_MAX), \
            "atime-sensor bait was not planted as an armed regular file"
        # read the FIFO bait (blocks until the agent serves it) -> fires with pid
        threading.Thread(target=lambda: open(fifo).read(), daemon=True).start()
        # 'read' the atime bait -> fires (detection)
        os.utime(atin, (time.time(), os.stat(atin).st_mtime))
        assert _wait(lambda: _fired("/cb/dep_fifo")), "FIFO bait did not fire"
        assert _wait(lambda: _fired("/cb/dep_atime")), "atime bait did not fire"
    finally:
        agent.terminate(); agent.wait(timeout=5)
