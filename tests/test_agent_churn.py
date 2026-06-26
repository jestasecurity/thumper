"""Churn-ledger best-effort suspect shortlist (#124): the atime sensor is
detection-only (no pid). A lightweight process-churn ledger records recently
-spawned processes; when an atime bait trips, the agent attaches a best-effort
`suspects=` shortlist to the alert. Validated behaviour: the shortlist *captures*
the reader (it does not claim a single definitive pid - that would be a false
attribution). Here we assert a known recently-spawned process appears in it.

Cross-platform (atime layer runs on macOS + Linux). The 'read' is simulated by
bumping atime via os.utime(), so detection is deterministic."""
import http.server, subprocess, threading, os, time
from pathlib import Path
import pytest

AGENT = Path(__file__).resolve().parents[1] / "agent" / "thumper_agent.sh"
BAIT_BODY = "AKIA-BAIT\nsecret=shhh\n"
ARMED_MAX = 1_000_000_000


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


def _wait(cond, t=15.0):
    end = time.time() + t
    while time.time() < end:
        if cond(): return True
        time.sleep(0.05)
    return False


def _suspect_lines():
    return [c for c in Stub.callbacks if "suspects=" in c]


def test_atime_alert_carries_a_suspect_shortlist_with_the_reader(server, tmp_path):
    bait = tmp_path / "credentials"; Stub.bait_path = str(bait)
    agent = _spawn(server, tmp_path)
    # A recently-spawned, still-alive process the churn ledger should record.
    reader = subprocess.Popen(["sleep", "30"])
    try:
        assert _wait(lambda: bait.exists() and os.stat(bait).st_atime < ARMED_MAX), "bait not planted+armed"
        time.sleep(2.0)  # let the churn ledger tick and record `reader`
        os.utime(bait, (time.time(), os.stat(bait).st_mtime))  # simulate a read -> trip
        assert _wait(lambda: _suspect_lines()), "alert carried no suspects= shortlist"
        # the shortlist must CAPTURE the recently-spawned reader (by pid)
        assert _wait(lambda: any(str(reader.pid) in c for c in _suspect_lines())), \
            "suspect shortlist did not capture the recently-spawned reader pid"
    finally:
        reader.terminate(); reader.wait(timeout=5)
        agent.terminate(); agent.wait(timeout=5)
