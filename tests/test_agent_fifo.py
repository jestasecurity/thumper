"""FIFO bait sensor (#100): bait is planted as a named pipe; a read of it
unblocks the agent's write and fires a callback. Driven against a stub server,
like test_agent_live_sync.py."""
import http.server, socket, subprocess, threading, time, os, stat
from pathlib import Path
import pytest

AGENT = Path(__file__).resolve().parents[1] / "agent" / "thumper_agent.sh"
BAIT_BODY = "AKIA-BAIT\nsecret=shhh\n"

class Stub(http.server.BaseHTTPRequestHandler):
    callbacks = []           # POSTed callback bodies
    bait_path = ""           # absolute path the agent should plant
    def log_message(self, *a): pass
    def _t(self, body=""):
        self.send_response(200); self.send_header("Content-Type","text/plain")
        self.end_headers(); self.wfile.write(body.encode())
    def do_POST(self):
        n=int(self.headers.get("Content-Length",0)); body=self.rfile.read(n).decode()
        if self.path == "/api/enroll": return self._t("agent_token=tok-1\nendpoint_id=ep_1\n")
        if self.path.startswith("/cb/"): Stub.callbacks.append(body); return self._t("ok")
        if self.path.endswith("/state"): return self._t("ok")
        return self._t("ok")
    def do_GET(self):
        if self.path == "/api/agent/deployments":
            base=f"http://127.0.0.1:{self.server.server_port}"
            rec="\t".join(["dep_1", Stub.bait_path, "sekret", f"{base}/content/dep_1", f"{base}/cb/dep_1"])
            return self._t(rec+"\n")
        if self.path.startswith("/content/"): return self._t(BAIT_BODY)
        return self._t("")

@pytest.fixture
def server():
    httpd = http.server.HTTPServer(("127.0.0.1",0), Stub)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    Stub.callbacks = []
    yield httpd
    httpd.shutdown()

def _run(server, tmp_path, *extra, timeout=15):
    port = server.server_port
    state = tmp_path / "agent.json"
    return subprocess.run(
        ["sh", str(AGENT), "run", "--server", f"http://127.0.0.1:{port}",
         "--enroll-token", "e", "--tripwire", "tw_1", "--state-file", str(state),
         "--heartbeat", "0", *extra],
        capture_output=True, text=True, timeout=timeout)

def test_plant_creates_a_fifo_and_caches_content(server, tmp_path):
    bait = tmp_path / "bait_aws"
    Stub.bait_path = str(bait)
    _run(server, tmp_path, "--once")
    assert bait.exists() and stat.S_ISFIFO(bait.stat().st_mode), "bait is not a FIFO"
    cache = tmp_path / "bait" / "dep_1"
    assert cache.read_text() == BAIT_BODY, "bait content not cached"
