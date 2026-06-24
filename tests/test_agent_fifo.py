"""FIFO bait sensor (#100): bait is planted as a named pipe; a read of it
unblocks the agent's write and fires a callback. Driven against a stub server,
like test_agent_live_sync.py."""
import http.server, subprocess, threading, os, stat, time
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

def _wait(pred, timeout=12):
    end=time.time()+timeout
    while time.time()<end:
        if pred(): return True
        time.sleep(0.2)
    return False

def test_callback_includes_reader_pid_and_user(server, tmp_path):
    bait = tmp_path / "bait_aws"; Stub.bait_path = str(bait)
    p = subprocess.Popen(
        ["sh", str(AGENT), "run", "--server", f"http://127.0.0.1:{server.server_port}",
         "--enroll-token","e","--tripwire","tw_1","--state-file",str(tmp_path/"agent.json"),
         "--heartbeat","0","--sync-interval","0"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        assert _wait(lambda: bait.exists() and stat.S_ISFIFO(bait.stat().st_mode))
        time.sleep(0.5)
        Path(bait).read_text()
        assert _wait(lambda: Stub.callbacks)
        body = Stub.callbacks[-1]
        assert "pid=" in body and "os_user=" in body
        pid_line = [l for l in body.splitlines() if l.startswith("pid=")][0]
        user_line = [l for l in body.splitlines() if l.startswith("os_user=")][0]
        assert pid_line != "pid=" and user_line != "os_user=", f"reader not attributed: {body!r}"
    finally:
        p.terminate(); p.wait(timeout=5)

def test_reading_the_fifo_fires_a_callback(server, tmp_path):
    bait = tmp_path / "bait_aws"; Stub.bait_path = str(bait)
    p = subprocess.Popen(
        ["sh", str(AGENT), "run", "--server", f"http://127.0.0.1:{server.server_port}",
         "--enroll-token","e","--tripwire","tw_1","--state-file",str(tmp_path/"agent.json"),
         "--heartbeat","0","--sync-interval","0"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        assert _wait(lambda: bait.exists() and stat.S_ISFIFO(bait.stat().st_mode)), "no FIFO planted"
        time.sleep(0.5)
        got = Path(bait).read_text()                      # the "attacker" read
        assert got == BAIT_BODY, f"served wrong content: {got!r}"
        assert _wait(lambda: any("event_type=open" in c for c in Stub.callbacks)), "no callback fired"
    finally:
        p.terminate(); p.wait(timeout=5)

def test_clean_exit_removes_fifos(server, tmp_path):
    bait = tmp_path / "bait_aws"; Stub.bait_path = str(bait)
    p = subprocess.Popen(
        ["sh", str(AGENT), "run", "--server", f"http://127.0.0.1:{server.server_port}",
         "--enroll-token","e","--tripwire","tw_1","--state-file",str(tmp_path/"agent.json"),
         "--heartbeat","0","--sync-interval","0"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    assert _wait(lambda: bait.exists())
    p.terminate(); p.wait(timeout=5)
    assert not bait.exists(), "FIFO left behind after clean exit"

def test_startup_sweeps_a_stale_fifo(server, tmp_path):
    # Simulate a prior hard-killed run: a manifest naming a leftover FIFO.
    bait = tmp_path / "bait_aws"; Stub.bait_path = str(bait)
    os.mkfifo(bait)
    (tmp_path / "planted.list").write_text(str(bait) + "\n")
    _run(server, tmp_path, "--once")
    # After --once the agent re-plants; the stale pipe must have been swept and
    # re-created (still a FIFO) rather than colliding on mkfifo EEXIST.
    assert bait.exists() and stat.S_ISFIFO(bait.stat().st_mode)
