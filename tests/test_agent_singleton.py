"""Agent singleton (#35): only one agent runs per install location.

Drives the real agent/thumper_agent.sh against a stub server. The agent acquires
an atomic mkdir lock (with a liveness + identity check) before doing any work, so
a second start while one is alive exits 0 without enrolling; a stale/foreign lock
is reclaimed.
"""
import http.server
import signal
import subprocess
import threading
import time
from pathlib import Path

import pytest

AGENT = Path(__file__).resolve().parents[1] / "agent" / "thumper_agent.sh"
BAIT_BODY = "BAIT-honeytoken-content"


class _StubHandler(http.server.BaseHTTPRequestHandler):
    deployments = []   # [{"id","path"}]; set per-test
    seen = []          # request paths received

    def log_message(self, *_a):
        pass

    def _text(self, body):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(body.encode())

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        _StubHandler.seen.append(self.path)
        if self.path == "/api/enroll":
            self._text("agent_token=tok-123\nendpoint_id=ep_1\n")
        else:
            self._text("ok")

    def do_GET(self):
        _StubHandler.seen.append(self.path)
        if self.path == "/api/agent/deployments":
            base = f"http://{self.headers['Host']}"
            self._text("".join(
                "\t".join([d["id"], d["path"], "secret",
                           f"{base}/content/{d['id']}", f"{base}/cb/{d['id']}"]) + "\n"
                for d in self.deployments))
        elif self.path.startswith("/content/"):
            self._text(BAIT_BODY)
        else:
            self.send_response(404)
            self.end_headers()


@pytest.fixture
def agent(tmp_path):
    httpd = http.server.HTTPServer(("127.0.0.1", 0), _StubHandler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    state = tmp_path / "state" / "agent.json"
    lock_dir = tmp_path / "state" / "agent.lock"
    _StubHandler.deployments = [{"id": "dep_0", "path": str(tmp_path / "bait")}]
    _StubHandler.seen = []
    procs = []

    def run(*flags):
        return subprocess.run(
            ["sh", str(AGENT), "run", "--server", base,
             "--enroll-token", "dev-enroll-token", "--tripwire", "tw_test",
             "--state-file", str(state), "--once", *flags],
            capture_output=True, text=True, timeout=30)

    def fake_holder(name):
        """Start a live process whose command line contains `name`; return its pid."""
        script = tmp_path / name
        script.write_text("sleep 30\n")
        p = subprocess.Popen(["sh", str(script)])
        procs.append(p)
        return p.pid

    def write_lock(pid):
        lock_dir.mkdir(parents=True, exist_ok=True)
        (lock_dir / "pid").write_text(f"{pid}\n")

    try:
        yield {"run": run, "fake_holder": fake_holder, "write_lock": write_lock,
               "lock_dir": lock_dir}
    finally:
        for p in procs:
            p.send_signal(signal.SIGKILL)
        httpd.shutdown()


def test_second_agent_registers_but_does_not_watch(agent):
    """A live agent holds the lock; a second start REGISTERS its tripwires with the
    server (so the running agent live-syncs them, #12) but does NOT become a second
    watcher or take the lock."""
    holder = agent["fake_holder"]("thumper_agent.sh")
    agent["write_lock"](holder)

    result = agent["run"]()

    assert result.returncode == 0
    assert "/api/enroll" in _StubHandler.seen, "second start should register its tripwires"
    assert "/api/agent/deployments" not in _StubHandler.seen, "second start must not become a watcher"
    assert "already running" in (result.stdout + result.stderr).lower()
    # the live holder's lock is untouched
    assert (agent["lock_dir"] / "pid").read_text().strip() == str(holder)


def test_stale_lock_is_reclaimed(agent):
    """A lock whose PID is dead is reclaimed; the agent enrolls normally."""
    agent["write_lock"](99999999)  # not a live pid

    result = agent["run"]()

    assert result.returncode == 0
    assert "/api/enroll" in _StubHandler.seen


def test_foreign_live_holder_is_reclaimed(agent):
    """A lock held by a live NON-thumper process is reclaimed (PID-reuse guard)."""
    foreign = agent["fake_holder"]("not_us")  # command contains 'not_us', not 'thumper_agent'
    agent["write_lock"](foreign)

    result = agent["run"]()

    assert result.returncode == 0
    assert "/api/enroll" in _StubHandler.seen


def test_initializing_holder_is_not_reclaimed(agent):
    """Race: holder won `mkdir` but hasn't written `pid` yet. A second start must
    treat the empty pid as 'still initializing' (re-read after a pause), not stale,
    so it defers to the live holder instead of reclaiming its lock."""
    holder = agent["fake_holder"]("thumper_agent.sh")
    agent["lock_dir"].mkdir(parents=True)  # lock dir present, pid not written yet

    def write_pid_late():
        time.sleep(0.5)  # within the agent's 1s re-read window
        (agent["lock_dir"] / "pid").write_text(f"{holder}\n")

    threading.Thread(target=write_pid_late, daemon=True).start()
    result = agent["run"]()

    assert result.returncode == 0
    # Deferred to the initializing holder (didn't steal its lock); it registers
    # rather than reclaiming - the lock still belongs to the holder.
    assert "/api/agent/deployments" not in _StubHandler.seen, "reclaimed an initializing holder's lock"
    assert "already running" in (result.stdout + result.stderr).lower()
    assert (agent["lock_dir"] / "pid").read_text().strip() == str(holder)


def test_lock_released_on_clean_exit(agent):
    """After a normal --once run the lock directory is gone."""
    result = agent["run"]()

    assert result.returncode == 0
    assert "/api/enroll" in _StubHandler.seen
    assert not agent["lock_dir"].exists()


@pytest.mark.parametrize("flag", ["--poll", "--heartbeat", "--sync-interval"])
def test_numeric_interval_args_reject_non_numbers(agent, flag):
    result = agent["run"](flag, "abc")

    assert result.returncode == 2
    assert f"{flag} must be a non-negative integer" in result.stderr
    assert "/api/enroll" not in _StubHandler.seen


def test_zero_disables_optional_agent_intervals(agent):
    result = agent["run"]("--heartbeat", "0", "--sync-interval", "0")

    assert result.returncode == 0
    assert "/api/enroll" in _StubHandler.seen
