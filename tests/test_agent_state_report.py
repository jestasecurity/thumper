"""Agent reports each deployment's plant outcome (#45) and cleans up a --force
leftover. Drives the real agent against a stub that can fail one content fetch
and records state reports."""
import http.server
import platform
import stat
import subprocess
import threading
from pathlib import Path

import pytest

AGENT = Path(__file__).resolve().parents[1] / "agent" / "thumper_agent.sh"
BAIT = "BAIT-honeytoken-content"


class _Stub(http.server.BaseHTTPRequestHandler):
    deployments = []        # [{"id","path"}]
    fail_content = set()    # deployment ids whose /content returns 500
    states = {}             # id -> last reported state

    def log_message(self, *_a):
        pass

    def _text(self, body, code=200):
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(body.encode())

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(n).decode()
        if self.path == "/api/enroll":
            self._text("agent_token=tok-123\nendpoint_id=ep_1\n")
        elif self.path.startswith("/api/agent/deployments/") and self.path.endswith("/state"):
            did = self.path.split("/")[4]
            state = dict(p.split("=", 1) for p in body.split("&")).get("state")
            _Stub.states[did] = state
            self._text("ok\n")
        else:
            self._text("ok\n")

    def do_GET(self):
        if self.path == "/api/agent/deployments":
            base = f"http://{self.headers['Host']}"
            self._text("".join(
                "\t".join([d["id"], d["path"], "secret",
                           f"{base}/content/{d['id']}", f"{base}/cb/{d['id']}"]) + "\n"
                for d in self.deployments))
        elif self.path.startswith("/content/"):
            did = self.path.split("/")[-1]
            if did in _Stub.fail_content:
                self._text("nope", code=500)
            else:
                self._text(BAIT)
        else:
            self._text("", code=404)


@pytest.fixture
def agent(tmp_path):
    httpd = http.server.HTTPServer(("127.0.0.1", 0), _Stub)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    _Stub.deployments = []
    _Stub.fail_content = set()
    _Stub.states = {}

    def run(*flags):
        return subprocess.run(
            ["sh", str(AGENT), "run", "--server", base,
             "--enroll-token", "dev-enroll-token", "--tripwire", "tw",
             "--state-file", str(tmp_path / "state" / "agent.json"),
             "--once", *flags],
            capture_output=True, text=True, timeout=30)

    try:
        yield {"run": run, "tmp": tmp_path}
    finally:
        httpd.shutdown()


def test_reports_planted_for_good_and_failed_for_bad(agent):
    good = str(agent["tmp"] / "good")
    bad = str(agent["tmp"] / "bad")
    _Stub.deployments = [{"id": "dp_good", "path": good}, {"id": "dp_bad", "path": bad}]
    _Stub.fail_content = {"dp_bad"}     # content fetch 500s for dp_bad

    agent["run"]()

    assert _Stub.states.get("dp_good") == "planted"
    assert _Stub.states.get("dp_bad") == "failed"
    if platform.system() == "Darwin":
        assert stat.S_ISFIFO(Path(good).stat().st_mode), "bait not planted as FIFO"
    else:
        assert Path(good).read_text() == BAIT, "bait body not planted"


def test_force_curl_failure_leaves_no_leftover(agent):
    bad = str(agent["tmp"] / "bad")
    _Stub.deployments = [{"id": "dp_bad", "path": bad}]
    _Stub.fail_content = {"dp_bad"}

    agent["run"]("--force")

    # A 500 makes `curl -fsS` exit non-zero without creating the destination file, so the
    # `rm -f` cleanup is at worst a safe no-op.  The partial-file case it guards is a
    # mid-transfer network drop where curl wrote partial bytes before failing.
    assert not Path(bad).exists(), "partial/leftover file remained after a failed --force plant"
    assert _Stub.states.get("dp_bad") == "failed"


def test_reports_failed_when_refusing_to_overwrite(agent):
    real = str(agent["tmp"] / "real_creds")
    Path(real).write_text("REAL-SECRET")
    _Stub.deployments = [{"id": "dp_real", "path": real}]

    agent["run"]()   # no --force: plant() must refuse and report failed

    assert _Stub.states.get("dp_real") == "failed"
    assert Path(real).read_text() == "REAL-SECRET", "real file must be left untouched"
