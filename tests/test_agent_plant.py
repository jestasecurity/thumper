"""End-to-end tests for the bash agent's plant() safety behavior.

These drive the real agent/thumper_agent.sh via subprocess against a stub HTTP
server, so they exercise the actual curl-based fetch+write path.

Policy under test (issue #29): planting must NEVER overwrite a pre-existing file
the agent did not plant itself (a likely-real credential). And if ANY target
path is occupied, the WHOLE install aborts - nothing is planted and the agent
does not start watching - rather than skipping one file and continuing.
"""

import http.server
import stat
import subprocess
import threading
from pathlib import Path

import pytest

AGENT = Path(__file__).resolve().parents[1] / "agent" / "thumper_agent.sh"
BAIT_BODY = "BAIT-honeytoken-content"
REAL_SECRET = "REAL-SECRET-DO-NOT-DELETE"


class _StubHandler(http.server.BaseHTTPRequestHandler):
    """Minimal Thumper server: path-preview, enroll, N deployments, bait content."""

    deployments = []  # list of {"id": str, "path": str}; set per-test
    seen = []         # request paths received, in order; reset per-test

    def log_message(self, *_args):  # silence test noise
        pass

    def _text(self, body: str):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(body.encode())

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        _StubHandler.seen.append(self.path)
        if self.path == "/api/agent/tripwire-paths":
            self._text("".join(d["path"] + "\n" for d in self.deployments))
        elif self.path == "/api/enroll":
            self._text("agent_token=tok-123\nendpoint_id=ep_1\n")
        else:  # callback endpoint, etc.
            self._text("ok")

    def do_GET(self):
        _StubHandler.seen.append(self.path)
        if self.path == "/api/agent/deployments":
            base = f"http://{self.headers['Host']}"
            lines = "".join(
                "\t".join([
                    d["id"], d["path"], "hmac-secret",
                    f"{base}/content/{d['id']}", f"{base}/cb/{d['id']}",
                ]) + "\n"
                for d in self.deployments
            )
            self._text(lines)
        elif self.path.startswith("/content/"):
            self._text(BAIT_BODY)
        else:
            self.send_response(404)
            self.end_headers()


@pytest.fixture
def agent(tmp_path):
    """Yield (configure, run). configure(*names) registers deployments and
    returns their absolute paths; run(*flags) executes the agent."""
    httpd = http.server.HTTPServer(("127.0.0.1", 0), _StubHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"

    def configure(*names):
        paths = [str(tmp_path / n) for n in names]
        _StubHandler.deployments = [
            {"id": f"dep_{i}", "path": p} for i, p in enumerate(paths)
        ]
        _StubHandler.seen = []
        return paths

    def run(*flags):
        return subprocess.run(
            [
                "sh", str(AGENT), "run",
                "--server", base,
                "--enroll-token", "dev-enroll-token",
                "--tripwire", "tw_test",
                "--state-file", str(tmp_path / "state" / "agent.json"),
                "--once",
                *flags,
            ],
            capture_output=True, text=True, timeout=30,
        )

    configure("bait_target")  # sensible default: one deployment
    try:
        yield configure, run
    finally:
        httpd.shutdown()


def test_aborts_before_enrolling_when_a_path_is_occupied(agent):
    """If one path holds a real file, the whole install aborts BEFORE enrolling:
    the real file survives, the other (free) path is left unplanted, the agent
    exits non-zero - and crucially it never hits /api/enroll, so no endpoint
    appears in the dashboard (issue #29)."""
    configure, run = agent
    occupied, free = configure("real_creds", "free_path")
    Path(occupied).write_text(REAL_SECRET)

    result = run()

    assert result.returncode != 0, "install should abort with non-zero exit"
    assert Path(occupied).read_text() == REAL_SECRET, "real file was clobbered"
    assert not Path(free).exists(), "free path planted despite the abort"
    assert "abort" in result.stderr.lower()
    assert "/api/enroll" not in _StubHandler.seen, (
        "the agent enrolled despite aborting - a ghost endpoint would appear"
    )


def test_plants_all_when_no_conflicts(agent):
    """With every path clear, the agent enrolls and plants all bait, exit 0."""
    configure, run = agent
    a, b = configure("path_a", "path_b")

    result = run()

    assert result.returncode == 0
    assert "/api/enroll" in _StubHandler.seen, "did not enroll on a clean install"
    assert stat.S_ISFIFO(Path(a).stat().st_mode), "bait not planted as FIFO"
    assert stat.S_ISFIFO(Path(b).stat().st_mode), "bait not planted as FIFO"


def test_refreshes_its_own_bait(agent):
    """A second run may overwrite bait the agent itself planted (no abort)."""
    configure, run = agent
    (path,) = configure("bait_target")

    assert run().returncode == 0
    Path(path).write_text("stale-bait")  # simulate server-side rotation
    assert run().returncode == 0
    assert stat.S_ISFIFO(Path(path).stat().st_mode), "bait not planted as FIFO"


def test_force_overwrites_occupied_path(agent):
    """--force lets an operator knowingly clobber (dedicated honeypot boxes)."""
    configure, run = agent
    (path,) = configure("real_creds")
    Path(path).write_text(REAL_SECRET)

    result = run("--force")

    assert result.returncode == 0
    assert stat.S_ISFIFO(Path(path).stat().st_mode), "bait not planted as FIFO"
