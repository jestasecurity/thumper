"""Tests for the --ephemeral flag (B1c of issue #3).

Covers:
1. Enroll body contains ephemeral=1 when --ephemeral is passed.
2. Agent auto-decommissions (POSTs /api/agent/decommissioned) when terminated.

Run against a stub HTTP server; the agent is a real subprocess of
agent/thumper_agent.sh. Uses --once for the enroll body test (simpler to
reason about on macOS where the FIFO sensor blocks) and watch mode for the
decommission test.

macOS note: reading a writer-less FIFO blocks, so tests assert on the stub's
received requests rather than reading bait files directly.
"""
import http.server
import signal
import subprocess
import threading
import time
import urllib.parse
from pathlib import Path

import pytest

AGENT = Path(__file__).resolve().parents[1] / "agent" / "thumper_agent.sh"
BAIT_BODY = "BAIT-honeytoken-content"


class _StubHandler(http.server.BaseHTTPRequestHandler):
    """Minimal Thumper server stub for ephemeral tests."""

    deployments = []       # list of {"id": str, "path": str}
    seen_paths = []        # request paths received, in order
    enroll_bodies = []     # raw POST bodies received at /api/enroll
    decommission_count = 0

    def log_message(self, *_a):
        pass

    def _text(self, body: str):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(body.encode())

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(length)
        _StubHandler.seen_paths.append(self.path)
        if self.path == "/api/agent/tripwire-paths":
            self._text("".join(d["path"] + "\n" for d in _StubHandler.deployments))
        elif self.path == "/api/enroll":
            _StubHandler.enroll_bodies.append(raw_body.decode("utf-8", errors="replace"))
            self._text("agent_token=tok-ephemeral\nendpoint_id=ep_eph\n")
        elif self.path == "/api/agent/decommissioned":
            _StubHandler.decommission_count += 1
            self._text("ok")
        elif self.path.startswith("/api/agent/deployments/"):
            # state report (planted/failed)
            self._text("ok")
        else:
            self._text("ok")

    def do_GET(self):
        _StubHandler.seen_paths.append(self.path)
        if self.path == "/api/agent/deployments":
            base = f"http://{self.headers['Host']}"
            lines = "".join(
                "\t".join([
                    d["id"], d["path"], "hmac-secret",
                    f"{base}/content/{d['id']}", f"{base}/cb/{d['id']}",
                ]) + "\n"
                for d in _StubHandler.deployments
            )
            self._text(lines)
        elif self.path.startswith("/content/"):
            self._text(BAIT_BODY)
        else:
            self.send_response(404)
            self.end_headers()


def _wait_until(predicate, timeout=15):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.2)
    return False


@pytest.fixture
def stub(tmp_path):
    """Start stub HTTP server; yield a helper dict; shutdown on teardown."""
    httpd = http.server.HTTPServer(("127.0.0.1", 0), _StubHandler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    port = httpd.server_address[1]
    base = f"http://127.0.0.1:{port}"

    _StubHandler.deployments = []
    _StubHandler.seen_paths = []
    _StubHandler.enroll_bodies = []
    _StubHandler.decommission_count = 0

    bait_path = str(tmp_path / "bait.txt")
    state_file = str(tmp_path / "state" / "agent.json")

    _StubHandler.deployments = [{"id": "dep_eph", "path": bait_path}]

    procs = []

    def start(*extra_flags):
        p = subprocess.Popen(
            [
                "sh", str(AGENT), "run",
                "--server", base,
                "--enroll-token", "dev-enroll-token",
                "--tripwire", "tw_eph",
                "--state-file", state_file,
                *extra_flags,
            ],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        procs.append(p)
        return p

    try:
        yield {
            "base": base,
            "bait_path": bait_path,
            "state_file": state_file,
            "start": start,
        }
    finally:
        for p in procs:
            try:
                p.send_signal(signal.SIGTERM)
                p.wait(timeout=5)
            except (subprocess.TimeoutExpired, ProcessLookupError):
                try:
                    p.send_signal(signal.SIGKILL)
                except ProcessLookupError:
                    pass
        httpd.shutdown()
        # Belt-and-suspenders: kill any stray agent processes
        subprocess.run(
            ["pkill", "-f", "thumper_agent.sh run --server http://127.0.0.1"],
            capture_output=True,
        )


def test_ephemeral_enroll_body_contains_ephemeral_flag(stub):
    """--ephemeral causes the enroll POST body to include ephemeral=1."""
    proc = stub["start"]("--ephemeral", "--once")
    proc.wait(timeout=30)

    assert _StubHandler.enroll_bodies, "no enroll request received"
    body = _StubHandler.enroll_bodies[0]
    # The body is URL-encoded (--data-urlencode); decode to verify the field.
    parsed = dict(urllib.parse.parse_qsl(body))
    assert parsed.get("ephemeral") == "1", (
        f"enroll body missing ephemeral=1; got: {body!r}"
    )


def test_non_ephemeral_enroll_body_has_no_ephemeral_flag(stub):
    """Without --ephemeral the enroll body must NOT contain ephemeral=1."""
    proc = stub["start"]("--once")
    proc.wait(timeout=30)

    assert _StubHandler.enroll_bodies, "no enroll request received"
    body = _StubHandler.enroll_bodies[0]
    parsed = dict(urllib.parse.parse_qsl(body))
    assert "ephemeral" not in parsed, (
        f"enroll body unexpectedly contains ephemeral; got: {body!r}"
    )


def test_ephemeral_auto_decommissions_on_terminate(stub):
    """In watch mode, terminating an --ephemeral agent triggers self-destruct:
    it POSTs /api/agent/decommissioned before exiting."""
    proc = stub["start"](
        "--ephemeral",
        "--sync-interval", "1",
        "--heartbeat", "0",
    )

    # Wait until the agent has enrolled and planted bait (confirms it is running).
    assert _wait_until(lambda: "/api/enroll" in _StubHandler.seen_paths), \
        "agent never enrolled"
    assert _wait_until(lambda: "/api/agent/deployments" in _StubHandler.seen_paths), \
        "agent never pulled deployments"

    # Give the agent a moment to complete planting and install the ephemeral traps.
    assert _wait_until(
        lambda: any("/api/agent/deployments/" in p for p in _StubHandler.seen_paths),
        timeout=10,
    ), "agent never reported plant state (bait not planted yet)"

    before = _StubHandler.decommission_count

    # Terminate the agent — should trigger self_destruct via the ephemeral trap.
    proc.send_signal(signal.SIGTERM)

    assert _wait_until(
        lambda: _StubHandler.decommission_count > before,
        timeout=10,
    ), (
        "agent did not POST /api/agent/decommissioned after SIGTERM "
        f"(seen_paths={_StubHandler.seen_paths})"
    )

    # Agent should exit cleanly.
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.send_signal(signal.SIGKILL)
        pytest.fail("agent did not exit after SIGTERM + decommission")
