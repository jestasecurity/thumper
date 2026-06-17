"""plant() must never write THROUGH a symlink (#32). If a bait path we already
planted is swapped for a symlink (so planted_by_us is true and the overwrite
guard is skipped), a re-plant would `curl -o` through the link and clobber its
target. Drive the real agent against a stub and assert the victim is untouched.
"""
import http.server
import subprocess
import threading
from pathlib import Path

import pytest

AGENT = Path(__file__).resolve().parents[1] / "agent" / "thumper_agent.sh"
BAIT_BODY = "BAIT-honeytoken-content"


class _Stub(http.server.BaseHTTPRequestHandler):
    deployments = []

    def log_message(self, *_a):
        pass

    def _text(self, body):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(body.encode())

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        if self.path == "/api/enroll":
            self._text("agent_token=tok-123\nendpoint_id=ep_1\n")
        else:
            self._text("ok")

    def do_GET(self):
        if self.path == "/api/agent/deployments":
            base = f"http://{self.headers['Host']}"
            self._text("".join(
                "\t".join([d["id"], d["path"], "secret",
                           f"{base}/content/{d['id']}", f"{base}/cb/{d['id']}"]) + "\n"
                for d in _Stub.deployments))
        elif self.path.startswith("/content/"):
            self._text(BAIT_BODY)
        else:
            self.send_response(404); self.end_headers()


@pytest.fixture
def agent(tmp_path):
    httpd = http.server.HTTPServer(("127.0.0.1", 0), _Stub)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    state = tmp_path / "state" / "agent.json"

    def run():
        return subprocess.run(
            ["sh", str(AGENT), "run", "--server", base,
             "--enroll-token", "dev-enroll-token", "--tripwire", "tw_test",
             "--state-file", str(state), "--once"],
            capture_output=True, text=True, timeout=30)

    try:
        yield {"run": run, "state": state, "tmp": tmp_path, "base": base}
    finally:
        httpd.shutdown()


def test_plant_refuses_to_write_through_symlink(agent):
    tmp = agent["tmp"]
    victim = tmp / "victim.txt"
    victim.write_text("REAL-SECRET-do-not-touch")
    bait_path = tmp / "bait"
    bait_path.symlink_to(victim)            # our bait path is now a symlink → victim

    # Mark the bait path as previously planted by us, so the overwrite guard is
    # skipped - reproducing the re-plant case the issue describes.
    state_dir = agent["state"].parent
    state_dir.mkdir(parents=True, exist_ok=True)
    (state_dir / "planted.list").write_text(f"{bait_path}\n")

    _Stub.deployments = [{"id": "dep_0", "path": str(bait_path)}]

    result = agent["run"]()

    assert result.returncode == 0
    # The link target must be untouched - the agent refused to write through it.
    assert victim.read_text() == "REAL-SECRET-do-not-touch", \
        "agent wrote bait THROUGH the symlink and clobbered the target"
