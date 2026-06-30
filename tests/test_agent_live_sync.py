"""Agent live sync (SP2 of #34): a running agent re-pulls /api/agent/deployments
on --sync-interval and reconciles - plants newly-added bait, removes dropped
bait - without a restart.

Driven against a stub whose deployment set changes between pulls. The sync loop
runs independently of the watcher, so the test is deterministic regardless of
whether fs_usage is usable in CI.
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
REAL_SECRET = "REAL-SECRET-DO-NOT-DELETE"


class _StubHandler(http.server.BaseHTTPRequestHandler):
    deployments = []         # current set: [{"id","path"}]
    seen = []
    valid_token = "tok-123"  # current agent token; enroll issues it, GET requires it
    heartbeats_ok = 0
    fail_content = set()

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
            self._text(f"agent_token={_StubHandler.valid_token}\nendpoint_id=ep_1\n")
        elif self.path == "/api/agent/heartbeat":
            if self.headers.get("Authorization") != f"Bearer {_StubHandler.valid_token}":
                self.send_response(401)
                self.end_headers()
                return
            _StubHandler.heartbeats_ok += 1
            self._text("ok")
        else:
            self._text("ok")

    def do_GET(self):
        _StubHandler.seen.append(self.path)
        if self.path == "/api/agent/deployments":
            # Enforce the bearer token so a "DB reset" (rotated token) makes stale
            # pulls 401 until the agent re-enrolls - exercises the resync path.
            if self.headers.get("Authorization") != f"Bearer {_StubHandler.valid_token}":
                self.send_response(401)
                self.end_headers()
                return
            base = f"http://{self.headers['Host']}"
            self._text("".join(
                "\t".join([d["id"], d["path"], "secret",
                           f"{base}/content/{d['id']}", f"{base}/cb/{d['id']}"]) + "\n"
                for d in self.deployments))
        elif self.path.startswith("/content/"):
            did = self.path.split("/")[-1]
            if did in _StubHandler.fail_content:
                self.send_response(500)
                self.end_headers()
                return
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
    procs = []

    keep = str(tmp_path / "keep")
    drop = str(tmp_path / "drop")
    add = str(tmp_path / "add")

    def set_deployments(items):
        _StubHandler.deployments = items

    def reset_token(tok):
        """Simulate a server-side DB reset: old token invalid, new one issued."""
        _StubHandler.valid_token = tok

    def start(*flags):
        p = subprocess.Popen(
            ["sh", str(AGENT), "run", "--server", base,
             "--enroll-token", "dev-enroll-token", "--tripwire", "tw_test",
             "--state-file", str(state), *flags],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        procs.append(p)
        return p

    _StubHandler.seen = []
    _StubHandler.valid_token = "tok-123"
    _StubHandler.heartbeats_ok = 0
    _StubHandler.fail_content = set()
    try:
        yield {"set": set_deployments, "start": start, "reset_token": reset_token,
               "keep": keep, "drop": drop, "add": add}
    finally:
        for p in procs:
            p.send_signal(signal.SIGTERM)
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.send_signal(signal.SIGKILL)
        httpd.shutdown()


def _wait_until(predicate, timeout=15):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.2)
    return False


def test_live_sync_plants_added_and_removes_dropped(agent):
    keep, drop, add = agent["keep"], agent["drop"], agent["add"]
    # Initial set: keep + drop.
    agent["set"]([{"id": "dep_keep", "path": keep}, {"id": "dep_drop", "path": drop}])

    agent["start"]("--sync-interval", "1")

    # Both initial baits planted.
    assert _wait_until(lambda: Path(keep).exists() and Path(drop).exists()), \
        "initial bait not planted"

    # Server set changes: drop -> add (keep stays).
    agent["set"]([{"id": "dep_keep", "path": keep}, {"id": "dep_add", "path": add}])

    # After a sync: dropped bait gone, added bait present, kept untouched.
    assert _wait_until(lambda: Path(add).exists() and not Path(drop).exists()), \
        "live sync did not reconcile (add planted / drop removed)"
    assert Path(keep).read_text() == BAIT_BODY, "kept bait disturbed"


def test_reconcile_never_deletes_a_file_it_did_not_plant(agent):
    """Un-assigning a tripwire must NEVER delete a real credential sitting at that
    path - reconcile may only remove bait WE planted (issue #29 invariant). A
    sentinel bait we *did* plant gates the timing of each reconcile pass."""
    keep = agent["keep"]
    tmp = Path(keep).parent
    real = str(tmp / "real_creds")        # a real secret we did NOT plant
    sentinel = str(tmp / "sentinel")      # bait we DID plant; proves reconcile ran
    Path(real).write_text(REAL_SECRET)

    # Start with just `keep` (free path) so preflight passes and the agent runs.
    agent["set"]([{"id": "dep_keep", "path": keep}])
    agent["start"]("--sync-interval", "1")
    assert _wait_until(lambda: Path(keep).exists()), "initial bait not planted"

    # Sync ADDS a deployment at the real file's path (+ a sentinel). plant() must
    # refuse the occupied non-bait path; the sentinel appearing proves the pass ran.
    agent["set"]([{"id": "dep_keep", "path": keep},
                  {"id": "dep_real", "path": real},
                  {"id": "dep_sentinel", "path": sentinel}])
    assert _wait_until(lambda: Path(sentinel).exists()), "reconcile add pass did not run"
    assert Path(real).read_text() == REAL_SECRET, "plant clobbered a real file"

    # Sync REMOVES dep_real and the sentinel. reconcile must delete the sentinel
    # (ours) but leave the real file (not ours) untouched.
    agent["set"]([{"id": "dep_keep", "path": keep}])
    assert _wait_until(lambda: not Path(sentinel).exists()), "reconcile remove pass did not run"
    assert Path(real).read_text() == REAL_SECRET, \
        "reconcile deleted a real credential it never planted"


def test_sync_recovers_from_dead_token_and_reconciles(agent):
    """A dead token (server DB reset) must not stall the sync loop forever: the
    agent re-enrolls (resync) AND reconciles the refreshed set. Guards the bug
    where resync succeeded but the loop `continue`d past reconcile, leaving bait
    added during the outage unplanted."""
    keep, add = agent["keep"], agent["add"]
    agent["set"]([{"id": "dep_keep", "path": keep}])
    agent["start"]("--sync-interval", "1")
    assert _wait_until(lambda: Path(keep).exists()), "initial bait not planted"

    # DB reset: rotate the token (stale pulls now 401) AND add new bait.
    agent["set"]([{"id": "dep_keep", "path": keep}, {"id": "dep_add", "path": add}])
    agent["reset_token"]("tok-RESET")

    assert _wait_until(lambda: Path(add).exists()), \
        "agent did not recover from a dead token and plant the new bait"
    assert _StubHandler.seen.count("/api/enroll") >= 2, \
        "agent never re-enrolled (resync) after the 401"


def test_sync_interval_zero_does_not_repull(agent):
    keep = agent["keep"]
    agent["set"]([{"id": "dep_keep", "path": keep}])

    agent["start"]("--sync-interval", "0", "--once")

    assert _wait_until(lambda: Path(keep).exists()), "bait not planted"
    # --once exits after planting; with sync disabled there is no second pull.
    time.sleep(1)
    assert _StubHandler.seen.count("/api/agent/deployments") == 1


def test_heartbeat_recovers_token_after_reset(agent):
    keep = agent["keep"]
    agent["set"]([{"id": "dep_keep", "path": keep}])
    agent["start"]("--sync-interval", "1", "--heartbeat", "1")
    assert _wait_until(lambda: Path(keep).exists()), "initial bait not planted"

    before = _StubHandler.heartbeats_ok
    assert _wait_until(lambda: _StubHandler.heartbeats_ok > before), "no heartbeats before reset"

    # heartbeat_loop runs in a subshell: its $AGENT_TOKEN is a fork-time copy that
    # is never mutated, so only reading the state file can deliver the rotated
    # token here. Snapshot the count BEFORE the reset so the post-reset increment
    # is unambiguously from new-token heartbeats.
    recovered = _StubHandler.heartbeats_ok
    # DB reset: rotate the token. Stale heartbeats now 401; the sync-loop resync
    # rewrites the state file, and the heartbeat must pick up the new token.
    agent["reset_token"]("tok-HB")
    assert _wait_until(lambda: _StubHandler.heartbeats_ok > recovered + 1, timeout=20), \
        "heartbeat did not recover the rotated token from the state file"


def test_heartbeat_success_is_logged(agent):
    keep = agent["keep"]
    agent["set"]([{"id": "dep_keep", "path": keep}])
    proc = agent["start"]("--sync-interval", "1", "--heartbeat", "1")
    assert _wait_until(lambda: Path(keep).exists()), "initial bait not planted"

    before = _StubHandler.heartbeats_ok
    assert _wait_until(lambda: _StubHandler.heartbeats_ok > before), "no heartbeat sent"

    proc.send_signal(signal.SIGTERM)
    stdout, stderr = proc.communicate(timeout=5)
    assert "heartbeat succeeded" in stdout + stderr


def test_verify_replants_a_deleted_bait(agent):
    keep = agent["keep"]
    agent["set"]([{"id": "dep_keep", "path": keep}])
    agent["start"]("--sync-interval", "1")
    assert _wait_until(lambda: Path(keep).exists()), "initial bait not planted"

    Path(keep).unlink()                       # attacker/accident deletes the bait
    assert _wait_until(lambda: Path(keep).exists()), \
        "verify pass did not re-plant the deleted bait"
    assert Path(keep).read_text() == BAIT_BODY


def test_replant_is_bounded(agent):
    import time
    keep, bad = agent["keep"], agent["add"]
    # dep_keep plants fine (keeps the agent alive in the sync loop); dep_bad's
    # content always 500s, so its initial plant + every re-plant fail. Must stop
    # after REPLANT_MAX (3) re-plants rather than hammering forever.
    _StubHandler.fail_content = {"dep_bad"}
    agent["set"]([{"id": "dep_keep", "path": keep}, {"id": "dep_bad", "path": bad}])
    agent["start"]("--sync-interval", "1")
    assert _wait_until(lambda: Path(keep).exists()), "good bait not planted (agent not in sync loop)"

    # Wait (machine-speed-independent) until the cap is reached: 1 initial plant +
    # REPLANT_MAX(3) re-plants = 4 content fetches for the always-failing dep.
    assert _wait_until(lambda: _StubHandler.seen.count("/content/dep_bad") >= 4, timeout=20), \
        "bad dep was not re-planted up to the cap"
    stable = _StubHandler.seen.count("/content/dep_bad")
    time.sleep(3)   # several more cycles - must NOT keep growing
    final = _StubHandler.seen.count("/content/dep_bad")
    assert final == stable == 4, f"re-plant not bounded at the cap: stable={stable} final={final}"


def test_verify_does_not_write_through_a_symlink(agent):
    """Tamper guard: if the bait path becomes a (dangling) symlink, verify must NOT
    treat it as missing and re-plant through it - curl -o would write the target."""
    import os
    import time
    keep = agent["keep"]
    sensitive = str(Path(keep).parent / "sensitive")   # a path that does NOT exist
    agent["set"]([{"id": "dep_keep", "path": keep}])
    agent["start"]("--sync-interval", "1")
    assert _wait_until(lambda: Path(keep).exists()), "initial bait not planted"

    os.unlink(keep)
    os.symlink(sensitive, keep)   # bait replaced by a dangling symlink

    time.sleep(4)   # several verify cycles
    assert not os.path.exists(sensitive), "agent wrote bait THROUGH the symlink"
    assert os.path.islink(keep), "agent replaced the symlink instead of leaving it"
