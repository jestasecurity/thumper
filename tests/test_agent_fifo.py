"""FIFO bait sensor (#100): bait is planted as a named pipe; a read of it
unblocks the agent's write and fires a callback. Driven against a stub server,
like test_agent_live_sync.py."""

import http.server
import subprocess
import threading
import os
import stat
import time
import platform as _platform
from pathlib import Path
import pytest

pytestmark = pytest.mark.skipif(
    _platform.system() != "Darwin",
    reason="FIFO sensor is macOS-only; Linux uses inotify",
)

AGENT = Path(__file__).resolve().parents[1] / "agent" / "thumper_agent.sh"
BAIT_BODY = "AKIA-BAIT\nsecret=shhh\n"


class Stub(http.server.BaseHTTPRequestHandler):
    callbacks = []  # POSTed callback bodies
    bait_path = ""  # absolute path the agent should plant

    def log_message(self, *a):
        pass

    def _t(self, body=""):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(body.encode())

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(n).decode()
        if self.path == "/api/enroll":
            return self._t("agent_token=tok-1\nendpoint_id=ep_1\n")
        if self.path.startswith("/cb/"):
            Stub.callbacks.append(body)
            return self._t("ok")
        if self.path.endswith("/state"):
            return self._t("ok")
        return self._t("ok")

    def do_GET(self):
        if self.path == "/api/agent/deployments":
            base = f"http://127.0.0.1:{self.server.server_port}"
            rec = "\t".join(
                [
                    "dep_1",
                    Stub.bait_path,
                    "sekret",
                    f"{base}/content/dep_1",
                    f"{base}/cb/dep_1",
                ]
            )
            return self._t(rec + "\n")
        if self.path.startswith("/content/"):
            return self._t(BAIT_BODY)
        return self._t("")


@pytest.fixture
def server():
    httpd = http.server.HTTPServer(("127.0.0.1", 0), Stub)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    Stub.callbacks = []
    yield httpd
    httpd.shutdown()


def _run(server, tmp_path, *extra, timeout=15):
    port = server.server_port
    state = tmp_path / "agent.json"
    return subprocess.run(
        [
            "sh",
            str(AGENT),
            "run",
            "--server",
            f"http://127.0.0.1:{port}",
            "--enroll-token",
            "e",
            "--tripwire",
            "tw_1",
            "--state-file",
            str(state),
            "--heartbeat",
            "0",
            *extra,
        ],
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def test_plant_creates_a_fifo_and_caches_content(server, tmp_path):
    bait = tmp_path / "bait_aws"
    Stub.bait_path = str(bait)
    _run(server, tmp_path, "--once")
    assert bait.exists() and stat.S_ISFIFO(bait.stat().st_mode), "bait is not a FIFO"
    cache = tmp_path / "bait" / "dep_1"
    assert cache.read_text() == BAIT_BODY, "bait content not cached"


def _wait(pred, timeout=12):
    end = time.time() + timeout
    while time.time() < end:
        if pred():
            return True
        time.sleep(0.2)
    return False


def test_callback_includes_reader_pid_and_user(server, tmp_path):
    bait = tmp_path / "bait_aws"
    Stub.bait_path = str(bait)
    p = subprocess.Popen(
        [
            "sh",
            str(AGENT),
            "run",
            "--server",
            f"http://127.0.0.1:{server.server_port}",
            "--enroll-token",
            "e",
            "--tripwire",
            "tw_1",
            "--state-file",
            str(tmp_path / "agent.json"),
            "--heartbeat",
            "0",
            "--sync-interval",
            "0",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert _wait(lambda: bait.exists() and stat.S_ISFIFO(bait.stat().st_mode))
        time.sleep(0.5)
        Path(bait).read_text()
        assert _wait(lambda: Stub.callbacks)
        body = Stub.callbacks[-1]
        assert "pid=" in body and "os_user=" in body
        pid_line = [ln for ln in body.splitlines() if ln.startswith("pid=")][0]
        user_line = [ln for ln in body.splitlines() if ln.startswith("os_user=")][0]
        assert pid_line != "pid=" and user_line != "os_user=", (
            f"reader not attributed: {body!r}"
        )
    finally:
        p.terminate()
        p.wait(timeout=5)


def test_reading_the_fifo_fires_a_callback(server, tmp_path):
    bait = tmp_path / "bait_aws"
    Stub.bait_path = str(bait)
    p = subprocess.Popen(
        [
            "sh",
            str(AGENT),
            "run",
            "--server",
            f"http://127.0.0.1:{server.server_port}",
            "--enroll-token",
            "e",
            "--tripwire",
            "tw_1",
            "--state-file",
            str(tmp_path / "agent.json"),
            "--heartbeat",
            "0",
            "--sync-interval",
            "0",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert _wait(lambda: bait.exists() and stat.S_ISFIFO(bait.stat().st_mode)), (
            "no FIFO planted"
        )
        time.sleep(0.5)
        got = Path(bait).read_text()  # the "attacker" read
        assert got == BAIT_BODY, f"served wrong content: {got!r}"
        assert _wait(lambda: any("event_type=open" in c for c in Stub.callbacks)), (
            "no callback fired"
        )
    finally:
        p.terminate()
        p.wait(timeout=5)


def test_clean_exit_removes_fifos(server, tmp_path):
    bait = tmp_path / "bait_aws"
    Stub.bait_path = str(bait)
    p = subprocess.Popen(
        [
            "sh",
            str(AGENT),
            "run",
            "--server",
            f"http://127.0.0.1:{server.server_port}",
            "--enroll-token",
            "e",
            "--tripwire",
            "tw_1",
            "--state-file",
            str(tmp_path / "agent.json"),
            "--heartbeat",
            "0",
            "--sync-interval",
            "0",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert _wait(lambda: bait.exists())
    p.terminate()
    p.wait(timeout=5)
    assert not bait.exists(), "FIFO left behind after clean exit"


def test_startup_sweeps_a_stale_fifo(server, tmp_path):
    # An orphan FIFO from a prior run: listed in the manifest but NOT a current
    # deployment, so ONLY the startup sweep (not plant's own EEXIST handling) can
    # remove it. Without the sweep it persists and blocks readers forever.
    bait = tmp_path / "bait_aws"
    Stub.bait_path = str(bait)  # the current deployment
    orphan = tmp_path / "orphan_fifo"  # NOT a current deployment
    os.mkfifo(orphan)
    (tmp_path / "planted.list").write_text(f"{orphan}\n")  # manifest from a prior run
    _run(server, tmp_path, "--once")
    assert not orphan.exists(), "orphan FIFO from manifest was not swept on startup"
    assert bait.exists() and stat.S_ISFIFO(bait.stat().st_mode), (
        "current bait not planted"
    )


def test_two_agents_one_host_both_detect(server, tmp_path):
    procs = []
    baits = []
    for i in (1, 2):
        d = tmp_path / f"inst{i}"
        d.mkdir()
        bait = d / "bait_aws"
        baits.append(bait)
        # each install gets its own bait path (distinct deployment per server stub run)
        Stub.bait_path = str(bait)
        procs.append(
            subprocess.Popen(
                [
                    "sh",
                    str(AGENT),
                    "run",
                    "--server",
                    f"http://127.0.0.1:{server.server_port}",
                    "--enroll-token",
                    "e",
                    "--tripwire",
                    f"tw_{i}",
                    "--state-file",
                    str(d / "agent.json"),
                    "--heartbeat",
                    "0",
                    "--sync-interval",
                    "0",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        )
        assert _wait(lambda: bait.exists() and stat.S_ISFIFO(bait.stat().st_mode))
    try:
        time.sleep(0.5)
        for b in baits:
            Path(b).read_text()
        assert _wait(
            lambda: sum("event_type=open" in c for c in Stub.callbacks) >= 2
        ), "both agents should detect — no single-consumer collision"
    finally:
        for p in procs:
            p.terminate()
        for p in procs:
            p.wait(timeout=5)


def test_duplicate_install_does_not_sweep_live_agents_fifo(server, tmp_path):
    """C1 regression: a second invocation with the SAME --state-file must exit at
    the singleton lock WITHOUT deleting the live agent's bait FIFO. The startup
    sweep (remove_fifos) must only run AFTER acquire_singleton succeeds, so the
    duplicate invocation — which loses the mutex race and exits early — never
    touches the first agent's manifest or FIFOs."""
    bait = tmp_path / "bait_aws"
    Stub.bait_path = str(bait)
    state = tmp_path / "agent.json"

    # Start agent A — the live agent.
    p_a = subprocess.Popen(
        [
            "sh",
            str(AGENT),
            "run",
            "--server",
            f"http://127.0.0.1:{server.server_port}",
            "--enroll-token",
            "e",
            "--tripwire",
            "tw_1",
            "--state-file",
            str(state),
            "--heartbeat",
            "0",
            "--sync-interval",
            "0",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        # Wait for agent A to plant its FIFO.
        assert _wait(lambda: bait.exists() and stat.S_ISFIFO(bait.stat().st_mode)), (
            "agent A did not plant a FIFO in time"
        )

        # Start agent B with the SAME state-file — it must detect the singleton and exit.
        result_b = subprocess.run(
            [
                "sh",
                str(AGENT),
                "run",
                "--server",
                f"http://127.0.0.1:{server.server_port}",
                "--enroll-token",
                "e",
                "--tripwire",
                "tw_1",
                "--state-file",
                str(state),
                "--heartbeat",
                "0",
                "--sync-interval",
                "0",
            ],
            capture_output=True,
            text=True,
            timeout=15,
        )

        # B should have exited cleanly (returncode 0, logged "already running").
        assert result_b.returncode == 0, f"agent B exited with rc={result_b.returncode}"

        # CRITICAL: agent A's FIFO must still exist after B exits.
        assert bait.exists() and stat.S_ISFIFO(bait.stat().st_mode), (
            "agent B's startup sweep deleted agent A's live bait FIFO!"
        )

        # Confirm the FIFO is still readable — agent A is still serving it.
        content = Path(bait).read_text()
        assert content == BAIT_BODY, (
            f"bait FIFO no longer serves the expected content: {content!r}"
        )
    finally:
        p_a.terminate()
        p_a.wait(timeout=5)
        import subprocess as _sp

        _sp.run(
            ["pkill", "-f", "thumper_agent.sh run --server http://127.0.0.1"],
            capture_output=True,
        )


def test_tampered_fifo_is_recovered(server, tmp_path):
    # Roee #123 F1: replacing the FIFO bait with a regular file must RECOVER (rm the
    # impostor + re-create the FIFO), not just report failed forever and go blind.
    # Needs live-sync (--sync-interval) so verify_planted runs.
    bait = tmp_path / "bait_aws"
    Stub.bait_path = str(bait)
    p = subprocess.Popen(
        [
            "sh",
            str(AGENT),
            "run",
            "--server",
            f"http://127.0.0.1:{server.server_port}",
            "--enroll-token",
            "e",
            "--tripwire",
            "tw_1",
            "--state-file",
            str(tmp_path / "agent.json"),
            "--heartbeat",
            "0",
            "--sync-interval",
            "1",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert _wait(lambda: bait.exists() and stat.S_ISFIFO(bait.stat().st_mode)), (
            "no FIFO planted"
        )
        os.remove(bait)
        bait.write_text("attacker regular file")  # tamper: replace pipe with a file
        assert _wait(
            lambda: bait.exists() and stat.S_ISFIFO(bait.stat().st_mode), timeout=15
        ), "tampered FIFO was not recovered - sensor left permanently blind"
    finally:
        p.terminate()
        p.wait(timeout=5)


def test_simulate_does_not_leave_a_no_reader_fifo(server, tmp_path):
    # Roee #123 F2: --simulate plants, fires test callbacks, exits - it must sweep
    # its FIFOs, else a leftover no-reader pipe blocks every real open() forever.
    bait = tmp_path / "bait_aws"
    Stub.bait_path = str(bait)
    _run(server, tmp_path, "--simulate")
    assert not (bait.exists() and stat.S_ISFIFO(bait.stat().st_mode)), (
        "--simulate left a no-reader FIFO"
    )
    assert any("simulated" in c for c in Stub.callbacks), (
        "simulate callback did not fire"
    )


def test_simulate_does_not_leave_cached_credential_files(server, tmp_path):
    # Roee #123 F2 residual: --simulate must also remove the cached fake-credential
    # content it planted during planting, not just the FIFOs.
    bait = tmp_path / "bait_aws"
    Stub.bait_path = str(bait)
    _run(server, tmp_path, "--simulate")
    cache = tmp_path / "bait"
    assert not cache.exists(), "--simulate left cached credential content behind"


def test_fifo_supervisor_restarts_individual_dead_writers():
    # Roee #123 F3 residual: watch_fifo must poll each writer's liveness (kill -0)
    # and restart a SINGLE dead one whose FIFO still exists - a bare `wait` blocks
    # until ALL writers exit, leaving one dead bait silently blind until the next
    # full re-plant restart.
    src = AGENT.read_text()
    assert "kill -0" in src, "watch_fifo must check per-writer liveness"
    assert "restarted dead FIFO writer" in src, "watch_fifo must restart a dead writer"
    assert "re-serving in 1s" not in src, "the bare-wait/re-serve-all recovery must be gone"


def test_atime_stat_order_prefers_portable_access_time():
    # #28: `stat -f %a` on Linux is statfs (free blocks), so the portable
    # `stat -c %X` must be tried FIRST. Assert BOTH call sites use the right order
    # so that a future refactor of one cannot silently pass by matching the other.
    src = AGENT.read_text()
    # Site 1: initial atime capture at the top of watch_atime
    assert (
        'stat -c %X "$p" 2>/dev/null || stat -f %a "$p" 2>/dev/null || echo 0)' in src
    ), "watch_atime initialisation must try `stat -c %X` before `stat -f %a`"
    # Site 2: per-poll atime refresh inside the watch loop
    assert (
        'stat -c %X "$p" 2>/dev/null || stat -f %a "$p" 2>/dev/null || echo 0' in src
    ), "watch_atime poll loop must try `stat -c %X` before `stat -f %a`"
    # The reversed (wrong) order must not appear anywhere in the source
    assert 'stat -f %a "$p" 2>/dev/null || stat -c %X' not in src, (
        "source must not contain the wrong stat order (stat -f %a before stat -c %X)"
    )
    assert "watch_fs_usage" not in src, "fs_usage sensor must be removed"
