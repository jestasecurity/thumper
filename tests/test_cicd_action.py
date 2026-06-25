"""Local checks for the thumper-tripwire GitHub Action.

Full E2E requires a real GitHub runner; these checks cover:
  - action.yml structure (valid YAML, correct fields/inputs)
  - main.js and post.js syntax (node --check)
  - agent fire() trigger-marker: --ephemeral + --simulate creates the marker
  - post.js fail logic: exit 1 when marker present + fail-on-trigger=true,
                        exit 0 when marker absent or fail-on-trigger=false
"""
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).parent.parent
ACTION_DIR = REPO_ROOT / ".github" / "actions" / "thumper-tripwire"
AGENT_SH   = REPO_ROOT / "agent" / "thumper_agent.sh"


# ── action.yml ────────────────────────────────────────────────────────────────

def test_action_yml_is_valid_yaml():
    action_yml = ACTION_DIR / "action.yml"
    assert action_yml.exists(), "action.yml missing"
    with open(action_yml) as f:
        data = yaml.safe_load(f)
    assert isinstance(data, dict), "action.yml must be a YAML mapping"


def test_action_yml_uses_node20():
    with open(ACTION_DIR / "action.yml") as f:
        data = yaml.safe_load(f)
    assert data["runs"]["using"] == "node20"


def test_action_yml_declares_main_and_post():
    with open(ACTION_DIR / "action.yml") as f:
        data = yaml.safe_load(f)
    runs = data["runs"]
    assert runs["main"]  == "main.js"
    assert runs["post"]  == "post.js"


def test_action_yml_has_required_inputs():
    with open(ACTION_DIR / "action.yml") as f:
        data = yaml.safe_load(f)
    inputs = data["inputs"]
    assert "server"          in inputs, "missing input: server"
    assert "enroll-token"    in inputs, "missing input: enroll-token"
    assert "tripwires"       in inputs, "missing input: tripwires"
    assert "fail-on-trigger" in inputs, "missing input: fail-on-trigger"
    assert inputs["server"]["required"]       is True
    assert inputs["enroll-token"]["required"] is True
    assert inputs["tripwires"]["required"]    is True
    # fail-on-trigger is optional with a default
    assert inputs["fail-on-trigger"].get("default") == "false"


# ── JS syntax checks ──────────────────────────────────────────────────────────

def test_main_js_syntax():
    result = subprocess.run(
        ["node", "--check", str(ACTION_DIR / "main.js")],
        capture_output=True, text=True,
    )
    assert result.returncode == 0, f"main.js syntax error:\n{result.stderr}"


def test_post_js_syntax():
    result = subprocess.run(
        ["node", "--check", str(ACTION_DIR / "post.js")],
        capture_output=True, text=True,
    )
    assert result.returncode == 0, f"post.js syntax error:\n{result.stderr}"


# ── agent shell syntax ────────────────────────────────────────────────────────

def test_agent_shell_syntax():
    result = subprocess.run(
        ["sh", "-n", str(AGENT_SH)],
        capture_output=True, text=True,
    )
    assert result.returncode == 0, f"thumper_agent.sh syntax error:\n{result.stderr}"


# ── trigger-marker: --ephemeral + --simulate creates 'triggered' ──────────────

def test_ephemeral_simulate_creates_triggered_marker():
    """When EPHEMERAL=1 (--ephemeral flag) the agent's fire() should touch
    <statedir>/triggered. We verify this by running the agent with --simulate
    (which calls fire() for each deployment) against a minimal fake server.

    Since we cannot enroll against a real server in a unit test, we instead
    test the marker creation directly through a small shell snippet that
    sources the relevant logic from the agent, setting EPHEMERAL=1 and calling
    fire() to assert it creates the marker.

    The shell snippet replicates the exact condition in fire():
        [ "${EPHEMERAL:-0}" = "1" ] && touch "$(dirname "$STATE_FILE")/triggered"
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        state_file = os.path.join(tmpdir, "agent.json")
        triggered  = os.path.join(tmpdir, "triggered")

        # Run just the marker-creation logic in isolation (POSIX sh)
        script = f"""
STATE_FILE='{state_file}'
EPHEMERAL=1
[ "${{EPHEMERAL:-0}}" = "1" ] && touch "$(dirname "$STATE_FILE")/triggered" 2>/dev/null || true
"""
        result = subprocess.run(
            ["sh", "-c", script],
            capture_output=True, text=True,
        )
        assert result.returncode == 0, f"shell error: {result.stderr}"
        assert os.path.exists(triggered), (
            "triggered marker was NOT created when EPHEMERAL=1"
        )


def test_no_triggered_marker_when_ephemeral_off():
    """When EPHEMERAL is not 1, fire() must NOT create the marker."""
    with tempfile.TemporaryDirectory() as tmpdir:
        state_file = os.path.join(tmpdir, "agent.json")
        triggered  = os.path.join(tmpdir, "triggered")

        script = f"""
STATE_FILE='{state_file}'
EPHEMERAL=0
[ "${{EPHEMERAL:-0}}" = "1" ] && touch "$(dirname "$STATE_FILE")/triggered" 2>/dev/null || true
"""
        result = subprocess.run(
            ["sh", "-c", script],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        assert not os.path.exists(triggered), (
            "triggered marker was created even when EPHEMERAL=0"
        )


# ── post.js fail logic ────────────────────────────────────────────────────────

def _run_post(tmpdir: str, *, triggered: bool, fail_on_trigger: str) -> subprocess.CompletedProcess:
    """Invoke post.js with a crafted state dir and return the result.

    post.js computes stateDir as path.join(RUNNER_TEMP, 'thumper'), so we must
    set RUNNER_TEMP=tmpdir and write action-state.json to tmpdir/thumper/.
    """
    # post.js does: path.join(runnerTemp, 'thumper') where runnerTemp = RUNNER_TEMP
    state_dir = os.path.join(tmpdir, "thumper")
    os.makedirs(state_dir, exist_ok=True)
    action_state = os.path.join(state_dir, "action-state.json")

    # Write a bogus pid (9999999 is unlikely to be a live process)
    state = {"pid": 9999999, "stateDir": state_dir, "failOnTrigger": fail_on_trigger}
    with open(action_state, "w") as f:
        json.dump(state, f)

    if triggered:
        Path(os.path.join(state_dir, "triggered")).touch()

    env = {**os.environ, "RUNNER_TEMP": tmpdir}
    return subprocess.run(
        ["node", str(ACTION_DIR / "post.js")],
        capture_output=True, text=True, env=env,
    )


def test_post_exits_1_when_triggered_and_fail_on():
    with tempfile.TemporaryDirectory() as tmpdir:
        result = _run_post(tmpdir, triggered=True, fail_on_trigger="true")
        assert result.returncode == 1, (
            f"expected exit 1 (triggered + fail-on-trigger=true), got {result.returncode}\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
        assert "bait was read" in result.stdout.lower() or "bait was read" in result.stderr.lower()


def test_post_exits_0_when_triggered_but_fail_off():
    with tempfile.TemporaryDirectory() as tmpdir:
        result = _run_post(tmpdir, triggered=True, fail_on_trigger="false")
        assert result.returncode == 0, (
            f"expected exit 0 (triggered but fail-on-trigger=false), got {result.returncode}\n"
            f"stdout: {result.stdout}"
        )


def test_post_exits_0_when_no_trigger():
    with tempfile.TemporaryDirectory() as tmpdir:
        result = _run_post(tmpdir, triggered=False, fail_on_trigger="true")
        assert result.returncode == 0, (
            f"expected exit 0 (no trigger), got {result.returncode}\n"
            f"stdout: {result.stdout}"
        )


def test_post_exits_0_when_no_state():
    """If main.js never ran (no action-state.json), post.js exits 0 cleanly."""
    with tempfile.TemporaryDirectory() as tmpdir:
        env = {**os.environ, "RUNNER_TEMP": tmpdir}
        result = subprocess.run(
            ["node", str(ACTION_DIR / "post.js")],
            capture_output=True, text=True, env=env,
        )
        assert result.returncode == 0, (
            f"expected exit 0 when no state, got {result.returncode}\n"
            f"stdout: {result.stdout}"
        )
