"""Shared helpers for waiting on the agent's steady-state signal (#237).

The agent writes a `ready` marker (and, for atime, bumps an `atime_armed`
generation counter) once its watchers are up and baselines are captured. Tests
wait on these instead of racing the sub-second startup window with weak "armed?"
gates + ad-hoc sleeps.
"""
import time
from pathlib import Path


def wait_for(cond, timeout=12.0, interval=0.05):
    """Poll `cond` until it returns truthy or `timeout` elapses. Returns bool."""
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return True
        time.sleep(interval)
    return False


def wait_ready(state_dir, timeout=12.0):
    """Block until the agent signals steady state: watchers up and, for atime,
    baselines captured. `state_dir` is the dir holding the agent's --state-file
    (the agent writes `ready` there)."""
    ready = Path(state_dir) / "ready"
    return wait_for(ready.exists, timeout)


def atime_armed_gen(state_dir):
    """The atime 'armed generation' - incremented after every (re)baseline. Wait
    for it to ADVANCE before simulating the next atime read, so the bump can't
    land in the arm->baseline window and be captured as the baseline (#235)."""
    try:
        return int((Path(state_dir) / "atime_armed").read_text())
    except (FileNotFoundError, ValueError):
        return 0


def wait_atime_gen(state_dir, at_least, timeout=12.0):
    """Block until the atime armed generation reaches `at_least`."""
    return wait_for(lambda: atime_armed_gen(state_dir) >= at_least, timeout)
