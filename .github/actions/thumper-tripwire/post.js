'use strict';
// Thumper CI tripwire — post step (node20, no npm deps)
// Runs at job end (after all other steps, including failed steps).
// 1. Sends SIGTERM to the agent so its --ephemeral trap fires (unplant + decommission).
// 2. If fail-on-trigger is truthy AND the triggered marker file exists, fails the job.

const fs   = require('fs');
const path = require('path');
const os   = require('os');

const _sab = new Int32Array(new SharedArrayBuffer(4));
const sleepMs = (ms) => { try { Atomics.wait(_sab, 0, 0, ms); } catch (_) {} };

function wfCmd(cmd, msg) { process.stdout.write(`::${cmd}::${msg}\n`); }
function error(msg)   { wfCmd('error', msg); }

// ── locate action-state.json ──────────────────────────────────────────────────
const runnerTemp  = process.env['RUNNER_TEMP'] || os.tmpdir();
const stateDir    = path.join(runnerTemp, 'thumper');  // legacy fallback dir
// main.js hands us the randomized state path via GITHUB_STATE; fall back to the
// old fixed path for older runs / tests that don't set it.
const actionState = process.env['STATE_actionState'] || path.join(stateDir, 'action-state.json');

let state;
try {
  state = JSON.parse(fs.readFileSync(actionState, 'utf8'));
} catch (err) {
  // main.js never ran (skipped step, runner issue) — nothing to clean up.
  console.log(`[thumper] post: no action state found (${err.message}); nothing to clean up`);
  process.exit(0);
}

const { pid, stateDir: savedDir, failOnTrigger } = state;
const resolvedStateDir = savedDir || stateDir;

// ── decommission: SIGTERM → agent's --ephemeral EXIT trap ────────────────────
if (pid) {
  try {
    process.kill(pid, 'SIGTERM');
    console.log(`[thumper] post: sent SIGTERM to agent (pid ${pid})`);
    // Give the agent a moment to run its self-destruct trap and confirm to the server.
    const deadline = Date.now() + 5000;
    while (Date.now() < deadline) {
      try { process.kill(pid, 0); } catch (_) { break; }  // 0 = liveness probe
      sleepMs(100);
    }
  } catch (err) {
    // ESRCH = no such process (already exited); anything else is unexpected but non-fatal.
    if (err.code !== 'ESRCH') {
      console.log(`[thumper] post: SIGTERM failed (${err.message}); agent may have already exited`);
    } else {
      console.log(`[thumper] post: agent already exited (pid ${pid})`);
    }
  }
}

// ── fail-on-trigger ───────────────────────────────────────────────────────────
const triggered = path.join(resolvedStateDir, 'triggered');
const didTrigger = fs.existsSync(triggered);

if (didTrigger) {
  const triggerMsg = 'Thumper tripwire: bait was read during this job';
  const isFail = failOnTrigger === 'true' || failOnTrigger === '1';
  if (isFail) {
    error(`thumper: ${triggerMsg}`);
    process.exitCode = 1;
  } else {
    console.log(`[thumper] post: ${triggerMsg} (fail-on-trigger is not set)`);
  }
} else {
  console.log('[thumper] post: no tripwire trigger detected during this job');
}
