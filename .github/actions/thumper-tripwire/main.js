'use strict';
// Thumper CI tripwire — main step (node20, no npm deps)
// Plants honeytoken bait via the Thumper agent and starts watching for reads.
// The agent runs detached so this step returns while the job continues;
// post.js decommissions it and optionally fails the job if bait was read.

const https = require('https');
const http = require('http');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { execSync, spawn } = require('child_process');

// ── inputs ────────────────────────────────────────────────────────────────────
const server    = (process.env['INPUT_SERVER']        || '').replace(/\/$/, '');
const enrollTok = process.env['INPUT_ENROLL-TOKEN']   || '';
const tripwires = process.env['INPUT_TRIPWIRES']      || '';
const failOn    = (process.env['INPUT_FAIL-ON-TRIGGER'] || 'false').toLowerCase();

function wfCmd(cmd, msg) { process.stdout.write(`::${cmd}::${msg}\n`); }
function error(msg)   { wfCmd('error', msg); }
function warning(msg) { wfCmd('warning', msg); }

if (enrollTok) { process.stdout.write(`::add-mask::${enrollTok}\n`); }

if (!server)    { error('thumper: input "server" is required');       process.exit(1); }
if (!enrollTok) { error('thumper: input "enroll-token" is required'); process.exit(1); }
if (!tripwires) { error('thumper: input "tripwires" is required');     process.exit(1); }

// ── state dir ─────────────────────────────────────────────────────────────────
const runnerTemp = process.env['RUNNER_TEMP'] || os.tmpdir();
const stateDir   = path.join(runnerTemp, 'thumper');
const agentPath  = path.join(stateDir, 'thumper_agent.sh');
const stateFile  = path.join(stateDir, 'agent.json');
const actionState = path.join(stateDir, 'action-state.json');

fs.mkdirSync(stateDir, { recursive: true });
console.log(`[thumper] state dir: ${stateDir}`);

// ── fetch agent from server ──────────────────────────────────────────────────
// The server serves the agent at GET /api/agent/thumper_agent.sh (no auth needed).
function fetchAgent(serverUrl, destPath) {
  return new Promise((resolve, reject) => {
    const agentUrl = `${serverUrl}/api/agent/thumper_agent.sh`;
    console.log(`[thumper] fetching agent from ${agentUrl}`);
    const client = agentUrl.startsWith('https') ? https : http;
    const req = client.get(agentUrl, (res) => {
      if (res.statusCode !== 200) {
        reject(new Error(`agent download failed: HTTP ${res.statusCode} from ${agentUrl}`));
        res.resume();
        return;
      }
      const out = fs.createWriteStream(destPath);
      res.pipe(out);
      res.on('error', reject);
      out.on('finish', () => {
        out.close();
        try { fs.chmodSync(destPath, 0o755); } catch (_) {}
        resolve();
      });
      out.on('error', reject);
    });
    req.on('error', reject);
    req.setTimeout(30000, () => { req.destroy(new Error('agent download timed out')); });
  });
}

// ── ensure inotify-tools (Linux) ─────────────────────────────────────────────
// The install.sh already does this; we mirror it here so CI runners that skip
// install.sh still get the real inotify sensor. Best-effort; failure is non-fatal.
function ensureInotify() {
  if (process.platform !== 'linux') return;
  try {
    execSync('command -v inotifywait', { stdio: 'ignore' });
    console.log('[thumper] inotify-tools already available');
    return;
  } catch (_) { /* not installed */ }
  console.log('[thumper] installing inotify-tools...');
  try {
    execSync('sudo apt-get install -y inotify-tools', { stdio: 'pipe', timeout: 60000 });
    console.log('[thumper] inotify-tools installed');
  } catch (err) {
    warning(`thumper: could not install inotify-tools (${err.message}); agent will use atime fallback`);
  }
}

// ── spawn the agent detached ──────────────────────────────────────────────────
function spawnAgent() {
  // Build --tripwire args: the input is a comma-separated list of ids.
  const tripwireArgs = tripwires
    .split(',')
    .map(t => t.trim())
    .filter(Boolean)
    .flatMap(t => ['--tripwire', t]);

  const args = [
    agentPath, 'run',
    '--server',       server,
    '--enroll-token', enrollTok,
    ...tripwireArgs,
    '--ephemeral',
    '--heartbeat', '30',
    '--sync-interval', '0',
    '--state-file', stateFile,
  ];

  console.log(`[thumper] spawning agent: watching ${tripwires} on ${server}`);
  const child = spawn('sh', args, {
    detached: true,
    stdio: 'ignore',
  });
  child.on('error', (err) => { error(`thumper: agent failed to spawn: ${err.message}`); process.exit(1); });
  child.unref();
  if (!child.pid) { error('thumper: agent failed to start (no pid)'); process.exit(1); }
  const agentPid = child.pid;
  console.log(`[thumper] agent spawned (pid ${agentPid})`);
  return agentPid;
}

// ── main ──────────────────────────────────────────────────────────────────────
(async () => {
  try {
    await fetchAgent(server, agentPath);
    ensureInotify();
    const pid = spawnAgent();

    const readyFile = path.join(stateDir, 'ready');
    const sleep = (ms) => new Promise(r => setTimeout(r, ms));
    let ready = false;
    for (let i = 0; i < 40; i++) {                 // up to ~20s
      if (fs.existsSync(readyFile)) { ready = true; break; }
      await sleep(500);
    }
    if (!ready) warning('thumper: agent did not signal ready within 20s; bait may not be planted yet — protection for early steps is not guaranteed');
    else console.log('[thumper] agent ready; bait planted and watching');

    // Persist state for post.js — written to a file in stateDir so no
    // GITHUB_STATE parsing is needed; post.js just reads this JSON.
    const state = { pid, stateDir, failOnTrigger: failOn };
    fs.writeFileSync(actionState, JSON.stringify(state, null, 2));
    console.log(`[thumper] action state written to ${actionState}`);
    console.log('[thumper] tripwire planted and agent watching; post.js will decommission on job end');
  } catch (err) {
    error(`thumper: ${err.message}`);
    process.exit(1);
  }
})();
