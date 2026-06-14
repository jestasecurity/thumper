# Thumper architecture

One Docker image, three parts: a **UI**, a **server** with two plugin
points, and an **endpoint agent** delivered by a deploy plugin.

## The model (definition → instance)

```
Tripwire (definition)   ──build install command──▶  [org's MDM / SSH / Ansible
  name, type, path,                                    pushes it to chosen devices]
  source                                                      │
                                                              ▼  each device:
Endpoint  ◀── self-enroll (shared enroll token) ──────────────┤  POST /api/enroll
   │                                                           │  GET  /api/agent/deployments
   └─ Deployment (UNIQUE content + UNIQUE hmac_secret) ◀───────┘  plant + watch
                    │
                    └─ on read → HMAC-signed, enriched callback → Alert → alert plugins
```

## Data model

| Entity | Purpose | Key fields |
| --- | --- | --- |
| **Tripwire** | Honeytoken definition | id, name, token_type, path, source, token, active |
| **Endpoint** | Registered machine | id, hostname, platform, machine_id (unique), agent_token, last_seen |
| **Deployment** | Per-(tripwire, endpoint) instance | id, tripwire_id, endpoint_id, path, content, hmac_secret, state |
| **Alert** | Fired event | id, deployment_id, process, pid, os_user, event_type, accessed_path, timestamp |
| **Integration** | Plugin config | plugin (PK), kind, configured, config_json, last_test_status |
| **DeliveryAttempt** | Per-plugin alert outcome | id, alert_id, plugin, status, error |

Deployment states: `pending` → `planted` | `failed`.

## Components

### 1. UI (`ui/`)

SPA served from the server in production.

### 2. Server (`server/thumper/`)

| Module | Role |
| --- | --- |
| `main.py` | App setup, lifespan, SPA fallback |
| `api/routes.py` | JSON UI contract + plain-text agent protocol |
| `db.py` | ORM models, engine setup, migrations |
| `store.py` | Repository layer |
| `models.py` | Pydantic request/response schemas |
| `config.py` | Runtime config from environment |
| `tokens/` | Honeytoken generators + recommended-path catalog |
| `plugins/` | Plugin contracts + discovery |
| `services/` | Deploy, alerting, signing, content rendering, integrations |

### 3. Endpoint agent (`agent/thumper_agent.sh`)

Pure shell (`curl` + `openssl`, no runtime dependencies) so endpoints need no
language runtime. Delivered by a deploy plugin or manual copy.

The agent checks for path conflicts, self-enrolls with the server, pulls its
unique deployments (each with its own bait content and HMAC secret), plants the
files, and continuously monitors them for read access. On macOS it uses
`fs_usage` for real-time process-level detection; elsewhere it falls back to
`st_atime` polling. When a read is detected, the agent sends an HMAC-signed
callback to the server with enriched context (process, pid, user, path).

#### Singleton lock

Atomic `mkdir` on `agent.lock` ensures only one watcher per install location.
PID file inside tracks the process; stale locks are recovered on reboot.

## Configuration

All options overridable via environment:

| Variable | Default | Purpose |
| --- | --- | --- |
| `THUMPER_DB` | `./thumper.db` | Database URL |
| `THUMPER_BASE_URL` | `http://localhost:8000` | Server's public URL (must be reachable from endpoints) |
| `THUMPER_ENROLL_TOKEN` | `dev-enroll-token` | Shared token for agent enrollment |
| `THUMPER_INSTALL_TOKEN` | `dev-install-token` | Gates `/install.sh` |
| `THUMPER_UI_DIST` | `./ui/dist` | Built SPA location |
| `THUMPER_AGENT_PATH` | `./agent/thumper_agent.sh` | Agent script to serve |
| `THUMPER_PLUGINS_DIR` | `./plugins` | Plugin discovery root |
| `THUMPER_DASHBOARD_REFRESH` | `60` | Auto-refresh interval (seconds, 0 = off) |
