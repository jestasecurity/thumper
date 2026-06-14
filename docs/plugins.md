# Writing a Thumper plugin

Plugins are how Thumper stays a *tool, not a solution*: deployment and alerting
are pluggable so an org wires Thumper into whatever it already runs. Adding one
is intentionally trivial - **drop a directory in, get a UI for free.**

## Plugin structure

A plugin is a directory under `plugins/{deploy,alert}/<name>/` with two files:

```
plugins/alert/slack/
  manifest.yaml   # metadata + config_schema (the UI renders a form from this)
  plugin.py       # a class named `Plugin`
```

No registration, no imports to edit - the loader discovers it on startup.

## Two kinds

| Kind | Contract | Job |
| --- | --- | --- |
| **Alert** | `AlertPlugin.alert(event)` | Deliver a fired-tripwire event to an external system |
| **Deploy** | `DeployPlugin.deploy(install, targets)` | Run the install command on target machines |

A plugin is one or the other, never both.

## manifest.yaml

```yaml
name: slack                 # unique id (must match the directory)
kind: alert                 # deploy | alert
display_name: "Slack"
version: "0.1.0"
author: your-handle
description: "Posts a message to a Slack channel when a tripwire fires."
config_schema:              # each field becomes a form input in the UI
  - key: webhook_url
    label: "Incoming webhook URL"
    type: secret            # string | secret | boolean
    required: true
    placeholder: "https://hooks.slack.com/services/…"
    help: "Optional helper text shown under the field."
```

`secret` fields are stored as given but masked (`••••••••`) when read back.

## plugin.py

The class **must** be named `Plugin` and extend the appropriate base class.
It's constructed with the saved config dict (`self.config`).

### Alert plugin

```python
import httpx
from thumper.plugins.base import AlertPlugin, PluginError

class Plugin(AlertPlugin):
    def alert(self, event: dict) -> None:
        url = self.config.get("webhook_url")
        if not url:
            raise PluginError("slack: webhook_url is required")
        text = (f":rotating_light: Honeytoken read on *{event['endpoint_hostname']}* "
                f"by `{event.get('process')}` (user {event.get('os_user')}) "
                f"- {event['tripwire_name']} at {event.get('accessed_path')}")
        httpx.post(url, json={"text": text}, timeout=10).raise_for_status()
```

The `event` dict carries identifiers (`alert_id`, `tripwire_id`, `endpoint_id`,
`deployment_id`), display fields (`tripwire_name`, `endpoint_hostname`,
`token_type`), and enrichment from the endpoint monitor (`accessed_path`,
`process`, `pid`, `os_user`, `event_type`, `timestamp`).

Raise `PluginError` (or any exception) on failure - the router logs it and keeps
going; one bad plugin never drops the alert.

### Deploy plugin

```python
from thumper.plugins.base import AgentInstall, DeployPlugin, DeployResult, PluginError

class Plugin(DeployPlugin):
    def deploy(self, install: AgentInstall, targets: list[str]) -> DeployResult:
        # Run install.command on the machines you target (from self.config or targets).
        # Each machine self-enrolls and pulls its own unique token instance.
        ...
        return DeployResult(state="deployed", deployed_count=N, message="…")
```

`AgentInstall` carries `tripwire_id`, `server_url`, `enroll_token`, and the
ready-to-run `command`. A deploy plugin's only job is to **run that command** on
the chosen machines - it never handles token content or secrets.

## Test it

Drop the directory in, restart the server, and it appears under **Integrations**
with a generated config form. Verify it loads:

```bash
python -c "from thumper.plugins.registry import load_plugin; load_plugin('slack', {})"
```
