"""Build a tripwire's install command and distribute it via configured deploy
plugins. The org's MDM/SSH/etc is the control plane for *which* machines get it;
each machine that runs the command self-enrolls and pulls its own instance.
"""
import json

from ..config import BASE_URL, ENROLL_TOKEN, INSTALL_TOKEN
from ..plugins.base import AgentInstall, PluginError
from ..plugins.registry import load_plugin
from .. import store


def _install_command(tripwire_ids: list[str]) -> str:
    # Self-bootstrapping: downloads the agent from the server and starts it
    # watching. Works pasted on an endpoint or pushed via MDM/SSH. We download
    # THEN `sudo sh <file>` (not `curl | sudo sh`) so sudo keeps the terminal for
    # its password prompt. sudo because macOS fs_usage read-detection needs root.
    # The install token gates /api/install.sh (it embeds the enroll token), so we
    # pass it here - this command is generated server-side, never exposed publicly.
    # One `tripwire=` param per tripwire; the agent enrolls for the whole set and
    # a single watcher plants/monitors them all.
    qs = "".join(f"tripwire={tid}&" for tid in tripwire_ids)
    return (
        f"curl -fsSL '{BASE_URL}/api/install.sh?{qs}token={INSTALL_TOKEN}' "
        f"-o /tmp/thumper-install.sh && sudo sh /tmp/thumper-install.sh"
    )


def build_install(tripwire_id: str) -> AgentInstall:
    return AgentInstall(
        tripwire_id=tripwire_id,
        server_url=BASE_URL,
        enroll_token=ENROLL_TOKEN,
        command=_install_command([tripwire_id]),
    )


def build_install_command(tripwire_ids: list[str]):
    # The multi-tripwire builder for the UI's "Build install command" flow. Kept
    # parallel to build_install() so the single-tripwire path (and the deploy
    # plugins that read AgentInstall.tripwire_id) stay untouched.
    from ..models import InstallCommandOut
    return InstallCommandOut(
        tripwire_ids=list(tripwire_ids),
        command=_install_command(tripwire_ids),
    )


def distribute(conn, tripwire_id: str) -> dict:
    """Hand the install command to every configured deploy plugin. Returns a
    summary; raises PluginError if none are configured."""
    configured = [
        row for row in store.list_integrations(conn)
        if row.kind == "deploy" and row.configured
    ]
    if not configured:
        raise PluginError("No deploy integration configured. Add one under Integrations, "
                          "or copy the install command and distribute it yourself.")

    install = build_install(tripwire_id)
    results = []
    for integ in configured:
        # Isolate each plugin: one failing (bad creds, unreachable host, a bug)
        # must not abort the rest or discard their results - report it as failed
        # and carry on.
        try:
            plugin = load_plugin(integ.plugin, json.loads(integ.config_json))
            res = plugin.deploy(install, [])
            results.append({"plugin": integ.plugin, "state": res.state,
                            "deployed_count": res.deployed_count, "message": res.message})
        except Exception as exc:  # noqa: BLE001 - one plugin must not break the others
            results.append({"plugin": integ.plugin, "state": "failed",
                            "deployed_count": 0, "message": str(exc)})
    return {"results": results}
