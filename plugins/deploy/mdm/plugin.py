"""MDM deploy plugin - Jamf Pro.

Gets the Thumper agent RUNNING on managed Macs by upserting a Jamf script and a
policy (scoped to a smart group, recurring check-in trigger) that runs it. Each
device self-enrolls and pulls its own unique token instance - nothing secret
travels in the policy. Real coverage truth is the Endpoints page (enroll
callbacks), not this plugin.

Jamf Pro only: this drives Jamf Pro's scripts + policies + smart-groups APIs
(Classic + Jamf Pro API). Jamf Now, Jamf School, and other MDMs do not expose
that surface - there, copy the install command and distribute it yourself
(paste on the endpoint, or push via that MDM).
"""
from thumper.plugins.base import AgentInstall, DeployPlugin, DeployResult, PluginError
from thumper.services.jamf import JamfClient, JamfError
from thumper.services.ssrf import assert_url_allowed

_REQUIRED = ("base_url", "client_id", "client_secret", "smart_group")
_NAME_PREFIX = "Thumper Agent"
_POLICY_PREFIX = f"{_NAME_PREFIX} - "  # script + policy names: "Thumper Agent - <tripwire_id>"
_ROOT_SUFFIX = "sh /tmp/thumper-install.sh"


def _to_root(command: str) -> str:
    """Jamf script policies run as root, non-interactively - drop the `sudo` the
    human-paste install command carries. Asserted replace: fail loudly if the
    command shape changes rather than ship a broken policy."""
    needle = f"sudo {_ROOT_SUFFIX}"
    if needle not in command:
        raise PluginError("unexpected install command shape; cannot derive root form")
    return command.replace(needle, _ROOT_SUFFIX, 1)


def _script_body(root_command: str) -> str:
    return f"#!/bin/sh\n{root_command}\n"


class Plugin(DeployPlugin):
    def _check_config(self) -> None:
        missing = [key for key in _REQUIRED if not self.config.get(key)]
        if missing:
            raise PluginError(f"MDM plugin missing required config: {', '.join(missing)}")

    def _client(self) -> JamfClient:
        assert_url_allowed(self.config["base_url"])  # SSRF guard (#74)
        return JamfClient(self.config["base_url"], self.config["client_id"],
                          self.config["client_secret"])

    def _policy_name(self, tripwire_id: str) -> str:
        return f"{_POLICY_PREFIX}{tripwire_id}"

    def deploy(self, install: AgentInstall, targets: list[str]) -> DeployResult:
        self._check_config()
        name = self._policy_name(install.tripwire_id)
        group = self.config["smart_group"]
        body = _script_body(_to_root(install.command))
        client = self._client()
        try:
            # Resolve the smart group FIRST: a missing/mistyped group is the most
            # likely failure, and validating it up front avoids creating an orphan
            # script that no policy references. (Both upserts are idempotent by
            # name, so if policy creation fails after the script is written, a
            # re-deploy heals it in place rather than duplicating.)
            group_id = client.find_smart_group_id(group)
            script_id = client.upsert_script(name, body)
            policy_id = client.upsert_policy(name, script_id, group_id)
            count = client.smart_group_member_count(group_id)
        except JamfError as exc:
            raise PluginError(str(exc)) from exc

        return DeployResult(
            state="pending", deployed_count=0,
            message=(f"Policy {policy_id} created/updated, scoped to '{group}' "
                     f"({count} devices in scope). Devices install on next check-in."),
        )

    def status(self, targets: list[str]) -> dict:
        self._check_config()
        client = self._client()
        try:
            return {pid: client.policy_status(pid)
                    for pid in client.find_policies_by_prefix(_POLICY_PREFIX)}
        except JamfError as exc:
            raise PluginError(str(exc)) from exc
