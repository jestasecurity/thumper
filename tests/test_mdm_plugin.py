import importlib.util
from pathlib import Path

import pytest

from thumper.plugins.base import AgentInstall, PluginError

PLUGIN_FILE = Path(__file__).resolve().parents[1] / "plugins" / "deploy" / "mdm" / "plugin.py"


def load_plugin_module():
    spec = importlib.util.spec_from_file_location("thumper_plugin_mdm_test", PLUGIN_FILE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeClient:
    instances = []

    def __init__(self, *args, **kwargs):
        self.scripts = []
        self.policies = []
        FakeClient.instances.append(self)

    def upsert_script(self, name, contents):
        self.scripts.append((name, contents))
        return "script-1"

    def find_smart_group_id(self, name):
        return "group-1"

    def upsert_policy(self, name, script_id, group_id):
        self.policies.append((name, script_id, group_id))
        return "policy-1"

    def smart_group_member_count(self, group_id):
        return 5


def make_install(command):
    return AgentInstall(tripwire_id="tw1", server_url="https://t", enroll_token="e", command=command)


GOOD_CONFIG = {"base_url": "https://jss", "client_id": "c", "client_secret": "s",
               "smart_group": "All Macs"}
GOOD_COMMAND = ("curl -fsSL 'https://t/api/install.sh?tripwire=tw1&token=x' "
                "-o /tmp/thumper-install.sh && sudo sh /tmp/thumper-install.sh")


@pytest.fixture
def plugin_module(monkeypatch):
    module = load_plugin_module()
    FakeClient.instances = []
    monkeypatch.setattr(module, "JamfClient", FakeClient)
    # base_url here is a non-resolvable stub ("https://jss"); neutralize the SSRF
    # guard so these orchestration tests don't do DNS (covered in test_ssrf.py).
    monkeypatch.setattr(module, "assert_url_allowed", lambda url: None)
    return module


def test_deploy_missing_config_raises(plugin_module):
    plugin = plugin_module.Plugin({"base_url": "https://jss"})
    with pytest.raises(PluginError, match="missing required config"):
        plugin.deploy(make_install(GOOD_COMMAND), [])


def test_deploy_rejects_unexpected_command_shape(plugin_module):
    plugin = plugin_module.Plugin(GOOD_CONFIG)
    with pytest.raises(PluginError, match="unexpected install command shape"):
        plugin.deploy(make_install("curl whatever | sh"), [])


def test_deploy_strips_sudo_and_orchestrates(plugin_module):
    plugin = plugin_module.Plugin(GOOD_CONFIG)
    result = plugin.deploy(make_install(GOOD_COMMAND), [])

    client = FakeClient.instances[-1]
    name, body = client.scripts[0]
    assert name == "Thumper Agent - tw1"
    assert "sudo" not in body
    assert "sh /tmp/thumper-install.sh" in body
    assert client.policies[0] == ("Thumper Agent - tw1", "script-1", "group-1")
    assert result.state == "pending"
    assert result.deployed_count == 0
    assert "policy-1" in result.message
    assert "5 devices" in result.message


def test_deploy_translates_jamf_error(plugin_module):
    from thumper.services.jamf import JamfError

    class Boom(FakeClient):
        def find_smart_group_id(self, name):
            raise JamfError("smart group 'All Macs' not found in Jamf")

    plugin_module.JamfClient = Boom
    plugin = plugin_module.Plugin(GOOD_CONFIG)
    with pytest.raises(PluginError, match="not found in Jamf"):
        plugin.deploy(make_install(GOOD_COMMAND), [])


def test_status_missing_config_raises(plugin_module):
    plugin = plugin_module.Plugin({"base_url": "https://jss"})
    with pytest.raises(PluginError, match="missing required config"):
        plugin.status([])


def test_status_enumerates_thumper_policies(plugin_module):
    class StatusClient(FakeClient):
        def find_policies_by_prefix(self, prefix):
            assert prefix == "Thumper Agent - "
            return ["55", "66"]

        def policy_status(self, policy_id):
            return {"policy_id": policy_id, "enabled": True,
                    "smart_group": "All Macs", "scope_count": 5}

    plugin_module.JamfClient = StatusClient
    plugin = plugin_module.Plugin(GOOD_CONFIG)
    status = plugin.status([])
    assert set(status.keys()) == {"55", "66"}
    assert status["55"]["scope_count"] == 5
