"""distribute() must isolate deploy-plugin failures: one plugin raising should
not abort the others or lose their results (#30)."""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from thumper import store
from thumper.db import Base
from thumper.plugins.base import DeployResult
from thumper.services import deploy as deploy_svc


@pytest.fixture
def db():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    yield s
    s.close()


def test_one_failing_deploy_plugin_does_not_abort_others(db, monkeypatch):
    tw = store.create_tripwire(db, name="t", token_type="aws",
                               path="~/.aws/credentials", token="x")
    # Two configured deploy plugins; the first one will blow up.
    store.upsert_integration(db, plugin="ssh", kind="deploy", config={})
    store.upsert_integration(db, plugin="mdm", kind="deploy", config={})

    class Boom:
        def deploy(self, install, targets):
            raise RuntimeError("ssh unreachable")

    class Ok:
        def deploy(self, install, targets):
            return DeployResult(state="deployed", deployed_count=2, message="pushed")

    monkeypatch.setattr(deploy_svc, "load_plugin",
                        lambda name, config: Boom() if name == "ssh" else Ok())

    out = deploy_svc.distribute(db, tw.id)
    results = {r["plugin"]: r for r in out["results"]}

    assert set(results) == {"ssh", "mdm"}, "a failing plugin aborted the others"
    assert results["ssh"]["state"] == "failed"
    assert "ssh unreachable" in results["ssh"]["message"]
    assert results["mdm"]["state"] == "deployed"
    assert results["mdm"]["deployed_count"] == 2
