import json

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from thumper import store
from thumper.db import Base, DeliveryAttempt, Integration
from thumper.services import alerting


@pytest.fixture
def db():
    engine = create_engine("sqlite://", echo=False)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    yield session
    session.close()


def test_record_and_list_delivery_ok(db):
    store.record_delivery(db, alert_id="al_1", plugin="webhook", status="ok", error=None)
    rows = store.list_deliveries(db, "al_1")
    assert len(rows) == 1
    assert rows[0].plugin == "webhook"
    assert rows[0].status == "ok"
    assert rows[0].error is None
    assert rows[0].id.startswith("dl_")
    assert rows[0].created_at


def test_record_delivery_failed_keeps_error(db):
    store.record_delivery(db, alert_id="al_1", plugin="splunk", status="failed",
                          error="connection refused")
    rows = store.list_deliveries(db, "al_1")
    assert rows[0].status == "failed"
    assert rows[0].error == "connection refused"


def test_list_deliveries_scoped_to_alert(db):
    store.record_delivery(db, alert_id="al_1", plugin="webhook", status="ok", error=None)
    store.record_delivery(db, alert_id="al_2", plugin="webhook", status="ok", error=None)
    assert len(store.list_deliveries(db, "al_1")) == 1


class FakePlugin:
    def __init__(self, fail=False):
        self._fail = fail

    def alert(self, event):
        if self._fail:
            raise RuntimeError("boom")


def _add_alert_integration(db, plugin):
    store.upsert_integration(db, plugin=plugin, kind="alert", config={"url": "http://x"})


def test_route_alert_records_ok_per_successful_plugin(db, monkeypatch):
    _add_alert_integration(db, "webhook")
    monkeypatch.setattr(alerting, "load_plugin", lambda name, cfg: FakePlugin())

    alerting.route_alert(db, {"alert_id": "al_1"})

    rows = store.list_deliveries(db, "al_1")
    assert [r.status for r in rows] == ["ok"]
    assert rows[0].plugin == "webhook"


def test_route_alert_records_failed_with_error(db, monkeypatch):
    _add_alert_integration(db, "webhook")
    monkeypatch.setattr(alerting, "load_plugin", lambda name, cfg: FakePlugin(fail=True))

    alerting.route_alert(db, {"alert_id": "al_1"})

    rows = store.list_deliveries(db, "al_1")
    assert rows[0].status == "failed"
    assert "boom" in rows[0].error


def test_route_alert_best_effort_one_failure_does_not_stop_others(db, monkeypatch):
    _add_alert_integration(db, "webhook")
    _add_alert_integration(db, "splunk")
    plugins = {"webhook": FakePlugin(fail=True), "splunk": FakePlugin()}
    monkeypatch.setattr(alerting, "load_plugin", lambda name, cfg: plugins[name])

    alerting.route_alert(db, {"alert_id": "al_1"})

    rows = {r.plugin: r.status for r in store.list_deliveries(db, "al_1")}
    assert rows == {"webhook": "failed", "splunk": "ok"}


def test_route_alert_skips_unconfigured_and_non_alert(db, monkeypatch):
    store.upsert_integration(db, plugin="mdm", kind="deploy", config={"x": 1})
    monkeypatch.setattr(alerting, "load_plugin", lambda name, cfg: FakePlugin())

    alerting.route_alert(db, {"alert_id": "al_1"})

    assert store.list_deliveries(db, "al_1") == []


def test_route_alert_skips_unconfigured_alert_integration(db, monkeypatch):
    db.add(Integration(plugin="webhook", kind="alert", configured=False, config_json="{}"))
    db.commit()
    monkeypatch.setattr(alerting, "load_plugin", lambda name, cfg: FakePlugin())

    alerting.route_alert(db, {"alert_id": "al_1"})

    assert store.list_deliveries(db, "al_1") == []


def test_deliver_alert_opens_own_session_fans_out_and_records(monkeypatch):
    engine = create_engine("sqlite://", echo=False,
                           connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    TestSession = sessionmaker(bind=engine)
    seed = TestSession()
    store.upsert_integration(seed, plugin="webhook", kind="alert", config={"url": "http://x"})
    seed.close()
    monkeypatch.setattr(alerting, "SessionLocal", TestSession)
    monkeypatch.setattr(alerting, "load_plugin", lambda name, cfg: FakePlugin())

    alerting.deliver_alert({"alert_id": "al_bg"})

    check = TestSession()
    rows = store.list_deliveries(check, "al_bg")
    check.close()
    assert [r.status for r in rows] == ["ok"]
    assert rows[0].plugin == "webhook"


def test_route_alert_recovers_when_record_delivery_poisons_session(db, monkeypatch):
    # If recording one plugin's delivery fails mid-commit, the shared session is
    # left pending-rollback; without a rollback the next plugin is silently
    # dropped. The second delivery must still be recorded.
    _add_alert_integration(db, "webhook")
    _add_alert_integration(db, "splunk")
    monkeypatch.setattr(alerting, "load_plugin", lambda name, cfg: FakePlugin())

    real = store.record_delivery
    calls = {"n": 0}

    def flaky(session, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            session.add(DeliveryAttempt(id=None, alert_id="x", plugin="x",
                                        status="ok", error=None, created_at="t"))
            session.commit()  # NULL primary key -> IntegrityError, poisons session
        return real(session, **kwargs)

    monkeypatch.setattr(alerting.store, "record_delivery", flaky)

    alerting.route_alert(db, {"alert_id": "al_1"})

    recorded = {r.plugin for r in store.list_deliveries(db, "al_1")}
    assert "splunk" in recorded


def test_upsert_integration_idempotent_preserves_test_results(db):
    # Re-upserting an existing plugin (e.g. a config edit) must not raise and must
    # not wipe a previously recorded connection-test result.
    store.upsert_integration(db, plugin="webhook", kind="alert", config={"url": "a"})
    store.set_integration_test_result(db, plugin="webhook", status="ok", error=None)

    store.upsert_integration(db, plugin="webhook", kind="alert", config={"url": "b"})

    row = store.get_integration(db, "webhook")
    assert json.loads(row.config_json) == {"url": "b"}
    assert row.last_test_status == "ok"


def test_deliver_alert_never_raises(monkeypatch):
    engine = create_engine("sqlite://", echo=False,
                           connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    TestSession = sessionmaker(bind=engine)
    monkeypatch.setattr(alerting, "SessionLocal", TestSession)

    def boom(db, event):
        raise RuntimeError("fan-out exploded")

    monkeypatch.setattr(alerting, "route_alert", boom)
    alerting.deliver_alert({"alert_id": "al_x"})  # must return normally
