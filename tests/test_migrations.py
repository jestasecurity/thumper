"""Migration-chain integrity. A second head sneaks in whenever two PRs each add
a migration off the same parent and both merge - and it breaks `init_db` for
everyone (alembic upgrade head -> "Multiple head revisions"). Guard against it."""
from pathlib import Path

from alembic.config import Config
from alembic.script import ScriptDirectory


def _script_dir() -> ScriptDirectory:
    migrations = Path(__file__).resolve().parents[1] / "server" / "thumper" / "migrations"
    cfg = Config()
    cfg.set_main_option("script_location", str(migrations))
    return ScriptDirectory.from_config(cfg)


def test_single_migration_head():
    heads = _script_dir().get_heads()
    assert len(heads) == 1, f"expected one alembic head, found {heads}"
