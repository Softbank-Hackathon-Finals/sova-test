"""Keep integration code free of demo imports and preserve legacy type identity."""

import ast
import importlib
import json
from pathlib import Path
from bravo_security.migrations import MIGRATIONS, migration_sql

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = json.loads((ROOT / "integration/security/manifest.json").read_text())


def test_legacy_imports_are_the_same_modules_not_duplicate_domain_types():
    for legacy, canonical in MANIFEST["compatibility_aliases"].items():
        assert importlib.import_module(legacy) is importlib.import_module(canonical)


def test_security_module_does_not_import_console_or_demo_runtimes():
    forbidden = {
        "demo",
        "preview",
        "frontend",
        "console",
        "operator_auth",
        "security_console",
        "graph_demo",
        "relocation_server",
    }
    for path in (ROOT / MANIFEST["canonical_python_root"]).rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text())):
            names = (
                [node.module]
                if isinstance(node, ast.ImportFrom) and node.module
                else [x.name for x in node.names]
                if isinstance(node, ast.Import)
                else []
            )
            assert all(name.split(".")[0] not in forbidden for name in names), str(path)


def test_canonical_directories_and_sql_point_to_single_sources():
    assert (ROOT / "demo").is_dir() and not (ROOT / "demo").is_symlink()
    assert (ROOT / "console").is_dir() and not (ROOT / "console").is_symlink()
    assert not (ROOT / "preview").exists() and not (ROOT / "preview").is_symlink()
    assert not (ROOT / "frontend").exists() and not (ROOT / "frontend").is_symlink()
    assert len(MIGRATIONS) == 6
    for name in MIGRATIONS:
        assert migration_sql(name)
        assert not (ROOT / "src/sova/adapters/sql" / name).exists()
    for path in (ROOT / "src/sova/security/adapters/sql").glob("*.sql"):
        legacy = ROOT / "src/sova/adapters/sql" / path.name
        assert legacy.resolve() == path
        assert legacy.read_bytes() == path.read_bytes()
