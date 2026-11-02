import pytest
from console_web import ConsoleWebBundle
from sova.domain.contracts import ContractError


def bundle(tmp_path):
    (tmp_path / "assets").mkdir()
    (tmp_path / "index.html").write_text(
        '<script src="/console/assets/app.js"></script>'
    )
    (tmp_path / "assets/app.js").write_text("console.log('public')")
    return tmp_path


def test_only_fixed_build_assets_are_served(tmp_path):
    root = bundle(tmp_path)
    (root / ".env").write_text("private-canary")
    web = ConsoleWebBundle(root)
    assert web.get("/")[1].startswith("text/html")
    assert web.get("/console/assets/app.js")[1] == "text/javascript"
    for path in (
        "/console/../.env",
        "/console/assets/../../.env",
        "/console/%2e%2e/.env",
        "/console/.env",
        "/console/assets/app.js?x=1",
    ):
        assert web.get(path) is None


@pytest.mark.parametrize("location", ["index", "asset", "directory"])
def test_build_symlinks_are_not_public_files(tmp_path, location):
    root = bundle(tmp_path)
    private = root / "private"
    private.write_text("private-canary")
    if location == "index":
        (root / "index.html").unlink()
        (root / "index.html").symlink_to(private)
    elif location == "asset":
        (root / "assets/leak.js").symlink_to(private)
    else:
        (root / "assets/app.js").unlink()
        (root / "assets").rmdir()
        (root / "assets").symlink_to(root)
    with pytest.raises(ContractError):
        ConsoleWebBundle(root)


def test_source_maps_and_private_build_files_are_not_admitted(tmp_path):
    root = bundle(tmp_path)
    (root / "assets/app.js.map").write_text("private-source")
    with pytest.raises(ContractError):
        ConsoleWebBundle(root)
