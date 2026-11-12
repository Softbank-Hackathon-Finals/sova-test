import subprocess

import pytest
from starlette.responses import Response
from starlette.testclient import TestClient

from onprem_response.native_assets import PREFIX, NativeConsoleAssets


async def fallback(scope, receive, send):
    await Response(status_code=404)(scope, receive, send)


@pytest.fixture
def assets(tmp_path):
    def git(*args):
        return subprocess.check_output(
            ["git", "-C", str(tmp_path), *args], text=True
        ).strip()

    git("init", "-q")
    root = tmp_path / PREFIX
    root.mkdir(parents=True)
    (root / "index.html").write_text(
        '<head><script src="/console/app.js"></script></head><main id="workspace-main"></main>'
    )
    (root / "app.js").write_text('import "./model.js"; const prefix="/console/";')
    git("add", ".")
    git(
        "-c",
        "user.name=Test",
        "-c",
        "user.email=test@example.invalid",
        "-c",
        "commit.gpgsign=false",
        "commit",
        "-qm",
        "fixture",
    )
    revision = git("rev-parse", "HEAD")
    # A dirty working tree must not be served under a qualified source revision.
    (root / "app.js").write_text("UNQUALIFIED WORKTREE CHANGE")
    app = NativeConsoleAssets(
        fallback,
        repository=tmp_path,
        revision=revision,
        origin="http://127.0.0.1:18131",
    )
    return TestClient(app, base_url="http://127.0.0.1:18131")


def test_immutable_source_and_original_native_logic(assets):
    html = assets.get("/__native/console/")
    assert html.status_code == 200
    assert "/__native/console/app.js" in html.text
    assert "/__native/guard.js" in html.text and "native-transport-status" in html.text
    script = assets.get("/__native/console/app.js")
    assert script.text == 'import "./model.js"; const prefix="/__native/console/";'
    assert "UNQUALIFIED" not in script.text
    assert "frame-ancestors 'none'" in html.headers["content-security-policy"]


@pytest.mark.parametrize(
    "path,headers,status",
    [
        ("/__native/console/?anything=1", {}, 403),
        ("/__native/console/", {"Host": "other.example"}, 403),
        ("/__native/console/not-in-commit.js", {}, 404),
    ],
)
def test_asset_boundary(assets, path, headers, status):
    assert assets.get(path, headers=headers).status_code == status


def test_mutable_revision_ref_is_not_accepted(tmp_path):
    with pytest.raises(ValueError, match="immutable"):
        NativeConsoleAssets(
            fallback,
            repository=tmp_path,
            revision="develop",
            origin="http://127.0.0.1:18131",
        )
