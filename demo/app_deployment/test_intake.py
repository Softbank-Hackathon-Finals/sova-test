import io
import json
import zipfile
import pytest
from .intake import unpack, github_archive


def archive(items):
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as z:
        for name, data in items:
            z.writestr(name, data)
    return b.getvalue()


def test_real_static_source(tmp_path):
    s = unpack(archive([("site/index.html", "hello")]), tmp_path / "out")
    assert s.runtime == "static" and s.file_count == 1
    assert (s.root / "index.html").read_text() == "hello"


@pytest.mark.parametrize(
    "name", ["../outside", "/tmp/out", "a/../../out", "a\\out", ".env", "id.key"]
)
def test_dangerous_archive_paths(tmp_path, name):
    with pytest.raises(ValueError):
        unpack(archive([("index.html", "ok"), (name, "bad")]), tmp_path / "out")
    assert not (tmp_path / "outside").exists()


def test_duplicate_case_conflict(tmp_path):
    with pytest.raises(ValueError):
        unpack(archive([("index.html", "ok"), ("INDEX.html", "bad")]), tmp_path / "out")


def test_symlink_denied(tmp_path):
    i = zipfile.ZipInfo("link")
    i.external_attr = 0o120777 << 16
    with pytest.raises(ValueError):
        unpack(archive([("index.html", "ok"), (i, "/etc/passwd")]), tmp_path / "out")


def test_pinned_github_only():
    calls = []

    def fetch(url, limit):
        calls.append(url)
        return json.dumps({"sha": "a" * 40}).encode() if len(calls) == 1 else b"archive"

    data, source = github_archive("https://github.com/team/project.git", "main", fetch)
    assert data == b"archive" and source["commit"] == "a" * 40
    assert calls[-1] == "https://codeload.github.com/team/project/zip/" + "a" * 40
    with pytest.raises(ValueError):
        github_archive("http://127.0.0.1/repo", "main", fetch)
    with pytest.raises(ValueError):
        github_archive("https://github.com/team/project", "../../secrets", fetch)


def test_local_database_requires_explicit_persistent_profile(tmp_path):
    with pytest.raises(ValueError, match="persistent_database_profile_required"):
        unpack(
            archive(
                [("index.html", "hello"), ("data/scores.db", b"SQLite format 3\0")]
            ),
            tmp_path / "out",
        )
