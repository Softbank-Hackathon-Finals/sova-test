import base64
import hashlib
import json
import pytest
from .builder import node_vendor


def lock(root, url="https://registry.npmjs.org/pkg/-/pkg-1.tgz", body=b"package"):
    (root / "package-lock.json").write_text(
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {
                    "": {},
                    "node_modules/pkg": {
                        "resolved": url,
                        "integrity": "sha512-"
                        + base64.b64encode(hashlib.sha512(body).digest()).decode(),
                    },
                },
            }
        )
    )


def test_prefetch_verified_package_without_running_code(tmp_path):
    lock(tmp_path)
    assert node_vendor(tmp_path, tmp_path / "vendor", lambda u, n: b"package") == 1
    assert (tmp_path / "vendor/0.tgz").read_bytes() == b"package"


def test_prefetch_integrity_failure(tmp_path):
    lock(tmp_path)
    with pytest.raises(ValueError, match="integrity"):
        node_vendor(tmp_path, tmp_path / "vendor", lambda u, n: b"changed")


@pytest.mark.parametrize(
    "url",
    [
        "http://registry.npmjs.org/p.tgz",
        "https://127.0.0.1/p.tgz",
        "https://registry.npmjs.org@evil.test/p.tgz",
        "https://registry.npmjs.org/../p.tgz",
    ],
)
def test_no_arbitrary_dependency_fetch(tmp_path, url):
    lock(tmp_path, url)

    def forbidden(*a):
        raise AssertionError("fetch must not run")

    with pytest.raises(ValueError):
        node_vendor(tmp_path, tmp_path / "vendor", forbidden)
