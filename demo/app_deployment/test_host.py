from starlette.testclient import TestClient
from .host import AppHost


class FakeApps:
    def __init__(self):
        self.calls = []

    def states(self):
        return []

    def deploy(self, *args):
        self.calls.append(args)
        return {"phase": "queued"}


def client(auth=True):
    apps = FakeApps()

    async def fallback(scope, receive, send):
        raise AssertionError("unexpected fallback")

    host = AppHost(
        fallback, origin="http://127.0.0.1:18131", authorize=lambda s: auth, apps=apps
    )
    return TestClient(host, base_url="http://127.0.0.1:18131"), apps


def test_cross_origin_deployment_denied():
    c, a = client()
    assert (
        c.post(
            "/__apps/deploy", headers={"origin": "https://evil.test"}, json={}
        ).status_code
        == 403
    )
    assert not a.calls


def test_no_session_cannot_read_or_deploy():
    c, a = client(False)
    assert c.get("/__apps/status").status_code == 403
    assert (
        c.post(
            "/__apps/deploy", headers={"origin": "http://127.0.0.1:18131"}, json={}
        ).status_code
        == 403
    )
    assert not a.calls


def test_extra_cluster_fields_denied():
    c, a = client()
    assert (
        c.post(
            "/__apps/deploy",
            headers={"origin": "http://127.0.0.1:18131"},
            json={
                "id": "a" * 16,
                "source_digest": "b" * 64,
                "health": "/",
                "public": False,
                "cluster": "evil",
            },
        ).status_code
        == 400
    )
    assert not a.calls


def test_exact_request_forwarded():
    c, a = client()
    assert (
        c.post(
            "/__apps/deploy",
            headers={"origin": "http://127.0.0.1:18131"},
            json={
                "id": "a" * 16,
                "source_digest": "b" * 64,
                "health": "/",
                "public": False,
            },
        ).status_code
        == 202
    )
    assert a.calls == [("a" * 16, "b" * 64, "/", False)]
