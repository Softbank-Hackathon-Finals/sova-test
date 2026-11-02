import json
from types import SimpleNamespace
import pytest
from kubernetes_response import IndependentPodProbe
from sova.domain.contracts import ContractError


@pytest.mark.parametrize("wrong", ["application", "component"])
def test_response_must_match_registered_application_and_component(monkeypatch, wrong):
    class Connection:
        def __init__(self, *args, **kwargs):
            pass

        def request(self, method, path, headers):
            self.request_id = headers["X-Request-ID"]

        def getresponse(self):
            body = {
                "request_id": self.request_id,
                "environment": "green",
                "application": "order-service",
                "component": "api",
            }
            body[wrong] = "unregistered"
            result = {
                "ok": True,
                "target": "green",
                "connected": True,
                "response": body,
            }
            return SimpleNamespace(
                status=200, read=lambda _: json.dumps(result).encode()
            )

        def close(self):
            pass

    monkeypatch.setattr("kubernetes_response.http.client.HTTPConnection", Connection)
    probe = IndependentPodProbe(1)
    with pytest.raises(ContractError, match="identity mismatch"):
        probe.probe("green")
    assert probe.last_probes == {}
