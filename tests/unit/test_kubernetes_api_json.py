import json
import pytest
from sova.adapters.kubernetes.api_json import decode_api_json
from sova.domain.contracts import ContractError


def test_real_managed_fields_depth_is_allowed_without_weakening_public_contracts():
    node = {}
    for _ in range(24):
        node = {"f:spec": node}
    assert decode_api_json(json.dumps({"metadata": {"managedFields": [node]}}).encode())


@pytest.mark.parametrize(
    "raw",
    [
        b'{"a":1,"a":2}',
        b'{"a":NaN}',
        b'{"a":1e9999}',
        b"[" * 66 + b"0" + b"]" * 66,
        b"\xff",
    ],
)
def test_malformed_and_unbounded_wire_json_refused(raw):
    with pytest.raises(ContractError):
        decode_api_json(raw)
