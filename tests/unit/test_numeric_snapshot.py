from decimal import Decimal, localcontext
import pytest
from sova.adapters.postgres_dataset import exact_decimal, lossless_json, normalize_value
from sova.domain.contracts import ContractError


def test_decimal_snapshot_does_not_round_under_ambient_context():
    value = "123456789012345678901234567890.1234567890123456789"
    with localcontext() as context:
        context.prec = 5
        assert exact_decimal(Decimal(value)) == value
        assert exact_decimal(Decimal("1000.000")) == "1000"
        assert exact_decimal(Decimal("-0.00")) == "0"
    with pytest.raises(ContractError, match="capacity"):
        exact_decimal(Decimal("1e100000000"))


def test_lossless_json_numbers_and_type_tags_cannot_collide():
    def value(text):
        return normalize_value(lossless_json(text.encode()))

    assert value('{"amount":12345678901234567890.01}') != value(
        '{"amount":12345678901234567890.02}'
    )
    assert value("null") != normalize_value(None)
    assert value("1.0") == value("1")
    assert value("1.0") != value('{"type":"decimal","value":"1"}')
    with pytest.raises(ContractError):
        value('{"a":1,"a":2}')
