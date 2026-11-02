from unittest.mock import Mock

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("opentelemetry.sdk")
import boto3
from examples.consultation.service import configured_objects
from examples.consultation.objects import LocalObjects, S3Objects


def test_local_backend_is_explicit_and_never_falls_back_from_a_cloud_failure(
    monkeypatch, tmp_path
):
    monkeypatch.setenv("CONSULTATION_OBJECT_DIR", str(tmp_path / "objects"))
    monkeypatch.setenv("CONSULTATION_OBJECT_BACKEND", "local")
    assert isinstance(configured_objects(), LocalObjects)
    monkeypatch.setenv("CONSULTATION_OBJECT_BACKEND", "unknown")
    with pytest.raises(ValueError):
        configured_objects()


def test_s3_configuration_uses_fixed_owner_key_region_and_bounded_transport(
    monkeypatch,
):
    client = Mock()
    client.meta.region_name = "ap-northeast-2"
    factory = Mock(return_value=client)
    monkeypatch.setattr(boto3, "client", factory)
    values = {
        "CONSULTATION_OBJECT_BACKEND": "s3",
        "CONSULTATION_S3_REGION": "ap-northeast-2",
        "CONSULTATION_S3_BUCKET": "sova-private-fixture",
        "CONSULTATION_S3_PREFIX": "apps/app-a",
        "CONSULTATION_S3_OWNER_ACCOUNT": "111122223333",
        "CONSULTATION_S3_KMS_KEY_ARN": "arn:aws:kms:ap-northeast-2:111122223333:key/12345678-1234-1234-1234-123456789abc",
    }
    for key, value in values.items():
        monkeypatch.setenv(key, value)
    result = configured_objects()
    assert isinstance(result, S3Objects)
    config = factory.call_args.kwargs["config"]
    assert (
        config.connect_timeout == 2
        and config.read_timeout == 3
        and config.retries["total_max_attempts"] == 1
    )
    monkeypatch.setenv("AWS_ENDPOINT_URL_S3", "https://unregistered.invalid")
    factory.reset_mock()
    with pytest.raises(ValueError):
        configured_objects()
    factory.assert_not_called()
