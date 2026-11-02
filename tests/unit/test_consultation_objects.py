"""S3 SDK contract doubles; not a claim of real S3/KMS qualification."""

import base64
import hashlib
from io import BytesIO
from uuid import uuid4

import boto3
from botocore.response import StreamingBody
from botocore.stub import Stubber
import pytest

from examples.consultation.objects import S3Objects, ObjectUnavailable

ACCOUNT = "111122223333"
KMS = (
    "arn:aws:kms:ap-northeast-2:"
    + ACCOUNT
    + ":key/12345678-1234-1234-1234-123456789abc"
)


@pytest.fixture
def objects():
    client = boto3.client(
        "s3",
        region_name="ap-northeast-2",
        aws_access_key_id="synthetic",
        aws_secret_access_key="synthetic",
    )
    with Stubber(client) as stub:
        yield (
            S3Objects(
                client,
                bucket="sova-private-fixture",
                prefix="apps/app-a",
                kms_key_id=KMS,
                account_id=ACCOUNT,
            ),
            stub,
        )
        stub.assert_no_pending_responses()
    client.close()


def expected_get(key):
    return dict(
        Bucket="sova-private-fixture",
        ExpectedBucketOwner=ACCOUNT,
        Key="apps/app-a/" + key,
        ChecksumMode="ENABLED",
    )


def response(data):
    return dict(
        Body=StreamingBody(BytesIO(data), len(data)),
        ContentLength=len(data),
        ServerSideEncryption="aws:kms",
        SSEKMSKeyId=KMS,
        ChecksumSHA256=base64.b64encode(hashlib.sha256(data).digest()).decode(),
    )


def test_s3_write_is_owner_scoped_encrypted_checked_and_nonoverwriting(objects):
    store, stub = objects
    key = str(uuid4())
    data = b"synthetic attachment"
    stub.add_response(
        "put_object",
        {},
        dict(
            Bucket=store.bucket,
            ExpectedBucketOwner=ACCOUNT,
            ContentType="application/octet-stream",
            CacheControl="no-store",
            Key=store.prefix + "/" + key,
            Body=data,
            IfNoneMatch="*",
            ServerSideEncryption="aws:kms",
            SSEKMSKeyId=KMS,
            ChecksumSHA256=base64.b64encode(hashlib.sha256(data).digest()).decode(),
        ),
    )
    store.put(key, data)
    stub.add_response("get_object", response(data), expected_get(key))
    assert store.get(key) == data


@pytest.mark.parametrize(
    "field,value",
    [
        ("ServerSideEncryption", "AES256"),
        ("SSEKMSKeyId", "different-key"),
        ("ChecksumSHA256", "incorrect"),
        ("ContentLength", 2000000),
    ],
)
def test_different_encryption_checksum_or_oversize_object_is_not_accepted(
    objects, field, value
):
    store, stub = objects
    key = str(uuid4())
    result = response(b"synthetic")
    result[field] = value
    stub.add_response("get_object", result, expected_get(key))
    with pytest.raises(ObjectUnavailable):
        store.get(key)
    assert result["Body"]._raw_stream.closed


def test_owner_or_kms_permission_failure_is_generic_and_not_success(objects):
    store, stub = objects
    key = str(uuid4())
    stub.add_client_error(
        "get_object",
        service_error_code="AccessDenied",
        http_status_code=403,
        expected_params=expected_get(key),
    )
    with pytest.raises(ObjectUnavailable) as exc:
        store.get(key)
    assert str(exc.value) == ""


def test_cross_account_kms_and_mutable_key_alias_registration_rejected(objects):
    store, _ = objects
    for key in ("alias/application-key", KMS.replace(ACCOUNT, "999988887777")):
        with pytest.raises(ValueError):
            S3Objects(
                store.client,
                bucket=store.bucket,
                prefix=store.prefix,
                kms_key_id=key,
                account_id=ACCOUNT,
            )
