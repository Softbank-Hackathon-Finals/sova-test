"""Opaque attachment keys. Authorization is checked before any object lookup."""

import base64
import hashlib
import os
import re
import hmac
from pathlib import Path
import tempfile
from uuid import UUID

from .storage import AppError, Conflict


class ObjectUnavailable(AppError):
    status = 503
    code = "object_store_unavailable"


def object_id(value):
    try:
        return str(UUID(str(value)))
    except (ValueError, TypeError, AttributeError) as exc:
        raise AppError() from exc


class LocalObjects:
    def __init__(self, root):
        self.root = Path(root).resolve()
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.root.stat().st_mode & 0o077:
            raise ValueError("Private object directory required")

    def get(self, key):
        path = self.root / object_id(key)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as source:
            data = source.read(1048577)
        if len(data) > 1048576:
            raise AppError()
        return data

    def put(self, key, content):
        key = object_id(key)
        if type(content) is not bytes or not 1 <= len(content) <= 1048576:
            raise AppError()
        target = self.root / key
        fd, temporary = tempfile.mkstemp(prefix=".upload-", dir=self.root)
        try:
            with os.fdopen(fd, "wb") as output:
                output.write(content)
                output.flush()
                os.fsync(output.fileno())
            try:
                os.link(temporary, target, follow_symlinks=False)
            except FileExistsError:
                if self.get(key) != content:
                    raise Conflict()
        finally:
            Path(temporary).unlink(missing_ok=True)


class S3Objects:
    def __init__(self, client, *, bucket, prefix, kms_key_id, account_id):
        if type(account_id) is not str or not re.fullmatch(r"[0-9]{12}", account_id):
            raise ValueError("Expected bucket owner account required")
        if (
            type(bucket) is not str
            or not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", bucket)
            or ".." in bucket
        ):
            raise ValueError("Registered private bucket name required")
        if (
            type(prefix) is not str
            or not re.fullmatch(r"[a-zA-Z0-9_-]+(?:/[a-zA-Z0-9_-]+)*", prefix)
            or len(prefix) > 240
        ):
            raise ValueError("Registered fixed object prefix required")
        key = (
            re.fullmatch(
                r"arn:(aws|aws-cn|aws-us-gov):kms:([a-z0-9-]+):([0-9]{12}):key/([a-f0-9-]{36}|mrk-[a-f0-9]{32})",
                kms_key_id,
            )
            if type(kms_key_id) is str
            else None
        )
        if not key or key[3] != account_id or key[2] != client.meta.region_name:
            raise ValueError(
                "Exact registered KMS key ARN in the expected account and region required"
            )
        self.client, self.bucket, self.prefix, self.kms_key_id, self.account_id = (
            client,
            bucket,
            prefix,
            kms_key_id,
            account_id,
        )

    def close(self):
        self.client.close()

    def put(self, key, content):
        from botocore.exceptions import ClientError, BotoCoreError

        if type(content) is not bytes or not 1 <= len(content) <= 1048576:
            raise AppError()
        try:
            self.client.put_object(
                Bucket=self.bucket,
                ExpectedBucketOwner=self.account_id,
                ContentType="application/octet-stream",
                CacheControl="no-store",
                Key=self.prefix + "/" + object_id(key),
                Body=content,
                IfNoneMatch="*",
                ServerSideEncryption="aws:kms",
                SSEKMSKeyId=self.kms_key_id,
                ChecksumSHA256=base64.b64encode(
                    hashlib.sha256(content).digest()
                ).decode("ascii"),
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in {"PreconditionFailed", "412"}:
                raise ObjectUnavailable() from exc
            if self.get(key) != content:
                raise Conflict() from exc
        except BotoCoreError as exc:
            raise ObjectUnavailable() from exc

    def get(self, key):
        from botocore.exceptions import ClientError, BotoCoreError

        try:
            response = self.client.get_object(
                Bucket=self.bucket,
                ExpectedBucketOwner=self.account_id,
                Key=self.prefix + "/" + object_id(key),
                ChecksumMode="ENABLED",
            )
        except (ClientError, BotoCoreError) as exc:
            raise ObjectUnavailable() from exc
        try:
            if (
                response.get("ServerSideEncryption") != "aws:kms"
                or response.get("SSEKMSKeyId") != self.kms_key_id
                or type(response.get("ContentLength")) is not int
                or not 1 <= response["ContentLength"] <= 1048576
            ):
                raise ObjectUnavailable()
            data = response["Body"].read(1048577)
            checksum = base64.b64encode(hashlib.sha256(data).digest()).decode("ascii")
            if len(data) != response["ContentLength"] or not hmac.compare_digest(
                checksum, response.get("ChecksumSHA256", "")
            ):
                raise ObjectUnavailable()
            return data
        finally:
            response["Body"].close()
