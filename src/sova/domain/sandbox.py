"""Credential-free sandbox request; preparing a request grants no execution right."""

from dataclasses import dataclass
from datetime import datetime
import re
import hashlib
from dataclasses import asdict

from sova.domain.contracts import (
    ContractError,
    ResourceScope,
    canonical_json,
    digest,
    identifier,
    utc,
)


@dataclass(frozen=True, slots=True)
class SandboxRequest:
    scope: ResourceScope
    request_id: str
    source_digest: str
    tests_digest: str
    agent_image: str
    verifier_image: str
    timeout_seconds: int
    valid_until: datetime

    def __post_init__(self):
        if not isinstance(self.scope, ResourceScope):
            raise ContractError("Sandbox scope required")
        identifier(self.request_id)
        digest(self.source_digest)
        digest(self.tests_digest)
        for image in (self.agent_image, self.verifier_image):
            if not isinstance(image, str) or not re.fullmatch(
                r"[a-z0-9][a-z0-9./:_-]{0,255}@sha256:[0-9a-f]{64}", image
            ):
                raise ContractError("Digest-pinned sandbox images required")
        if (
            self.agent_image.rsplit("@sha256:", 1)[1]
            == self.verifier_image.rsplit("@sha256:", 1)[1]
        ):
            raise ContractError(
                "Agent and independent verifier image digests must differ"
            )
        if (
            type(self.timeout_seconds) is not int
            or not 1 <= self.timeout_seconds <= 1800
        ):
            raise ContractError("Sandbox timeout outside policy")
        object.__setattr__(self, "valid_until", utc(self.valid_until))

    @property
    def fingerprint(self):
        document = asdict(self)
        document["valid_until"] = self.valid_until.isoformat()
        return hashlib.sha256(canonical_json(document).encode()).hexdigest()

    def require_current(self, now):
        if utc(now) >= self.valid_until:
            raise ContractError("Expired sandbox request")
