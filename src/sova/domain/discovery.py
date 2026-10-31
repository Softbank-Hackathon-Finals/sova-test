"""Immutable operator-registered Kubernetes read scope, not an authentication token."""

from dataclasses import dataclass
from datetime import datetime
import hashlib
import ipaddress
import re
from urllib.parse import urlsplit

from sova.domain.contracts import ContractError, canonical_json, digest, identifier, utc


@dataclass(frozen=True, slots=True)
class KubernetesReadRegistration:
    tenant_id: str
    application_id: str
    environment_id: str
    location: str
    endpoint: str
    approved_addresses: tuple[str, ...]
    ca_digest: str
    namespace: str
    namespace_uid: str
    revision: int
    registered_at: datetime
    valid_until: datetime

    def __post_init__(self):
        for name in (
            "tenant_id",
            "application_id",
            "environment_id",
            "location",
            "namespace_uid",
        ):
            identifier(getattr(self, name), name)
        if not isinstance(self.namespace, str) or not re.fullmatch(
            r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", self.namespace
        ):
            raise ContractError("DNS label namespace required")
        if not re.fullmatch(
            r"[a-z0-9](?:[a-z0-9._-]{0,61}[a-z0-9])?", self.application_id
        ):
            raise ContractError("Safe application label required")
        identifier(self.endpoint, "endpoint", limit=2048)
        try:
            endpoint = urlsplit(self.endpoint)
            if (
                endpoint.scheme != "https"
                or not endpoint.hostname
                or endpoint.username
                or endpoint.password
                or endpoint.path
                or endpoint.query
                or endpoint.fragment
                or self.endpoint != "https://" + endpoint.netloc
                or any(c.isspace() or c == "\\" for c in endpoint.netloc)
                or not 1 <= (443 if endpoint.port is None else endpoint.port) <= 65535
            ):
                raise ValueError()
        except (ValueError, TypeError) as exc:
            raise ContractError("Bare registered HTTPS endpoint required") from exc
        digest(self.ca_digest)
        if (
            type(self.approved_addresses) is not tuple
            or not 1 <= len(self.approved_addresses) <= 8
        ):
            raise ContractError("Explicit immutable peer IP allowlist required")
        addresses = []
        try:
            for value in self.approved_addresses:
                if not isinstance(value, str):
                    raise ValueError()
                address = ipaddress.ip_address(value)
                checked = getattr(address, "ipv4_mapped", None) or address
                if (
                    checked.is_link_local
                    or checked.is_unspecified
                    or checked.is_multicast
                ):
                    raise ValueError()
                addresses.append(str(address))
        except (ValueError, TypeError) as exc:
            raise ContractError("Invalid registered peer address") from exc
        if len(set(addresses)) != len(addresses):
            raise ContractError("Duplicate peer address")
        object.__setattr__(self, "approved_addresses", tuple(sorted(addresses)))
        if type(self.revision) is not int or self.revision < 1:
            raise ContractError("Positive registration revision required")
        object.__setattr__(self, "registered_at", utc(self.registered_at))
        object.__setattr__(self, "valid_until", utc(self.valid_until))
        if self.valid_until <= self.registered_at:
            raise ContractError("Invalid registration validity")

    def require_current(self, now):
        if not self.registered_at <= utc(now) < self.valid_until:
            raise ContractError("Registration expired or not yet valid")

    @property
    def document(self):
        return {
            "schema_version": 1,
            **{
                key: getattr(self, key)
                for key in (
                    "tenant_id",
                    "application_id",
                    "environment_id",
                    "location",
                    "endpoint",
                    "ca_digest",
                    "namespace",
                    "namespace_uid",
                    "revision",
                )
            },
            "approved_addresses": list(self.approved_addresses),
            "registered_at": self.registered_at.isoformat(),
            "valid_until": self.valid_until.isoformat(),
        }

    @property
    def fingerprint(self):
        return hashlib.sha256(canonical_json(self.document).encode()).hexdigest()
