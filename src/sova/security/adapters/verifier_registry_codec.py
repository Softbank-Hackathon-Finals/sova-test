from datetime import datetime
from sova.adapters.registration.graph_codec import exact
from sova.domain.contracts import ContractError, ResourceScope
from sova.security.domain.signed_evidence import VerifierTrust
from sova.security.domain.verifier_registry import VerifierTrustChange


def decode_trust_change(data):
    try:
        exact(
            data,
            (
                "schema_version",
                "tenant_id",
                "application_id",
                "revision",
                "trust",
                "requested_by",
                "approved_by",
                "reason",
                "approved_at",
                "approval_until",
            ),
        )
        if type(data["schema_version"]) is not int or data["schema_version"] != 1:
            raise ContractError("Unsupported verifier registry schema")
        trust = data["trust"]
        exact(
            trust,
            (
                "issuer_id",
                "key_id",
                "public_key_hex",
                "allowed_scopes",
                "allowed_verifiers",
                "valid_from",
                "valid_until",
                "revoked",
            ),
        )
        if (
            type(trust["allowed_scopes"]) is not list
            or type(trust["allowed_verifiers"]) is not list
        ):
            raise ContractError("Immutable verifier trust scope/version lists required")
        for scope in trust["allowed_scopes"]:
            exact(
                scope, ("tenant_id", "application_id", "environment_id", "resource_id")
            )
        value = VerifierTrust(
            trust["issuer_id"],
            trust["key_id"],
            trust["public_key_hex"],
            tuple(ResourceScope(**s) for s in trust["allowed_scopes"]),
            tuple(trust["allowed_verifiers"]),
            datetime.fromisoformat(trust["valid_from"]),
            datetime.fromisoformat(trust["valid_until"]),
            trust["revoked"],
        )
        return VerifierTrustChange(
            data["tenant_id"],
            data["application_id"],
            data["revision"],
            value,
            data["requested_by"],
            data["approved_by"],
            data["reason"],
            datetime.fromisoformat(data["approved_at"]),
            datetime.fromisoformat(data["approval_until"]),
        )
    except (KeyError, ValueError, TypeError) as exc:
        raise ContractError("Invalid verifier trust change") from exc
