"""AI invocation boundary; no guest keys, caller-chosen URL, or fallback.

Providers are operator-registered callables. This gate is not yet the hosted
gateway, OPA, a DLP service, or a provider-location certification. Receipts omit
prompt, response, credentials and content hashes of potentially sensitive text.
"""

from sova.security.domain.ai_residency import assess_ai_route
from sova.domain.contracts import ContractError, identifier, utc


class AIGateway:
    def __init__(
        self,
        *,
        policy_provider,
        endpoint_provider,
        classify,
        authorize,
        authenticate_policy,
        authenticate_endpoint,
        invoke,
        clock,
    ):
        self.policy_provider = policy_provider
        self.endpoint_provider = endpoint_provider
        self.classify = classify
        self.authorize = authorize
        self.authenticate_policy = authenticate_policy
        self.authenticate_endpoint = authenticate_endpoint
        self.invoke = invoke
        self.clock = clock

    def complete(
        self,
        actor,
        *,
        scope,
        request_id,
        endpoint_id,
        expected_deployment,
        expected_policy_digest,
        purpose,
        capability,
        payload,
    ):
        for value in (
            request_id,
            endpoint_id,
            expected_deployment,
            purpose,
            capability,
        ):
            identifier(value)
        self.authorize(actor, scope, "ai:invoke")
        if type(payload) is not str:
            raise ContractError("Text AI input required")
        try:
            size = len(payload.encode("utf-8"))
        except UnicodeError as exc:
            raise ContractError("Valid UTF-8 AI input required") from exc
        if size > 262144:
            raise ContractError("AI input exceeds hard limit")
        data_class = self.classify(scope, purpose, payload)
        policy = self.policy_provider(scope, data_class)
        endpoint = self.endpoint_provider(scope, endpoint_id)
        self.authenticate_policy(policy)
        self.authenticate_endpoint(endpoint)
        if (
            endpoint.endpoint_id != endpoint_id
            or policy.fingerprint != expected_policy_digest
            or endpoint.deployment_revision != expected_deployment
        ):
            raise ContractError(
                "AI policy or deployment changed; inspect current route"
            )
        admitted_at = utc(self.clock())
        decision = assess_ai_route(
            policy,
            endpoint,
            scope=scope,
            data_class=data_class,
            purpose=purpose,
            capability=capability,
            input_bytes=size,
            now=admitted_at,
        )
        if not decision["allowed"]:
            raise ContractError("AI route denied: " + ",".join(decision["reasons"]))
        # Re-read current authority state immediately before dispatch. These
        # callbacks must check revocation, not merely return a cached boolean.
        self.authorize(actor, scope, "ai:invoke")
        current_policy = self.policy_provider(scope, data_class)
        current_endpoint = self.endpoint_provider(scope, endpoint_id)
        self.authenticate_policy(current_policy)
        self.authenticate_endpoint(current_endpoint)
        if current_policy != policy or current_endpoint != endpoint:
            raise ContractError("AI admission changed during authorization")
        dispatch_at = utc(self.clock())
        if dispatch_at < admitted_at:
            raise ContractError("AI admission clock moved backwards")
        final = assess_ai_route(
            current_policy,
            current_endpoint,
            scope=scope,
            data_class=data_class,
            purpose=purpose,
            capability=capability,
            input_bytes=size,
            now=dispatch_at,
        )
        if not final["allowed"]:
            raise ContractError("AI admission expired before dispatch")
        # Invoke exactly once. Transport uncertainty is returned to the caller;
        # another provider or location is never tried automatically.
        response = self.invoke(current_endpoint, payload, request_id=request_id)
        if type(response) is not str or len(response.encode("utf-8")) > 262144:
            raise ContractError("AI output format/limit unverified")
        return {
            "response": response,
            "receipt": {
                "request_id": request_id,
                "endpoint_id": endpoint_id,
                "deployment_revision": expected_deployment,
                "policy_digest": expected_policy_digest,
                "classification": str(data_class),
                "automatic_fallback": False,
                "admitted_at": admitted_at.isoformat(),
                "dispatched_at": dispatch_at.isoformat(),
            },
        }
