"""Authorized comparison of authenticated estimates; never provisions or moves.

Quote providers are trusted ports, not request-supplied URLs. Authentication must
cover the complete estimate and current revocation state, including allocation,
usage, prices and transition inputs. No AWS prices or on-prem costs are invented.
"""

from dataclasses import asdict
from datetime import datetime
from decimal import Decimal
import hashlib

from sova.domain.contracts import ContractError, ResourceScope, canonical_json, digest
from sova.domain.costs import CostEstimate, TransitionEstimate, compare_estimates


def quote_digest(quote):
    if not isinstance(quote, (CostEstimate, TransitionEstimate)):
        raise ContractError("Typed cost estimate required")

    def normalize(value):
        if isinstance(value, Decimal):
            return str(value)
        if isinstance(value, datetime):
            return value.isoformat()
        if isinstance(value, dict):
            return {key: normalize(item) for key, item in value.items()}
        if isinstance(value, (tuple, list)):
            return [normalize(item) for item in value]
        return value

    return hashlib.sha256(
        canonical_json(normalize(asdict(quote)), limit=32768).encode()
    ).hexdigest()


class CostAdvisor:
    def __init__(
        self,
        *,
        quote_provider,
        transition_provider,
        authorize,
        authenticate_quote,
        clock,
    ):
        self.quote_provider = quote_provider
        self.transition_provider = transition_provider
        self.authorize = authorize
        self.authenticate_quote = authenticate_quote
        self.clock = clock

    def compare(
        self,
        actor,
        *,
        source_scope,
        target_scope,
        workload_digest,
        slo_digest,
        horizon_hours,
    ):
        if not isinstance(source_scope, ResourceScope) or not isinstance(
            target_scope, ResourceScope
        ):
            raise ContractError("Typed cost comparison scopes required")
        digest(workload_digest)
        digest(slo_digest)
        for scope in (source_scope, target_scope):
            self.authorize(actor, scope, "cost:compare")
        source = self.quote_provider(source_scope, workload_digest, slo_digest)
        target = self.quote_provider(target_scope, workload_digest, slo_digest)
        transition = self.transition_provider(
            source_scope, target_scope, workload_digest, slo_digest
        )
        for quote in (source, target, transition):
            self.authenticate_quote(quote)
        if (
            not isinstance(source, CostEstimate)
            or not isinstance(target, CostEstimate)
            or source.scope != source_scope
            or target.scope != target_scope
            or any(
                (q.workload_digest, q.slo_digest) != (workload_digest, slo_digest)
                for q in (source, target)
            )
        ):
            raise ContractError(
                "Quote registry returned a different app/environment/workload/SLO"
            )
        for scope in (source_scope, target_scope):
            self.authorize(actor, scope, "cost:compare")
        report = compare_estimates(
            source,
            target,
            one_time_costs=transition,
            horizon_hours=horizon_hours,
            now=self.clock(),
        )
        return {
            **report,
            "source_scope": asdict(source_scope),
            "target_scope": asdict(target_scope),
            "workload_digest": workload_digest,
            "slo_digest": slo_digest,
            "quote_digests": {
                "source": quote_digest(source),
                "target": quote_digest(target),
                "transition": quote_digest(transition),
            },
            "analysis_only": True,
        }
