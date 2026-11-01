"""Synthetic registration for local contract exploration, never live inventory."""

from datetime import timedelta

from sova.domain.contracts import ResourceScope
from sova.domain.system_graph import (
    Portability,
    RelationKind,
    ResourceKind,
    SystemGraph,
    SystemRelation,
    SystemResource,
)


def example_graph(now):
    def resource(node, kind, backend, portability):
        return SystemResource(
            node,
            node,
            ResourceScope(
                "example-tenant", "order-service", "example-aws", "example://" + node
            ),
            kind,
            backend,
            "example-region",
            "synthetic-v1",
            portability,
            ("synthetic-not-live-inventory",),
        )

    return SystemGraph(
        "example-tenant",
        "order-service",
        1,
        "registration",
        now,
        now + timedelta(hours=1),
        (
            resource("entry", ResourceKind.EDGE, "aws-alb", Portability.PROVIDER_BOUND),
            resource("api", ResourceKind.SERVICE, "aws-ecs", Portability.CONFIGURATION),
            resource(
                "database",
                ResourceKind.DATABASE,
                "aws-rds-postgresql",
                Portability.UNKNOWN,
            ),
        ),
        (
            SystemRelation("entry", "api", RelationKind.CALLS, True),
            SystemRelation("api", "database", RelationKind.WRITES, True),
        ),
    )
