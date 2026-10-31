"""Bridge the local registered demo to Sova's shared graph contract."""

from datetime import datetime, timezone

from sova.domain.contracts import ResourceScope
from sova.domain.system_graph import (
    Portability,
    RelationKind,
    ResourceKind,
    SystemGraph,
    SystemRelation,
    SystemResource,
)


def demo_graph(profile, *, observed_at, valid_until, revision):
    return SystemGraph(
        "local-operator",
        profile["id"],
        revision,
        "local_demo",
        observed_at,
        valid_until,
        tuple(
            SystemResource(
                n["id"],
                n["name"],
                ResourceScope(
                    "local-operator",
                    profile["id"],
                    "local-demo",
                    "local-demo://" + profile["id"] + "/" + n["id"],
                ),
                ResourceKind.DATABASE
                if n["kind"] == "storage"
                else ResourceKind.SERVICE,
                "local-process",
                "operator-workstation",
                "registered-profile-v1",
                Portability.UNKNOWN,
                ("demo-only-not-production",),
            )
            for n in profile["nodes"]
        ),
        tuple(
            SystemRelation(n["id"], d["target"], RelationKind.CALLS, d["required"])
            for n in profile["nodes"]
            for d in n["dependencies"]
        ),
    )


def runtime_graph(profile, revision, deadline):
    return demo_graph(
        profile,
        observed_at=datetime.now(timezone.utc),
        valid_until=datetime.fromtimestamp(deadline, timezone.utc),
        revision=revision,
    )
