"""Project a registered team application's observations without granting changes."""

from datetime import UTC, datetime
import re

REPOSITORY = "https://github.com/Softbank-Hackathon-Finals/demo-app"


def project_team_app(receipt, *, at=None):
    at = at or datetime.now(UTC)
    if receipt.get("repository") != REPOSITORY or not re.fullmatch(
        r"[a-f0-9]{40}", receipt.get("repository_revision", "")
    ):
        raise ValueError("registered_team_repository_required")
    environments = []
    for lane in ("source", "target"):
        raw = receipt.get("environments", {}).get(lane)
        current = False
        if raw:
            observed = datetime.fromisoformat(raw["observed_at"])
            age = (at - observed).total_seconds()
            current = (
                observed.tzinfo is not None
                and raw.get("identity_verified") is True
                and 0 <= age < 90
            )
        environments.append(
            {
                "lane": lane,
                "current": current,
                "observed_at": raw.get("observed_at") if raw else None,
                "deployment_uid": raw.get("deployment_uid") if raw else None,
                "namespace": raw.get("namespace") if raw else None,
                "images": raw.get("images", []) if raw else [],
                "desired_replicas": raw.get("desired_replicas") if current else None,
                "ready_replicas": raw.get("ready_replicas") if current else None,
                "pod_uids": raw.get("pod_uids", []) if current else [],
                "http_status": raw.get("http_status") if current else None,
                "application_info": raw.get("application_info") if current else None,
            }
        )
    return {
        "id": "team-demo-app",
        "kind": "registered-team-app",
        "name": "브라보톡 · 팀 demo-app",
        "repository": REPOSITORY,
        "repository_revision": receipt["repository_revision"],
        "environments": environments,
        "source_matches_repository_head": None,
        "authorizes_execution": False,
        "migration_complete": False,
    }
