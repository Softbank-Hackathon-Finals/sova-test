from datetime import UTC, datetime, timedelta
import pytest
from .team_app import project_team_app, REPOSITORY


def test_team_repo_and_actual_deployment_are_not_conflated():
    at = datetime.now(UTC)
    receipt = {
        "repository": REPOSITORY,
        "repository_revision": "a" * 40,
        "environments": {
            "source": {
                "observed_at": at.isoformat(),
                "identity_verified": True,
                "ready_replicas": 1,
                "desired_replicas": 1,
                "images": ["runtime@sha256:" + "b" * 64],
                "pod_uids": ["actual-pod"],
            }
        },
    }
    v = project_team_app(receipt, at=at)
    assert v["environments"][0]["ready_replicas"] == 1
    assert v["source_matches_repository_head"] is None
    assert v["authorizes_execution"] is False and v["migration_complete"] is False
    v = project_team_app(receipt, at=at + timedelta(seconds=90))
    assert v["environments"][0]["ready_replicas"] is None
    assert v["environments"][0]["pod_uids"] == []


def test_other_repository_cannot_become_team_app():
    with pytest.raises(ValueError):
        project_team_app(
            {
                "repository": "https://github.com/other/project",
                "repository_revision": "a" * 40,
            }
        )
