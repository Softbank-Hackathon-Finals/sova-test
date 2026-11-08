from .aws_target import manifests


def test_scoped_stateless_manifest_has_no_team_secrets_or_privileges():
    d = manifests("a" * 16, "registry/app@sha256:" + "b" * 64, "/health", "c" * 64)
    resources = d["items"]
    deployment = next(x for x in resources if x["kind"] == "Deployment")
    pod = deployment["spec"]["template"]["spec"]
    container = pod["containers"][0]
    assert (
        deployment["spec"]["replicas"] == 2
        and pod["automountServiceAccountToken"] is False
    )
    assert container["securityContext"]["readOnlyRootFilesystem"]
    assert all("hostPath" not in v and "secret" not in v for v in pod["volumes"])
    assert all(
        x.get("metadata", {}).get("namespace", "sova-app-" + "a" * 16)
        == "sova-app-" + "a" * 16
        for x in resources
    )
