"""Registry image findings for patch rescans (MIG-SPEC-001 Part III, P-G5).

A rollout that succeeded is not a resolved finding. Before a patch the runner
records the registry's scan findings for the deployed image digest; after the
rollout it reads the scan for the new digest and classifies each finding as
resolved, remaining or newly introduced. Only the hybrid source has a registry
scan (ECR basic scanning on push); the local topology reports NOT_RUN, never
PASS.
"""

import json
import subprocess

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL", "UNDEFINED")


class ScanUnavailable(RuntimeError):
    pass


def scan(settings, image_ref, timeout=60):
    """Findings for one pinned image reference, from the run's ECR repository."""
    aws = settings.get("aws")
    if not aws:
        raise ScanUnavailable("no_registry_scan_in_this_topology")
    repository, digest = image_ref.split("@", 1)
    name = repository.split("/", 1)[1]
    if repository != aws["repository_url"]:
        raise ScanUnavailable("image_outside_run_repository")
    result = subprocess.run(
        [
            "aws",
            "ecr",
            "describe-image-scan-findings",
            "--region",
            aws["region"],
            "--repository-name",
            name,
            "--image-id",
            "imageDigest=" + digest,
            "--output",
            "json",
        ],
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if result.returncode:
        raise ScanUnavailable("registry_scan_unreadable")
    value = json.loads(result.stdout)
    status = value.get("imageScanStatus", {}).get("status")
    if status != "COMPLETE":
        raise ScanUnavailable("registry_scan_" + str(status).lower())
    findings = value.get("imageScanFindings", {})
    items = sorted(
        {
            (item.get("name", "?"), item.get("severity", "UNDEFINED"))
            for item in findings.get("findings", [])
        }
    )
    return {
        "image_digest": digest,
        "completed_at": findings.get("imageScanCompletedAt"),
        "findings": [list(item) for item in items],
        "counts": {
            severity: sum(1 for _name, s in items if s == severity)
            for severity in SEVERITIES
            if any(s == severity for _name, s in items)
        },
    }


def compare(before, after):
    old = {tuple(item) for item in before["findings"]}
    new = {tuple(item) for item in after["findings"]}

    def counts(items):
        result = {}
        for _name, severity in items:
            result[severity] = result.get(severity, 0) + 1
        return result

    return {
        "before_digest": before["image_digest"],
        "after_digest": after["image_digest"],
        "resolved": counts(old - new),
        "remaining": counts(old & new),
        "introduced": counts(new - old),
        "introduced_names": sorted(name for name, _s in new - old)[:50],
    }
