"""Qualification records and the support declaration for one direction.

A passing nine-scenario run is turned into a StrategyQualification record
(MIG-SPEC-001 §28.4): the exact source and target profiles it ran on, the
direction, the runner code, per-scenario results and signed evidence, tested
limits, exclusions, an expiry and what invalidates it. The record is signed
with the runner's evidence key.

`declare()` answers "is this path supported now?" only from such a record:
the direction must match exactly (no symmetric support, AT-02), the profiles
observed now must equal the qualified ones (a CNI or Kubernetes upgrade needs
requalification), the record must be unexpired and the runner code unchanged.
Anything else is NEEDS_EVIDENCE or UNSUPPORTED with the reason (AT-03).
"""

import argparse
from datetime import UTC, datetime, timedelta
import json
from pathlib import Path

from .evidence import producer_digest, sha
from .manifests import NAMESPACES, PROFILE, configure, placement
from .provision import private_json

RECORD_KIND = "sova.workload-response.strategy-qualification.v1"
VALID_FOR = timedelta(days=7)
REQUIRED = (
    "isolate",
    "segment",
    "egress",
    "credentials",
    "patch",
    "restart",
    "scale",
    "migrate",
    "rollback",
)


def image_tag(image):
    return image.rsplit("/", 1)[-1]


def cluster_profile(cluster):
    """Read-only platform facts that the qualification depends on."""
    version = json.loads(cluster.run(["version", "-o", "json"]))["serverVersion"][
        "gitVersion"
    ]
    nodes = json.loads(cluster.run(["get", "nodes", "-o", "json"]))["items"]
    daemonsets = json.loads(
        cluster.run(["get", "daemonsets", "-n", "kube-system", "-o", "json"])
    )["items"]
    images = {
        ds["metadata"]["name"]: [
            image_tag(c["image"]) for c in ds["spec"]["template"]["spec"]["containers"]
        ]
        for ds in daemonsets
    }
    if "aws-node" in images:
        network = {
            "cni": "aws-vpc-cni",
            "images": images["aws-node"],
            "policy_engine": "vpc-cni-network-policy-agent",
        }
        provider, backend, storage = "aws", "eks", "ebs-csi-gp3"
    else:
        canal = images.get("rke2-canal") or images.get("calico-node") or []
        network = {"cni": "canal-calico", "images": canal, "policy_engine": "calico"}
        provider, backend, storage = "on-prem", "rke2", "local-pv"
    return {
        "provider": provider,
        "backend": backend,
        "kubernetes": version,
        "network": network,
        "storage": storage,
        "nodes": sorted(
            {
                (
                    n["status"]["nodeInfo"]["architecture"],
                    n["metadata"]
                    .get("labels", {})
                    .get("node.kubernetes.io/instance-type", "vm"),
                    n["status"]["nodeInfo"]["osImage"].split(" (")[0],
                )
                for n in nodes
            }
        ),
    }


def profiles(kube):
    side_of = {"source": "source", "target": "target"}
    found = {}
    for role, side in side_of.items():
        found[role] = cluster_profile(kube.cluster(side))
        found[role]["placement"] = placement(side)
    return found


def build(report, observed, *, evidence, now=None):
    now = now or datetime.now(UTC)
    results = {r["scenario"]: r for r in report["results"]}
    missing = [s for s in REQUIRED if not results.get(s, {}).get("passed")]
    if not report.get("passed") or missing:
        raise ValueError(
            "full passing nine-scenario report required: " + ",".join(missing)
        )
    scenarios = {}
    for name in REQUIRED:
        session = results[name]["state"]["session"]
        signed = session.get("evidence", {}).get("signed", {})
        scenarios[name] = {
            "passed": True,
            "checks": [c["name"] for c in session.get("checks", [])],
            "signed_evidence": {
                stage: receipt["fingerprint"] for stage, receipt in signed.items()
            },
        }
    record = {
        "kind": RECORD_KIND,
        "record_id": "sq-" + sha([report["started_at"], report["base_commit"]])[:16],
        "topology": PROFILE["name"],
        "direction": {
            "from": observed["source"]["provider"]
            + "/"
            + observed["source"]["backend"],
            "to": observed["target"]["provider"] + "/" + observed["target"]["backend"],
            "reverse_qualified": False,
            "failback": "not qualified; a separate plan and qualification are required",
        },
        "source_profile": observed["source"],
        "target_profile": observed["target"],
        "strategy": {
            "runner_commit": report["base_commit"],
            "runner_digest": producer_digest(),
            "namespaces": dict(NAMESPACES),
        },
        "clusters": report["cluster_uid"],
        "scenarios": scenarios,
        "evidence_grade": "live" if PROFILE["name"] == "hybrid-aws" else "local-only",
        "tested_limits": {
            "data_migration": "bounded stop-and-copy through the control host, at most 2000 rows",
            "writers": "single business writer at any time",
            "cross_cluster_path": "SSM port forward to source API and DB only"
            if PROFILE["name"] == "hybrid-aws"
            else "none (one cluster)",
            "concurrency": "one runner per state directory",
        },
        "exclusions": [
            "reverse direction and failback",
            "production, shared or multi-tenant clusters",
            "CDC, zero-downtime or RPO=0 claims",
            "provider or CNI versions other than the recorded profiles",
            "independent verifier identity (the runner signs its own readbacks)",
        ],
        "issued_at": now.isoformat(),
        "expires_at": (now + VALID_FOR).isoformat(),
        "invalidated_by": [
            "cluster identity change",
            "runner code change",
            "Kubernetes, CNI or policy engine version change",
            "node architecture, instance type or OS change",
        ],
        "source_report": {
            "started_at": report["started_at"],
            "completed_at": report.get("completed_at"),
            "producer_files_sha256": report.get("producer_files_sha256"),
        },
    }
    record["digest"] = sha(record)
    receipt = evidence.issue(
        run_id=record["record_id"],
        scenario="qualification",
        stage="record",
        revision=1,
        plan_digest=record["digest"],
        environment=sha({"source": observed["source"], "target": observed["target"]}),
        checks=[{"name": "nine_scenarios_passed", "passed": True}],
    )
    record["signed_evidence"] = receipt
    return record


def declare(record, observed, *, direction=None, now=None):
    """Support declaration for the observed path, from the record only."""
    now = now or datetime.now(UTC)
    if record is None:
        return {"status": "NEEDS_EVIDENCE", "reasons": ["no qualification record"]}
    want = direction or {
        "from": observed["source"]["provider"] + "/" + observed["source"]["backend"],
        "to": observed["target"]["provider"] + "/" + observed["target"]["backend"],
    }
    reasons = []
    if (want["from"], want["to"]) != (
        record["direction"]["from"],
        record["direction"]["to"],
    ):
        return {
            "status": "UNSUPPORTED",
            "reasons": [
                "direction not qualified: " + want["from"] + " -> " + want["to"]
            ],
            "qualified_direction": record["direction"],
        }
    for role in ("source", "target"):
        expected = {k: v for k, v in record[role + "_profile"].items()}
        current = {k: v for k, v in observed[role].items()}
        if json.loads(json.dumps(expected)) != json.loads(json.dumps(current)):
            changed = sorted(
                k
                for k in expected
                if expected.get(k) != json.loads(json.dumps(current)).get(k)
            )
            reasons.append(role + " profile changed: " + ",".join(changed))
    if now >= datetime.fromisoformat(record["expires_at"]):
        reasons.append("qualification expired")
    if record["strategy"]["runner_digest"] != producer_digest():
        reasons.append("runner code changed since qualification")
    if reasons:
        return {
            "status": "NEEDS_EVIDENCE",
            "reasons": reasons,
            "record_id": record["record_id"],
        }
    return {
        "status": "SUPPORTED",
        "record_id": record["record_id"],
        "direction": record["direction"],
        "evidence_grade": record["evidence_grade"],
        "expires_at": record["expires_at"],
    }


def latest(root):
    records = sorted(
        Path(root).glob("support-record-*.json"), key=lambda p: p.stat().st_mtime
    )
    return json.loads(records[-1].read_text()) if records else None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    from .runtime import Runtime

    runtime = Runtime(args.state.resolve())
    report = json.loads(args.report.read_text())
    if report.get("topology", "local") != runtime.topology()["name"]:
        raise SystemExit("report topology does not match this state")
    record = build(report, profiles(runtime.kube), evidence=runtime.evidence)
    path = args.state.resolve() / ("support-record-" + record["record_id"] + ".json")
    private_json(path, record)
    print(json.dumps(declare(record, profiles(runtime.kube)), ensure_ascii=False))


if __name__ == "__main__":
    configure("local")
    main()
