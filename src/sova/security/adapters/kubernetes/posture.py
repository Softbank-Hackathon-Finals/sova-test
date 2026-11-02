"""Bounded allowlisted projection. Never copy env values, annotations or secrets.

Only pod-template configuration is verified here. CNI behavior, live pod state,
image provenance/vulnerabilities, encrypted storage and IAM remain unverified.
"""

import hashlib
import re
from decimal import Decimal, InvalidOperation

from sova.domain.contracts import ContractError, canonical_json
from sova.domain.evidence import VerificationResult as R
from sova.security.domain.governance import ControlFamily as F
from sova.security.domain.posture import FindingBasis, PostureFinding

RULES = (
    ("no-privileged", F.IDENTITY),
    ("non-root", F.IDENTITY),
    ("no-escalation", F.IDENTITY),
    ("drop-capabilities", F.IDENTITY),
    ("read-only-root", F.IDENTITY),
    ("runtime-seccomp", F.IDENTITY),
    ("no-host-namespaces", F.NETWORK),
    ("no-host-mounts", F.NETWORK),
    ("no-auto-token", F.SECRETS),
    ("no-literal-sensitive-env", F.SECRETS),
    ("digest-pinned-images", F.POLICY),
    ("bounded-resources", F.POLICY),
)
SENSITIVE_NAME = re.compile(
    r"(?:^|_)(?:TOKEN|PASSWORD|SECRET|API_KEY|PRIVATE_KEY|ACCESS_KEY|CREDENTIALS?)(?:$|_)",
    re.I,
)


def _mapping(value):
    if not isinstance(value, dict):
        raise ContractError("Invalid workload configuration structure")
    return value


def _list(value):
    if not isinstance(value, list) or len(value) > 128:
        raise ContractError("Invalid workload configuration list")
    return value


def _status(values, *, missing_unknown=True):
    if any(v is False for v in values):
        return R.FAIL
    if not values or any(v is None for v in values):
        return R.UNKNOWN if missing_unknown else R.PASS
    return R.PASS


def _positive_quantity(value, kind):
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        return None
    match = re.fullmatch(
        r"([+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+))([a-zA-Z]*)", str(value)
    )
    if match is None:
        return None
    units = (
        {"", "m", "u", "n"}
        if kind == "cpu"
        else {
            "",
            "m",
            "k",
            "K",
            "M",
            "G",
            "T",
            "P",
            "E",
            "Ki",
            "Mi",
            "Gi",
            "Ti",
            "Pi",
            "Ei",
        }
    )
    if match[2] not in units:
        return None
    try:
        return Decimal(match[1]) > 0
    except InvalidOperation:
        return None


def workload_projection(item):
    spec = _mapping(_mapping(_mapping(item.get("spec")).get("template")).get("spec"))
    pod = _mapping(spec.get("securityContext", {}))
    containers = (
        _list(spec.get("containers", []))
        + _list(spec.get("initContainers", []))
        + _list(spec.get("ephemeralContainers", []))
    )
    if not containers:
        raise ContractError("Workload requires containers")
    settings = {name: [] for name, _ in RULES}
    settings["no-host-namespaces"] = [
        all(spec.get(k, False) is False for k in ("hostNetwork", "hostPID", "hostIPC"))
    ]
    settings["no-auto-token"] = [
        spec.get("automountServiceAccountToken") is False
        if "automountServiceAccountToken" in spec
        else None
    ]
    volumes = _list(spec.get("volumes", []))
    settings["no-host-mounts"] = [not any("hostPath" in _mapping(v) for v in volumes)]
    for container in containers:
        container = _mapping(container)
        context = _mapping(container.get("securityContext", {}))
        settings["no-privileged"].append(context.get("privileged", False) is False)
        non_root = context.get("runAsNonRoot", pod.get("runAsNonRoot"))
        settings["non-root"].append(None if non_root is None else non_root is True)
        for rule, field in (
            ("no-escalation", "allowPrivilegeEscalation"),
            ("read-only-root", "readOnlyRootFilesystem"),
        ):
            value = context.get(field)
            settings[rule].append(
                None if value is None else value is (field == "readOnlyRootFilesystem")
            )
        caps = _mapping(context.get("capabilities", {}))
        drop = _list(caps.get("drop", []))
        add = _list(caps.get("add", []))
        settings["drop-capabilities"].append("ALL" in drop and not add)
        seccomp = _mapping(context.get("seccompProfile", pod.get("seccompProfile", {})))
        settings["runtime-seccomp"].append(
            seccomp.get("type") == "RuntimeDefault" if "type" in seccomp else None
        )
        image = container.get("image", "")
        settings["digest-pinned-images"].append(
            isinstance(image, str)
            and re.fullmatch(r"[^\s]+@sha256:[0-9a-f]{64}", image) is not None
        )
        limits = _mapping(_mapping(container.get("resources", {})).get("limits", {}))
        values = [_positive_quantity(limits.get(k), k) for k in ("cpu", "memory")]
        settings["bounded-resources"].append(
            False if False in values else None if None in values else True
        )
        environment = _list(container.get("env", []))
        unsafe = False
        for env in environment:
            env = _mapping(env)
            name = env.get("name", "")
            if not isinstance(name, str):
                raise ContractError("Invalid environment name")
            if (
                SENSITIVE_NAME.search(name)
                and "value" in env
                and env["value"] not in ("", None)
            ):
                unsafe = True
        settings["no-literal-sensitive-env"].append(not unsafe)
    return {name: str(_status(values)) for name, values in settings.items()}


def posture_projection(items, graph):
    if type(items) is not tuple or len(items) > 128:
        raise ContractError("Bounded workload snapshot required")
    # Joining by UID AND resourceVersion prevents findings from another revision.
    resources = {r.scope.resource_id: r for r in graph.resources}
    findings = []
    for item in items:
        if not isinstance(item, dict) or item.get("kind") not in {
            "Deployment",
            "StatefulSet",
        }:
            continue
        metadata = _mapping(item.get("metadata"))
        namespace = metadata.get("namespace")
        name = metadata.get("name")
        uid = metadata.get("uid")
        resource_id = (
            "k8s://"
            + str(namespace)
            + "/"
            + item["kind"]
            + "/"
            + str(name)
            + "#"
            + str(uid)
        )
        resource = resources.get(resource_id)
        if resource is None or resource.resource_revision != metadata.get(
            "resourceVersion"
        ):
            raise ContractError("Posture resource does not match inventory revision")
        projected = workload_projection(item)
        # Hash a safe projection, never the raw pod spec / low-entropy secret value.
        source = hashlib.sha256(
            canonical_json(
                {
                    "scope": resource.document["scope"],
                    "resource_revision": resource.resource_revision,
                    "checks": projected,
                }
            ).encode()
        ).hexdigest()
        for name, family in RULES:
            result = R(projected[name])
            finding = PostureFinding(
                name,
                family,
                resource.scope,
                resource.resource_revision,
                result,
                FindingBasis.CONFIGURATION,
                "declared-config-" + str(result),
                source,
                graph.observed_at,
                graph.valid_until,
            )
            findings.append(finding.document)
    return {
        "verifier": "sova-kubernetes-configuration-v1",
        "graph_digest": graph.fingerprint,
        "findings": findings,
        "unverified": [
            "runtime-enforcement",
            "live-pod-drift",
            "network-policy-enforcement",
            "secret-access-permissions",
            "image-provenance-and-vulnerabilities",
            "storage-encryption",
            "audit-and-backup",
        ],
        "raw_values_included": False,
    }
