"""Opt-in, destructive ONLY to newly created labelled qualification namespaces.

Run with the Sova project interpreter and --state-dir pointing to the private
linux-target registration. No kubeconfig, token or Secret is printed. This is
an operator qualification harness, not a hosted credential provider.
"""

import argparse
from datetime import UTC, datetime, timedelta
import hashlib
import http.client
import json
import os
from pathlib import Path
import secrets
import ssl
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).absolute().parents[2] / "src"))
from sova.adapters.kubernetes.https import KubernetesHTTPS, private_text
from sova.application.kubernetes_discovery import KubernetesDiscovery
from sova.domain.contracts import ContractError
from sova.domain.discovery import KubernetesReadRegistration


VM = "sova-target"
IMAGE = "sova-consultation:phase-integration-20261102"
LABEL = "sova.example/qualification"


def run(args, *, value=None, timeout=60, check=True):
    result = subprocess.run(
        args, input=value, capture_output=True, text=True, timeout=timeout
    )
    if check and result.returncode:
        raise RuntimeError("Qualification command refused; output withheld")
    return result


def guest(*args, **kwargs):
    return run(["limactl", "shell", "--workdir=/", VM, "--", *args], **kwargs)


def kubectl(*args, **kwargs):
    return guest("sudo", "k3s", "kubectl", *args, **kwargs)


def apply(items):
    kubectl(
        "create",
        "-f",
        "-",
        value=json.dumps({"apiVersion": "v1", "kind": "List", "items": items}),
    )


def absent(kind, name):
    """An API failure is unknown, never evidence that a resource was removed."""
    try:
        response = kubectl(
            "get", kind, name, "--ignore-not-found=true", "-o", "json", check=False
        )
        return response.returncode == 0 and not response.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return False


def check(condition, name, results):
    if not condition:
        raise RuntimeError("Qualification failed: " + name)
    results[name] = True
    print(json.dumps({"verified": name}), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--soak-seconds", type=int, default=0)
    args = parser.parse_args()
    if os.environ.get("SOVA_QUALIFY_LINUX_VM") != "1":
        parser.error("Explicit SOVA_QUALIFY_LINUX_VM=1 required")
    if not 0 <= args.soak_seconds <= 1800:
        parser.error("Soak duration must be between 0 and 1800 seconds")
    os.umask(0o077)
    state = args.state_dir.absolute()
    owner = json.loads(private_text(state / "ownership.json"))
    assert owner["name"] == VM and owner["status"] == "ready"
    assert datetime.fromisoformat(owner["expires_at"]) > datetime.now(UTC), (
        "Target registration expired"
    )
    assert guest("cat", "/etc/machine-id").stdout.strip() == owner["machine_id"]
    node = json.loads(kubectl("get", "node", VM, "-o", "json").stdout)
    assert node["metadata"]["uid"] == owner["node_uid"]
    config_path = Path(owner["lima_config_path"])
    assert (
        hashlib.sha256(config_path.read_bytes()).hexdigest()
        == owner["lima_config_sha256"]
    )
    assert not args.output.exists(), "Use a fresh, private qualification output"
    args.output.mkdir(mode=0o700, parents=True)
    started = datetime.now(UTC)
    qualification = "q-" + secrets.token_hex(6)
    namespaces = ["sova-" + qualification + "-a", "sova-" + qualification + "-b"]
    created = {}
    # Track intent before mutation so a lost create reply cannot hide leftovers.
    cluster_roles = ["sova-" + qualification]
    results = {}
    failure = None
    try:
        # Import a local, operator-owned reference image; no registry credentials.
        image = json.loads(run(["docker", "image", "inspect", IMAGE]).stdout)[0]
        assert (
            image["Architecture"] == "arm64"
            and image["Config"]["User"] == "10001:10001"
        )
        exporter = subprocess.Popen(
            ["docker", "image", "save", IMAGE],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            imported = subprocess.run(
                [
                    "limactl",
                    "shell",
                    "--workdir=/",
                    VM,
                    "--",
                    "sudo",
                    "k3s",
                    "ctr",
                    "images",
                    "import",
                    "-",
                ],
                stdin=exporter.stdout,
                capture_output=True,
                timeout=180,
            )
            exporter.stdout.close()
            _, error = exporter.communicate(timeout=30)
            assert imported.returncode == exporter.returncode == 0, (
                "Local image import failed"
            )
        finally:
            if exporter.poll() is None:
                exporter.kill()
                exporter.wait()
        reference = "docker.io/library/" + IMAGE
        descriptors = guest("sudo", "k3s", "ctr", "images", "list").stdout
        descriptor = next(
            line.split()
            for line in descriptors.splitlines()
            if line.split() and line.split()[0] == reference
        )
        manifest_digest = descriptor[2]
        manifest = json.loads(
            guest("sudo", "k3s", "ctr", "content", "get", manifest_digest).stdout
        )
        source_descriptor = image.get("Descriptor", {})
        assert source_descriptor.get("digest") == manifest_digest, (
            "Source manifest descriptor differs or unavailable"
        )
        assert (
            source_descriptor.get("annotations", {}).get("config.digest")
            == manifest["config"]["digest"]
        ), "Imported image config differs"
        pinned_image = "docker.io/library/sova-consultation@" + manifest_digest
        # Add an immutable local digest reference; never fetch a different image.
        names = guest(
            "sudo", "k3s", "ctr", "images", "list", "--quiet"
        ).stdout.splitlines()
        if pinned_image not in names:
            guest("sudo", "k3s", "ctr", "images", "tag", reference, pinned_image)
        for ns in namespaces:
            apply(
                [
                    {
                        "apiVersion": "v1",
                        "kind": "Namespace",
                        "metadata": {
                            "name": ns,
                            "labels": {
                                LABEL: qualification,
                                "pod-security.kubernetes.io/enforce": "restricted",
                                "pod-security.kubernetes.io/enforce-version": "v1.37",
                            },
                        },
                    }
                ]
            )
            created[ns] = json.loads(kubectl("get", "ns", ns, "-o", "json").stdout)[
                "metadata"
            ]["uid"]

        ns = namespaces[0]
        server_labels = {"app": "server", "app.kubernetes.io/part-of": "orders"}
        security = {
            "runAsNonRoot": True,
            "runAsUser": 10001,
            "runAsGroup": 10001,
            "seccompProfile": {"type": "RuntimeDefault"},
        }
        container_security = {
            "allowPrivilegeEscalation": False,
            "readOnlyRootFilesystem": True,
            "capabilities": {"drop": ["ALL"]},
        }

        def pod_spec(command):
            return {
                "terminationGracePeriodSeconds": 5,
                "automountServiceAccountToken": False,
                "securityContext": security,
                "containers": [
                    {
                        "name": "app",
                        "image": pinned_image,
                        "imagePullPolicy": "Never",
                        "command": command,
                        "securityContext": container_security,
                        "resources": {
                            "requests": {"cpu": "25m", "memory": "32Mi"},
                            "limits": {"cpu": "250m", "memory": "128Mi"},
                        },
                    }
                ],
            }

        server = pod_spec(
            [
                "python",
                "-m",
                "http.server",
                "8080",
                "--bind",
                "0.0.0.0",
                "--directory",
                "/app/consultation/web",
            ]
        )
        server["containers"][0]["readinessProbe"] = {
            "tcpSocket": {"port": 8080},
            "periodSeconds": 2,
        }
        items = [
            {
                "apiVersion": "v1",
                "kind": "ServiceAccount",
                "metadata": {"name": "inventory", "namespace": ns},
                "automountServiceAccountToken": False,
            },
            {
                "apiVersion": "apps/v1",
                "kind": "Deployment",
                "metadata": {
                    "name": "server",
                    "namespace": ns,
                    "labels": server_labels,
                },
                "spec": {
                    "replicas": 1,
                    "selector": {"matchLabels": {"app": "server"}},
                    "template": {"metadata": {"labels": server_labels}, "spec": server},
                },
            },
            {
                "apiVersion": "v1",
                "kind": "Service",
                "metadata": {
                    "name": "server",
                    "namespace": ns,
                    "labels": server_labels,
                },
                "spec": {
                    "selector": {"app": "server"},
                    "ports": [{"port": 8080, "targetPort": 8080}],
                },
            },
        ]
        for client_ns in namespaces:
            items.append(
                {
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "metadata": {
                        "name": "client",
                        "namespace": client_ns,
                        "labels": {"app": "client"},
                    },
                    "spec": pod_spec(["python", "-c", "import time; time.sleep(3600)"]),
                }
            )
            items.append(
                {
                    "apiVersion": "networking.k8s.io/v1",
                    "kind": "NetworkPolicy",
                    "metadata": {"name": "deny-all", "namespace": client_ns},
                    "spec": {"podSelector": {}, "policyTypes": ["Ingress", "Egress"]},
                }
            )
        apply(items)
        kubectl(
            "rollout",
            "status",
            "deployment/server",
            "-n",
            ns,
            "--timeout=120s",
            timeout=140,
        )
        for client_ns in namespaces:
            kubectl(
                "wait",
                "--for=condition=Ready",
                "pod/client",
                "-n",
                client_ns,
                "--timeout=90s",
                timeout=100,
            )
        check(True, "restricted_nonroot_image_started", results)
        pod = json.loads(
            kubectl("get", "pods", "-n", ns, "-l", "app=server", "-o", "json").stdout
        )["items"][0]
        check(
            manifest_digest in pod["status"]["containerStatuses"][0]["imageID"],
            "runtime_manifest_digest_matches",
            results,
        )
        results["image"] = {
            "local_config_digest": manifest["config"]["digest"],
            "imported_manifest_digest": manifest_digest,
            "cross_runtime_manifest_identity_qualified": True,
        }
        target_ip = pod["status"]["podIP"]
        probe = (
            "import urllib.request; r=urllib.request.urlopen('http://"
            + target_ip
            + ":8080/',timeout=2); assert r.status==200"
        )

        def can_reach(client_ns):
            return (
                kubectl(
                    "exec",
                    "-n",
                    client_ns,
                    "client",
                    "--",
                    "python",
                    "-c",
                    probe,
                    check=False,
                    timeout=12,
                ).returncode
                == 0
            )

        # Wait for the actual packet policy, not just an accepted API response.
        time.sleep(3)
        check(
            not can_reach(ns) and not can_reach(namespaces[1]),
            "default_deny_actual_connections",
            results,
        )
        policies = []
        for client_ns in namespaces:
            policies.append(
                {
                    "apiVersion": "networking.k8s.io/v1",
                    "kind": "NetworkPolicy",
                    "metadata": {"name": "allow-client-egress", "namespace": client_ns},
                    "spec": {
                        "podSelector": {"matchLabels": {"app": "client"}},
                        "policyTypes": ["Egress"],
                        "egress": [
                            {
                                "to": [
                                    {
                                        "namespaceSelector": {
                                            "matchLabels": {
                                                "kubernetes.io/metadata.name": ns
                                            }
                                        },
                                        "podSelector": {
                                            "matchLabels": {"app": "server"}
                                        },
                                    }
                                ],
                                "ports": [{"protocol": "TCP", "port": 8080}],
                            }
                        ],
                    },
                }
            )
        policies.append(
            {
                "apiVersion": "networking.k8s.io/v1",
                "kind": "NetworkPolicy",
                "metadata": {"name": "allow-owned-client", "namespace": ns},
                "spec": {
                    "podSelector": {"matchLabels": {"app": "server"}},
                    "policyTypes": ["Ingress"],
                    "ingress": [
                        {
                            "from": [
                                {"podSelector": {"matchLabels": {"app": "client"}}}
                            ],
                            "ports": [{"protocol": "TCP", "port": 8080}],
                        }
                    ],
                },
            }
        )
        apply(policies)
        deadline = time.monotonic() + 30
        while not can_reach(ns) and time.monotonic() < deadline:
            time.sleep(1)
        check(can_reach(ns), "explicit_owned_link_reachable", results)
        check(
            not can_reach(namespaces[1]),
            "other_namespace_denied_despite_egress_allow",
            results,
        )
        if args.soak_seconds:
            service = json.loads(
                kubectl("get", "service/server", "-n", ns, "-o", "json").stdout
            )
            service_ip = service["spec"]["clusterIP"]
            soak_source = r"""
import collections, concurrent.futures, json, time, urllib.request
deadline = time.monotonic() + DURATION
def worker():
    counts, durations = collections.Counter(), []
    while time.monotonic() < deadline:
        started = time.monotonic()
        try:
            with urllib.request.urlopen("http://SERVICE_IP:8080/", timeout=2) as response:
                response.read(65536)
                counts[str(response.status)] += 1
        except Exception as exc:
            counts[type(exc).__name__] += 1
        durations.append(time.monotonic() - started)
        time.sleep(0.2)
    return counts, durations
with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
    samples = list(pool.map(lambda _: worker(), range(4)))
counts, durations = collections.Counter(), []
for count, duration in samples:
    counts.update(count)
    durations.extend(duration)
durations.sort()
print(json.dumps({"responses": dict(counts), "requests": len(durations), "latency_p95_seconds": durations[int(len(durations)*0.95)], "latency_max_seconds": max(durations)}), flush=True)
""".replace("DURATION", str(args.soak_seconds)).replace("SERVICE_IP", service_ip)
            soak_path = args.output / "soak.json"
            with (
                soak_path.open("w") as stdout,
                (args.output / "soak-errors.log").open("w") as stderr,
            ):
                soak = subprocess.Popen(
                    [
                        "limactl",
                        "shell",
                        "--workdir=/",
                        VM,
                        "--",
                        "sudo",
                        "k3s",
                        "kubectl",
                        "exec",
                        "-n",
                        ns,
                        "client",
                        "--",
                        "python",
                        "-u",
                        "-c",
                        soak_source,
                    ],
                    stdout=stdout,
                    stderr=stderr,
                )
                begin = time.monotonic()
                next_rollout = begin + 60
                rollouts = 0
                try:
                    while soak.poll() is None:
                        if time.monotonic() > begin + args.soak_seconds + 30:
                            raise RuntimeError(
                                "Soak exceeded bounded execution deadline"
                            )
                        if (
                            time.monotonic() >= next_rollout
                            and time.monotonic() < begin + args.soak_seconds - 20
                        ):
                            kubectl("rollout", "restart", "deployment/server", "-n", ns)
                            kubectl(
                                "rollout",
                                "status",
                                "deployment/server",
                                "-n",
                                ns,
                                "--timeout=60s",
                                timeout=70,
                            )
                            rollouts += 1
                            next_rollout += 300
                            print(
                                json.dumps(
                                    {
                                        "soak_elapsed_seconds": int(
                                            time.monotonic() - begin
                                        ),
                                        "rollouts_completed": rollouts,
                                    }
                                ),
                                flush=True,
                            )
                        time.sleep(1)
                    if soak.returncode:
                        raise RuntimeError("Bounded load probe failed")
                finally:
                    if soak.poll() is None:
                        soak.terminate()
                        soak.wait(timeout=10)
            sample = json.loads(soak_path.read_text())
            results["rolling_soak"] = {
                **sample,
                "duration_seconds": args.soak_seconds,
                "rollouts_completed": rollouts,
                "scope": "single-vm-stateless-reference-service-not-data-migration",
            }
            check(
                sample["requests"] >= args.soak_seconds
                and set(sample["responses"]) == {"200"},
                "rolling_soak_no_failed_requests",
                results,
            )
            # Target a currently running replacement pod for the revoke test.
            current_pods = json.loads(
                kubectl(
                    "get", "pods", "-n", ns, "-l", "app=server", "-o", "json"
                ).stdout
            )["items"]
            pod = next(
                p
                for p in current_pods
                if not p["metadata"].get("deletionTimestamp")
                and any(
                    c["type"] == "Ready" and c["status"] == "True"
                    for c in p["status"].get("conditions", [])
                )
            )
            target_ip = pod["status"]["podIP"]
            probe = (
                "import urllib.request; r=urllib.request.urlopen('http://"
                + target_ip
                + ":8080/',timeout=2); assert r.status==200"
            )
            check(
                not can_reach(namespaces[1]),
                "other_namespace_denied_after_rolling_soak",
                results,
            )
        kubectl("delete", "networkpolicy/allow-owned-client", "-n", ns)
        deadline = time.monotonic() + 30
        while can_reach(ns) and time.monotonic() < deadline:
            time.sleep(1)
        check(not can_reach(ns), "revoked_link_actual_connection_denied", results)

        role = "sova-" + qualification
        apply(
            [
                {
                    "apiVersion": "rbac.authorization.k8s.io/v1",
                    "kind": "Role",
                    "metadata": {"name": "inventory", "namespace": ns},
                    "rules": [
                        {
                            "apiGroups": ["apps"],
                            "resources": ["deployments", "statefulsets"],
                            "verbs": ["list"],
                        },
                        {
                            "apiGroups": [""],
                            "resources": ["services", "persistentvolumeclaims"],
                            "verbs": ["list"],
                        },
                    ],
                },
                {
                    "apiVersion": "rbac.authorization.k8s.io/v1",
                    "kind": "RoleBinding",
                    "metadata": {"name": "inventory", "namespace": ns},
                    "subjects": [
                        {"kind": "ServiceAccount", "name": "inventory", "namespace": ns}
                    ],
                    "roleRef": {
                        "apiGroup": "rbac.authorization.k8s.io",
                        "kind": "Role",
                        "name": "inventory",
                    },
                },
                {
                    "apiVersion": "rbac.authorization.k8s.io/v1",
                    "kind": "ClusterRole",
                    "metadata": {"name": role, "labels": {LABEL: qualification}},
                    "rules": [
                        {
                            "apiGroups": [""],
                            "resources": ["namespaces"],
                            "resourceNames": [ns],
                            "verbs": ["get"],
                        }
                    ],
                },
            ]
        )
        apply(
            [
                {
                    "apiVersion": "rbac.authorization.k8s.io/v1",
                    "kind": "ClusterRoleBinding",
                    "metadata": {"name": role, "labels": {LABEL: qualification}},
                    "subjects": [
                        {"kind": "ServiceAccount", "name": "inventory", "namespace": ns}
                    ],
                    "roleRef": {
                        "apiGroup": "rbac.authorization.k8s.io",
                        "kind": "ClusterRole",
                        "name": role,
                    },
                }
            ]
        )
        token = kubectl(
            "create", "token", "inventory", "-n", ns, "--duration=10m"
        ).stdout.strip()
        ca = (state / "cluster-ca.pem").read_bytes()
        now = datetime.now(UTC)
        registration = KubernetesReadRegistration(
            "tenant-trial",
            "orders",
            "linux-trial",
            "onprem-linux-vm",
            "https://localhost:19743",
            ("127.0.0.1",),
            hashlib.sha256(ca).hexdigest(),
            ns,
            created[ns],
            1,
            now,
            now + timedelta(minutes=10),
        )

        def inventory(credential):
            transport = KubernetesHTTPS(
                registration, ca_pem=ca, token_provider=lambda: credential
            )
            return KubernetesDiscovery(
                registration,
                transport,
                authorize=lambda *args: None,
                clock=lambda: datetime.now(UTC),
            ).inspect(actor="private-local-operator")

        result = inventory(token)
        check(
            result["executable"] is False and len(result["graph"]["resources"]) == 2,
            "real_api_readonly_inventory",
            results,
        )
        (args.output / "inventory.json").write_text(json.dumps(result, indent=2))
        context = ssl.create_default_context(cadata=ca.decode())

        def status(path, method="GET", body=None, credential=token):
            conn = http.client.HTTPSConnection(
                "localhost", 19743, context=context, timeout=5
            )
            try:
                headers = {"Content-Type": "application/json"}
                if credential:
                    headers["Authorization"] = "Bearer " + credential
                conn.request(method, path, body=body, headers=headers)
                response = conn.getresponse()
                code = response.status
                response.read(1048576)
                return code
            finally:
                conn.close()

        check(
            status("/api/v1/namespaces/" + ns + "/secrets") == 403,
            "secret_read_rbac_denied",
            results,
        )
        check(
            status("/apis/apps/v1/namespaces/" + namespaces[1] + "/deployments") == 403,
            "other_namespace_rbac_denied",
            results,
        )
        check(
            status(
                "/api/v1/namespaces/" + ns + "/configmaps",
                "POST",
                '{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"forbidden"}}',
            )
            == 403,
            "mutation_rbac_denied",
            results,
        )
        check(
            status("/api/v1/namespaces/" + ns, credential="") in (401, 403),
            "anonymous_api_denied",
            results,
        )
        kubectl("delete", "rolebinding/inventory", "-n", ns)
        try:
            inventory(token)
        except ContractError:
            check(True, "revoked_inventory_returns_no_partial_graph", results)
        else:
            raise RuntimeError("Revoked RBAC still returned inventory")
        # The real API must reject privileged pods under namespace admission.
        unsafe = {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "unsafe", "namespace": ns},
            "spec": {
                "containers": [
                    {
                        "name": "unsafe",
                        "image": pinned_image,
                        "securityContext": {"privileged": True},
                    }
                ]
            },
        }
        refused = kubectl("create", "-f", "-", value=json.dumps(unsafe), check=False)
        check(
            refused.returncode != 0 and "violates PodSecurity" in refused.stderr,
            "privileged_pod_admission_denied",
            results,
        )
    except BaseException as exc:
        failure = type(exc).__name__ + ": " + str(exc)
        raise
    finally:
        cleanup = True
        for kind in ("clusterrolebinding", "clusterrole"):
            for role in cluster_roles:
                current = kubectl("get", kind, role, "-o", "json", check=False)
                if current.returncode == 0:
                    metadata = json.loads(current.stdout)["metadata"]
                    if metadata.get("labels", {}).get(LABEL) == qualification:
                        cleanup &= (
                            kubectl("delete", kind, role, check=False).returncode == 0
                        )
                    else:
                        cleanup = False
                cleanup &= absent(kind, role)
        for ns, uid in created.items():
            current = kubectl("get", "ns", ns, "-o", "json", check=False)
            if current.returncode == 0:
                metadata = json.loads(current.stdout)["metadata"]
                if (
                    metadata["uid"] == uid
                    and metadata.get("labels", {}).get(LABEL) == qualification
                ):
                    cleanup &= (
                        kubectl(
                            "delete",
                            "ns",
                            ns,
                            "--wait=true",
                            "--timeout=90s",
                            check=False,
                            timeout=100,
                        ).returncode
                        == 0
                    )
                else:
                    cleanup = False
        # Include names whose creation reply/UID lookup may have been lost.
        # Unknown ownership is not deleted by guessing; it remains incomplete.
        for ns in namespaces:
            cleanup &= absent("namespace", ns)
        report = {
            "started_at": started.isoformat(),
            "completed_at": datetime.now(UTC).isoformat(),
            "checks": results,
            "failure": failure,
            "owned_resources_removed": cleanup,
            "actual_cloud_migration_verified": False,
            "production_ha_qualified": False,
            "operator_credentials_used_for_fixture_setup": True,
        }
        (args.output / "result.json").write_text(json.dumps(report, indent=2) + "\n")
        print(
            json.dumps(
                {
                    "checks_passed": sum(value is True for value in results.values()),
                    "owned_resources_removed": cleanup,
                    "failed": failure is not None,
                }
            ),
            flush=True,
        )
        if not cleanup and failure is None:
            raise RuntimeError("Owned fixture cleanup incomplete")


if __name__ == "__main__":
    main()
