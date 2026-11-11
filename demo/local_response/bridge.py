"""Supervised SSM port forwards from this Mac to the EKS source Services.

Local RKE2 pods reach the EKS source API and DB only through these forwards:

    local pod -> local Service (EndpointSlice 192.168.5.2) -> Lima host loopback
    -> session-manager-plugin -> SSM -> source node -> source Service ClusterIP

IAM authenticates every session and nothing on the source is exposed publicly.
A forward that exits is restarted against a node that is Online in SSM now.
The supervisor never changes cluster resources; it only carries traffic.
"""

import argparse
from datetime import UTC, datetime, timedelta
import fcntl
import json
import os
from pathlib import Path
import pty
import select
import signal
import socket
import subprocess
import threading
import time

from .manifests import BRIDGE, configure
from .kube import Kube
from .provision import private_json

# Directory holding the AWS-signed session-manager-plugin, when not on PATH.
PLUGIN_DIR = os.environ.get("SOVA_SSM_PLUGIN_DIR", "")


def aws(args, settings, timeout=30):
    result = subprocess.run(
        ["aws", *args, "--region", settings["aws"]["region"], "--output", "json"],
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if result.returncode:
        raise RuntimeError("aws_call_failed: " + " ".join(args[:2]))
    return json.loads(result.stdout)


def online_nodes(settings):
    if (
        aws(["sts", "get-caller-identity"], settings)["Account"]
        != settings["aws"]["account_id"]
    ):
        raise RuntimeError("wrong_aws_account")
    group = aws(
        [
            "eks",
            "describe-nodegroup",
            "--cluster-name",
            settings["aws"]["cluster_name"],
            "--nodegroup-name",
            "source",
        ],
        settings,
    )["nodegroup"]
    asg = group["resources"]["autoScalingGroups"][0]["name"]
    instances = aws(
        [
            "autoscaling",
            "describe-auto-scaling-groups",
            "--auto-scaling-group-names",
            asg,
        ],
        settings,
    )["AutoScalingGroups"][0]["Instances"]
    ids = [
        item["InstanceId"]
        for item in instances
        if item["LifecycleState"] == "InService"
    ]
    if not ids:
        return []
    info = aws(
        [
            "ssm",
            "describe-instance-information",
            "--filters",
            "Key=InstanceIds,Values=" + ",".join(ids),
        ],
        settings,
    )["InstanceInformationList"]
    online = [item["InstanceId"] for item in info if item["PingStatus"] == "Online"]
    if not online:
        return []
    # Forward only through nodes the bridge-ingress policy admits.
    reservations = aws(
        ["ec2", "describe-instances", "--instance-ids", *online], settings
    )["Reservations"]
    allowed = set(settings["aws"].get("node_ips") or [])
    return sorted(
        instance["InstanceId"]
        for reservation in reservations
        for instance in reservation["Instances"]
        if instance.get("PrivateIpAddress") in allowed
    )


def listening(port):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=1):
            return True
    except OSError:
        return False


class Forward:
    def __init__(self, name, settings, cluster_ip, log):
        self.name, self.settings, self.cluster_ip, self.log = (
            name,
            settings,
            cluster_ip,
            log,
        )
        self.item = BRIDGE[name]
        self.pid = None
        self.master = None
        self.instance = None
        self.started_at = None
        self.restarts = 0

    def start(self, instance):
        arguments = [
            "aws",
            "ssm",
            "start-session",
            "--region",
            self.settings["aws"]["region"],
            "--target",
            instance,
            "--document-name",
            "AWS-StartPortForwardingSessionToRemoteHost",
            "--parameters",
            json.dumps(
                {
                    "host": [self.cluster_ip],
                    "portNumber": [str(self.item["port"])],
                    "localPortNumber": [str(self.item["local_port"])],
                }
            ),
        ]
        env = dict(os.environ)
        if PLUGIN_DIR:
            env["PATH"] = PLUGIN_DIR + os.pathsep + env["PATH"]
        # The plugin needs a controlling terminal, not just an inherited TTY FD.
        pid, master = pty.fork()
        if pid == 0:
            os.execvpe(arguments[0], arguments, env)
        self.pid, self.master, self.instance = pid, master, instance
        self.started_at = datetime.now(UTC).isoformat()
        threading.Thread(target=self.drain, args=(master,), daemon=True).start()

    def drain(self, master):
        while True:
            try:
                ready, _, _ = select.select([master], [], [], 5)
                if ready:
                    chunk = os.read(master, 4096)
                    if not chunk:
                        return
                    with self.log.open("ab") as stream:
                        stream.write(b"[" + self.name.encode() + b"] " + chunk[-1024:])
            except OSError:
                return

    def alive(self):
        if self.pid is None:
            return False
        try:
            done, _ = os.waitpid(self.pid, os.WNOHANG)
        except ChildProcessError:
            return False
        return done == 0

    def stop(self):
        if self.pid and self.alive():
            try:
                os.kill(self.pid, signal.SIGTERM)
                os.waitpid(self.pid, 0)
            except (ProcessLookupError, ChildProcessError):
                pass
        if self.master is not None:
            try:
                os.close(self.master)
            except OSError:
                pass
        self.pid = self.master = None

    def status(self):
        return {
            "local_port": self.item["local_port"],
            "remote_port": self.item["port"],
            "cluster_ip": self.cluster_ip,
            "instance": self.instance,
            "pid": self.pid,
            "alive": self.alive(),
            "listening": listening(self.item["local_port"]),
            "restarts": self.restarts,
            "started_at": self.started_at,
        }


def supervise(root, hours):
    os.umask(0o077)
    lock = open(root / "bridge.lock", "a")
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    settings = json.loads((root / "settings.private.json").read_text())
    if settings.get("topology") != "hybrid-aws":
        raise ValueError("hybrid_topology_required")
    configure("hybrid-aws")
    kube = Kube.from_settings(settings)
    kube.identity()
    deadline = datetime.now(UTC) + timedelta(hours=hours)
    log = root / "bridge.log"
    forwards = {}
    for name in BRIDGE:
        role = "api" if name == "api" else "db"
        cluster_ip = kube.get("source", "service", role)["spec"]["clusterIP"]
        forwards[name] = Forward(name, settings, cluster_ip, log)
    stopping = threading.Event()

    def stop(*_):
        stopping.set()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    backoff = {name: 0.0 for name in forwards}
    next_try = {name: 0.0 for name in forwards}
    try:
        while not stopping.is_set() and datetime.now(UTC) < deadline:
            nodes = None
            for name, forward in forwards.items():
                if forward.alive() or time.monotonic() < next_try[name]:
                    continue
                if forward.pid is not None:
                    forward.stop()
                    forward.restarts += 1
                try:
                    nodes = nodes if nodes is not None else online_nodes(settings)
                except (RuntimeError, subprocess.TimeoutExpired, KeyError, IndexError):
                    nodes = []
                if not nodes:
                    backoff[name] = min(30.0, max(2.0, backoff[name] * 2))
                    next_try[name] = time.monotonic() + backoff[name]
                    continue
                # Spread the forwards over the Online nodes; rotate on restarts.
                index = (list(forwards).index(name) + forward.restarts) % len(nodes)
                forward.start(nodes[index])
                backoff[name] = 0.0
            private_json(
                root / "bridge-status.json",
                {
                    "kind": "sova.hybrid-bridge.v1",
                    "updated_at": datetime.now(UTC).isoformat(),
                    "deadline": deadline.isoformat(),
                    "path": "local pod -> 192.168.5.2 (Lima host loopback) -> SSM -> EKS node -> Service ClusterIP",
                    "forwards": {name: f.status() for name, f in forwards.items()},
                },
            )
            stopping.wait(2)
    finally:
        for forward in forwards.values():
            forward.stop()
        private_json(
            root / "bridge-status.json",
            {
                "kind": "sova.hybrid-bridge.v1",
                "updated_at": datetime.now(UTC).isoformat(),
                "stopped": True,
                "forwards": {name: f.status() for name, f in forwards.items()},
            },
        )
        lock.close()


def read_status(root, max_age=15):
    """Bridge health for observation; stale or missing status is not healthy."""
    try:
        value = json.loads((Path(root) / "bridge-status.json").read_text())
        updated = datetime.fromisoformat(value["updated_at"])
    except (OSError, ValueError, KeyError):
        return {"healthy": False, "error": "bridge_status_unavailable"}
    fresh = (datetime.now(UTC) - updated).total_seconds() <= max_age
    forwards = value.get("forwards", {})
    healthy = (
        fresh
        and not value.get("stopped")
        and bool(forwards)
        and all(
            item.get("alive") and item.get("listening") for item in forwards.values()
        )
    )
    return {
        "healthy": healthy,
        "fresh": fresh,
        "forwards": {
            name: {
                key: item.get(key)
                for key in ("local_port", "alive", "listening", "restarts", "instance")
            }
            for name, item in forwards.items()
        },
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", required=True, type=Path)
    parser.add_argument("--hours", type=float, default=8)
    args = parser.parse_args()
    if not 0 < args.hours <= 12:
        parser.error("bounded runtime required")
    supervise(args.state.resolve(), args.hours)


if __name__ == "__main__":
    main()
