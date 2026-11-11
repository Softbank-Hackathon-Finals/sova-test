"""Read-only actual local resource and HTTP observation."""

import json
import time
from .contracts import now
from .kube import BATCH_HTTP_PROBE
from .manifests import NAMESPACES, probe_side


class RuntimeObservation:
    def observe(self):
        generation = self.state["revision"]
        self.identity()
        inventory = {}
        for side in ("source", "target", "control"):
            pods = self.kube.get(side, "pods")["items"]
            inventory[side] = [
                {
                    "name": p["metadata"]["name"],
                    "uid": p["metadata"]["uid"],
                    "role": p["metadata"].get("labels", {}).get("sova.io/role"),
                    "phase": p.get("status", {}).get("phase"),
                    "ready": any(
                        c["type"] == "Ready" and c["status"] == "True"
                        for c in p.get("status", {}).get("conditions", [])
                    ),
                    "images": [
                        {
                            "image": c.get("image"),
                            "image_id": c.get("imageID"),
                            "restart_count": c.get("restartCount"),
                        }
                        for c in p.get("status", {}).get("containerStatuses", [])
                    ],
                }
                for p in pods
            ]
        secret = self.kube.get("source", "secret", "workload-credentials")
        endpoints = {
            side + "/" + role: role + "." + NAMESPACES[side]
            for side, roles in {
                "source": ("api", "worker", "auth", "objects", "external"),
                "target": ("api", "worker"),
                "control": ("edge",),
            }.items()
            for role in roles
        }
        # Probe each endpoint from inside its own cluster.
        http = {}
        groups = {}
        for key, address in endpoints.items():
            groups.setdefault(probe_side(key.split("/", 1)[0]), {})[key] = address
        for prober, group in groups.items():
            http.update(
                json.loads(self.kube.execute(prober, "probe", BATCH_HTTP_PROBE, group))
            )
        writers = {
            side: self.sql(
                side, "SELECT rolcanlogin FROM pg_roles WHERE rolname='app'"
            )[0][0]
            for side in ("source", "target")
        }
        observed = {
            "current": True,
            "observed_at": now(),
            "expires_at_epoch": time.time() + 20,
            "cluster_uid": self.settings["cluster_uid"],
            "pods": inventory,
            "http": http,
            "database_app_login": writers,
            "entry": self.kube.request("control", "edge", "/messages"),
            "source_database": self.fingerprint("source"),
            "target_database": self.fingerprint("target"),
            "secret": {
                "uid": secret["metadata"]["uid"],
                "resource_version": secret["metadata"]["resourceVersion"],
            },
            "state_revision": generation,
        }
        if self.security.active():
            # Keep the approver's view of the hold bound to fresh revisions.
            self.security.export()
        if self.topology()["name"] == "hybrid-aws":
            from .bridge import read_status

            observed["bridge"] = read_status(self.root)
        if self.state["revision"] != generation:
            observed["current"] = False
            observed["error"] = "changed_during_observation"
        self.observation = observed
        return self.observation
