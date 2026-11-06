"""Independent read-only graph/portability CLI. No sibling imports or keys."""

import argparse
from datetime import datetime, timezone, timedelta
import json
import sys
import os
import time
from pathlib import Path

from sova.adapters.registration.graph_codec import decode_graph, read_document
from sova.application.portability import assess_portability
from sova.domain.contracts import ContractError
from sova.adapters.kubernetes.inventory import snapshot_graph
from sova.application.examples import example_graph
from sova.adapters.kubernetes.https import KubernetesHTTPS, private_text
from sova.adapters.kubernetes.registration import decode_registration
from sova.adapters.registration.graph_codec import json_document
from sova.application.kubernetes_discovery import KubernetesDiscovery
from sova.adapters.kubernetes.posture import posture_projection


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="sova",
        description="Sova independent system registration and portability assessment",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    from sova.interfaces.security_program import add_commands
    add_commands(commands)
    from sova.interfaces.security_intake import add_commands as add_intake_commands
    add_intake_commands(commands)
    commands.add_parser(
        "example",
        help="Print a synthetic registration valid for one hour; no live resources",
    )
    inspect = commands.add_parser(
        "inspect", help="Validate a registered graph; no live inspection"
    )
    inspect.add_argument("registration")
    assess = commands.add_parser(
        "assess", help="Produce a non-executable portability proposal"
    )
    assess.add_argument("registration")
    assess.add_argument("--target-environment", required=True)
    assess.add_argument("--target-backend", required=True)
    inventory = commands.add_parser(
        "import-kubernetes",
        help="Normalize a scoped local export; no cluster connection",
    )
    inventory.add_argument("snapshot")
    for option in ("tenant", "application", "environment", "namespace", "location"):
        inventory.add_argument("--" + option, required=True)
    discover = commands.add_parser(
        "discover-kubernetes",
        help="Operator-only bounded HTTPS reads using a private registration; no kubeconfig execution",
    )
    for option in ("registration", "ca-file", "token-file"):
        discover.add_argument("--" + option, required=True)
    discover.add_argument(
        "--posture",
        action="store_true",
        help="Include sanitized pod-template security configuration findings; not runtime qualification",
    )
    rds = commands.add_parser(
        "discover-rds-security",
        help="Owner-only fixed RDS configuration reads; no SQL, Secret access or modifications",
    )
    rds.add_argument("--registration", required=True)
    rds.add_argument(
        "--aws-profile",
        help="Existing operator AWS profile; credentials are never accepted in registration JSON",
    )
    args = parser.parse_args(argv)
    try:
        now = datetime.now(timezone.utc)
        if args.command == "security-intake-plan":
            from sova.interfaces.security_intake import run as run_intake
            return run_intake(args, now)
        if args.command.startswith("security-program-"):
            from sova.interfaces.security_program import run
            return run(args, now)
        if args.command == "discover-rds-security":
            from sova.adapters.aws_security_codec import decode_rds_registration
            from sova.adapters.aws_rds_security import (
                RdsSecurityCollector,
                fixed_clients,
            )

            registration = decode_rds_registration(
                json_document(private_text(args.registration))
            )
            actor = "local-uid:" + str(os.geteuid())

            def authorize_rds(current_actor, current_registration, action):
                fresh = decode_rds_registration(
                    json_document(private_text(args.registration))
                )
                if (
                    current_actor != actor
                    or action != "security:rds-metadata-read"
                    or fresh != current_registration
                ):
                    raise ContractError("Local RDS operator registration changed")

            authorize_rds(actor, registration, "security:rds-metadata-read")
            registration.require_current(now)
            try:
                import boto3
            except ImportError as exc:
                raise ContractError(
                    "RDS discovery requires the AWS optional dependency"
                ) from exc

            def clients(reg):
                try:
                    return fixed_clients(
                        boto3.Session(profile_name=args.aws_profile), reg
                    )
                except Exception as exc:
                    raise ContractError(
                        "AWS operator reader could not be initialized"
                    ) from exc

            snapshot = RdsSecurityCollector(
                registration,
                clients=clients,
                authorize=authorize_rds,
                clock=lambda: datetime.now(timezone.utc),
                monotonic=time.monotonic,
            ).collect(actor=actor)
            print(json.dumps(snapshot.document, ensure_ascii=False, indent=2))
            return 0
        if args.command == "discover-kubernetes":
            registration = decode_registration(
                json_document(private_text(args.registration))
            )
            actor = "local-uid:" + str(os.geteuid())

            def authorize(current_actor, scope, action):
                current = decode_registration(
                    json_document(private_text(args.registration))
                )
                if (
                    current_actor != actor
                    or action != "inventory:read"
                    or current.fingerprint != scope.fingerprint
                ):
                    raise ContractError("Local operator registration changed")

            # No network or credential access before local authorization.
            authorize(actor, registration, "inventory:read")
            with Path(args.ca_file).open("rb") as ca_file:
                ca = ca_file.read(65537)
            if len(ca) > 65536:
                raise ContractError("CA file size limit exceeded")
            transport = KubernetesHTTPS(
                registration,
                ca_pem=ca,
                token_provider=lambda: private_text(
                    args.token_file, limit=16384
                ).strip(),
            )
            service = KubernetesDiscovery(
                registration,
                transport,
                authorize=authorize,
                clock=lambda: datetime.now(timezone.utc),
                projection=posture_projection if args.posture else None,
            )
            print(
                json.dumps(service.inspect(actor=actor), ensure_ascii=False, indent=2)
            )
            return 0
        if args.command == "example":
            print(json.dumps(example_graph(now).document, ensure_ascii=False, indent=2))
            return 0
        if args.command == "import-kubernetes":
            graph = snapshot_graph(
                read_document(args.snapshot),
                tenant_id=args.tenant,
                application_id=args.application,
                environment_id=args.environment,
                namespace=args.namespace,
                location=args.location,
                observed_at=now,
                valid_until=now + timedelta(hours=1),
            )
            print(json.dumps(graph.document, ensure_ascii=False, indent=2))
            return 0
        graph = decode_graph(read_document(args.registration))
        if args.command == "inspect":
            result = {
                "status": "valid-registration",
                "live_verified": False,
                "graph_digest": graph.fingerprint,
                "application_id": graph.application_id,
                "resources": len(graph.resources),
                "relations": len(graph.relations),
                "valid_until": graph.valid_until.isoformat(),
                "review_units": [list(g) for g in graph.movement_groups()],
            }
        else:
            result = assess_portability(
                graph,
                target_environment=args.target_environment,
                target_backend=args.target_backend,
                now=datetime.now(timezone.utc),
            )
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except (ContractError, OSError, ValueError):
        print(
            "Sova: invalid, expired or unreadable registration/assessment input",
            file=sys.stderr,
        )
        return 2
