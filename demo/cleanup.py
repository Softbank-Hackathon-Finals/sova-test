"""Inspect by default; --execute retires only this preview's registered resources."""

import argparse
import json
import os
import signal
import subprocess
import time
from pathlib import Path

import boto3

ROOT = Path(__file__).resolve().parents[1]
STATE = ROOT / ".local-notes/live-preview"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()
    r = json.loads((STATE / "resources.json").read_text())
    if not args.execute:
        print(
            json.dumps(
                {
                    "mode": "inspect_only",
                    "name": r["name"],
                    "expires_at": r["expires_at"],
                    "resources": [
                        "one Fargate task",
                        "one VM container/config volume",
                        "one TLS Secret",
                        "one execution role/boundary",
                        "one SG and exact bastion rule",
                    ],
                    "game_or_db_resources": False,
                },
                indent=2,
            )
        )
        return
    session = boto3.Session(profile_name="default", region_name=r["region"])
    assert session.client("sts").get_caller_identity()["Account"] == r["account"]
    ecs, ec2, iam, sm = [
        session.client(n) for n in ("ecs", "ec2", "iam", "secretsmanager")
    ]
    task = ecs.describe_tasks(
        cluster=r["cluster"], tasks=[r["task_arn"]], include=["TAGS"]
    )["tasks"][0]
    assert {t["key"]: t["value"] for t in task["tags"]}.get("sova-preview") == r[
        "run_id"
    ]
    assert task["taskDefinitionArn"] == r["task_definition"]
    role = iam.get_role(RoleName=r["name"])["Role"]
    assert (
        role["Arn"] == r["role_arn"]
        and {t["Key"]: t["Value"] for t in role["Tags"]}.get("sova-preview")
        == r["run_id"]
    )
    assert role["PermissionsBoundary"]["PermissionsBoundaryArn"] == r["boundary_arn"]
    secret = sm.describe_secret(SecretId=r["secret_arn"])
    assert {t["Key"]: t["Value"] for t in secret["Tags"]}.get("sova-preview") == r[
        "run_id"
    ]
    group = ec2.describe_security_groups(GroupIds=[r["security_group"]])[
        "SecurityGroups"
    ][0]
    assert {t["Key"]: t["Value"] for t in group["Tags"]}.get("sova-preview") == r[
        "run_id"
    ]
    for rule in ec2.describe_security_group_rules(
        SecurityGroupRuleIds=r["bastion_rule_ids"]
    )["SecurityGroupRules"]:
        assert (
            rule["GroupId"] == "sg-0ced6f1f02aa791c5"
            and rule["IsEgress"]
            and rule["ReferencedGroupInfo"]["GroupId"] == r["security_group"]
        )
    vm_info = subprocess.run(
        [
            "limactl",
            "shell",
            "sky-vm",
            "--",
            "sudo",
            "docker",
            "inspect",
            r["vm_container"],
        ],
        capture_output=True,
        text=True,
        check=True,
        timeout=20,
    )
    container = json.loads(vm_info.stdout)[0]
    assert (
        container["Config"]["Labels"]["sova-preview"] == r["run_id"]
        and container["Image"] == r["local_image"]
    )
    pid_file = STATE / "server.pid"
    if pid_file.exists():
        pid = int(pid_file.read_text())
        process = subprocess.run(
            ["ps", "-p", str(pid), "-o", "command="],
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )
        if process.returncode == 0:
            assert "preview/server.py" in process.stdout
            cwd = subprocess.run(
                ["lsof", "-a", "-p", str(pid), "-d", "cwd", "-Fn"],
                capture_output=True,
                text=True,
                check=True,
                timeout=5,
            ).stdout
            assert "n" + str(ROOT) + "\n" in cwd
            os.kill(pid, signal.SIGTERM)
    if task["lastStatus"] != "STOPPED":
        ecs.stop_task(
            cluster=r["cluster"],
            task=r["task_arn"],
            reason="Sova stateless preview retired by operator",
        )
    subprocess.run(
        [
            "limactl",
            "shell",
            "sky-vm",
            "--",
            "sudo",
            "docker",
            "rm",
            "-f",
            r["vm_container"],
        ],
        check=True,
        capture_output=True,
        timeout=30,
    )
    subprocess.run(
        [
            "limactl",
            "shell",
            "sky-vm",
            "--",
            "sudo",
            "docker",
            "volume",
            "rm",
            r["vm_volume"],
        ],
        check=True,
        capture_output=True,
        timeout=30,
    )
    ec2.revoke_security_group_egress(
        GroupId="sg-0ced6f1f02aa791c5", SecurityGroupRuleIds=r["bastion_rule_ids"]
    )
    ecs.deregister_task_definition(taskDefinition=r["task_definition"])
    sm.delete_secret(SecretId=r["secret_arn"], RecoveryWindowInDays=7)
    iam.delete_role_policy(
        RoleName=r["name"], PolicyName="only-own-probe-image-and-tls"
    )
    iam.delete_role_permissions_boundary(RoleName=r["name"])
    iam.delete_role(RoleName=r["name"])
    iam.delete_policy(PolicyArn=r["boundary_arn"])
    for _ in range(30):
        interfaces = ec2.describe_network_interfaces(
            Filters=[{"Name": "group-id", "Values": [r["security_group"]]}]
        )["NetworkInterfaces"]
        if not interfaces:
            ec2.delete_security_group(GroupId=r["security_group"])
            break
        time.sleep(3)
    else:
        raise RuntimeError(
            "Task ENI still detaching; verify then delete only the registered preview SG"
        )
    (STATE / "cleanup-receipt.json").write_text(
        json.dumps(
            {
                "status": "retired",
                "run_id": r["run_id"],
                "at": time.time(),
                "secret_recovery_days": 7,
                "evidence_retained": True,
            }
        )
    )
    print("Sova preview retired. Game, DB, base image and evidence preserved.")


if __name__ == "__main__":
    main()
