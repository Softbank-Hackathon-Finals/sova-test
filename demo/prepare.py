"""Operator-only setup of a separate, bounded stateless AWS/VM preview.

No game resources, existing roles, DBs or routes are modified. No code from
uploaded projects is executed. Run using the existing operator Python venv.
"""

import argparse
import hashlib
import json
import os
import secrets
import subprocess
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import boto3

ROOT = Path(__file__).resolve().parents[1]
STATE = ROOT / ".local-notes" / "live-preview"
REFERENCE = ROOT.parent / "sky/.local-notes/validation/aws-vm-demo-20261030"
ACCOUNT, REGION = "265233844540", "ap-northeast-2"


def command(args, *, data=None):
    result = subprocess.run(
        args, input=data, capture_output=True, timeout=90, check=False
    )
    if result.returncode:
        raise RuntimeError("Operator command failed: " + result.stderr.decode()[-600:])
    return result.stdout.decode().strip()


def verified_subnet(ec2, subnet_id):
    """Operator-selected existing public subnet; never create or alter networking."""
    entries = ec2.describe_subnets(SubnetIds=[subnet_id])["Subnets"]
    if len(entries) != 1 or entries[0]["VpcId"] != "vpc-08a6d158760b6117a":
        raise ValueError("Preview subnet ownership boundary mismatch")
    tables = ec2.describe_route_tables(
        Filters=[{"Name": "vpc-id", "Values": [entries[0]["VpcId"]]}]
    )["RouteTables"]
    table = next(
        (
            t
            for t in tables
            if any(a.get("SubnetId") == subnet_id for a in t["Associations"])
        ),
        None,
    )
    if table is None:
        table = next(t for t in tables if any(a.get("Main") for a in t["Associations"]))
    if not any(
        r.get("DestinationCidrBlock") == "0.0.0.0/0"
        and r.get("GatewayId", "").startswith("igw-")
        and r.get("State") == "active"
        for r in table["Routes"]
    ):
        raise ValueError("Preview requires a verified existing public route")
    return subnet_id


def main(argv=None):
    global STATE
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--subnet-id", help="Existing subnet, required if reference task expired"
    )
    parser.add_argument("--until", help="Timezone-aware deadline, at most two hours")
    parser.add_argument("--state-root", type=Path, help="Separate private registration directory")
    args = parser.parse_args(argv)
    if args.state_root:
        selected = args.state_root.resolve()
        if not selected.is_relative_to((ROOT / ".local-notes").resolve()):
            parser.error("state root must be within private local notes")
        STATE = selected
    started = datetime.now(UTC)
    deadline = (
        datetime.fromisoformat(args.until)
        if args.until
        else started + timedelta(hours=2)
    )
    if deadline.tzinfo is None or not started + timedelta(
        minutes=5
    ) <= deadline <= started + timedelta(hours=2):
        parser.error("deadline must be 5 minutes to 2 hours from now")
    os.umask(0o077)
    STATE.mkdir(parents=True, exist_ok=True)
    path = STATE / "resources.json"
    if path.exists():
        raise RuntimeError(
            "Preview registration exists; inspect it rather than blindly replaying setup"
        )
    session = boto3.Session(profile_name="default", region_name=REGION)
    assert session.client("sts").get_caller_identity()["Account"] == ACCOUNT
    old = json.loads((REFERENCE / "source-app-resources.json").read_text())
    ec2, ecs, iam, sm = [
        session.client(n) for n in ("ec2", "ecs", "iam", "secretsmanager")
    ]
    if args.subnet_id:
        subnet = verified_subnet(ec2, args.subnet_id)
    else:
        tasks = ecs.describe_tasks(
            cluster="sky-personal-outbox", tasks=[old["task_arn"]]
        )["tasks"]
        if not tasks:
            raise ValueError("Reference task expired; select an existing --subnet-id")
        eni_id = next(
            d["value"]
            for a in tasks[0]["attachments"]
            for d in a["details"]
            if d["name"] == "networkInterfaceId"
        )
        subnet = verified_subnet(
            ec2,
            ec2.describe_network_interfaces(NetworkInterfaceIds=[eni_id])[
                "NetworkInterfaces"
            ][0]["SubnetId"],
        )
    command(
        [
            "limactl",
            "shell",
            "sky-vm",
            "--",
            "sudo",
            "docker",
            "image",
            "inspect",
            old["local_image_id"],
        ]
    )
    run = secrets.token_hex(6)
    name = "sova-probe-" + run
    code = (ROOT / "preview/workload.py").read_text()
    revision = hashlib.sha256(code.encode()).hexdigest()
    state = {
        "run_id": run,
        "name": name,
        "account": ACCOUNT,
        "region": REGION,
        "revision": revision,
        "image": old["image_uri"],
        "local_image": old["local_image_id"],
        "created_at": datetime.now(UTC).isoformat(),
        "expires_at": deadline.isoformat(),
        "subnet_id": subnet,
        "steps": [],
        "cluster": "sky-personal-outbox",
        "scope": "stateless HTTPS request routing; no DB migration",
    }

    def save(step):
        state["steps"].append(step)
        temporary = path.with_suffix(".next")
        temporary.write_text(json.dumps(state, indent=2))
        temporary.replace(path)

    save("intent_prepare_owned_preview")
    command(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "3",
            "-subj",
            "/CN=Sova preview CA",
            "-keyout",
            str(STATE / "ca.key"),
            "-out",
            str(STATE / "ca.pem"),
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
        ]
    )
    configs = {}
    for side in ("aws", "vm"):
        host = side + ".sova.test"
        command(
            [
                "openssl",
                "req",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-subj",
                "/CN=" + host,
                "-keyout",
                str(STATE / (side + ".key")),
                "-out",
                str(STATE / (side + ".csr")),
            ]
        )
        ext = STATE / (side + ".ext")
        ext.write_text(
            "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\nsubjectAltName=DNS:"
            + host
            + "\n"
        )
        command(
            [
                "openssl",
                "x509",
                "-req",
                "-in",
                str(STATE / (side + ".csr")),
                "-CA",
                str(STATE / "ca.pem"),
                "-CAkey",
                str(STATE / "ca.key"),
                "-CAcreateserial",
                "-days",
                "3",
                "-extfile",
                str(ext),
                "-out",
                str(STATE / (side + ".pem")),
            ]
        )
        configs[side] = {
            "environment": side,
            "instance": name + "-" + side,
            "revision": revision,
            "run_id": run,
            "expires_at": deadline.isoformat(),
            "cert": (STATE / (side + ".pem")).read_text(),
            "key": (STATE / (side + ".key")).read_text(),
        }
    tags = [
        {"Key": "sova-preview", "Value": run},
        {"Key": "purpose", "Value": "stateless-workload-map"},
    ]
    ec2, ecs, iam, sm = [
        session.client(n) for n in ("ec2", "ecs", "iam", "secretsmanager")
    ]
    secret = sm.create_secret(
        Name=name, SecretString=json.dumps(configs["aws"]), Tags=tags
    )
    state["secret_arn"] = secret["ARN"]
    save("own_tls_secret_created")
    repository = old["repository_arn"]
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "ecr:GetAuthorizationToken", "Resource": "*"},
            {
                "Effect": "Allow",
                "Action": [
                    "ecr:BatchCheckLayerAvailability",
                    "ecr:GetDownloadUrlForLayer",
                    "ecr:BatchGetImage",
                ],
                "Resource": repository,
            },
            {
                "Effect": "Allow",
                "Action": "secretsmanager:GetSecretValue",
                "Resource": state["secret_arn"],
            },
        ],
    }
    boundary = iam.create_policy(
        PolicyName=name, PolicyDocument=json.dumps(policy), Tags=tags
    )
    state["boundary_arn"] = boundary["Policy"]["Arn"]
    save("execution_boundary_created")
    role = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "ecs-tasks.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                        "Condition": {
                            "StringEquals": {"aws:SourceAccount": ACCOUNT},
                            "ArnLike": {
                                "aws:SourceArn": f"arn:aws:ecs:{REGION}:{ACCOUNT}:*"
                            },
                        },
                    }
                ],
            }
        ),
        PermissionsBoundary=state["boundary_arn"],
        Tags=tags,
    )
    state["role_arn"] = role["Role"]["Arn"]
    save("bounded_execution_role_created")
    iam.put_role_policy(
        RoleName=name,
        PolicyName="only-own-probe-image-and-tls",
        PolicyDocument=json.dumps(policy),
    )
    save("bounded_execution_role_created_no_app_role")
    group = ec2.create_security_group(
        GroupName=name,
        Description="Own Sova HTTPS probe; bastion only",
        VpcId="vpc-08a6d158760b6117a",
        TagSpecifications=[{"ResourceType": "security-group", "Tags": tags}],
    )
    state["security_group"] = group["GroupId"]
    save("own_security_group_created")
    ec2.authorize_security_group_ingress(
        GroupId=state["security_group"],
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 8443,
                "ToPort": 8443,
                "UserIdGroupPairs": [{"GroupId": "sg-0ced6f1f02aa791c5"}],
            }
        ],
    )
    ec2.revoke_security_group_egress(
        GroupId=state["security_group"],
        IpPermissions=[{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
    )
    # Existing runtime SG supplies outbound image/Secret access; its rules are unchanged.
    rule = ec2.authorize_security_group_egress(
        GroupId="sg-0ced6f1f02aa791c5",
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 8443,
                "ToPort": 8443,
                "UserIdGroupPairs": [
                    {"GroupId": state["security_group"], "Description": name}
                ],
            }
        ],
    )
    state["bastion_rule_ids"] = [
        v["SecurityGroupRuleId"] for v in rule["SecurityGroupRules"]
    ]
    save("bastion_only_tls_path_created")
    definition = ecs.register_task_definition(
        family=name,
        networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"],
        cpu="256",
        memory="512",
        executionRoleArn=state["role_arn"],
        runtimePlatform={"cpuArchitecture": "ARM64", "operatingSystemFamily": "LINUX"},
        containerDefinitions=[
            {
                "name": "probe",
                "image": state["image"],
                "essential": True,
                "user": "10001:10001",
                "readonlyRootFilesystem": True,
                "linuxParameters": {"capabilities": {"drop": ["ALL"]}},
                "portMappings": [{"containerPort": 8443, "protocol": "tcp"}],
                "entryPoint": ["python", "-u", "-c"],
                "command": [code],
                "secrets": [
                    {"name": "SOVA_PROBE_CONFIG", "valueFrom": state["secret_arn"]}
                ],
            }
        ],
        tags=[{"key": t["Key"], "value": t["Value"]} for t in tags],
    )
    state["task_definition"] = definition["taskDefinition"]["taskDefinitionArn"]
    save("stateless_task_definition_registered")
    print("Own AWS preview prepared; waiting for role propagation", flush=True)
    time.sleep(12)
    result = ecs.run_task(
        cluster=state["cluster"],
        taskDefinition=state["task_definition"],
        launchType="FARGATE",
        count=1,
        clientToken=run,
        networkConfiguration={
            "awsvpcConfiguration": {
                "subnets": [subnet],
                "securityGroups": [state["security_group"], "sg-00167b37ffaf6979c"],
                "assignPublicIp": "ENABLED",
            }
        },
        tags=[{"key": t["Key"], "value": t["Value"]} for t in tags],
    )
    if result.get("failures") or len(result.get("tasks", [])) != 1:
        raise RuntimeError(
            "Own preview task not admitted; inspect resources before retry"
        )
    state["task_arn"] = result["tasks"][0]["taskArn"]
    save("own_task_requested")
    # The VM uses exactly the same base image and source code; no new pull/build.
    volume = name + "-config"
    state["vm_volume"] = volume
    state["vm_container_name"] = name
    save("own_vm_prepare_intent")
    command(
        [
            "limactl",
            "shell",
            "sky-vm",
            "--",
            "sudo",
            "docker",
            "volume",
            "create",
            "--label",
            "sova-preview=" + run,
            volume,
        ]
    )
    # Deliver only this probe's config through stdin. No game config is mounted.
    loader = "import sys,pathlib,os;p=pathlib.Path('/config/config.json');p.write_bytes(sys.stdin.buffer.read());os.chmod(p,0o400);os.chown(p,10001,10001)"
    command(
        [
            "limactl",
            "shell",
            "sky-vm",
            "--",
            "sudo",
            "docker",
            "run",
            "--rm",
            "-i",
            "--network",
            "none",
            "--cap-drop",
            "ALL",
            "--cap-add",
            "CHOWN",
            "--user",
            "0",
            "--mount",
            "type=volume,src=" + volume + ",dst=/config",
            "--entrypoint",
            "python",
            state["local_image"],
            "-c",
            loader,
        ],
        data=json.dumps(configs["vm"]).encode(),
    )
    start = (
        "import os,json;os.environ['SOVA_PROBE_CONFIG']=open('/config/config.json').read();"
        + code.replace('if __name__ == "__main__":', "if True:")
    )
    container = command(
        [
            "limactl",
            "shell",
            "sky-vm",
            "--",
            "sudo",
            "docker",
            "run",
            "-d",
            "--name",
            name,
            "--label",
            "sova-preview=" + run,
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--user",
            "10001:10001",
            "--memory",
            "96m",
            "--cpus",
            "0.25",
            "--pids-limit",
            "32",
            "-p",
            "127.0.0.1::8443",
            "--mount",
            "type=volume,src=" + volume + ",dst=/config,readonly",
            "--entrypoint",
            "python",
            state["local_image"],
            "-u",
            "-c",
            start,
        ]
    )
    state.update(vm_container=container, vm_volume=volume)
    save("own_vm_probe_started")
    print("Own VM probe started; waiting for AWS RUNNING", flush=True)
    for _ in range(100):
        task = ecs.describe_tasks(
            cluster=state["cluster"], tasks=[state["task_arn"]], include=["TAGS"]
        )["tasks"][0]
        if task["lastStatus"] == "STOPPED":
            raise RuntimeError(
                "Own task stopped: " + task.get("stoppedReason", "unknown")
            )
        if task["lastStatus"] == "RUNNING":
            eni_id = next(
                d["value"]
                for a in task["attachments"]
                for d in a["details"]
                if d["name"] == "networkInterfaceId"
            )
            state["private_ip"] = ec2.describe_network_interfaces(
                NetworkInterfaceIds=[eni_id]
            )["NetworkInterfaces"][0]["PrivateIpAddress"]
            save("aws_running")
            print("Sova preview registration ready", flush=True)
            return
        time.sleep(3)
    raise TimeoutError("Task readiness unknown; inspect before retry")


if __name__ == "__main__":
    main()
