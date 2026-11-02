"""An exact, owned preview ingress boundary, not a generic cloud command API."""

import boto3


class PreviewIngress:
    def __init__(self, config):
        self.config = config
        session = boto3.Session(profile_name="default", region_name=config["region"])
        self.sts = session.client("sts")
        self.ec2 = session.client("ec2")
        self.ecs = session.client("ecs")
        self.peer = "sg-0ced6f1f02aa791c5"

    def read(self):
        c = self.config
        if self.sts.get_caller_identity()["Account"] != c["account"]:
            raise PermissionError("Preview account changed")
        groups = self.ec2.describe_security_groups(
            GroupIds=[c["security_group"], "sg-00167b37ffaf6979c"]
        )["SecurityGroups"]
        group = next(g for g in groups if g["GroupId"] == c["security_group"])
        shared = next(g for g in groups if g["GroupId"] != c["security_group"])
        if shared["IpPermissions"]:
            raise PermissionError("An alternate ingress path exists")
        if (
            group["GroupName"] != c["name"]
            or group["VpcId"] != "vpc-08a6d158760b6117a"
            or {t["Key"]: t["Value"] for t in group.get("Tags", [])}.get("sova-preview")
            != c["run_id"]
        ):
            raise PermissionError("Preview ownership changed")
        task = self.ecs.describe_tasks(
            cluster=c["cluster"], tasks=[c["task_arn"]], include=["TAGS"]
        )["tasks"][0]
        if (
            task["lastStatus"] != "RUNNING"
            or task["taskDefinitionArn"] != c["task_definition"]
            or {t["key"]: t["value"] for t in task.get("tags", [])}.get("sova-preview")
            != c["run_id"]
        ):
            raise PermissionError("Preview task binding changed")
        eni_id = next(
            d["value"]
            for a in task["attachments"]
            for d in a["details"]
            if d["name"] == "networkInterfaceId"
        )
        eni = self.ec2.describe_network_interfaces(NetworkInterfaceIds=[eni_id])[
            "NetworkInterfaces"
        ][0]
        if eni["PrivateIpAddress"] != c["private_ip"] or {
            g["GroupId"] for g in eni["Groups"]
        } != {c["security_group"], shared["GroupId"]}:
            raise PermissionError("Preview network binding changed")
        permissions = group["IpPermissions"]
        if permissions:
            if len(permissions) != 1:
                raise PermissionError("Unexpected preview ingress")
            rule = permissions[0]
            if (
                rule["IpProtocol"] != "tcp"
                or rule["FromPort"] != 8443
                or rule["ToPort"] != 8443
                or rule.get("IpRanges")
                or rule.get("Ipv6Ranges")
                or rule.get("PrefixListIds")
                or len(rule["UserIdGroupPairs"]) != 1
                or rule["UserIdGroupPairs"][0]["GroupId"] != self.peer
                or rule["UserIdGroupPairs"][0]["UserId"] != c["account"]
            ):
                raise PermissionError("Unexpected preview ingress")
        return {
            "blocked": not bool(permissions),
            "task_running": True,
            "binding_verified": True,
            "scope": "Sova 전용 AWS 앱 TCP8443 유입만",
        }

    def set_blocked(self, blocked):
        before = self.read()
        if before["blocked"] == blocked:
            return before
        permission = {
            "IpProtocol": "tcp",
            "FromPort": 8443,
            "ToPort": 8443,
            "UserIdGroupPairs": [{"GroupId": self.peer}],
        }
        method = (
            self.ec2.revoke_security_group_ingress
            if blocked
            else self.ec2.authorize_security_group_ingress
        )
        method(GroupId=self.config["security_group"], IpPermissions=[permission])
        after = self.read()
        if after["blocked"] != blocked:
            raise RuntimeError("Ingress result requires reconciliation")
        return after
