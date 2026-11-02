"""Fault-injection tests. No real AWS mutation or tunnel is used here."""

import copy
import http.client
import json
import ssl
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import Mock

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from security import PreviewIngress
from server import Console


class FakeBoundary:
    def __init__(self):
        self.blocked = False
        self.calls = []

    def read(self):
        return {"blocked": self.blocked, "task_running": True, "binding_verified": True}

    def set_blocked(self, value):
        self.calls.append(value)
        self.blocked = value
        return self.read()


@pytest.fixture
def console(tmp_path):
    boundary = FakeBoundary()
    config = {
        "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
        "name": "test-probe",
        "revision": "a" * 64,
        "run_id": "test-run",
        "account": "test-account",
        "security_group": "test-owned-ingress",
    }
    obj = Console(
        config,
        {"aws": 1, "vm": 2},
        network=boundary,
        database=tmp_path / "state.sqlite",
        start_collector=False,
        tls_context=ssl.create_default_context(),
    )

    def remote(side, *, request_id=None, message=None):
        if side == "aws" and boundary.blocked:
            raise TimeoutError("controlled blocked connection")
        return {
            "environment": side,
            "instance": "test-" + side,
            "revision": "a" * 64,
            "request_id": request_id,
            "message": message,
        }, 1.0

    obj.remote = Mock(side_effect=remote)
    obj.controlled_denial = Mock(
        return_value={"type": "controlled_security_test", "status_code": 404}
    )
    yield obj
    obj.db.close()


def start(console, kind="security_drill"):
    labels = (
        [
            ("scope", "scope"),
            ("signal", "signal"),
            ("standby", "standby"),
            ("isolate", "isolate"),
            ("blocked", "blocked"),
            ("route", "route"),
            ("verify", "verify"),
        ]
        if kind == "security_drill"
        else [("scope", "scope"), ("restore", "restore"), ("verify", "verify")]
    )
    return console.begin_workflow(
        kind, "vm" if kind == "security_drill" else "aws", labels
    )


def test_real_boundary_effect_is_required_before_declaring_isolation(console):
    operation = start(console)
    console.execute_security(operation, "drill")
    assert console.network.calls == [True]
    assert console.security["probe_blocked"] and console.route == "vm"
    assert console.last_operation["status"] == "succeeded"
    assert all(
        s["status"] == "succeeded" and s.get("evidence")
        for s in console.last_operation["steps"]
    )
    assert console.last_operation["steps"][4]["evidence"][
        "new_https_connection_blocked"
    ]
    with pytest.raises(ValueError, match="명시적으로"):
        console.switch("aws")


def test_failed_standby_never_changes_ingress_or_route(console):
    original = console.remote.side_effect

    def fail_vm(side, **kwargs):
        if side == "vm":
            raise ValueError("revision differs")
        return original(side, **kwargs)

    console.remote.side_effect = fail_vm
    console.execute_security(start(console), "drill")
    assert console.network.calls == [] and console.route == "aws"
    assert console.security["state"] == "needs_attention"
    assert [s["status"] for s in console.last_operation["steps"]] == [
        "succeeded",
        "succeeded",
        "failed",
        "blocked",
        "blocked",
        "blocked",
        "blocked",
    ]


def test_rule_change_without_failed_connection_is_not_isolation(console):
    console.remote.side_effect = lambda side, **kw: (
        {
            "environment": side,
            "instance": "test",
            "revision": "a" * 64,
            "request_id": kw.get("request_id"),
        },
        1,
    )
    console.execute_security(start(console), "drill")
    assert console.network.blocked and console.route == "aws"
    assert (
        console.security["state"] == "needs_attention"
        and not console.security["probe_blocked"]
    )
    assert console.last_operation["steps"][4]["status"] == "failed"


@pytest.mark.parametrize(
    "error",
    [
        ssl.SSLCertVerificationError("unexpected certificate"),
        ssl.SSLError("TLS negotiation failed"),
        http.client.RemoteDisconnected("HTTP peer closed connection"),
        ConnectionResetError("reset does not prove ingress denial"),
    ],
)
def test_tls_or_application_failure_does_not_prove_isolation(console, error):
    original = console.remote.side_effect

    def uncertain(side, **kwargs):
        if side == "aws" and console.network.blocked:
            raise error
        return original(side, **kwargs)

    console.remote.side_effect = uncertain
    console.execute_security(start(console), "drill")
    assert console.network.calls == [True]
    assert console.route == "aws"
    assert console.security["state"] == "needs_attention"
    assert not console.security["probe_blocked"]
    assert console.last_operation["steps"][4]["status"] == "failed"
    assert (
        console.last_operation["steps"][4]["evidence"]["error_type"]
        == type(error).__name__
    )


def test_expired_registration_rejects_requests_and_changes_before_effects(console):
    console.config["expires_at"] = (
        datetime.now(UTC) - timedelta(seconds=1)
    ).isoformat()
    with pytest.raises(ValueError, match="만료"):
        console.action("expired")
    with pytest.raises(ValueError, match="만료"):
        console.switch("vm")
    with pytest.raises(ValueError, match="만료"):
        console.security_action("drill")
    assert console.remote.call_count == 0
    assert console.network.calls == []
    assert console.db.execute("SELECT count(*) FROM workflows").fetchone()[0] == 0
    assert console.db.execute("SELECT count(*) FROM requests").fetchone()[0] == 0


def test_restore_is_explicit_and_does_not_automatically_route_back(console):
    console.execute_security(start(console), "drill")
    console.execute_security(start(console, "security_restore"), "restore")
    assert console.network.calls == [True, False]
    assert console.security["state"] == "normal" and console.route == "vm"
    assert console.last_operation["status"] == "succeeded"


def test_restore_waits_for_readonly_connectivity_without_repeating_effect(console):
    operation = start(console, "security_restore")
    original = console.remote.side_effect
    reads = 0

    def delayed(side, **kwargs):
        nonlocal reads
        if not kwargs.get("request_id"):
            reads += 1
            if reads < 3:
                raise TimeoutError("SG data path not ready")
        return original(side, **kwargs)

    console.remote.side_effect = delayed
    result = console.verify_restored(operation, pause=0)
    assert [c["result"] for c in result["connection_checks"]] == [
        "transport_not_ready",
        "transport_not_ready",
        "https_identity_verified",
    ]
    assert console.network.calls == []
    assert (
        sum(bool(c.kwargs.get("request_id")) for c in console.remote.call_args_list)
        == 1
    )


def test_restore_readiness_has_a_finite_attempt_budget(console):
    operation = start(console, "security_restore")
    console.remote.side_effect = TimeoutError("still blocked")
    with pytest.raises(RuntimeError, match="bounded checks"):
        console.verify_restored(operation, pause=0)
    assert console.remote.call_count == 4 and console.network.calls == []
    assert all(not c.kwargs.get("request_id") for c in console.remote.call_args_list)


def test_restore_never_retries_a_certificate_mismatch(console):
    operation = start(console, "security_restore")
    console.remote.side_effect = ssl.SSLCertVerificationError("wrong certificate")
    with pytest.raises(ssl.SSLCertVerificationError):
        console.verify_restored(operation, pause=0)
    assert console.remote.call_count == 1 and console.network.calls == []


def test_unknown_application_post_is_not_replayed(console):
    operation = start(console, "security_restore")
    original = console.remote.side_effect

    def uncertain(side, **kwargs):
        if kwargs.get("request_id"):
            raise TimeoutError("POST outcome unknown")
        return original(side, **kwargs)

    console.remote.side_effect = uncertain
    with pytest.raises(TimeoutError):
        console.verify_restored(operation, pause=0)
    assert console.remote.call_count == 2
    assert (
        sum(bool(c.kwargs.get("request_id")) for c in console.remote.call_args_list)
        == 1
    )


def test_effect_response_loss_preserves_unknown_result(console):
    def unknown(value):
        console.network.blocked = value
        raise RuntimeError("lost effect response")

    console.network.set_blocked = unknown
    console.execute_security(start(console), "drill")
    assert console.network.blocked and console.route == "aws"
    assert console.last_operation["status"] == "needs_attention"
    assert console.security["state"] == "needs_attention"


def test_conflicting_workflows_cannot_both_start(console):
    start(console)
    with pytest.raises(RuntimeError):
        start(console)
    assert console.db.execute("SELECT count(*) FROM workflows").fetchone()[0] == 1


def test_pending_step_survives_restart_as_attention(console):
    op = start(console)
    console.step(op, "scope", console.network.read)
    assert (
        json.loads(console.db.execute("SELECT steps FROM workflows").fetchone()[0])[0][
            "status"
        ]
        == "succeeded"
    )
    second = Console(
        console.config,
        console.ports,
        network=FakeBoundary(),
        database=console.db.execute("PRAGMA database_list").fetchone()[2],
        start_collector=False,
        tls_context=ssl.create_default_context(),
    )
    try:
        assert second.last_operation["status"] == "needs_attention"
        assert second.network.calls == [] and second.operation is None
    finally:
        second.db.close()


def registered_network():
    n = PreviewIngress.__new__(PreviewIngress)
    n.config = {
        "account": "123",
        "security_group": "owned",
        "run_id": "run",
        "name": "owned-name",
        "cluster": "cluster",
        "task_arn": "task",
        "task_definition": "definition",
        "private_ip": "10.0.0.1",
    }
    n.peer = "peer"
    rule = {
        "IpProtocol": "tcp",
        "FromPort": 8443,
        "ToPort": 8443,
        "UserIdGroupPairs": [{"GroupId": "peer", "UserId": "123"}],
        "IpRanges": [],
        "Ipv6Ranges": [],
        "PrefixListIds": [],
    }
    groups = [
        {
            "GroupId": "owned",
            "GroupName": "owned-name",
            "VpcId": "vpc-08a6d158760b6117a",
            "Tags": [{"Key": "sova-preview", "Value": "run"}],
            "IpPermissions": [rule],
        },
        {"GroupId": "sg-00167b37ffaf6979c", "IpPermissions": []},
    ]
    n.sts = Mock()
    n.sts.get_caller_identity.return_value = {"Account": "123"}
    n.ec2 = Mock()
    n.ec2.describe_security_groups.side_effect = lambda **kw: {
        "SecurityGroups": copy.deepcopy(groups)
    }
    n.ec2.describe_network_interfaces.return_value = {
        "NetworkInterfaces": [
            {
                "PrivateIpAddress": "10.0.0.1",
                "Groups": [{"GroupId": "owned"}, {"GroupId": "sg-00167b37ffaf6979c"}],
            }
        ]
    }
    n.ecs = Mock()
    n.ecs.describe_tasks.return_value = {
        "tasks": [
            {
                "lastStatus": "RUNNING",
                "taskDefinitionArn": "definition",
                "tags": [{"key": "sova-preview", "value": "run"}],
                "attachments": [
                    {"details": [{"name": "networkInterfaceId", "value": "eni"}]}
                ],
            }
        ]
    }
    return n, groups


@pytest.mark.parametrize(
    "tamper", ["account", "owner", "alternate_ingress", "public_rule", "task", "eni"]
)
def test_resource_binding_tampering_never_mutates_rules(tamper):
    n, groups = registered_network()
    if tamper == "account":
        n.sts.get_caller_identity.return_value = {"Account": "other"}
    if tamper == "owner":
        groups[0]["Tags"] = []
    if tamper == "alternate_ingress":
        groups[1]["IpPermissions"] = [{"IpProtocol": "-1"}]
    if tamper == "public_rule":
        groups[0]["IpPermissions"][0]["IpRanges"] = [{"CidrIp": "0.0.0.0/0"}]
    if tamper == "task":
        n.ecs.describe_tasks.return_value["tasks"][0]["taskDefinitionArn"] = "other"
    if tamper == "eni":
        n.ec2.describe_network_interfaces.return_value["NetworkInterfaces"][0][
            "Groups"
        ] = []
    with pytest.raises(PermissionError):
        n.set_blocked(True)
    n.ec2.revoke_security_group_ingress.assert_not_called()
    n.ec2.authorize_security_group_ingress.assert_not_called()
