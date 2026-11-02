"""Real AWS SDK request/response contract via Stubber; no AWS account calls."""

from copy import deepcopy
from dataclasses import replace
from datetime import timedelta
import boto3
from botocore.stub import Stubber
import pytest
from sova.domain.aws_security import RdsReadRegistration
from sova.domain.contracts import ContractError, ResourceScope
from sova.adapters.aws_rds_security import RdsSecurityCollector, VERIFIER
from sova.domain.protection_parity import (
    ProtectionEndpoint,
    ProtectionRequirement,
    ProtectionPolicy,
    Availability,
)
from sova.domain.governance import ControlFamily
from sova.adapters.aws_security_codec import decode_rds_registration


@pytest.fixture
def rds_case(now):
    account = "123456789012"
    region = "ap-northeast-2"
    arn = f"arn:aws:rds:{region}:{account}:db:orders"
    scope = ResourceScope("tenant-a", "orders", "aws-prod", arn)
    reg = RdsReadRegistration(
        scope,
        account,
        region,
        "db-immutable-identity",
        7,
        1,
        now,
        now + timedelta(minutes=5),
    )
    clients = {
        name: boto3.client(
            name,
            region_name=region,
            aws_access_key_id="test-only",
            aws_secret_access_key="test-only",
        )
        for name in ("rds", "sts")
    }
    stubs = {name: Stubber(client) for name, client in clients.items()}
    db = {
        "DBInstanceArn": arn,
        "DBInstanceIdentifier": "orders",
        "DbiResourceId": reg.immutable_resource_id,
        "Engine": "postgres",
        "StorageEncrypted": True,
        "BackupRetentionPeriod": 7,
        "PubliclyAccessible": False,
        "DeletionProtection": True,
        "EnabledCloudwatchLogsExports": ["postgresql"],
        "MultiAZ": True,
        "DBInstanceStatus": "available",
        "MasterUsername": "canary-secret-do-not-persist",
        "Endpoint": {"Address": "private.canary.example", "Port": 5432},
        "PendingModifiedValues": {},
    }
    tags = [
        {"Key": k, "Value": v}
        for k, v in {
            "sova:managed-by": "sova",
            "sova:tenant-id": scope.tenant_id,
            "sova:application-id": scope.application_id,
        }.items()
    ]
    yield reg, clients, stubs, db, tags
    for stub in stubs.values():
        stub.deactivate()


def run_case(
    case,
    now,
    *,
    account=None,
    db=None,
    tags=None,
    authorize=lambda *_: None,
    clock=None,
):
    reg, clients, stubs, default_db, default_tags = case
    stubs["sts"].add_response(
        "get_caller_identity",
        {
            "Account": account or reg.account_id,
            "Arn": "arn:aws:iam::" + reg.account_id + ":role/test-reader",
            "UserId": "test",
        },
    )
    if account is None:
        stubs["rds"].add_response(
            "describe_db_instances",
            {"DBInstances": [db or default_db]},
            {"DBInstanceIdentifier": reg.scope.resource_id},
        )
        if (db or default_db).get("DbiResourceId") == reg.immutable_resource_id:
            stubs["rds"].add_response(
                "list_tags_for_resource",
                {"TagList": tags if tags is not None else default_tags},
                {"ResourceName": reg.scope.resource_id},
            )
    for stub in stubs.values():
        stub.activate()
    collector = RdsSecurityCollector(
        reg,
        clients=lambda _: clients,
        authorize=authorize,
        clock=clock or (lambda: now),
        monotonic=lambda: 0,
    )
    return collector.collect(actor="registered-reader")


def test_sdk_exact_resource_reads_produce_only_sanitized_configuration(rds_case, now):
    result = run_case(rds_case, now)
    assert all(v == "pass" for v in result.checks.values())
    assert "canary" not in str(result.document) and "MasterUsername" not in str(
        result.document
    )
    assert (
        "tls-enforcement" in result.document["unverified"]
        and "restore-test" in result.document["unverified"]
    )
    assert result.document["basis"] == "configuration_only"


def test_wrong_account_prevents_rds_calls_and_recreated_instance_rejected(
    rds_case, now
):
    with pytest.raises(ContractError, match="account"):
        run_case(rds_case, now, account="999999999999")
    reg, _, stubs, db, _ = rds_case
    stubs["rds"].assert_no_pending_responses()


def test_immutable_id_not_name_is_registered_identity(rds_case, now):
    db = {**rds_case[3], "DbiResourceId": "db-recreated"}
    with pytest.raises(ContractError, match="replaced"):
        run_case(rds_case, now, db=db)


@pytest.mark.parametrize(
    "field,value,control,expected",
    [
        ("StorageEncrypted", False, "storage-encryption", "fail"),
        ("BackupRetentionPeriod", 0, "backup-retention", "fail"),
        ("PubliclyAccessible", True, "private-endpoint", "fail"),
        ("DeletionProtection", False, "deletion-protection", "fail"),
        ("EnabledCloudwatchLogsExports", [], "postgres-log-export", "fail"),
        ("MultiAZ", False, "multi-az-configuration", "fail"),
    ],
)
def test_declared_protection_failure_is_not_suitable(
    field, value, control, expected, rds_case, now
):
    result = run_case(rds_case, now, db={**rds_case[3], field: value})
    assert result.checks[control] == expected


@pytest.mark.parametrize(
    "field",
    [
        "StorageEncrypted",
        "BackupRetentionPeriod",
        "PubliclyAccessible",
        "DeletionProtection",
        "EnabledCloudwatchLogsExports",
        "MultiAZ",
        "PendingModifiedValues",
        "DBInstanceStatus",
    ],
)
def test_missing_metadata_is_unknown_not_default_pass(field, rds_case, now):
    db = deepcopy(rds_case[3])
    db.pop(field)
    assert "unknown" in run_case(rds_case, now, db=db).checks.values()


def test_pending_change_and_incomplete_ownership_rejected(rds_case, now):
    bad_tags = rds_case[4][:-1]
    with pytest.raises(ContractError, match="ownership"):
        run_case(rds_case, now, tags=bad_tags)


def test_pending_configuration_never_returns_pass(rds_case, now):
    result = run_case(
        rds_case,
        now,
        db={**rds_case[3], "PendingModifiedValues": {"BackupRetentionPeriod": 1}},
    )
    assert set(result.checks.values()) == {"unknown"}


def test_final_authorization_cannot_extend_collection_budget(rds_case, now):
    reg, clients, stubs, db, tags = rds_case
    elapsed = [0]
    calls = []

    def authorize(*_):
        calls.append(True)
        if len(calls) == 5:  # Entry, three reads, final projection.
            elapsed[0] = 13

    stubs["sts"].add_response("get_caller_identity", {"Account": reg.account_id})
    stubs["rds"].add_response("describe_db_instances", {"DBInstances": [db]})
    stubs["rds"].add_response("list_tags_for_resource", {"TagList": tags})
    for stub in stubs.values():
        stub.activate()
    collector = RdsSecurityCollector(
        reg,
        clients=lambda _: clients,
        authorize=authorize,
        clock=lambda: now,
        monotonic=lambda: elapsed[0],
    )
    with pytest.raises(ContractError, match="deadline"):
        collector.collect(actor="registered-reader")
    assert len(calls) == 5


def test_unauthorized_collector_never_constructs_sdk_clients(rds_case, now):
    reg, *_ = rds_case
    constructed = []

    def denied(*_):
        raise ContractError("denied")

    collector = RdsSecurityCollector(
        reg,
        clients=lambda _: constructed.append(True),
        authorize=denied,
        clock=lambda: now,
        monotonic=lambda: 0,
    )
    with pytest.raises(ContractError, match="denied"):
        collector.collect(actor="attacker")
    assert not constructed


def test_configuration_evidence_must_match_exact_policy_target(rds_case, now):
    snapshot = run_case(rds_case, now)
    reg = snapshot.registration
    target = ProtectionEndpoint(
        reg.scope,
        "aws",
        "rds-postgresql:storage-encryption",
        Availability.AVAILABLE,
        Availability.AVAILABLE,
        "a" * 64,
        snapshot.configuration_digest,
        reg.fingerprint,
        VERIFIER,
    )
    source = replace(
        target,
        scope=replace(reg.scope, environment_id="source", resource_id="source-db"),
    )
    req = ProtectionRequirement(
        "encrypted-storage",
        ControlFamily.ENCRYPTION,
        "Database storage encryption configured",
        source,
        target,
    )
    policy = ProtectionPolicy(
        reg.scope.tenant_id,
        reg.scope.application_id,
        1,
        (req,),
        now,
        now + timedelta(minutes=2),
    )
    record = snapshot.evidence(policy, req.requirement_id, side="target")
    assert record.result.value == "pass" and record.verifier_version == VERIFIER
    changed = replace(
        policy,
        requirements=(
            replace(req, target=replace(target, configuration_digest="b" * 64)),
        ),
    )
    with pytest.raises(ContractError, match="changed"):
        snapshot.evidence(changed, req.requirement_id, side="target")


def test_registration_rejects_credentials_endpoint_override_and_cross_account_arn(
    rds_case,
):
    reg = rds_case[0]
    assert decode_rds_registration(reg.document) == reg
    for key in ["aws_access_key_id", "endpoint_url", "command"]:
        data = {**reg.document, key: "untrusted"}
        with pytest.raises(ContractError):
            decode_rds_registration(data)
    with pytest.raises(ContractError):
        replace(reg, account_id="999999999999")
    with pytest.raises(ContractError):
        replace(reg, minimum_backup_days=True)
    with pytest.raises(ContractError):
        replace(reg, valid_until=reg.issued_at + timedelta(days=2))


def test_snapshot_conclusion_cannot_disagree_with_facts(rds_case, now):
    from sova.domain.contracts import canonical_json

    snapshot = run_case(rds_case, now)
    with pytest.raises(ContractError, match="conclusions differ"):
        replace(
            snapshot,
            checks_json=canonical_json(
                {**snapshot.checks, "storage-encryption": "fail"}
            ),
        )
    with pytest.raises(ContractError, match="Allowlisted"):
        replace(
            snapshot,
            facts_json=canonical_json(
                {**snapshot.facts, "MasterUsername": "do-not-save"}
            ),
        )


def test_fixed_sdk_factory_disables_endpoint_overrides_proxies_and_retries(rds_case):
    from sova.adapters.aws_rds_security import fixed_clients

    calls = []

    class Session:
        def client(self, name, **kwargs):
            calls.append((name, kwargs))
            return name

    assert set(fixed_clients(Session(), rds_case[0])) == {"sts", "rds"}
    for service, kwargs in calls:
        assert (
            kwargs["endpoint_url"]
            == "https://" + service + ".ap-northeast-2.amazonaws.com"
        )
        assert kwargs["verify"] is True
        assert kwargs["config"].proxies == {}
        assert kwargs["config"].ignore_configured_endpoint_urls
        assert kwargs["config"].retries["total_max_attempts"] == 1


def test_rds_cli_checks_private_registration_before_constructing_sdk_session(
    rds_case, tmp_path, monkeypatch, capsys
):
    from sova.interfaces.cli import main
    import json

    reg = rds_case[0]
    from datetime import datetime, UTC

    now = datetime.now(UTC)
    reg = replace(
        reg,
        issued_at=now - timedelta(seconds=1),
        valid_until=now + timedelta(minutes=5),
    )
    path = tmp_path / "registration.json"
    path.write_text(json.dumps(reg.document))
    path.chmod(0o644)
    constructed = []
    monkeypatch.setattr(boto3, "Session", lambda **kw: constructed.append(kw))
    assert main(["discover-rds-security", "--registration", str(path)]) == 2
    assert constructed == [] and "canary" not in capsys.readouterr().err
    path.chmod(0o600)
    data = {**reg.document, "endpoint_url": "http://metadata.invalid"}
    path.write_text(json.dumps(data))
    assert main(["discover-rds-security", "--registration", str(path)]) == 2
    assert constructed == []


def test_aws_api_failure_never_returns_partial_pass_or_echoes_service_error(
    rds_case, now
):
    reg, clients, stubs, *_ = rds_case
    stubs["sts"].add_client_error(
        "get_caller_identity",
        service_error_code="AccessDenied",
        service_message="canary-in-provider-error",
    )
    stubs["sts"].activate()
    reader = RdsSecurityCollector(
        reg,
        clients=lambda _: clients,
        authorize=lambda *_: None,
        clock=lambda: now,
        monotonic=lambda: 0,
    )
    with pytest.raises(ContractError) as error:
        reader.collect(actor="operator")
    assert "canary" not in str(error.value)


def test_existing_production_db_can_be_registered_read_only_without_sova_tags(
    rds_case, now
):
    from sova.domain.aws_security import RdsManagementRelation

    reg, clients, stubs, db, _ = rds_case
    reg = replace(reg, management_relation=RdsManagementRelation.REGISTERED_READ_ONLY)
    stubs["sts"].add_response(
        "get_caller_identity",
        {
            "Account": reg.account_id,
            "Arn": "arn:aws:iam::" + reg.account_id + ":role/customer-reader",
            "UserId": "test",
        },
    )
    stubs["rds"].add_response(
        "describe_db_instances",
        {"DBInstances": [db]},
        {"DBInstanceIdentifier": reg.scope.resource_id},
    )
    for stub in stubs.values():
        stub.activate()
    result = RdsSecurityCollector(
        reg,
        clients=lambda _: clients,
        authorize=lambda *_: None,
        clock=lambda: now,
        monotonic=lambda: 0,
    ).collect(actor="registered-customer-operator")
    assert result.document["ownership_tags_verified"] is False
    assert result.document["grants_modification_authority"] is False
    assert result.document["management_relation"] == "registered_read_only"
    for stub in stubs.values():
        stub.assert_no_pending_responses()


def test_legacy_registration_cannot_silently_opt_into_external_read_only(rds_case):
    reg = rds_case[0]
    v1 = reg.document
    v1.pop("management_relation")
    v1["schema_version"] = 1
    decoded = decode_rds_registration(v1)
    assert decoded.management_relation.value == "sova_managed"
    v1["management_relation"] = "registered_read_only"
    with pytest.raises(ContractError):
        decode_rds_registration(v1)
