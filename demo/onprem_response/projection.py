"""Display actual owned API/probe observations. Never an execution permission."""

from datetime import timedelta


def projection(trial):
    at = trial.observation_started_at
    expires = min(at + timedelta(seconds=30), trial.deadline)
    rows = {
        side: trial.api.get("deployment", side, "api") for side in ("blue", "green")
    }
    neighbor = trial.api.get("deployment", "blue", "neighbor")
    observer = trial.api.get("deployment", "probe", "probe")
    entry = trial.api.get("service", "probe", "probe")
    for side, original in (("blue", trial.source), ("green", trial.target)):
        if rows[side]["metadata"]["uid"] != original["metadata"]["uid"]:
            raise ValueError("Registered trial Deployment was replaced")
    original_uid = trial.neighbor["metadata"]["uid"]
    if neighbor["metadata"]["uid"] != original_uid:
        raise ValueError("Independent trial component was replaced")
    violated = (
        rows["blue"]["spec"]["template"]["spec"]["containers"][0]["securityContext"][
            "readOnlyRootFilesystem"
        ]
        is False
    )
    isolated = (
        trial.isolation is not None
        and trial.isolation.status.value == "confirmed_applied"
    )
    done = {s["action"] for s in trial.steps}
    green_ok = trial.probes["green"].get("ok") is True
    neighbor_ok = trial.probes["neighbor"].get("ok") is True
    target_checked = (
        rows["green"]["spec"]["template"]["spec"]["containers"][0]["securityContext"][
            "readOnlyRootFilesystem"
        ]
        is True
    )
    route = trial.routes.get(None, None)
    routed = (
        "switch_route" in done
        and route["environment_id"] == trial.ns["green"]
        and trial.entry.get("ok") is True
        and trial.entry.get("response", {}).get("environment") == "green"
    )
    recovered = routed and isolated and neighbor_ok
    doc = {
        "kind": "console-workload.v1",
        "authorizes_execution": False,
        **{
            k: v
            for k, v in trial.plan_binding.items()
            if k in {"plan_id", "plan_digest", "plan_version"}
        },
        "revision": trial.snapshot_revision,
        "stream_id": "onprem-trial-" + trial.run_id,
        "provenance": "live",
        "source_label": "실제 온프렘 전용 시험 · 같은 클러스터의 별도 namespace · 운영 제품 인수 아님",
        "observed_at": at.isoformat(),
        "expires_at": expires.isoformat(),
        "nodes": [],
        "edges": [],
        "evidence": [],
        "responses": [],
        "events": [],
    }

    def proof(resource, kind, summary):
        key = f"trial-{resource['id']}-{kind}"
        doc["evidence"].append(
            {
                "id": key,
                "resource_id": resource["id"],
                "resource_uid": resource["resource_uid"],
                "kind": kind,
                "outcome": "verified",
                "summary": summary,
                "observed_at": at.isoformat(),
                "expires_at": expires.isoformat(),
            }
        )
        return key

    for id, label, kind, lane, column, row, obj, healthy, security, detail in (
        (
            "entry",
            "고정 시험 진입점",
            "edge",
            "source",
            0,
            1,
            entry,
            trial.entry.get("ok") is True,
            "unknown",
            "개인 API 포워딩으로 접근하는 전용 HTTP 진입점",
        ),
        (
            "api",
            "원본 시험 API",
            "app",
            "source",
            1,
            1,
            rows["blue"],
            trial.probes["blue"].get("ok") is True,
            "isolated" if isolated else "warning" if violated else "clear",
            "readOnlyRootFilesystem 위반 주입 대상 · 운영 앱 아님",
        ),
        (
            "neighbor",
            "독립 의존 서비스",
            "app",
            "source",
            2,
            1,
            neighbor,
            neighbor_ok,
            "unknown",
            "격리 대상이 아닌 별도 무상태 HTTP 서비스 · DB 아님",
        ),
        (
            "green",
            "대체 시험 API",
            "app",
            "target",
            1,
            0,
            rows["green"],
            green_ok,
            "clear" if green_ok and target_checked else "unknown",
            "동일 이미지의 승인된 읽기 전용 root 설정 · 취약점 전체 해소를 뜻하지 않음",
        ),
        (
            "probe",
            "독립 확인 Pod",
            "observability",
            "control",
            0,
            0,
            observer,
            trial.routes.call("/health").get("probe") == "alive",
            "unknown",
            "서로 다른 Pod에서 새 HTTP 연결·nonce·응답 대상 확인",
        ),
    ):
        node = dict(
            id=id,
            label=label,
            kind=kind,
            lane=lane,
            column=column,
            row=row,
            resource_uid=obj["metadata"]["uid"],
            detail=detail,
            health="ready" if healthy else "unknown",
            security=security,
            health_evidence=None,
            security_evidence=None,
        )
        if healthy:
            node["health_evidence"] = proof(
                node, "health", "실제 시험 경로의 HTTP·응답 nonce 확인"
            )
        if security != "unknown":
            node["security_evidence"] = proof(
                node,
                "isolation" if security == "isolated" else "security",
                "정확한 정책·자원 UID와 독립 확인 Pod의 새 연결 거부 확인"
                if isolated and id == "api"
                else "현재 API 설정의 readOnlyRootFilesystem 확인 · 선정한 구성 시험",
            )
        doc["nodes"].append(node)

    for id, source, target, state in (
        (
            "probe-api",
            "probe",
            "api",
            "blocked"
            if isolated
            else "observed"
            if trial.probes["blue"].get("ok")
            else "unknown",
        ),
        (
            "probe-neighbor",
            "probe",
            "neighbor",
            "observed" if neighbor_ok else "unknown",
        ),
        ("probe-green", "probe", "green", "observed" if green_ok else "unknown"),
        (
            "entry-blue",
            "entry",
            "api",
            "blocked"
            if isolated
            else "observed"
            if trial.entry.get("target") == "blue" and trial.entry.get("ok")
            else "unknown",
        ),
        ("entry-green", "entry", "green", "observed" if routed else "unknown"),
    ):
        resource = next(n for n in doc["nodes"] if n["id"] == target)
        edge = dict(
            id=id,
            source=source,
            target=target,
            label="실제 전용 HTTP 확인 경로",
            kind="http",
            resource_uid=trial.run_id + "-" + resource["resource_uid"] + "-" + id,
            state=state,
            evidence_id=None,
        )
        if state != "unknown":
            edge["evidence_id"] = proof(
                edge,
                "isolation" if state == "blocked" else "health",
                "독립 확인 Pod의 해당 새 연결 거부"
                if state == "blocked"
                else "해당 시험 경로의 nonce 결속 HTTP 응답",
            )
        doc["edges"].append(edge)
    source = doc["nodes"][1]
    target = doc["nodes"][3]
    statuses = [
        ("detect", violated, source, "security"),
        ("hold", hasattr(trial, "hold"), source, "hold"),
        ("approve", hasattr(trial, "plan"), source, "approval"),
        ("isolate", isolated, source, "isolation"),
        ("replace", "activate_replacement" in done and green_ok, target, "replacement"),
        (
            "verify",
            "verify_replacement" in done and green_ok and target_checked,
            target,
            "security",
        ),
        ("route", routed, target, "route"),
        ("recover", recovered, target, "recovery"),
    ]
    for stage, verified, node, kind in statuses:
        evidence = (
            proof(
                node,
                kind,
                "로컬 개인 운영자의 전용 시험 범위 승인 · 제품 T10 승인 아님"
                if stage == "approve"
                else "전용 시험의 현재 API·HTTP 관측과 기존 효과 원장 확인",
            )
            if verified
            else None
        )
        # A node can have the same proof kind for several presentation stages;
        # use a distinct ID while preserving its exact resource binding.
        if evidence:
            item = doc["evidence"][-1]
            item["id"] += "-" + stage
            evidence = item["id"]
        doc["responses"].append(
            dict(
                stage=stage,
                status="verified" if verified else "pending",
                node_ids=[node["id"]],
                evidence_id=evidence,
                detail="실제 전용 시험의 해당 경로 확인 · 제품 운영 자격 아님"
                if verified
                else "현재 확인 근거 없음",
            )
        )
    mapping = {
        "normal": "detect",
        "detected": "detect",
        "apply_isolation": "isolate",
        "activate_replacement": "replace",
        "verify_replacement": "verify",
        "switch_route": "route",
        "watch": "recover",
    }
    for index, event in enumerate(trial.events[-50:]):
        if event["phase"] == "normal":
            continue
        doc["events"].append(
            dict(
                id=f"trial-event-{index + 1}",
                sequence=index + 1,
                occurred_at=event["occurred_at"],
                stage=mapping.get(event["phase"], "recover"),
                status="verified",
                summary="실제 온프렘 전용 시험 · " + event["phase"],
            )
        )
    return doc
