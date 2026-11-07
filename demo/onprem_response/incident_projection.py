"""Current owned resources and historical effect facts, using the existing UI schema."""

from datetime import timedelta


def projection(t):
    at = t.observation_started_at
    expiry = min(at + timedelta(seconds=25), t.deadline)
    doc = dict(
        kind="console-workload.v1",
        authorizes_execution=False,
        **{k: t.plan_binding[k] for k in ("plan_id", "plan_digest", "plan_version")},
        revision=t.snapshot_revision,
        stream_id="incident-" + t.run_id,
        provenance="live",
        source_label="실제 온프렘 전용 시험 · 부분 격리·fencing·실패 보류·재검증·별도 승인 복귀 · 운영 T10 아님",
        observed_at=at.isoformat(),
        expires_at=expiry.isoformat(),
        nodes=[],
        edges=[],
        evidence=[],
        responses=[],
        events=[],
    )

    def evidence(resource, kind, summary, *, outcome="verified"):
        key = "e-" + str(len(doc["evidence"]) + 1)
        doc["evidence"].append(
            dict(
                id=key,
                resource_id=resource["id"],
                resource_uid=resource["resource_uid"],
                kind=kind,
                outcome=outcome,
                summary=summary,
                observed_at=at.isoformat(),
                expires_at=expiry.isoformat(),
            )
        )
        return key

    nodes, probes = {}, {}
    for side, components in (
        ("blue", ("api", "worker", "neighbor")),
        ("green", ("api", "worker")),
    ):
        for c in components:
            obj = t.api.get("deployment", side, c)
            if obj["metadata"]["uid"] != t.artifacts[side, c]["uid"]:
                raise ValueError("Registered component was replaced")
            result = (
                t.routes.call("/probe?target=neighbor")
                if c == "neighbor"
                else t.probe(side, c)
            )
            probes[side, c] = result
            policies = t.policies(c) if side == "blue" and c in t.components else []
            isolated = bool(policies) and any(
                s["action"] == "isolate-" + c for s in t.steps
            )
            selected = side == "blue" and c in t.components
            node = dict(
                id=side + "-" + c,
                label=("원본 " if side == "blue" else "대체 ")
                + {"api": "API", "worker": "무상태 작업자", "neighbor": "이웃 서비스"}[
                    c
                ],
                resource_uid=obj["metadata"]["uid"],
                detail="선택한 격리 범위 · 원본 Pod와 새 복원 Pod는 구분"
                if selected
                else "별도 구성 요소 · 공유 DB·큐·실제 고객 앱 아님",
                kind="worker" if c == "worker" else "app",
                lane="source" if side == "blue" else "target",
                column=1 if c == "api" else 2,
                row=0 if c != "neighbor" else 1,
                health="ready" if result.get("ok") else "unknown",
                security="isolated"
                if isolated
                else "hold"
                if selected and t.attack
                else "unknown",
                health_evidence=None,
                security_evidence=None,
            )
            if result.get("ok"):
                node["health_evidence"] = evidence(
                    node, "health", "이번 관측의 독립 HTTP 확인 · 응답 nonce·앱 확인"
                )
            if isolated:
                node["security_evidence"] = evidence(
                    node,
                    "isolation",
                    "현재 선택 정책·Deployment UID 확인 · 새 수신/발신 거부는 효과 영수증의 당시 실측",
                )
            elif selected and t.attack:
                node["security_evidence"] = evidence(
                    node,
                    "hold",
                    "비인가 요청 사건 보류 유지 · 서비스 복귀와 사고 해제는 별도",
                )
            nodes[side, c] = node
            doc["nodes"].append(node)
    entry = t.api.get("service", "probe", "probe")
    pipeline = t.routes.call("/pipeline")
    entry_node = dict(
        id="entry",
        label="고정 시험 요청 경로",
        resource_uid=entry["metadata"]["uid"],
        detail="실제 API·작업자 두 HTTP 요청 · 앱 내부 호출 체인을 추정하지 않음",
        kind="edge",
        lane="control",
        column=0,
        row=0,
        health="ready" if pipeline.get("ok") else "unknown",
        security="unknown",
        health_evidence=None,
        security_evidence=None,
    )
    if pipeline.get("ok"):
        entry_node["health_evidence"] = evidence(
            entry_node, "health", "현재 고정 시험 경로의 두 구성 요소가 HTTP 응답"
        )
    doc["nodes"].append(entry_node)
    for c in ("api", "worker"):
        route = t.route(c)
        for side in ("blue", "green"):
            node = nodes[side, c]
            connected = pipeline.get("components", {}).get(c, {})
            active = (
                route["environment_id"] == t.ns[side]
                and connected.get("ok")
                and connected.get("response", {}).get("environment") == side
            )
            blocked = node["security"] == "isolated"
            edge = dict(
                id="entry-" + side + "-" + c,
                source="entry",
                target=node["id"],
                label="현재 시험 경로"
                if active
                else "격리된 시험 경로"
                if blocked
                else "비활성 시험 경로",
                kind="http",
                resource_uid=t.run_id + "-" + side + "-" + c,
                state="observed" if active else "blocked" if blocked else "unknown",
                evidence_id=None,
            )
            if active or blocked:
                edge["evidence_id"] = evidence(
                    edge,
                    "isolation" if blocked else "health",
                    "현재 격리 정책과 이전 거부 실측"
                    if blocked
                    else "현재 라우팅 revision과 실제 응답 환경 일치",
                )
            doc["edges"].append(edge)
        if c in t.components and nodes["blue", c]["security"] == "isolated":
            edge = dict(
                id="egress-" + c,
                source=nodes["blue", c]["id"],
                target=nodes["blue", "neighbor"]["id"],
                label="발신 차단 · 당시 직접 TCP 2회 실측",
                kind="http",
                resource_uid=t.run_id + "-egress-" + c,
                state="blocked",
                evidence_id=None,
            )
            edge["evidence_id"] = evidence(
                edge,
                "isolation",
                "정상 대조 뒤 같은 이웃 Pod IP로 새 발신 연결 2회 거부 · 현재 정책 확인",
            )
            doc["edges"].append(edge)
    selected_node = nodes["blue", t.components[0]]
    done = {s["action"] for s in t.steps}
    verified = [
        (
            "detect",
            bool(t.attack),
            "security",
            "실제 403 요청·독립 감사 대조 · 일반 공격 탐지 아님",
        ),
        ("hold", bool(t.attack), "hold", "사건 보류 유지"),
        (
            "approve",
            t.approved,
            "approval",
            "정확한 선택 집합·이미지·계획 해시에 대한 개인 시험 승인",
        ),
        (
            "isolate",
            all("fence-" + c in done for c in t.components),
            "isolation",
            "새 연결 거부 실측 후 원본 Pod 제거·등록한 기존 클라이언트 연결 닫기 영수증",
        ),
        (
            "replace",
            all("activate-" + c in done for c in t.components),
            "replacement",
            "대체 실행본 기동 영수증",
        ),
        (
            "verify",
            t.revalidated,
            "security",
            "실제 검증 실패 후 새 계획 승인·현재 HTTP 재검증",
        ),
        (
            "route",
            t.revalidated,
            "route",
            "대체 경로 전환 영수증 · 현재 경로는 지도에서 별도 표시",
        ),
        (
            "recover",
            t.returned and pipeline.get("ok"),
            "recovery",
            "새 원본 Pod·같은 이미지·설정 재검증과 별도 승인 복귀 완료 · 사건 보류 유지",
        ),
    ]
    for stage, passed, kind, detail in verified:
        status = (
            "verified"
            if passed
            else "failed"
            if stage == "verify"
            and t.phase in {"verification_failed", "awaiting_recheck"}
            else "pending"
        )
        doc["responses"].append(
            dict(
                stage=stage,
                status=status,
                node_ids=[selected_node["id"]],
                evidence_id=evidence(selected_node, kind, detail) if passed else None,
                detail=detail
                if passed or status == "failed"
                else "현재 확인 근거 없음",
            )
        )
    for index, event in enumerate(t.events[-60:]):
        phase = event["phase"]
        stage = (
            "verify"
            if "failure" in phase or "recheck" in phase or "verify" in phase
            else "recover"
            if "return" in phase or "restore" in phase or "release" in phase
            else "isolate"
            if "fence" in phase or "isolate" in phase
            else "replace"
            if "activate" in phase
            else "route"
            if "switch" in phase
            else "approve"
            if "respond" in phase
            else "detect"
        )
        doc["events"].append(
            dict(
                id="incident-event-" + str(index + 1),
                sequence=index + 1,
                occurred_at=event["occurred_at"],
                stage=stage,
                status="failed"
                if phase == "verification_failed"
                else "requested"
                if phase.startswith("awaiting_")
                else "verified",
                summary="전용 실제 시험 · " + phase,
            )
        )
    return doc
