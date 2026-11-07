"""Actual terminal exercise evidence through the existing display-only graph."""


from .projection import projection as configured_projection


def projection(trial):
    doc = configured_projection(trial)
    doc["source_label"] = (
        "실제 온프렘 전용 시험 · 터미널 유발 비인가 내부 HTTP 접근·격리 · 제품 T10 승인 아님"
    )
    nodes = {n["id"]: n for n in doc["nodes"]}
    nodes["api"]["label"] = "접근 시도 주체 · 시험 워크로드"
    nodes["api"]["detail"] = "본인 소유의 시험 Pod · 실제 비인가 내부 HTTP 요청의 주체"
    nodes["neighbor"]["label"] = "보호된 이웃 서비스"
    nodes["entry"]["detail"] = (
        "Tailscale Kubernetes API의 고정 시험 HTTP 경로 · 운영 Edge 아님"
    )
    attack = trial.attack
    if attack and nodes["api"]["security"] != "isolated":
        nodes["api"]["security"] = "hold"
        key = "terminal-incident-hold"
        doc["evidence"].append(
            dict(
                id=key,
                resource_id="api",
                resource_uid=nodes["api"]["resource_uid"],
                kind="hold",
                outcome="verified",
                summary="실제 비인가 요청·독립 403 감사 대조 후 등록한 전용 시험 보류",
                observed_at=doc["observed_at"],
                expires_at=doc["expires_at"],
            )
        )
        nodes["api"]["security_evidence"] = key
    for response in doc["responses"]:
        stage = response["stage"]
        if stage not in {"detect", "approve"}:
            continue
        verified = bool(attack) if stage == "detect" else trial.approved
        response.update(
            status="verified" if verified else "pending",
            evidence_id=None,
            detail="독립 감사 기록과 실제 Pod UID/IP 대조"
            if stage == "detect" and verified
            else "관측한 사건 이후 정확한 대응 계획에 대한 개인 시험 승인"
            if verified
            else "현재 확인 근거 없음",
        )
        if verified:
            key = "terminal-stage-" + stage
            doc["evidence"].append(
                dict(
                    id=key,
                    resource_id="api",
                    resource_uid=nodes["api"]["resource_uid"],
                    kind="security" if stage == "detect" else "approval",
                    outcome="verified",
                    summary=response["detail"],
                    observed_at=doc["observed_at"],
                    expires_at=doc["expires_at"],
                )
            )
            response["evidence_id"] = key
    if attack:
        doc["edges"].append(
            dict(
                id="unauthorized-attempt",
                source="api",
                target="neighbor",
                label="비인가 내부 HTTP 요청 · 403 감사 기록",
                kind="http",
                resource_uid=trial.run_id + "-attempt-" + nodes["api"]["resource_uid"],
                state="unknown",
                evidence_id=None,
            )
        )
        # This edge shows a recorded request, not continuing attack traffic or
        # proof that the network currently permits it.
    relevant = [e for e in trial.events[-50:] if e["phase"] != "normal"]
    for event, original in zip(doc["events"], relevant):
        if original["phase"] == "approved":
            event["stage"] = "approve"
    return doc
