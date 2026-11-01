"""Six-area requirement catalog; an assessment never grants execution rights.

Evidence authentication and security holds remain independent authorities. The
catalog makes future obligations visible rather than treating an early gate as
proof of full migration. Provider configuration checks cannot substitute for
runtime, data, sandbox or recovery verifier contracts.
"""

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
import hashlib

from sova.domain.contracts import (
    ContractError,
    ResourceScope,
    canonical_json,
    identifier,
    utc,
)
from sova.domain.evidence import (
    Gate,
    RevisionSet,
    VerificationObligation,
    evaluate_gate,
)


class MigrationArea(StrEnum):
    MIGRATION = "migration"
    GOVERNANCE = "governance"
    DESTINATION = "destination"
    AI_RESIDENCY = "ai_residency"
    SANDBOX = "sandbox"
    COST_OBSERVABILITY = "cost_observability"


AREA_TITLES = {
    MigrationArea.MIGRATION: "앱·데이터 이전과 복구",
    MigrationArea.GOVERNANCE: "보안·거버넌스",
    MigrationArea.DESTINATION: "목적지 기능·보호 재현",
    MigrationArea.AI_RESIDENCY: "AI 리소스·데이터 레지던시",
    MigrationArea.SANDBOX: "AI 에이전트·샌드박스",
    MigrationArea.COST_OBSERVABILITY: "비용·횡단 관측",
}


@dataclass(frozen=True, slots=True)
class ProgramRequirement:
    area: MigrationArea
    obligation: VerificationObligation
    objective: str

    def __post_init__(self):
        if not isinstance(self.area, MigrationArea) or not isinstance(
            self.obligation, VerificationObligation
        ):
            raise ContractError("Typed migration area and obligation required")
        identifier(self.objective, limit=1024)


# Trusted, versioned verifier contract identifiers, not claims of implemented probes.
_SPECIFICATIONS = (
    (
        MigrationArea.MIGRATION,
        "target-http",
        Gate.STARTUP,
        "migration-http-readback-v1",
        "목적지 HTTPS 신원·헬스 응답",
    ),
    (
        MigrationArea.MIGRATION,
        "single-writer",
        Gate.PREFLIGHT,
        "all-writer-fencing-v1",
        "모든 쓰기 경로 통제와 단일 writer",
    ),
    (
        MigrationArea.MIGRATION,
        "final-data",
        Gate.PREFLIGHT,
        "final-barrier-manifest-v1",
        "최종 변경 경계·스키마·데이터 비교",
    ),
    (
        MigrationArea.MIGRATION,
        "sequence-safety",
        Gate.PREFLIGHT,
        "sequence-collision-denial-v1",
        "신규 ID 충돌 방지",
    ),
    (
        MigrationArea.MIGRATION,
        "recovery-ready",
        Gate.PREFLIGHT,
        "new-write-recovery-rehearsal-v1",
        "신규 데이터 보존 복구 리허설",
    ),
    (
        MigrationArea.MIGRATION,
        "post-cutover-write",
        Gate.POSTFLIGHT,
        "post-cutover-read-write-v1",
        "전환 후 신규 데이터 저장·재조회",
    ),
    (
        MigrationArea.GOVERNANCE,
        "required-controls",
        Gate.PROTECTION,
        "required-control-outcomes-v1",
        "필수 통제별 실제 허용·거부 결과",
    ),
    (
        MigrationArea.GOVERNANCE,
        "holds-clear",
        Gate.PREFLIGHT,
        "independent-hold-authority-v1",
        "독립 보안 보류와 승인 상태 재검사",
    ),
    (
        MigrationArea.GOVERNANCE,
        "ownership",
        Gate.REGISTRATION,
        "environment-ownership-v1",
        "등록된 앱·환경·실행 주체 소유권",
    ),
    (
        MigrationArea.DESTINATION,
        "identity",
        Gate.PROTECTION,
        "destination-cross-app-denial-v1",
        "목적지의 교차 앱 접근 거부",
    ),
    (
        MigrationArea.DESTINATION,
        "secrets",
        Gate.PROTECTION,
        "destination-secret-rotation-v1",
        "목적지 비밀 접근·회전·폐기",
    ),
    (
        MigrationArea.DESTINATION,
        "audit",
        Gate.PROTECTION,
        "destination-audit-delivery-v1",
        "목적지 감사 수집·무결성",
    ),
    (
        MigrationArea.DESTINATION,
        "restore",
        Gate.PROTECTION,
        "destination-restore-v1",
        "목적지 백업 복원과 업무 검증",
    ),
    (
        MigrationArea.AI_RESIDENCY,
        "location-policy",
        Gate.CHANGE,
        "ai-location-enforcement-v1",
        "처리·저장·로그·복제·지원 위치 정책",
    ),
    (
        MigrationArea.AI_RESIDENCY,
        "compatibility",
        Gate.BEHAVIOR,
        "ai-functional-quality-v1",
        "목적지 모델 기능·품질·지연",
    ),
    (
        MigrationArea.AI_RESIDENCY,
        "fallback-denial",
        Gate.PROTECTION,
        "ai-forbidden-fallback-denial-v1",
        "금지된 외부 fallback 실제 거부",
    ),
    (
        MigrationArea.SANDBOX,
        "input-binding",
        Gate.CHANGE,
        "sandbox-source-tests-binding-v1",
        "원본·독립 테스트·실행 이미지 결합",
    ),
    (
        MigrationArea.SANDBOX,
        "egress-denial",
        Gate.CHANGE,
        "sandbox-egress-denial-v1",
        "운영·metadata·비허용 외부 통신 거부",
    ),
    (
        MigrationArea.SANDBOX,
        "independent-verifier",
        Gate.CHANGE,
        "sandbox-independent-verifier-v1",
        "에이전트와 분리된 검증 결과",
    ),
    (
        MigrationArea.SANDBOX,
        "same-artifact",
        Gate.STARTUP,
        "sandbox-artifact-readback-v1",
        "검증·승인한 산출물과 실행 digest 일치",
    ),
    (
        MigrationArea.COST_OBSERVABILITY,
        "priced-comparison",
        Gate.REQUIREMENTS,
        "priced-comparison-v1",
        "같은 기간·부하·범위의 출처 있는 비용 비교",
    ),
    (
        MigrationArea.COST_OBSERVABILITY,
        "cross-environment",
        Gate.BEHAVIOR,
        "cross-environment-telemetry-v1",
        "신원·revision에 결합된 횡단 관측",
    ),
    (
        MigrationArea.COST_OBSERVABILITY,
        "current-window",
        Gate.PREFLIGHT,
        "telemetry-window-freshness-v1",
        "지표의 신선도·범위·누락 확인",
    ),
    (
        MigrationArea.COST_OBSERVABILITY,
        "post-change-slo",
        Gate.POSTFLIGHT,
        "post-change-slo-v1",
        "변경 후 오류·지연·사용량 비교",
    ),
)


@dataclass(frozen=True, slots=True)
class MigrationProgram:
    source_scope: ResourceScope
    target_scope: ResourceScope
    revisions: RevisionSet
    issued_at: datetime
    valid_until: datetime
    requirements: tuple[ProgramRequirement, ...]

    def __post_init__(self):
        a, b = self.source_scope, self.target_scope
        if (
            not isinstance(a, ResourceScope)
            or not isinstance(b, ResourceScope)
            or not isinstance(self.revisions, RevisionSet)
        ):
            raise ContractError("Typed program scope and revisions required")
        if (a.tenant_id, a.application_id) != (
            b.tenant_id,
            b.application_id,
        ) or a.environment_id == b.environment_id:
            raise ContractError(
                "Distinct environments of the same application required"
            )
        object.__setattr__(self, "issued_at", utc(self.issued_at))
        object.__setattr__(self, "valid_until", utc(self.valid_until))
        if self.valid_until <= self.issued_at:
            raise ContractError("Positive program validity required")
        if (
            type(self.requirements) is not tuple
            or not 1 <= len(self.requirements) <= 256
            or any(not isinstance(r, ProgramRequirement) for r in self.requirements)
        ):
            raise ContractError("Bounded immutable program requirements required")
        ids = [r.obligation.obligation_id for r in self.requirements]
        if len(set(ids)) != len(ids) or set(r.area for r in self.requirements) != set(
            MigrationArea
        ):
            raise ContractError("Unique obligations covering all six areas required")
        for requirement in self.requirements:
            if (
                requirement.obligation.scope not in (a, b)
                or not requirement.obligation.required
            ):
                raise ContractError("Program cannot weaken or cross required scope")
        by_id = {r.obligation.obligation_id: r for r in self.requirements}
        for area, name, gate, verifier, _ in _SPECIFICATIONS:
            row = by_id.get(f"{area}:{name}")
            if (
                row is None
                or row.area != area
                or row.obligation.due_gate != gate
                or row.obligation.verifier_version != verifier
                or row.obligation.scope != b
            ):
                raise ContractError(
                    "Program omitted or weakened minimum six-area requirements"
                )

    @property
    def document(self):
        from dataclasses import asdict

        return {
            "schema_version": 1,
            "source_scope": asdict(self.source_scope),
            "target_scope": asdict(self.target_scope),
            "revisions": asdict(self.revisions),
            "issued_at": self.issued_at.isoformat(),
            "valid_until": self.valid_until.isoformat(),
            "requirements": [
                {
                    "area": str(r.area),
                    "id": r.obligation.obligation_id,
                    "scope": asdict(r.obligation.scope),
                    "gate": int(r.obligation.due_gate),
                    "verifier": r.obligation.verifier_version,
                    "required": r.obligation.required,
                    "objective": r.objective,
                }
                for r in self.requirements
            ],
        }

    @property
    def fingerprint(self):
        return hashlib.sha256(
            canonical_json(self.document, limit=131072).encode()
        ).hexdigest()

    def assess(self, evidence, gate, *, now):
        if not self.issued_at <= utc(now) < self.valid_until:
            raise ContractError("Program expired or from future")
        if type(evidence) is not tuple or len(evidence) > 4096:
            raise ContractError("Immutable evidence snapshot required")
        decision = evaluate_gate(
            gate,
            tuple(r.obligation for r in self.requirements),
            evidence,
            self.revisions,
            now=now,
        )
        by_id = {d.obligation.obligation_id: d for d in decision.decisions}
        areas = []
        for area in MigrationArea:
            items = []
            for requirement in self.requirements:
                if requirement.area != area:
                    continue
                d = by_id[requirement.obligation.obligation_id]
                items.append(
                    {
                        "id": d.obligation.obligation_id,
                        "objective": requirement.objective,
                        "due_gate": int(d.obligation.due_gate),
                        "result": str(d.result),
                        "evidence_id": d.evidence_id,
                        "reason": d.reason,
                    }
                )
            areas.append(
                {
                    "id": str(area),
                    "title": AREA_TITLES[area],
                    "requirements": items,
                    "fully_verified": all(
                        i["result"] in {"pass", "not_applicable"} for i in items
                    ),
                }
            )
        return {
            "program_digest": self.fingerprint,
            "status": "assessment-only",
            "execution_authorized": False,
            "gate": int(gate),
            "gate_accepted": decision.accepted,
            "all_areas_verified": all(a["fully_verified"] for a in areas),
            "carry_forward": list(decision.carry_forward),
            "areas": areas,
        }


def six_area_program(source_scope, target_scope, revisions, *, issued_at, valid_until):
    return MigrationProgram(
        source_scope,
        target_scope,
        revisions,
        issued_at,
        valid_until,
        tuple(
            ProgramRequirement(
                area,
                VerificationObligation(f"{area}:{name}", target_scope, gate, verifier),
                objective,
            )
            for area, name, gate, verifier, objective in _SPECIFICATIONS
        ),
    )


def six_area_catalog():
    """Public definitions, never environment facts or execution qualification."""
    return [
        {
            "id": str(area),
            "title": AREA_TITLES[area],
            "requirements": [
                {
                    "id": f"{area}:{name}",
                    "objective": objective,
                    "due_gate": int(gate),
                    "verifier": verifier,
                }
                for item_area, name, gate, verifier, objective in _SPECIFICATIONS
                if item_area == area
            ],
        }
        for area in MigrationArea
    ]
