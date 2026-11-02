# Sova 상세 설계

기준: [프로덕션 목표 명세 v2](../sova-production-spec-v2.md). 아래 문서는 목표 계약이며 각각의 실제 구현 상태는 [현황표](../implementation-status.md)로 확인한다.

| 영역 | 설계 문서 | 핵심 책임 |
| --- | --- | --- |
| 앱·DB 이전 | [이전과 복구](migration.md) | 단일 writer·동기화·경로·신규 쓰기 이후 복구 |
| 목적지 기능 | [기능과 보호 재현](destination-parity.md) | IAM·Secret·백업·관측·관리형 기능 |
| AI와 데이터 위치 | [AI 리소스·레지던시](ai-residency.md) | 기능별 이전·위치 정책·품질·금지된 fallback |
| AI 에이전트 | [Harbor와 샌드박스](sandbox.md) | 격리 변경·독립 검증·동일 산출물 승격 |
| 비용과 횡단 관측 | [관측과 배치 제안](observability-cost.md) | 실제 지표·비용 종류·이동 경제성 |
| 보안과 지도 | [통합 거버넌스](security-governance.md) | 공통 보호 목적·근거·보류·영향 시각화 |

담당 구분: [Harbor·보안 거버넌스 경계](../team-boundaries.md). 보안 첫 구현: [실행 계약](../security-governance.md).
