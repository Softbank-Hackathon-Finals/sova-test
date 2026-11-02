# Sova 구현 순서와 수용 기준

현재 담당: **보안 거버넌스 우선**. Harbor 실행 연동은 팀원이 담당한다. [담당 경계](team-boundaries.md) · [거버넌스 구현](security-governance.md).

2026-11-02 · 전체 목표는 명세 v2를 유지한다. 선행 검증 때문에 순서를 나누며 보류 항목을 삭제하지 않는다.

| 단계 | 작업 | 완료 기준 | 현재 |
| --- | --- | --- | --- |
| S0 독립 기반 | 패키징·CLI·공통 그래프·이식성 검토·snapshot 입력·Harbor 준비 계약 | 독립 설치·회귀·거부 시험, Sky import 없음 | 이번 재구성에서 구현 |
| S1 등록·실측 조사 | 기업 OIDC·tenant 인가·환경 등록·Kubernetes 읽기 전용 조사·resource UID/revision·근거 수집 | 다른 tenant/namespace 거부, 삭제·재생성·만료·부분 조사 처리, 실제 클러스터 시험 | 전용 로컬 k3s의 제한 조사·RBAC 시험, 기업 OIDC·중앙 등록 운영 미연결 |
| S2 실행면 연결 | PG 접수/outbox/worker, 앱 실행권·실제 provider proof/fencing, 큐 중복·인계 | crash/replay/응답 유실에서 범위 밖 효과·동시 변경 없음, 웹과 PG 통합 | 구성 요소만 시험 |
| S3 격리 리허설 | Harbor runner·backend·gateway·별도 verifier·산출물 전달·출발 의존 차단 | 실모델·악성 입력·egress·변조·정리·업무 비교·digest 승격 시험 | 준비·산출물 수용 계약 구현, Harbor 실행은 팀원 담당 |
| S4 첫 앱 이전 | 기존 AWS 앱→등록된 Linux/k3s, 안정 진입점·권한·Secret·관측 보존 | 공개/사내 접속 정책, 실제 readback·재시작·정리·동일 산출물 확인 | 프리뷰의 경로 변경만 별도 존재 |
| S5 데이터 이전 | PG 초기 복사·CDC·all-writer fencing·barrier·시퀀스·새 쓰기·역방향 복구 | bounded_write_pause 경로 자격, 각 경계의 장애·무결성·복구 시험 | snapshot/replication/sequence 검사, 서로 다른 PG 인스턴스에서 상담앱 신규 쓰기 후 역방향 복구 시험. PG 승인/실행권/원장→제한 쓰기 게이트 연결. 일반 writer·전체 이전 worker·실환경 미자격 |
| S6 보호·AI·관측 통합 | 목적지 보호·AI 기능/위치·OTel·비용·지도/보류 | 통제별 실제 허용/거부, 위치 금지·관측 누락·비용 근거·권한 시험 | AI 위치·비용·샌드박스 계약과 실제 Collector SDK 경로의 첫 구현. 실공급자·가격·운영 backend 통합 미완료 |
| S7 지속 운영 자격 | 연속 서비스·부하·HA/DR·운영 루프·서명 보고·업그레이드 | 승인 SLO/RPO/RTO·신규 쓰기 보존·재해복구·운영 훈련 통과 | 미자격 |

## 작업을 놓치지 않기 위한 연결 규칙

- 각 계획 단계는 아직 충족하지 못한 검증 의무와 다음 담당 게이트를 기록한다.
- 코드·단위 시험·통합 실행·실환경 자격을 별도 완료로 관리한다.
- 첫 앱은 작게 유지하지만 지원 요구를 없애서 backend에 맞추지 않는다.
- Sky의 P7·게임·RDS·블루그린 시험은 Sova 자격으로 복사하지 않는다. 이식 시 출처·변경·재검증을 기록한다.
- 보류 범위: GCP/Azure 실제 어댑터, 관리형 agent 기능별 이전, WebSocket 세션·파일·worker 이전, PgBouncer 대기 최적화, Temporal 비교, 독립 보안 리뷰. 모두 최종 목표 또는 별도 자격 경로로 유지한다.

S1의 운영자 등록 계약·직접 HTTPS 읽기·scope/UID/페이지 검증은 [조사 안내](kubernetes-discovery.md)의 범위로 구현했다. 전용 k3s의 제한된 조사·RBAC·토큰 폐기·admission 거부를 시험했다. 다음은 **기업 인증·중앙 등록·독립 broker와 실제 외부 환경 자격**이다. 클러스터 자격 증명은 운영자 등록으로 공급하고 사용자 업로드에서 임의 endpoint·kubeconfig를 실행하지 않는다. 자격 시험 클러스터는 prod와 분리한다.

## 보안 거버넌스 우선 순서

| 순서 | 작업 | 현재 |
| --- | --- | --- |
| G0 | 공통 통제·만료/미확인 차단·PG 독립 보류·해제·실행 게이트 | 첫 구현·시험 |
| G1 | provider별 읽기 전용 보안 수집·통제 매핑·실제 거부 시험 | 로컬 k3s 설정·격리/권한 거부 시험, RDS는 SDK 응답 대체물 시험. 외부 환경 미자격 |
| G2 | 중앙 정책/근거·인증된 verifier 발행·기업 권한·별도 보안 역할 | 보호 정책·판정·공개 발행자 신뢰/폐기 PG 저장 구현. 기업 승인·독립 broker 미연결 |
| G3 | 통제별 현황·근거·보류·예외·영향을 보여주는 대시보드 | 로컬 인증 콘솔·실제 설정 비교·보류·대응 원장 연결. 호스팅 제품 API·일반 예외 미연결 |
| G4 | 명시적 위험 예외·보완 통제·기한·보류 알림·감사 보호 | 미구현 |
| G5 | broker의 보안 revision·원격 fencing·진행 중 요청·장애/침해 대응 자격 | 미검증 |

기존 S1~S7 목표는 유지한다. 보안 작업과 Harbor 담당의 결과는 동일한 scope·revision·근거 계약으로 통합한다.

## 재개 후 체크포인트

2시간 재개 작업에서 운영자 bootstrap·origin 전용 proof, 보호 프로필/비교 guard, PG 발행자 폐기, 원자 대응 완료, 제한 권한 자격 시험과 제어 기록 복원을 추가했다. [현재 연결·검증 범위](security-workload-validation.md)를 따른다. 다음은 기업 인증·독립 broker·provider 보호 probe·외부 환경 연속 업무 시험이다. 로컬 자격을 기업·다중 provider 운영 자격으로 합산하지 않는다. Harbor는 계속 팀원 담당이다.

## 여섯 영역 후속 연결 순서

1. 실제 앱·목적지 등록과 의존성별 필수 의무를 저장된 계획에 결합한다. 준비·동기화·전환은 각 단계에 맞는 승인된 하위 계획으로 나누고, 준비 효과 전에 최종 전환 근거를 요구하는 순환 의존을 만들지 않는다.
2. 일반 writer/파일/worker의 통제, source publisher의 실제 연결 신원, final boundary·전체 dataset·sequence를 독립 verifier에 결합한다. 구독 설정 digest만으로 RPO 0을 선언하지 않는다.
3. 실제 AWS→온프렘의 앱·DB·파일·안정 진입점·새 쓰기 후 역방향 복구를 worker/원장에 연결한다.
4. 팀원 Harbor의 실행·독립 verifier·egress·서명 결과를 `request_digest` 계약으로 수용한다.
5. 실제 AI endpoint·전송/위치·사용량과 가격/청구·OTel backend·손실/SLO를 연결한다.
6. 부하·장애·HA/DR·기업 권한을 경로별로 자격 시험한다. 단위·합성 앱·로컬 Docker 결과를 전체 프로덕션 자격으로 확대하지 않는다.

단계별 승인과 쓰기 게이트의 연결 범위는 [실행 계약](migration-phase-execution.md)을 따른다. `quiesce`를 G6에서 별도 승인해 최종 경계를 준비하고, 실제 전환은 G7을 요구한다. 보안 보류·현재 실행권 검사와 원격 fencing은 별도로 유지한다.
