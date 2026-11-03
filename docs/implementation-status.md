
## 2026-11-03 보안 패키지 추출

보안 구현 36개를 팀 `security` 저장소의 `sova-security` 패키지로 추출했다. 현재 의존 버전은 0.9.0이며 보안 소유 SQL은 산출물 등록·폐기를 포함한 7개다. 기존 Python 경로는 같은 모듈로 연결한다. 공통 데이터 타입은 패키지 경계 계약 v1을 사용한다. 실제 실행 runner·시험 클러스터 어댑터·공통 작업 상태 및 원장은 Sova에 남긴다. 팀 platform의 계약 채택과 운영 통합 완료를 뜻하지 않는다.

# 구현·연결·운영 자격 현황

기준일: 2026-11-02. 검증 기록의 날짜는 결과 생성 시점이며 현재 서버 가동·자격을 뜻하지 않는다.

## 2026-11-02 · 여섯 영역 개발 체크포인트

### 같은 날 후속 실환경 검증

- 새로 만든 **Sova 전용 Linux VM의 k3s**에서 비루트·읽기 전용·capability 제거·seccomp·자원 제한과 digest 고정을 적용한 무상태 HTTP 시험 컨테이너를 실행했다. Docker의 원본 manifest와 VM containerd의 manifest, 실행 Pod의 imageID를 대조했다. 상담앱 이미지의 정적 파일을 별도 HTTP 명령으로 제공한 시험이며 상담앱·DB 전체 실행 자격은 아니다.
- 실제 연결로 default-deny, 명시한 같은 namespace 연결의 성공, 다른 namespace의 접근 거부, 허용 링크 삭제 후 재접속 거부를 확인했다. 실제 Kubernetes API에서도 제한된 인벤토리 조회, Secret/다른 namespace/변경 API 거부, RBAC 회수 후 부분 그래프 미반환, 특권 Pod admission 거부를 확인했다.
- 같은 시험 VM에서 Secret의 **실제 저장 암호문**과 AES-CBC 키 회전 후 재암호화·값 보존을 확인했다. 서비스 계정 삭제·동일 이름 재생성 후 이전 토큰 거부·새 토큰 성공, Secret 본문 없는 허용/거부 감사 이벤트를 확인했다. 호스트 root는 키에 접근할 수 있으며 외부 KMS 격리·감사 외부 전달/변조 탐지·HA/DR는 검증하지 않았다.
- `adapters/aws_public_prices.py`는 정확한 RDS PostgreSQL Single-AZ/current-generation 프로필의 공개 시간 단가를 읽는다. 실제 AWS Pricing API에서 출처·SKU·적용일을 수집했다. 누락 범주를 0원으로 채우거나 실행 단가만으로 전체 비용·청구·절감 효과를 판단하지 않는다. 모호한 SKU, 조건부/계층 단가, 잘못된 통화, 불완전 pagination, 만료를 거부한다.
- SQS 운송과 단계 처리기를 추가했다. 별도 실계정 시험에서 전용 큐 두 개를 생성해 outbox→수신→PG 쓰기 게이트→원자 완료, 중복 접수와 DLQ 이동·익명 발행 거부를 확인한 뒤 두 큐의 삭제를 확인했다. 시험 주체는 운영자 IAM 사용자이며 호스팅 워커의 최소 권한 역할·운영 배치 자격은 아니다.

후속 상세 과정은 비공개 로컬 기록에만 보관한다. 설정 검사·실제 부정 시험·제품의 전 과정 운영 자격을 합산하지 않는다. 실제 클라우드 간 앱·DB·파일 이전과 운영 SLO는 계속 미자격이다.

여섯 영역을 같은 계획·revision·근거 계약으로 연결하는 첫 구현을 추가했다. **아래 구성 요소의 시험 통과와 전체 이전의 운영 자격은 구분한다.** 상세 실행 기록·사진·자원 식별자·개발 과정은 비공개 `.local-notes/`에만 보관한다.

| 영역 | 새 코드와 연결 | 확인한 범위 | 남은 운영 연결 |
| --- | --- | --- | --- |
| 앱·DB 이전 | 데이터 검사 어댑터 + `application/migration_phases.py`, `adapters/postgres_write_gate.py` | 서로 다른 PostgreSQL 인스턴스의 실제 초기 복사·변경분·barrier·7개 테이블·시퀀스·파일·세션 비교, 대상 신규 쓰기 후 역방향 복구. 별도 시험에서 저장 승인·PG 실행권/효과 원장→제한 역할의 실제 쓰기 정지 연결 | 일반 writer 조사·원격 fencing, 실제 AWS→온프렘 DB/파일·고정 진입점, 전체 이전 어댑터·실환경 등록·호스팅 worker 통합 |
| 보안·거버넌스 | 기존 guard + `application/migration_readiness.py`, `domain/evidence.py` | 출발지·목적지 인가 분리, 불변·유한 근거 입력, 기존 폐기·보류 게이트 보존 | 기업 인증·독립 실행 broker·외부 환경 통제 자격 |
| 목적지 기능 | `examples/consultation/` | 실제 TLS PG 연결, 잘못된 CA/비밀번호 거부와 복원, 비루트·읽기 전용 이미지 재시작 후 데이터·파일 보존. S3 소유자/KMS/checksum은 SDK 대체물 시험 | S3/KMS·온프렘 비밀 저장소·암호화·감사·HA/복원 통합 자격 |
| AI·레지던시 | `domain/ai_residency.py`, `application/ai_gateway.py` | 처리·저장·로그·복제·지원 접근의 위치 규칙, 서버 분류, dispatch 직전 재검사, endpoint 바인딩, 자동 fallback 금지 | 실제 Bedrock/vLLM·품질·위치·전송·호스팅 gateway/사용량 통제 |
| 에이전트·샌드박스 | `domain/sandbox_artifacts.py`, `application/sandbox_admission.py` | 원래 요청 전체와 source/patch/tests/image digest 결합, 동일 bytes의 agent/verifier 별칭 거부, 변경 시 이전 근거 무효화 | 팀원 담당 Harbor 실행·실제 egress/독립 verifier·서명/배포 readback |
| 비용·횡단 관측 | `domain/costs.py`, `application/cost_advisor.py`, `adapters/aws_public_prices.py`, `otel_collector.py`, `otlp_projection.py` | 6개 운영비·3개 이전비의 비교 계약,RDS 실행 시간 단가의 실제 공개 API 수집. 실제 pinned Collector·mTLS/bearer·앱 OTel SDK·환경별 신원 고정·민감 필드 제거 | 남은 가격 범주/실제 사용량·청구 수집, metrics/logs/trace backend·수집 손실·HA, 변경 전후 SLO 비교 |

`domain/migration_program.py`는 최소 **24개 의무**를 유지한다. `domain/dependency_requirements.py`는 등록된 DB·파일·워커·큐·신원·Secret·AI·관측·진입점과 쓰기 관계에서 추가 의무를 생성한다. 조사 revision 변경은 프로그램 digest를 변경한다. 선언한 요구나 용량 초과를 조용히 생략하지 않는다. 조사 내용의 사실성·목적지 mapping과 실행 가능성은 별도 검증이다.

React에는 여섯 영역의 필수 의무·근거·미검증을 표시했다. 해당 AWS·VM 실행의 짧게 유효한 HTTPS 근거만 재사용하며 다른 앱의 로컬 시험 결과를 이 실행의 PASS로 복사하지 않는다. 시험 자원이 종료되면 현재 근거도 만료된다.

[단계별 실행 계약](migration-phase-execution.md)은 준비·동기화·리허설·쓰기 배출·전환·전환 후 점검을 구분한다. 미래 의무는 보존하며 기존 실행기의 기본 G7 기준은 유지한다. 프로그램/단계의 불변 PG 저장, 단기 명령 허가, 단계 워커의 원자 완료·중복 전달·응답 유실 복구와 실제 DB 게이트 변경을 시험했지만, 이 시험의 verifier 인증과 일부 근거는 대체물이며 전체 데이터 이전의 운영 자격이 아니다.

### 상담 reference workload

별도 상담앱은 PostgreSQL·WebSocket·비공개 첨부·일회용 시험 초대·고객/상담원 인가·요청 멱등성을 사용한다. 실제 Chrome에서 실시간 전달, 다른 고객 접근 거부, 한글 첨부, 오프라인 재시도, DB commit 후 응답 유실, 재조회·로그아웃·모바일을 확인했다. 관리자 DB 자격을 잘못 전달하면 실행을 거부한다. 관리 도구·schema·Docker CLI는 앱 이미지에서 제외한다.

이 앱은 합성 데이터의 재현용이다. 기업 SSO, 금융 서비스 인증, 일반 앱의 자동 변환, WebSocket 연결 자체의 무중단 유지 또는 제품의 ZIP→자동 이전 완료를 뜻하지 않는다. 앱에 AI gateway를 연결하지 않았을 때는 미연결로 응답한다. 상담 데이터 전환은 테스트의 운영자 setup과 ASGI 요청으로 수행했으며 Sova 저장 계획·승인·워커에 조립한 전체 경로가 아니다. 정상 DB 연결에서 진행 중인 파일 저장·메타데이터 확정을 쓰기 정지가 기다리는 것을 실제 동시 요청으로 확인했다. 로그인·로그아웃도 같은 게이트를 따른다. DB 연결 유실 후 원격 객체 요청이 계속되는 상황의 fencing, 일반 객체 이전 경계는 후속 자격 항목이다.

### 최신 검증 범위

최신 Python **929개 통과·1개 skip**(실제 독립 PG·TLS 논리 복제·Collector·ARM64 컨테이너 opt-in 포함), React **33개** 통과와 빌드를 확인했다. skip은 별도 실계정 SQS 시험이며 앞선 해당 시험의 실제 통과 기록과 구분한다. 상담앱 JavaScript **3개** 및 실제 브라우저 **11개 시나리오** 통과는 앞선 기록이다. Starlette TestClient의 httpx 사용 중단 예정 경고 1개가 있다. Linux ARM64·AMD64 이미지는 로컬에서 빌드했다. 이번 후속 검증에서 AWS 이미지 업로드나 ECS/RDS 생성은 하지 않았으며, 단기 SQS 시험 큐 두 개만 생성·삭제했다.

앞선 2시간 AWS·VM 시험 자원은 기한에 따라 정리됐고 오류가 없었다. 기존 계정의 모든 자원이나 청구액이 0이라는 뜻은 아니다.

최신 실제 브라우저는 큰 ID를 포함한 11개 흐름을 통과했다. 그 이전 한 차례의 상담원 연결 대기 초과는 원인이 확정되지 않았으며, 새 초대코드·별도 브라우저 재검증과 구분해 로컬 기록에 보존한다.

---

**환경 이전 UI 복원:** React 첫 화면에 AWS→Lima VM 경로·응답 관측·전환/복귀·단계 이력을 추가했다. `demo/migration_bridge.py`가 고정 localhost upstream(기본 8790)의 별도 쿠키를 보관하고 운영자 인증·origin proof 뒤에서만 호출한다. 승인한 실행본 digest·경로 revision을 기존 프리뷰의 실행 잠금 안에서 재검사한다. 만료·정지·미검증 시 변경을 차단하며 자원을 자동 생성하거나 등록을 연장하지 않는다. 11/1 조회에서 과거 AWS 시험 태스크는 `MISSING`이었다. UI 연결·대체물 HTTP 시험은 새 AWS 실배포 검증이 아니다. 범위는 미리 실행된 무상태 앱의 시험 요청 경로 변경이며 DB·세션·ALB/DNS 이전은 포함하지 않는다.

**후속 실제 환경 재가동:** 운영자 요청에 따라 별도 태그·등록·2시간 기한의 AWS Fargate 시험 태스크와 Lima VM 컨테이너를 새로 준비했다. 기존 네트워크의 확인된 서브넷을 사용하며 이전 참조 태스크가 사라져도 준비할 수 있게 했다. 실제 HTTPS 요청, VM 전환 4단계, AWS 복귀를 직접 검증한 뒤 React의 승인창·전환·업무 요청·복귀도 실제 환경에서 확인했다. 준비 과정에서 확인된 한글 요청의 UTF-8 전송 문제를 수정하고 HTTP 회귀 시험을 추가했다. 종료 시각의 앱 자체 종료와 별도 태그 검증 정리 작업을 함께 예약했다. 게임·업무 DB·공개 DNS는 변경하지 않았다. 현재 서버 수명과 상세 기록은 비공개 실행 등록을 기준으로 하며, 이 검증도 앱·DB·세션 전체 이전 또는 무중단 자격을 의미하지 않는다.

**후속 UI 통합:** [React 운영 콘솔](../console/README.md)을 추가했다. 동일 origin의 운영자 인증으로 로컬 프로세스 지도와 k3s 보안 대응을 선택한다. 실행 backend와 앱 신원을 합친 것은 아니다. Python 전체 **579개**(실제 임시 PG 110개), 프론트엔드 **17개** 시험과 실제 읽기 전용 브라우저·모바일·오프라인·로그아웃 검증을 통과했다. 최신 UI 작업에서도 앱의 격리 상태와 기존 작업·효과·경로·보류 기록을 유지했다. 상세 개발기록은 비공개 `.local-notes/react-console-validation-20261101/`에 보존한다.

**최신 체크포인트:** 아래 표가 현재 범위다. 뒤의 265·303·344개 결과는 이전 단계의 이력이며 현재 테스트 수가 아니다. 로컬 보안 콘솔과 PostgreSQL 보안 대응은 연결했지만, 기존 AWS·VM 프리뷰 전체를 새 제어면으로 교체한 상태는 아니다.

| 영역 | 코드 | 확인한 범위 | 남은 연결 |
| --- | --- | --- | --- |
| 독립 패키지·CLI | `pyproject.toml`, `interfaces/cli.py` | 독립 가상환경·입력/거부·설치 시험 | 운영 API·배포 이미지 |
| 시스템 그래프 | `domain/system_graph.py` | 범위·revision·유효기간·digest·SCC·잠재 영향 | 인증된 조사·실측 관계·DB 저장 |
| 이식성 검토 | `application/portability.py` | 등록된 주장에 따른 검토 단위·의무·차단 조건 | AI·비용·실행 가능한 계획 컴파일 |
| Kubernetes 입력 | `adapters/kubernetes/inventory.py` | 제한된 List snapshot·namespace/app/UID·PVC·선언 관계·값 제거 | 일반 클러스터 watch·운영 자격 |
| Kubernetes 직접 조사 | `domain/discovery.py`, `application/kubernetes_discovery.py`, `adapters/kubernetes/https.py` | 운영자 등록·scope/UID/페이지/권한 재조회·localhost TLS·전용 k3s의 제한 수집/RBAC·폐기 | 기업 OIDC·중앙 등록 운영·다중 클러스터 watch |
| Harbor 작업 준비 | `domain/sandbox.py`, `adapters/sandbox/harbor.py` | digest 고정·만료·초기 통신 차단·분리 검증 TOML·binding | 설치/버전 고정·실행·AI gateway·산출물·provider 격리 |
| 계획·승인·snapshot | `postgres_plans.py` 등 | 실제 임시 PG, 불변 저장·RLS·승인 재조회 | 기업 인증·웹·운영 TLS/복원 |
| 접수·outbox | `postgres_operations.py` 등 | 원자 접수·멱등·리스·relay·프로세스 종료 | 실제 큐 publisher/consumer |
| 실행권·효과 | `postgres_execution.py`, `postgres_effects.py` | epoch/token·CAS·미해결 효과 barrier·조회 복구 | 실제 provider quiescence proof·원격 fencing |
| 로컬 동적 지도 | `demo/graph_demo.py` | 등록된 실제 Python 프로세스·의존 호출·부분 격리·공통 그래프 연결 | Kubernetes 실행·OTel·제품 API |
| AWS·VM 프리뷰 | `demo/server.py` 등 | 과거 실제 HTTPS·SG 격리·준비된 앱 간 경로 변경 | 독립 환경 설치·데이터 이전·HA·상시 운영 |
| 보안 거버넌스 | `domain/governance.py`, `application/governance.py`, `postgres_governance.py` | 필수 통제 판정·독립 보류·분리 해제·실행 직전 재검사·PG 이력/CAS/RLS·앱별 보류 집합 DB 잠금 | 기업 인증·권한 broker·범용 예외·외부 환경 자격 |
| 보호 수준 비교 | `domain/protection_parity.py`, `protection_profiles.py`, `application/protection_parity.py` | provider/어댑터/실제 근거 구분·최소 프로필 고정·만료/드리프트/보류 차단·PG 정책/판정 이력 | 전체 보호 probe·호스팅 실행 경로의 필수 조립 |
| 발행자 신뢰 | `domain/verifier_registry.py`, `postgres_verifier_registry.py` | 실제 Ed25519 근거·공개키 등록/폐기·분리 승인 계약·PG 역할 거부 | 기업 승인 신원·독립 signer·키 보관/회전 운영 |
| RDS 보안 조사 | `adapters/aws_rds_security.py` | 정확한 DB 등록·읽기 전용 SDK·값 제거·6개 설정 검사. SDK 응답 대체물 시험 | 실제 AWS 계정 읽기 자격·런타임 접근/TLS/감사/복원 |
| 제한 보안 대응 | `application/security_response_runner.py`, `demo/security_console.py` | 실제 로컬 k3s 격리·대체 기동·시험 경로 전환·PG 원자 완료/실행권 반환·응답 유실 조회 복구 | 독립 권한 broker·일반 앱·DB/세션·외부 환경 이전 |
| 로컬 콘솔 | `demo/operator_auth.py`, `bounded_http.py`, `security_web/` | 일회용 소유자 로그인·origin 전용 proof·세션 만료·유한 HTTP 자원·설정 비교·실제 브라우저 흐름 | 공개 운영 API·기업 SSO·사용자/조직 인가 |
| 계획별 Kubernetes 권한 | `demo/kubernetes_access.py` | 실제 RBAC·admission·다른 앱 영향·권한 회수, 제한 토큰으로 실제 네 효과 완료 | 콘솔의 운영 권한 발급 연결·계획 기한 broker·외부 클러스터 자격 |
| 제어 기록 복원 | 비공개 검증 도구 | 동일 snapshot dump/restore·전체 행/hash·FORCE RLS·폐기 상태 보존 | 암호화 원격 백업·앱 DB 이전·HA/DR·운영 RPO/RTO |
| DB/AI 이전·비용·거버넌스 | `docs/design/` | 목표 계약 | Sova 통합·실환경 자격 |

핵심 패키지에 Sky Python import는 없다. 이전 AWS 프리뷰의 준비 스크립트는 기존 환경 자원을 참고하므로 독립 일반 설치와 구분한다. 이전 AWS·VM 웹 프리뷰는 SQLite를 유지한다. 새 로컬 보안 콘솔은 PostgreSQL 계획·작업·효과·보류와 연결했다. 이를 전체 제품 호스팅 연결 완료로 표현하지 않는다.

## 검증 경계

검증 숫자는 로컬 개발기록의 해당 실행을 따른다. 실제 임시 PG 시험, 로컬 HTTP 프로세스 시험, 외부 어댑터 대체물 시험을 구분한다. 이번 재구성으로 실제 Kubernetes 이전·Harbor 모델 실행·DB 이전·무중단·공격 탐지가 완료됐다고 주장하지 않는다.

## 이번 재구성 검증

독립 Sova 가상환경에서 전체 **265개** 시험이 통과했다. 이 중 **64개**는 Unix socket 전용 임시 PostgreSQL 17.11의 실제 저장·RLS·실행 시험이다. 나머지는 계약·대체 어댑터·로컬 HTTP 프로세스 시험이다. 시험 클러스터는 종료·삭제했으며 AWS 자원은 변경하지 않았다. Harbor TOML은 Python 파서와 계약 시험으로 확인했으며 Harbor runner에서 실행한 결과는 아니다.

## Kubernetes 조사 후속 작업

[읽기 전용 조사](kubernetes-discovery.md)는 운영자 CLI로 연결했다. 등록한 주소와 CA에 직접 HTTPS GET을 보내지만, 이번 통합 시험은 실제 Kubernetes가 아닌 로컬 TLS 시험 서버다. S1 전체 완료나 Kubernetes 운영 자격으로 표시하지 않는다. 등록 계약은 일반 `EnvironmentRegistration`의 중앙 저장·폐기 관리와 아직 연결하지 않았다.

후속 검증에서는 전체 **303개**가 통과했다. 임시 PostgreSQL 64개, 새 Kubernetes 조사 계약 31개·localhost TLS 통신 7개를 포함한다. 운영자 CLI의 TLS 조회·잘못된 토큰 파일 권한 거부도 확인했다. 실제 k3s/RBAC 검증은 포함하지 않는다. 임시 DB와 TLS 서버는 정리했다.

당시 담당 조정: Harbor 실행 연동은 팀원 담당으로 분리했다. 이후 보안 수집·콘솔·발행자 검증을 제한된 범위로 연결했으며 최신 범위는 맨 위 표를 따른다. 기존 guard 없는 실행 경로가 자동으로 보호되는 것은 아니다.

보안 거버넌스 추가 후 전체 **344개** 시험이 통과했다. 실제 임시 PostgreSQL 시험 **74개**와 새 거버넌스 계약 시험 **31개**를 포함한다. 보류의 동시 해제·RLS·역할 분리·저장 계획 guard 보존·apply 직전 차단을 확인했으며 외부 provider·신원 인증은 시험 대체물이다. 임시 DB는 종료·삭제했다.

## 보안·워크로드 대응 연결 검증 (일시 중지 체크포인트)

[검증 현황](security-workload-validation.md)에 실제 범위를 정리했다. Kubernetes 값 제거 posture 수집, 관측·이벤트 PG 원장, 중복 사고 보류, 목적별 대응 계획·실행 상태, 기존 효과 원장 연결, 로컬 k3s 격리·대체 기동·gateway 전환, 발행자 Ed25519 검증·PG 저장, 검증용 지도와 읽기 전용 재시작 복구를 추가했다.

실제 브라우저 대응 흐름·RBAC 폐기·namespace UID 재생성 거부를 검증했다. 같은 로컬 클러스터의 두 namespace·무상태 fixture에 한정하며 클라우드 간 이전·일반 앱·무중단·기업 인증 자격과 구분한다. 당시 미완료였던 운영자 bootstrap은 후속 2시간 작업에서 구현했다. 공개 운영 인증을 대신하지 않는다.

## 2시간 재개 작업의 회귀 결과

전체 **563개 통과, 실패·오류·skip 0**을 확인했다. 이 중 **109개**는 Unix socket 전용 임시 PostgreSQL 17.11을 사용하는 시험이다. 임시 DB는 종료·삭제했다. Ruff, Python 3.11 구문 호환 검사, 콘솔 JavaScript 구문 검사, 배포 wheel의 SQL 마이그레이션 12개 포함 여부도 확인했다. Python 3.11 런타임 전체 시험을 수행했다는 의미는 아니다.

실제 환경 시험은 로컬 k3s의 제한된 무상태 앱 대응·읽기 권한/네트워크 거부·발행자 폐기, 별도 제어 DB의 완료 영수증/실행권 반환과 메타데이터 복원까지다. RDS 수집은 AWS SDK 응답 대체물 시험이며 실계정 검증으로 합산하지 않는다. 전체 provider 보호·독립 broker·일반 앱 데이터 이전·무중단·기업 인증은 미완료다. 상세 범위는 [검증 현황](security-workload-validation.md)을 따른다.

## 2026-11-03 · 보안 운영 연결

- 제한적 Kubernetes 이미지 교체·독립 runtime digest 확인을 추가했다. 전용 kind와 전용 AWS EKS에서 실제 HTTP·RBAC 거부를 확인했다. [어댑터 범위](kubernetes-image-patch.md)를 따른다.
- 등록된 감시 작업·최신 입력 CAS·DB 리스·실패/주의 경보 outbox·제한 DB 역할·고정 CLI 워커를 연결했다. 실제 PG·서명·별도 프로세스로 검증했다. [감시 운영 조건](security-monitoring.md)을 따른다. CronJob은 배치 예제이며 실제 상시 예약 배치와 외부 알림 채널 운영을 자격화한 것은 아니다.
- `sova-security` 0.9.0의 팀 T33 탐지 계약 연결을 소비한다. 합성 관측을 실제 서명·PG 보류에 연결했다. 실제 외부 탐지기의 상시 수집 완료를 뜻하지 않는다.
- 기존 실행 조정기의 승인·근거·실행 인가 콜백에서 명시적인 False나 임의 truthy 값이 허용으로 처리되지 않도록 보강했다.

세부 과정·실행 등록·자원 식별자는 비공개 로컬 기록에 남긴다. 각 구성 요소의 검증을 서비스 전체의 프로덕션 운영 자격으로 합산하지 않는다.
