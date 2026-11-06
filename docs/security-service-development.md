# 보안 서비스 소비 개발 기록

2026-11-06 · security 0.11.0 · platform `f602b39a949b99f3e2e7be901103063e78a52a70`

- 요구: SEC-PATCH-05·06·07·08, POL-09·11, SG-2·3.
- 기반 Sova: `7d79d6517730e408d3663815e91e70e626806c88`.
- 수정: `src/sova/security/application/remote_program.py`,
  `tests/integration/test_security_patch_execution.py`, pyproject의 정확한 패키지 버전.
- 이유: 기존 effect 원장·승인·사후 검사 조합을 유지하며 판정 공급자만 선택적으로 원격화한다.
  패키지 코드를 복제하거나 서비스가 실행 권한을 가져가는 구조를 피한다.
- 시험: `python -m pytest tests/integration/test_security_patch_execution.py -q` 31 PASS.
  실제 SQLite 원장을 사용하되 권한/측정/전송은 합성이다. 신규 효과 전 서비스 장애·승인 철회는
  효과 0회, 효과 후 서비스 장애·철회·만료는 APPLIED 유지와 hold, 재시도 중복 효과 0회를 확인한다.
- 전체 Linux 실제 PostgreSQL 17.11·OPA 1.22 회귀: 1,102 PASS, 3 SKIP.
  skip은 실제 컨테이너 이미지/Collector/AWS SQS 등록이 필요한 세 시험이다.
- 미검증: Sova 실행 actor와 workload 신원의 실제 매핑, T7 서비스 audience,
  운영 verifier/클라우드 거부/복구 근거. 명시적 사용자 위임 없이 actor를 바꾸지 않는다.
- 상태: 구현·소비 모의 검증·로컬 SQLite/PG 원장 실측. 플랫폼 적용/운영 인수는 보류.

상세 설계·소스 SHA·실패 실험·서비스 실행 결과는 security의
`docs/development/security-service-2026-11-06.md`와 ADR을 정본으로 참조한다.

## 현재 기준 소비와 독립 CI

- 추가 기준: platform `b19488e2debbee8bbe120f1309eadbe19df85b6f`.
  앞선 f602b39도 별도 소비 기준으로 유지한다. schema 추출 기준 505d451과 구분한다.
- security producer `b3cbbe62cfdc2f762a4c223d13bb24c88963d620`을 고정한
  `security-consumer` workflow를 추가했다. producer 잠금 파일의 시험 의존성과 실제 wheel을
  설치하고 기존 패치 접수 시험을 수행한다. main의 미출시 패키지나 PyPI 동명 패키지로
  암묵 대체하지 않는다. 이 CI는 클라우드/전체 Sova 인수 시험이 아니다.
- 최신 로컬 전체 회귀: 1,102 PASS/3 SKIP, 107.56초. security 775 PASS와 함께 실행했다.
- 상태: CI 구성 완료, 원격 실행 결과 확인 중. 결과를 확인하기 전에 CI 통과로 표시하지 않는다.

## SOVA-SVC-02: 두 DB와 독립 보안 프로세스의 실제 연결

- 요구: SEC-PATCH-05·06·07, POL-09·11, SG-2·3. 플랫폼 기준 c225c86, 이전 두 기준도 유지.
- 생산자: `a33863c474bd170dc3aea7d7179953d17d8755d1`. 해당 security의
  [원격 CI](https://github.com/Softbank-Hackathon-Finals/security/actions/runs/42203712045)는
  세 플랫폼 계약·Python 3.11/3.14·secrets 모두 통과했다.
- 수정: `tests/security_review_runtime_support.py`, `test_security_review_runtime.py`, 기존 PG
  패치 fixture, 소비 manifest/CI. 운영 실행기나 platform 코드는 수정하지 않았다.
- 실제 Sova PostgreSQL 승인·lease·effect·hold와 별도 security PostgreSQL의 등록·원본
  Ed25519 서명·현재 신뢰를 연결한다. 보안 프로세스는 독립 TLS와 SELECT 전용 tenant 역할을
  사용한다. 시험용 TLS/DB 도구는 명시적으로 고정한 producer checkout에서 읽으며 실제 패키지는
  설치된 wheel을 소비한다. source 경로나 버전을 자동 추측하거나 src를 import 경로에 넣지 않는다.
- 8개 시나리오: 정상/서비스 사전 중단/응답 후 승인 철회/호스트 등록 철회/사후 서비스 중단/
  사후 issuer 철회/실행 이전 사후 관측/provider 응답 유실. 사전에는 효과 0회, 사후에는 기존
  APPLIED 또는 UNKNOWN과 host hold를 유지하며 재접수도 추가 apply가 없다.
- 첫 실행은 7 PASS/1 FAIL. 철회는 차단했지만 시험 호스트 callback이 저장소 예외를 그대로
  전달해 예상한 공통 오류와 달랐다. 현재 등록 조회는 revoked를 명시적으로 읽고 None을 반환해
  기존 소비자의 현재 등록 검사가 거부하도록 맞췄다. 거부를 허용으로 바꾸지 않았다.
- 기존 SQLite 및 PG 패치 시험과 합쳐 **46 PASS, 56.83초**. 전체 회귀와 소비 CI도 수행한다.
- 실제 컨테이너 이미지 적용/취약점 스캔/Tailscale·Kubernetes/CNI는 이 시험에서 모형 또는
  미실행이다. 호스트 registrar의 운영 writer 및 실행 접수 잠금 배선은 별도 플랫폼 인수다.

### 전체 회귀 결과

- **1,110 PASS / 3 SKIP / 경고 1건, 152.44초**. skip은 앞선 실제 이미지·OTEL Collector·AWS SQS
  등록 요구와 같다. 새 서비스 8개 시험은 실행됐다.
- 경고를 `-W error`로 재확인했을 때 기존 consultation 시험 두 파일의 수집 단계에서
  Starlette TestClient의 기존 httpx 사용 중단 예정 안내가 원인임을 확인했다.
  [Starlette 공식 안내](https://www.starlette.io/testclient/)는 httpx2 사용을 권한다.
  이 엄격 경고 실행은 수집 실패이며 통과로 집계하지 않는다. 보안 판정·서명·원장 실패가 아니며
  데모 시험 클라이언트 의존성 갱신 사항으로 구분한다. 경고를 숨기는 전역 필터는 추가하지 않았다.

## SOVA-SVC-03: 최신 보안 경계와 실제 서비스 컨테이너 소비

- 생산자 `269e1e509245bd5bb1cd62a753f7b3ef5e860992`, 플랫폼 기본 9e0d6a5 및 이전 세 SHA.
  단일 audience·원래 수명 600초, DB 간접 권한 거부, 고정 이미지 build를 포함한다.
- 기존 Sova fixture의 중복 프로세스 코드를 제거하고 명시적으로 고정한 producer의
  `review_process`를 소비한다. `ExitStack.close`로 자신의 프로세스/컨테이너만 중단하며,
  사전·사후 장애 주입 뒤 이중 정리에도 추가 효과를 만들지 않는다.
- 로컬 실제 PG/TLS + SQLite/PG 패치 회귀 **46 PASS, 57.21초**. 생산자 전체는
  잠금 Python 3.14/PG/OPA/API/최신 플랫폼에서 **847 PASS, 120.58초**였다.
- 소비 CI는 process/container 두 모드로 나눈다. container 모드는 정확한 producer의
  clean commit·lock·wheel만으로 이미지를 만들고 image ID/commit을 고정한다. 이미지나
  배포 자격을 외부 레지스트리로 발행하지 않는다. 원격 결과는 확인 후 기록한다.
- 실제 컨테이너인 것은 **보안 서비스**다. 패치 대상 provider의 이미지 적용·취약점 측정과
  TokenReview 공급자는 여전히 모형이다. 네트워크/CNI·운영 인증·팀 실행기 인수와 구분한다.
