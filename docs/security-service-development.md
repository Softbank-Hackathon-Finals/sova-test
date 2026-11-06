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

## SOVA-SVC-04: 짧은 승인 유효기간 안의 현재 증거 재검사

- `d1865f3` [소비 CI](https://github.com/Softbank-Hackathon-Finals/sova-test/actions/runs/42210670359)는
  process 통과, container **4 FAIL / 35 PASS**였다. 실행 전 재검사에서 원래 permit이
  29~92ms 만료되어 정상 효과도 거부됐다. 만료 검사와 승인 유효기간은 유지한다.
- 생산자를 `2898f54613874142c074a33cc2eb2f13461ce420`으로 고정한다. 명시적인 현재 전체
  collection 인증 계약을 추가해 동일 요청의 중복 원본 수집을 5회에서 3회로 줄였다.
  원본 서명·등록·현재 철회 및 collection 삭제 검사는 생략하거나 캐시하지 않는다.
- 생산자 전체 회귀 **867 PASS, 115.02초**. Sova 원장·접수·permit 코드 변경은 없다.
  수정 후 process/container 소비 CI를 다시 실행하며 결과는 확인한 뒤 기록한다.

### SOVA-SVC-04 결과 및 다음 생산자

- `4987c24` [CI](https://github.com/Softbank-Hackathon-Finals/sova-test/actions/runs/42212461099)
  process/container 모두 통과. 실제 컨테이너 소비 **39 PASS, 31.89초**로 앞선 만료 실패가 해소됐다.
- 다음 생산자 `c80b51842ee21ff37a6fa20c416bf637113617a4`를 고정한다. 공통 TLS 요청 기한/metadata 한도,
  관리 함수 EXECUTE 거부, 다섯 번째 플랫폼 기준 a610bbf를 포함한다. source/schema 계약은 유지한다.
- security 전체 **881 PASS**와 최신 플랫폼/T7/T10 **32 PASS**. DB 관리 함수 생산자 `a9b68a4`의
  [CI](https://github.com/Softbank-Hackathon-Finals/security/actions/runs/42213904868)도 모두 통과했으며
  PostgreSQL 18.4 경계 **42 PASS, 11.39초**, 실제 이미지/T10 연결 **11 PASS, 39.47초**였다.
- Sova 소비 결과는 해당 고정 SHA의 process/container CI에서 확인한다.

## SOVA-SVC-05: 감사 파일 부분 기록의 실행 전후 소비

- 이전 `b308a2d` [CI](https://github.com/Softbank-Hackathon-Finals/sova-test/actions/runs/42214730368)
  process/container 모두 통과했고 container는 **39 PASS, 43.47초**였다.
- 생산자 `465dc414b040e39566706ae4d95cc81901d37d11`의 전체 CI 성공을 확인하고 고정한다.
  부분 감사 쓰기 이후 새 판정을 거부하는 수정이다. 요구 SEC-PATCH-10, POL-09·10, SG-2.
- 별도 두 PostgreSQL과 실제 TLS 서비스 연결에서 실행 전/후 미완성 JSON tail을 주입한다.
  실행 전에는 effect 0회, 실행 후에는 기존 APPLIED와 hold 및 재시도 effect 1회를 요구한다.
  손상된 원본 bytes가 수정되지 않았는지도 검사한다. 디스크 전체를 소진시키는 시험은 아니다.
- process/container 소비 CI로 확인한다. 현재 producer 이미지의 취약점 검사는 별도 **BLOCK**이며
  이 기능 시험 성공을 운영 배포 승인으로 해석하지 않는다. OS/installer 후속 변경은 별도 검증 후 갱신한다.

### SOVA-SVC-05 결과

- `c7b9245` [CI](https://github.com/Softbank-Hackathon-Finals/sova-test/actions/runs/42219499703)는
  process/container 모두 성공했다. 실제 컨테이너 소비는 **41 PASS, 64.34초**였다.

## SOVA-SVC-06: 감사 이후 권한 확인과 여섯 번째 플랫폼 기준 소비

- producer `d9c878f7be63b72a2d693f24af37148776fb7fe2`의
  [CI](https://github.com/Softbank-Hackathon-Finals/security/actions/runs/42223422299) 전체 성공을 확인하고 고정한다.
  Python 3.14 전체 **928 PASS / 1 SKIP, 150.66초**, PostgreSQL 18.4 경계 **42 PASS**,
  실제 서비스 이미지/T10 **11 PASS**, 여섯 플랫폼 기준의 계약 시험을 통과했다.
- 감사 기록 이후에도 원본 증거·검증기 철회·hold를 확인하고 정확히 기록한 report만 반환한다.
  감사 중 신뢰 철회/보류 commit을 실제 PG/TLS 시험에서 거부한다. 기존 consumer API/원장/실행 책임은 유지한다.
- 서비스 이미지에서 불필요한 pip/ensurepip를 제거했다. v2 scanner는 실제 OS 87개와 Python 10개를
  모두 대조한다. 수집은 성공했지만 미수정 OS HIGH 49건 때문에 배포 BLOCK은 그대로다.
- platform 8b12236의 T7 object open·T15 host·T14 부분 증거를 인수 문서에 반영한다.
  작업 PASS를 보안 PASS로 확대하지 않는다. 현재 pin의 process/container 소비 결과는 후속 기록한다.

### SOVA-SVC-06 결과

- `65fc4e0` [CI](https://github.com/Softbank-Hackathon-Finals/sova-test/actions/runs/42224614030)는
  process/container 모두 성공했다. container **41 PASS, 47.84초**.
- 복구된 Ubuntu의 기존 Python 3.12/PG17/OPA 환경에서 전체 **1,112 PASS / 3 SKIP / 경고 1개, 160.22초**.
  skip은 상담 앱 이미지·OTEL Collector·실제 AWS SQS의 별도 환경 등록이다. 보안 서비스 소비는 실행했다.
  기존 Starlette/httpx 사용 중단 예정 경고는 그대로 표시한다. 이 환경은 CI의 잠금 3.14 환경과 구별한다.

## SOVA-SVC-07: 보안 신뢰 이력의 과거 복원과 독립 호스트 보류

- 복구가 철회 기록까지 과거로 되돌릴 수 있는 조건을 시험한다. 실제 보안 PG의 본인 테스트 키 revision 2만
  관리자로 제거해 신뢰 이력 회귀를 주입하고, 기존 독립 Sova PG의 보류/효과 원장은 유지한다.
  전체 백업·CNPG PITR·재해 복구를 실행한 시험은 아니다.
- 재복원된 유효한 과거 신뢰 아래 원격 preflight가 다시 PASS할 수 있음을 확인한다. 서비스에는 외부의
  단조 증가 복구 기준점이 없으므로 이 복원을 스스로 탐지했다고 주장하지 않는다.
- 원격 PASS 이후에도 기존 호스트 보류가 유지되어 재접수가 거부되고 APPLIED 효과는 정확히 1회다.
  시험 후 동일 테스트 키의 철회 revision을 다시 기록한다. 서비스 계정에 삭제/관리자 권한을 부여하지 않는다.
- 실제 두 PG/TLS 서비스의 관련 회귀 **11 PASS, 56.65초**. CI process/container에서도 검증한다.
  운영 복구 전에는 복원 대상과 독립된 실행 차단·원장 조정·현재 키/철회 재등록이 필요하다.

### SOVA-SVC-07 CI 결과

- `e14c17e` [CI](https://github.com/Softbank-Hackathon-Finals/sova-test/actions/runs/42227270467)
  process/container 모두 성공. 실제 서비스 container 소비 **42 PASS, 51.83초**.

## SOVA-SVC-08: 연결 전 DB 정책과 일곱 플랫폼 기준 소비

- producer `f25433a3905737c97e8aab3a6ced6832c8d6d7eb`의
  [CI](https://github.com/Softbank-Hackathon-Finals/security/actions/runs/42229814068) 전체 성공을 확인하고 고정한다.
  Python 3.14 **983 PASS / 2 SKIP, 154.27초**, PG18.4 권한 경계 **42 PASS, 8.66초**,
  실제 TLS/HBA **1 PASS, 1.11초**, image/T10 **11 PASS, 27.88초**, 일곱 기준 계약을 통과했다.
- 변경은 연결 전 TLS/단일 DB 경로 검증, DB별 HBA 규칙의 운영자 렌더링, bb17486 WorkflowHost 계약,
  전체 기준에서 생성하는 wheel 검증 명세다. 기존 Sova 승인·원장·실행 책임은 유지한다.
- 인계 문서의 오래된 producer SHA를 정정하고 T19의 같은 출발지 DB 사용 정정, 별도 DB 신원 확인,
  새 host의 SHIFT 책임 분리, shadow 일치와 실제 PASS의 차이를 명시한다.
- 새 pin의 process/container 소비를 CI에서 재검증한다. 결과 확인 전에는 완료로 집계하지 않는다.
  이미지 취약점 판정은 HIGH 49건으로 BLOCK이며 이 소비 시험은 운영 배포가 아니다.

### SOVA-SVC-08 pin 불일치와 수정

- `ca75e6e` [CI](https://github.com/Softbank-Hackathon-Finals/sova-test/actions/runs/42231127867)는
  **31 PASS / 11 ERROR**였다. workflow만 갱신되고 통합 manifest가 이전 SHA여서 producer checkout
  검증에서 거부됐다. 서비스 연결에 도달하지 않은 설정 오류이며 이 실행을 통과로 취급하지 않는다.
- 정확한 SHA와 일곱 플랫폼 기준을 manifest에 반영한다. CI는 그 manifest의 SHA만 읽어 checkout하며,
  설치한 package version/PLATFORM_BASELINES도 대조한다. 다음 갱신부터 중복 pin이 갈라지지 않게 한다.

### SOVA-SVC-08 수정 결과

- `319fe38` [CI](https://github.com/Softbank-Hackathon-Finals/sova-test/actions/runs/42231908277) 성공.
  process **42 PASS, 57.98초**, 실제 서비스 container **42 PASS, 65.89초**.
  이 결과는 producer f25433a 및 일곱 플랫폼 기준 manifest를 소비한 결과다.

## SOVA-SVC-09: shadow 일치와 실행 자격의 구분

- 기존 시험은 일치와 장애를 확인했지만 UNKNOWN/FAIL의 일치를 직접 확인하지 않았다.
  합성 위험 평가 근거를 각각 UNKNOWN/FAIL로 바꿔 양쪽 판정이 일치하더라도 실제 실행 접수가
  거부되고 effect가 등록되지 않음을 검증한다. 원격/로컬 정책과 실행 코드는 변경하지 않는다.
- 처음 두 시험은 빈 원장을 None으로 가정한 시험 코드 때문에 실패했다. 실제 원장 계약은
  EffectConflict이므로 이를 바로잡았다. SQLite/직렬화 경계 회귀 **33 PASS, 1.17초**.
- GitHub에서도 인계 경로가 열리도록 저장소 밖의 상대 링크를 고정 producer URL로 바꿨다.
  실제 두 DB/TLS container 소비는 같은 CI에서 다시 확인한다.

### SOVA-SVC-09 결과

- `1fae0e4` [CI](https://github.com/Softbank-Hackathon-Finals/sova-test/actions/runs/42232541073) 성공.
  process **44 PASS, 64.73초**, container **44 PASS, 56.71초**. UNKNOWN/FAIL끼리의 shadow 일치는
  실행 자격이 되지 않는다. 이 실행의 producer는 f25433a다.

## SOVA-SVC-10: 여덟 플랫폼 기준과 전용 DB 저장 생성 제한 소비

- producer를 `5ddf281b31568e49cdd1a2c993e8d8172cdc7b1e`로 고정한다. manifest를 CI checkout의
  단일 출처로 유지하고 기본 플랫폼 및 계약 목록에 `98885a69999398bfe3f49fbc8324a7b19aae3e16`을 반영한다.
- T19 현재 공개키 원장과 승인 후 철회를 실제 플랫폼 코드로 검증했다. T28 운영자 JSONL의
  결과 기록 전 중단/재시작 재호출 경계는 인계 조건으로 남기고 Sova 기존 effect 원장을 유지한다.
- 전용 보안 DB는 PUBLIC TEMP와 세 대형 객체 생성 함수 권한을 별도로 제한한다. 기존 producer의
  owned fixture가 준비/원상복구를 담당하므로 Sova에 관리자 변경 코드를 복제하지 않는다.
  사용자/운영 DB에는 적용하지 않는다. 역할 권한이 drift하면 신규 판정만 보류한다.
- producer의 Python 3.14 **1,008 PASS / 2 SKIP, 160.59초**, 여덟 플랫폼 계약 통과를 확인했다.
  실제 두 DB의 process/container 소비 결과는 아래에 따로 기록한다. 지속 시험의 이전 source를
  새 수정의 검증으로 소급하지 않는다. 이미지의 HIGH 49건/BLOCK은 유지한다.

### SOVA-SVC-10 결과

- `f9d5f42` [CI](https://github.com/Softbank-Hackathon-Finals/sova-test/actions/runs/42239334800) 성공.
  process **44 PASS, 72.83초**, container **44 PASS, 67.71초**. 실제 두 PG와 TLS 소비를 확인했다.

## SOVA-SVC-11: 아홉 플랫폼 기준과 역할별 연결 예산 소비

- producer `ec4aac6c3d839111f76ef7466f7b6fc7fcea1e49`와 platform
  `7edab5312f965bd683a7738e74d49b883190e8da`를 manifest에 고정한다. 앞선 여덟 기준도 유지한다.
- producer는 직접 DB 자격의 연결 수 예산과 현재 drift 검사를 추가했다. 플랫폼 새 공개 서명 원장을
  기존 실제 SQLite/Ed25519 경로로 소비해 원래 만료/현재 철회를 확인했고 26개 계약이 통과했다.
- 새로운 실행기나 발급기는 추가하지 않는다. 기존 Sova effect/hold와 T10/T31 집행 책임을 유지하며,
  T19의 새 양쪽 DB 관측도 만료된 부분 증거로 기록한다. 운영 역할 상한·ports 인수 조건을 보완했다.
- 새 고정 producer의 process/container 실제 소비는 이 commit의 CI로 확인하며 결과를 후속 기록한다.
- producer 전체 CI에서 시험 역할 정리와 autovacuum의 교착이 한 번 관측됐다. 동일한 정리 helper를
  고정 producer에서 읽어 사용한다. 본인 생성 역할의 DDL만 rollback 후 최대 3회 재시도하며
  실제 패치 효과나 시험 본문은 재시도하지 않는다. 운영 제품 경로에는 이 helper가 없다.

### SOVA-SVC-11 결과

- `5415fca` [CI](https://github.com/Softbank-Hackathon-Finals/sova-test/actions/runs/42242378539) 성공.
  process **44 PASS / 66.32초**, 실제 service container **44 PASS / 39.86초**.
  producer ec4aac6, 아홉 플랫폼 기준 manifest, 두 실제 PG/TLS 소비 및 정리 helper를 검증했다.

### 최종 인계 문서 연결

- 코드/서비스 계약 링크는 고정 producer source를 유지하고 후속 CI 결과를 추가하는 개발 기록·인계
  현황은 문서 브랜치로 연결했다. source commit 안에 자기 자신의 CI 완료 기록이 있다고 가정하지 않는다.
- 현재 이미지 실측이 linux/amd64임을 Sova 인계에도 명시한다. ARM64·실제 CNI/발급·T24·운영 복구
  인수는 별도이며 기존 HIGH 49건/BLOCK과 T28 운영자 JSONL의 재시작 경계도 그대로 남긴다.
