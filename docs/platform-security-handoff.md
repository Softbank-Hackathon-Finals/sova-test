# 두 보안 설계의 개인 검증과 platform 인계

2026-11-06 · `sova-security==0.11.0` · platform 현재 기준 `c225c86cf5e408b5fcd016b0e367d3672d1bac44`

앞선 f602b39와 b19488e도 소비 시험으로 유지한다. c225c86은 b19488e 이후 10개 커밋을
검토하고 실제 T10/T19 소비 및 전체 보안 회귀를 통과한 값이다. 운영 배포 자동 갱신은 하지 않는다.

## 사용하는 경로

```text
security (보안 판정·증거 계약의 정본)
  └─ 검증한 wheel + 선택형 제한 보안 서비스
      ├─ sova-test: 기존 승인·작업·effect 원장과 개인 검증
      └─ platform: T5/T14/T19, T10, T11/T15, T24/T31 어댑터로 소비
```

원문 보존·요구사항별 구현 위치는 security의 `docs/architecture-integration.md`와
`docs/proposals/manifest.json`에 있다. Python 코드를 Sova에 다시 복사하지 않는다.
`platform` 자체는 이번 변경 대상이 아니며 플랫폼 통합·운영 인수가 완료된 상태도 아니다.

## 서비스 확장과 현재 호환 기준

0.11.0은 패키지의 검사 로직을 유지하면서 별도 TLS 서비스·현재 workload 인증·테넌트별
읽기 계정·병행 판정과 실행 어댑터를 추가한다. 서비스의 정책/증거/신뢰 등록은 기존의
별도 관리 경로가 담당한다. 서비스는 승인·실행·자격 발급 API를 갖지 않는다.

Sova `RemoteProgramService(client)`를 기존 `with_patch_security_program`에 넣는다.
client는 고정 TLS origin, 기존 발급 경로의 현재 credential, 현재 호스트 등록 조회,
등록된 workload subject, 시계를 요구한다. preflight/postflight 등록을 따로 조회하고
postflight는 기존 실행기가 넘기는 실제 `not_before`와 operation ID에 결속한다.
실행 actor와 workload subject가 다르면 거부한다. 암묵적 사용자 위임은 지원하지 않는다.

기존 Sova 시험은 로컬 SQLite 원장과 합성 전송/측정을 사용한다. 사전 장애 시 외부 효과 0회,
사후 장애·철회·만료 시 기존 APPLIED 효과와 보류 유지, 재접수해도 재적용 없음, 병행 비교가
상태를 바꾸지 않음을 확인한다. 실제 TLS·온라인 서명 토큰 검증기 모형·PostgreSQL 및
독립 프로세스 시험은 security 저장소에서 수행한다. 추가 Sova 통합 시험은 실제 PG의 승인·
lease·effect 원장과 별도 보안 PG를 독립 TLS 서비스로 연결한다. 서명 원본과 현재 등록을 읽으며
서비스 중단·승인 철회·호스트 등록 철회·오래된 사후 관측·응답 유실을 검증한다.
이미지 실행과 측정 내용, TokenReview 공급자는 여전히 시험 모형이다.

platform 소비는 `T10ProgramAuthority`로 원래 `T10GateAuthority`를 감싼다. 원래 계획
digest/`PlanGateSession.fingerprint`, 문자열 profile version, `initial/post_apply`와
application_id를 그대로 사용한다. 프로그램 pre/postflight 축과 혼동하지 않는다.
`load_registration(connection, principal, plan, phase)`과 관련 writer는 기존 계획 잠금을
공유해야 한다. 원격 왕복만으로 즉각 철회나 분산 원자성을 보장하지 않는다.

전체 계약·설정·권한·시계·실패 동작·배포 명세 생성법은
[security 서비스 안내](../../security/docs/security-review-service.md), 개발 판단과 결과는
[개발 기록](../../security/docs/development/security-service-2026-11-06.md)에 있다.
서비스 자체가 통과해도 기존 T19 전체 판정과 인간 승인은 유지한다.

현재 T7의 `acquire`는 마지막에 API SelfSubjectReview를 수행하므로 서비스 전용 audience를
그대로 넣어 사용할 수 없다. 내부 소비자는 기존 SA의 별도 projected token과
`MountedTokenCredential`을 연결한다. 기존 Kubernetes 발급/회전을 쓰고 새 issuer를 만들지 않는다.
외부 소비자의 T7 확장은 별도 인계 사항이며 API audience나 복수 audience로 우회하지 않는다.
[구체적 경계와 시험](../../security/docs/adr/0005-service-credential-audience.md)을 따른다.
T33의 실제 Security Hub 접근 거부를 빈 탐지/PASS로 만들지 않는다. T14 listener v2의
source NET-01.3 FAIL과 나머지 UNKNOWN을 유지하고 운영 v1 결과로 치환하지 않는다.
강제 연결에 앞서 `compare_shadow`로 기존 결과와 차이를 읽기 전용으로 수집한다.

## 로컬 실행

동일 상위 폴더에 `security`와 `sova-test`가 있는 구성을 예로 든다.

```powershell
# C:/dev/softbank_2026에서, 준비된 로컬 검증 가상환경 사용
security/.venv/Scripts/python.exe -m pip install --no-deps --no-build-isolation -e ./security -e ./sova-test
security/.venv/Scripts/sova.exe security-program-catalog
security/.venv/Scripts/sova.exe security-program-example --kind migration
```

예제 출력을 UTF-8 JSON 파일로 저장한 뒤 `security-program-check FILE --phase preflight`
또는 `--phase postflight`로 검사한다. Windows PowerShell 5의 기본 리다이렉션은
UTF-16일 수 있으므로 아래처럼 저장한다.

```powershell
New-Item -ItemType Directory -Path sova-test/.local-notes -Force | Out-Null
security/.venv/Scripts/python.exe -c "import subprocess,pathlib; p=subprocess.run(['security/.venv/Scripts/sova.exe','security-program-example'],check=True,stdout=subprocess.PIPE); pathlib.Path('sova-test/.local-notes/program.json').write_bytes(p.stdout)"
security/.venv/Scripts/sova.exe security-program-check sova-test/.local-notes/program.json
```

예제는 증거가 없으므로 모든 검사가 UNKNOWN, 종료 코드는 1이다. 입력 오류는 2,
구조상 필요한 증거가 모두 PASS면 0이다. 결과의 `authenticated:false`와
`execution_authorized:false`는 항상 유지된다. CLI는 JSON의 서명을 인증하거나
클라우드·DB·모델을 호출하지 않으며 운영 실행에 직접 연결하지 않는다.

## 호스트 연결

1. 기존 계획을 먼저 구성한다. exact plan digest를 subject로 사용한다.
2. 신뢰된 서버가 `SecurityProgram`을 등록한다. 사용자/모델이 임의 verifier,
   scope 또는 정책을 정하게 하지 않는다. source/target의 현재 revision을 각각 넣는다.
3. `ProgramBinding`마다 기존 생산자의 결과를 읽는 검증 어댑터를 연결한다.
   예: 리허설 결과는 `RehearsalAdmissionService`, 재스캔은 `reassess_patch`,
   보호 비교는 `ProtectionParityGuard` 및 팀 T14/T19 결과를 사용한다.
   새 program obligation에 투영할 때 생산자의 원문 digest·scope·revision·현재 신뢰와
   실제 결과를 검증한다. `ProgramEvidenceRoute`와 `SignedProgramEvidence`는 원본
   EvidenceEnvelope를 재검증하며 결과·유효기간을 보존한다. boolean 문자열 변환은 금지한다.
4. `SecurityProgramService`에 등록/근거 lookup, 인증, 인가, 현재 보류 조회를 넣는다.
   저장된 과거 PASS를 인증 callback으로 대체하지 않는다.
5. 패치는 `with_patch_security_program(existing_patch_service, program_service, scope=...)`로
   사전·사후 검사를 함께 연결한다. 기존 서비스를 변경하지 않고 새 구성 객체를 반환한다.
   마이그레이션 전환 직전 검사는 `with_security_program(stored_executor, service, actor=..., scope=...)`로 연결한다.
6. 실제 실행 후에는 기존 command에 결속한 runtime 관측·재스캔·데이터 검증을 수행하고
   postflight 보고서를 함께 수집한다. 이번 실행 시작 이전 관측은 사후 PASS가 될 수 없다.
   누락·실패·만료·신뢰 철회는 기존 hold와 `PatchPostflightRequired`로 연결되며 재적용하지 않는다.

PostgreSQL의 기존 artifact/서명/검증기 저장소를 바로 조합하는 예시는 security의
`docs/program-evidence-integration.md`에 있다. 모든 새 프로필을 임의 PASS로 만드는
샘플 callback 없이 `RegisteredProgramAuthority`를 사용한다.

패치 연결은 `PlanPurpose.CHANGE`와 `apply-verified-patch`에 한정한다. 마이그레이션은
`MIGRATION_PHASE` 계획의 운영 전환 인수 시점에 연결한다. 환경 준비 단계에 전체
전환 전 검사를 무조건 요구하거나 기존 phase runner의 단계 권한을 변경하지 않는다.
복구·보안 보류 해제는 기존 별도 승인 경로를 유지한다.

## platform 어댑터 경계

| 통합 지점 | 재사용·인계 사항 |
|---|---|
| T5/T14/T19 | 현재 팀 ControlRun schema와 기존 정규화 어댑터를 대조한다. 새 22개 검사를 기존 6개 보안 통제와 일대일로 치환하지 않는다. 필요한 추가 증거가 없으면 UNKNOWN이다. |
| T10 | 현재 계획·운영자·승인·revocation을 제공한다. program의 PASS로 사람 승인이나 상태 전이를 생성하지 않는다. |
| T11/T15/T38 | 제안·검증 Job·독립 verifier·실제 자원 제한 결과를 소비한다. AI가 자기 검사나 trust key를 바꾸지 못하게 한다. |
| T31 | 승인 diff/image와 실제 배포 digest를 결속한다. 보안 패키지는 Git push 또는 배포를 수행하지 않는다. |
| T12/T13/T20 | 기존 단일 writer·무결성·failback·SAFE_HOLD를 유지한다. 이 패키지에 컷오버 실행기를 추가하지 않는다. |
| T24/T34/T37 | 기존 감사·지표·관측 수집기를 사용한다. 관측 데이터와 판정용 근거를 구분한다. |
| T21 | 검사별 근거·실측 여부·UNKNOWN을 표시한다. 원문 사건명이나 도구 설치를 녹색 상태의 근거로 쓰지 않는다. |

팀 CNPG/Kubernetes 경로를 우선한다. 제안서의 ECS/RDS, CloudFront/Shield,
SPIFFE/SPIRE는 후보와 확장 경로이며 현재 팀의 Cloudflare·EKS/RKE2 구성을 자동 교체하지 않는다.

## 인수 체크

- [x] 보안 구현 정본과 Sova 실행 책임을 분리하고 패키지 버전을 고정한다.
- [x] 두 문서의 SG/CTRL/POL/SEC-PATCH ID를 코드의 검사 목록과 연결한다.
- [x] 등록·근거·scope·revision·서명·만료·보류의 검증 경로를 구성한다.
- [x] Sova 기존 실행기에서 누락 차단·승인 철회·응답 유실을 로컬 시험한다.
- [x] 원본 생산자의 실제 서명과 PostgreSQL 등록·철회·최신 근거 조회를 연결한다.
- [x] 실행 후 증거 누락·변경 전 관측·만료 시 기존 effect를 보존하고 보류한다.
- [x] platform `505d451fd8c374de755b160fca24f1a481820a50`의 schema와 예제를 대조하고 명시적 소비 프로필을 추가한다.
- [x] f602b39 기준 실제 T10/T19 모듈과 initial/post_apply·현재 권한·단일 접수·원장 조정을 시험한다.
- [x] b19488e의 StoredGateServices·DB/pooler 원문 요구를 확인하고 같은 소비 시험을 통과한다.
- [x] c225c86의 추가 변경을 검토하고 세 기준의 계약 CI 및 현재 전체 보안 회귀를 통과한다.
- [x] 추가 서비스 소비에서 이전 PASS·만료·철회·shadow 우회를 차단하고 기존 실행 책임을 보존한다.
- [x] 실제 Sova PG 원장과 독립 TLS/보안 PG를 연결해 사전 차단·사후 hold·단일 효과를 시험한다.
- [ ] 실제 소비자의 projected audience·SA UID 등록과 CNPG 테넌트 전용 reader를 인수한다.
- [ ] 플랫폼 plan-lock 아래 등록/철회와 실행기 IAM/RBAC의 직접 우회 거부를 실측한다.
- [ ] platform 현재 계약별 실제 증거 생산자 어댑터를 담당자와 확정한다.
- [ ] 팀 실제 AWS/RKE2에서 격리·거부·복원·컷오버·회귀 결과를 얻는다.
- [ ] 기업 인증·신뢰 키 관리·배포·감사 보존·감시 운영을 인수한다.

기존 보안 tests, Sova 통합 tests, 실제 PostgreSQL/OPA, 실제 클라우드 운영 자격은
서로 다른 검증 수준이다. 0.10.0 결과는 security의 `docs/validation-2026-11-06.md`,
0.11.0 결과는 `docs/development/security-service-2026-11-06.md`를 따른다.
