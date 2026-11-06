# 두 보안 설계의 개인 검증과 platform 인계

2026-11-07 KST · `sova-security==0.11.0` · platform 개발 계약 `0795f65e24f58e43545b16b97757efcc0923fd4a`

최종 소비 source는 `546f6e0482cc06fa32f00ea8d554522551a84beb`다. 최신 개발 계약과 별도로
GitOps 호스트 발행 원본 `445848d2ed9878e31eb6f5aabad0575c61739b47`을 포함해 총 12개 계약을 검증했다.
실제 host binding에는 확인한 runtime source를 명시한다. develop SHA와 실제 이미지 source를 혼동하지 않는다.
[소비 CI 42266814087](https://github.com/Softbank-Hackathon-Finals/sova-test/actions/runs/42266814087)에서
process **44 PASS / 67.36초**, container **44 PASS / 48.77초**, 최신 T28 **36 PASS / 2.16초**,
이전 T28 **32 PASS / 4 SKIP / 2.02초**를 확인했다. 최신 전용 인자 시험 네 개만 이전 버전에서 건너뛴다.

실환경 로그인·인수는 사용자 요청에 따라 **데모용 맥에서 후속 진행**한다. 플랫폼 AWS RKE2는
`bravo-personal` SSO와 기존 SSM API 포워딩, namespace `platform-state`가 대상이다.
`default`는 다른 계정이고 `.local-tools/team-test.json`·`bravo-target-test`는 온프렘 목적지용이다.
플랫폼 일괄 배포가 끝난 뒤 공용 리소스를 바꾸지 않는 읽기 전용 확인부터 한다.
[실환경 인수 실행안](https://github.com/Softbank-Hackathon-Finals/security/blob/e2709ee075c62b6c7b2c5249b50a6ea114e972ff/docs/platform-live-acceptance.md)에
인증·권한·네트워크·감사·복구의 필요한 실제 근거와 변경을 수반하는 후속 시험을 구분했다.

앞선 f602b39·b19488e·c225c86·9e0d6a5·a610bbf·8b12236·bb17486·98885a6·7edab53·42811da도 소비 시험으로 유지한다. bb17486의
새 WorkflowHost는 plan/version별 준비 결과를 읽고 미연결 단계는 보류한다. SHIFT 실행은 이 드라이버의
대상이 아니며 기존 T10 접수 책임을 유지한다. 단계별 운영 조립은 별도 인수 대상이다.
실제 연결 계약을 시험한 정확한 SHA만 허용한다. 운영 배포 자동 갱신은 하지 않는다.

98885a6의 T19 `PlanAuthorityKeys`는 기존 계획 잠금 아래 현재 공개키 등록·철회를 제공한다.
실제 StoredGateServices/Ed25519Authority와 결합하여 승인 후 키 철회가 initial/post_apply의
추가 원격 판정과 외부 접수를 막는지 검증했다. 별도의 T19 키 원장을 만들지 않는다.

7edab53의 `PlanAuthorityRecords`는 같은 원장에 공개 서명을 저장하고 매번 현재 키/만료를 재조회한다.
새 인스턴스의 조회도 원래 20초 기한을 보존하고 철회·만료 후 거부하는 계약 시험을 추가했다.
개인 키 발급·서명 서버를 추가하지 않는다. 새 단계 구현의 REHEARSE/GATE는 기존 승인된 적용과
APPLIED 후 재검사를 사용하고 SHIFT는 계속 운영자 접수가 담당한다. WATCH는 T36/T19 둘 다 PASS가
필요하다. 최초 제안은 플랫폼 Job 경로를 사용하며 운영 ports·GitHub App·Job 권한 인수는 별도다.

T28 `happy_path.py`의 JSONL은 결과 기록 전 중단 뒤 재시작할 때 모의 효과를 다시 호출했다.
[고정 source 재현](https://github.com/Softbank-Hackathon-Finals/security/blob/ec4aac6c3d839111f76ef7466f7b6fc7fcea1e49/docs/evidence/t28-restart-boundary-2026-11-06/README.md)은 실제 운영 명령을 실행하지 않았다.
이 JSONL을 보안 집행 정본으로 채택하지 않는다. 개인 환경의 `DurableT28Port`는 기존 effect journal과
현재 승인·정확한 계획/명령/이미지 결속을 통해 재호출을 차단한다. 강제 종료·동시 접수·지연 HTTP 효과를
검증했고, 불명확한 결과는 재적용하지 않고 보류한다. 호출자 사망이나 lease 만료만으로 원격 작업의
종료를 추정하지 않는다. [구현·시험·조립 경계](platform-t28-restart.md)를 따른다.
원본 플랫폼 CLI는 변경하지 않았으므로 실제 T10/T31 조립과 직접 실행 권한 제한은 후속 인수다.
T10 코어 원장에 같은 결함이 있다는 뜻은 아니다.

0795f65의 실행 직전 T19 재평가는 기존 GATE 결과와 별도로 보존하고 initial/post_apply의 새 판정에
현재 계획 문맥을 결속한다. 원격 근거 누락, 새 BLOCK, binding 변경 시 실행하지 않는 소비 시험을 추가했다.
승인자와 WorkflowHost 실행 주체를 구분하고 기존 사람 승인을 유지한다. T24의 기존 SSE `follow`를
재사용하며 별도 감사 writer를 만들지 않는다. 런타임 writer 등록·상시 운영·실제 복원은 별도 인수다.

새 `open_after_apply.py`는 운영자 경로이며 원격 보안 판정의 강제 집행을 추가한 것이 아니다.
후속 인수는 쓰기 개방·Edge 전환·컷오버까지 현재 계획/반영 ID/이미지와 결속하고 직접 명령의
권한도 제한해야 한다. T10 집행 어댑터 통과만으로 그 경로의 우회가 제거됐다고 보지 않는다.

T7 object `open`은 명시적 `close`까지 개발용 익명 읽기를 유지한다. 작업의 FINISHED/PASS/CLEAN을
보안 PASS로 변환하지 않는다. `final_state=open`, `security_state=PUBLIC_READ`와 관측 시각을 보존한다.
T15의 manager/runner/AI 격리, admission 정책, 임시 record_key의 T9/OpenBao 이관은 플랫폼 책임이다.
새 T14 소스 검사 결과는 양쪽 각각 **1 PASS / 19 UNKNOWN**이며 이전 TLS 결과와 합산하지 않는다.

T19 정정 기록상 이전 두 앱 경로는 같은 출발지 DB를 사용했다. 이를 독립 출발지/목적지 DB 일치로
인정하지 않는다. 새 목적지 직접 수집은 한 시점의 관측이며 기존 복제 권한 역할을 사용했다.
pooler 뒤의 실제 DB 신원, 최소 권한 수집기, 현재 계획의 같은 유효 창 안에서 수집한 양쪽 증거가 필요하다.
T22의 실제 브라우저 재접속 8조합 역시 DB 컷오버·쓰기 개방의 증거가 아니다.
[정정 원문](https://github.com/Softbank-Hackathon-Finals/platform/blob/bb174860bedf100de3970c3e8e410f02f23994e2/docs/evidence/t19-direct-database-2026-11-06/README.md)을 보존한다.

[양쪽 직접 수집 후속 원문](https://github.com/Softbank-Hackathon-Finals/platform/blob/7edab5312f965bd683a7738e74d49b883190e8da/docs/evidence/t19-direct-database-2026-11-06/paired/README.md)은
서로 다른 DB의 두 schema/PK가 같은 검증 문맥과 겹치는 30초 창에서 일치한 새 관측이다.
이미 만료됐으며 운영 T10 신뢰 등록·전체 T19 PASS·업무 행 일치로 확대하지 않는다.

플랫폼 T15 이미지 발행 workflow의 `ignore-unfixed: true`와 달리 이 서비스의 수집 정책은 미수정
HIGH/CRITICAL도 BLOCK이다. OCI/digest 발행 경로는 재사용 후보지만 두 정책의 의미를 같다고 취급하지 않는다.
이전 Debian producer의 실제 OS 87개/Python 10개에서 **HIGH 49건 / BLOCK**을 보존한다.
이는 13개 고유 CVE의 여러 OS 패키지 탐지였다. 최종 producer는 공식 digest 고정 Alpine로 바꿔
native amd64·arm64 각각 OS 38개/Python 10개를 전체 대조했으며 **모든 심각도 0건 / PASS**다.
미수정 취약점 예외를 추가하지 않았다. scanner는 Docker socket/호스트 자격 없이 격리하고 실제 스캔은
network none으로 수행한다. 검사한 exact image archive를 저장·재로딩해 inventory를 재확인했다.
[scanner 원본·정책·source/image ID](https://github.com/Softbank-Hackathon-Finals/security/blob/e2709ee075c62b6c7b2c5249b50a6ea114e972ff/docs/evidence/service-image-scan-2026-11-07/README.md)를 인계한다.
이는 관측 시점의 이미지 정책 PASS이며 registry 발행·서명·실제 플랫폼 배포를 완료한 결과는 아니다.

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
현재 서비스 이미지의 실측 아키텍처는 native linux/amd64·linux/arm64다. 양쪽 모두 실제 PG18.4,
TLS/HBA, 서비스 이미지/T10 시험을 통과했다. 데모 맥의 아키텍처에 맞는 정확한 archive를 선택하고
hash·source를 확인한다. 로컬 Docker 검증과 실제 클러스터 운영 인수는 구분한다.

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
Sova 소비 CI에는 보안 서비스의 실제 컨테이너 모드도 추가한다. 패치 대상 이미지 실행과
측정 내용, TokenReview 공급자는 여전히 시험 모형이다. 두 이미지의 역할을 혼동하지 않는다.

현재 고정 생산자는 `546f6e0482cc06fa32f00ea8d554522551a84beb`다. 같은 0.11.0이라도 전체 source SHA와
lock/wheel hash를 함께 인수한다. 서비스 토큰은 단일
audience·원래 수명 600초 이하여야 한다. 전용 DB는 다섯 테이블의 고정 RLS뿐 아니라 PUBLIC
definer 함수/뷰·열 단위 쓰기·추가 객체 권한도 정리해야 한다. 자동 권한 변경은 하지 않는다.
security ADR-0008·0009와 실제 PG/Kubernetes 시험을 인계 자료로 사용한다.

ADR-0019의 전용 DB 준비도 필요하다. `reader_database_statements(database=...)`는 PUBLIC의
TEMPORARY와 `lo_create`/`lo_creat`/`lo_from_bytea` EXECUTE를 회수하는 SQL을 렌더링한다.
reader에게만 REVOKE해서는 PUBLIC 권한을 상쇄할 수 없다. 공유 DB라면 다른 사용자의 필요 권한을
먼저 검토하고 명시적으로 부여해야 한다. 서비스는 변경을 자동 적용하지 않으며 권한 재부여를
발견하면 새 판정을 거부한다. 운영 DB의 모든 자원 고갈 경로를 차단했다는 보증은 아니다.

ADR-0020은 직접 DB 로그인의 연결 수 예산도 제한한다. reader 생성 기본값은 16이며 운영자는
정수 1~64를 명시할 수 있다. 기존 역할은 자동 ALTER하지 않고 운영 전 상한을 인수해야 한다.
무제한/0/64 초과 변경은 현재 세션 검사에서도 거부한다. 같은 역할의 replica는 예산을 공유한다.
PostgreSQL의 근사 집행·관리자 예외·전체 DB 자원 제한을 별도로 고려한다.

TCP DB 연결은 접속 전에 단일 host/port/DB/reader, `sslmode=verify-full`과 절대 CA 경로를 요구한다.
혼합 host, service 환경 우회, TLS 대신 GSS 선택을 허용하지 않는다. T9의 mounted DSN 회전은 유지한다.
현재 DB의 RLS만으로 같은 서버의 다른 DB를 보호할 수 없으므로 운영자는 ADR-0017의
`reader_hba_rules`로 전용 DB/reader/허용 CIDR의 TLS/SCRAM 규칙을 준비한다. 이 함수는 렌더링만 한다.
CNPG 고정 규칙의 우선순위와 pooler의 실제 사용자/주소는 별도 확인한다. HBA reload는 기존 세션을
종료하지 않으므로 host hold와 자격·세션 철회 절차를 함께 인수해야 한다. ADR-0018은 연결 전 검증을 설명한다.

platform 소비는 `T10ProgramAuthority`로 원래 `T10GateAuthority`를 감싼다. 원래 계획
digest/`PlanGateSession.fingerprint`, 문자열 profile version, `initial/post_apply`와
application_id를 그대로 사용한다. 프로그램 pre/postflight 축과 혼동하지 않는다.
`load_registration(connection, principal, plan, phase)`과 관련 writer는 기존 계획 잠금을
공유해야 한다. 원격 왕복만으로 즉각 철회나 분산 원자성을 보장하지 않는다.

전체 계약·설정·권한·시계·실패 동작·배포 명세 생성법은
[security 서비스 안내](https://github.com/Softbank-Hackathon-Finals/security/blob/e2709ee075c62b6c7b2c5249b50a6ea114e972ff/docs/security-review-service.md), 개발 판단과 결과는
[현재 개발 기록](https://github.com/Softbank-Hackathon-Finals/security/blob/feature/security-service-integration/docs/development/security-acceptance-2026-11-07.md)에 있다.
구현 source pin과 결과를 추가하는 문서 브랜치를 구분한다. 완료된 CI·지속 시험·이미지 원본과
운영 인수 조건은 [현재 인계 현황](https://github.com/Softbank-Hackathon-Finals/security/blob/feature/security-service-integration/docs/platform-handoff-status.md)에 모았다.
서비스 자체가 통과해도 기존 T19 전체 판정과 인간 승인은 유지한다.

현재 T7의 `acquire`는 마지막에 API SelfSubjectReview를 수행하므로 서비스 전용 audience를
그대로 넣어 사용할 수 없다. 내부 소비자는 기존 SA의 별도 projected token과
`MountedTokenCredential`을 연결한다. 기존 Kubernetes 발급/회전을 쓰고 새 issuer를 만들지 않는다.
외부 소비자의 T7 확장은 별도 인계 사항이며 API audience나 복수 audience로 우회하지 않는다.
[구체적 경계와 시험](https://github.com/Softbank-Hackathon-Finals/security/blob/ec4aac6c3d839111f76ef7466f7b6fc7fcea1e49/docs/adr/0005-service-credential-audience.md)을 따른다.
T33의 실제 Security Hub 접근 거부를 빈 탐지/PASS로 만들지 않는다. T14 listener v2의
source NET-01.3 FAIL과 나머지 UNKNOWN을 유지하고 운영 v1 결과로 치환하지 않는다.
강제 연결에 앞서 `compare_shadow`로 기존 결과와 차이를 읽기 전용으로 수집한다.
`matched=true`는 같은 UNKNOWN/FAIL일 수도 있다. 일치율이나 서비스 응답 성공을 준비 완료로
변환하지 않고 원래 개별 판정·근거·기한을 검토한다. 실행 접수 때는 새 enforce 판정과 기존 T10 조건이 필요하다.

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

복구 전에는 복원 대상 DB와 독립된 실행 차단을 먼저 유지한다. 보안 DB의 과거 신뢰 이력을 복원하면
이전에 철회한 키의 유효한 서명이 다시 인정될 수 있다. Sova의 실제 두 DB 시험은 원격 PASS가 다시
나와도 별도 호스트 보류와 APPLIED 원장 때문에 재적용되지 않음을 확인한다. 호스트 원장까지 같은
과거 시점으로 되돌리는 경우는 이 시험의 범위 밖이다. T12/T13/T24 인수에서는 독립된 복구 기준점,
이미 실행된 effect 조정, 최신 키/철회/hold 복원, 별도 해제 승인 후 새 증거를 요구해야 한다.

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
- [x] 9e0d6a5·a610bbf·8b12236을 추가해 여섯 기준의 계약과 최신 실제 T10/이미지 소비를 통과한다.
- [x] bb17486을 추가해 일곱 기준을 유지하고 새 WorkflowHost의 SHIFT 소유권·version별 판독 경계를 시험한다.
- [x] 98885a6을 추가해 여덟 기준과 T19 현재 공개키 원장의 승인 후 철회 경계를 시험한다.
- [x] 7edab53을 추가해 아홉 기준과 T19 공개 서명의 현재 만료·철회 재조회를 시험한다.
- [x] 42811da·0795f65·호스트 발행 source 445848d를 포함한 12개 계약과 실행 직전 재평가 경계를 시험한다.
- [x] native amd64·arm64 이미지의 HIGH 49건을 예외 없이 해소하고 exact archive와 스캔 원본을 보존한다.
- [x] 개인 T28 bridge의 강제 종료·동시 접수·지연 효과·현재 승인·인자 변경을 실제 프로세스와 PG로 시험한다.
- [x] 추가 서비스 소비에서 이전 PASS·만료·철회·shadow 우회를 차단하고 기존 실행 책임을 보존한다.
- [x] 실제 Sova PG 원장과 독립 TLS/보안 PG를 연결해 사전 차단·사후 hold·단일 효과를 시험한다.
- [ ] 실제 소비자의 projected audience·SA UID 등록과 CNPG 테넌트 전용 reader를 인수한다.
- [ ] 플랫폼 plan-lock 아래 등록/철회와 실행기 IAM/RBAC의 직접 우회 거부를 실측한다.
- [ ] platform 현재 계약별 실제 증거 생산자 어댑터를 담당자와 확정한다.
- [ ] 팀 실제 AWS/RKE2에서 격리·거부·복원·컷오버·회귀 결과를 얻는다.
- [ ] 기업 인증·신뢰 키 관리·배포·감사 보존·감시 운영을 인수한다.

기존 보안 tests, Sova 통합 tests, 실제 PostgreSQL/OPA, 실제 클라우드 운영 자격은
서로 다른 검증 수준이다. 0.10.0 결과는 security의 `docs/validation-2026-11-06.md`,
0.11.0 초기 결과는 `docs/development/security-service-2026-11-06.md`, 이번 후속 결과는
`docs/development/security-acceptance-2026-11-07.md`를 따른다. 실환경 다섯 항목은 미검증으로 남긴다.
## T14·T33 로컬 인수 도구 (2026-11-07 추가)

`security` 0.11.1을 고정한 소비 환경에서 `sova security-intake-plan`으로 T5 `full:1`
20개 시험의 준비 조건과 source/target 보고 상태를 조회한다. 입력 없이 실행하면 모든 행은
NOT_PROVIDED이며 실제 시험·인증·실행 승인을 수행하지 않는다. 기존 공식 접속과 T14/T19/T33
원문 조회를 재사용하는 [맥 실행 안내](https://github.com/Softbank-Hackathon-Finals/security/blob/main/docs/mac-t14-t33-intake.md)를 따른다.
위 과거 산출물·이미지 기록의 소스 고정값은 이 새 버전으로 자동 갱신되지 않는다.

