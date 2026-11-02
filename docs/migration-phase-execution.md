# 단계별 이전 실행 계약

전체 이전 프로그램은 의무를 유지하고, 실제 변경은 별도로 승인된 하위 계획으로 실행한다. 준비에 필요한 효과를 실행하기 전부터 최종 데이터 비교를 요구하는 순환 의존을 피한다. 이 계약은 호스팅 API·일반 이전 워커 전체의 완성을 뜻하지 않는다.

## 단계와 실행 전 검증

| 단계 | 실행 전 게이트 | 역할 |
| --- | --- | --- |
| `prepare` | G2 변경 검증 | 검증된 변경으로 목적지 준비 |
| `synchronize` | G3 기동 검증 | 준비된 목적지로 초기 복사·동기화 |
| `rehearse` | G6 보호 검증 | 업무·보호 검사 후 리허설 |
| `quiesce` | G6 보호 검증 | 승인된 쓰기 통제·배출. 최종 barrier 검증을 수행할 조건 마련 |
| `cutover` | G7 전환 직전 검증 | 최종 데이터·단일 writer·시퀀스·복구 준비 확인 후 전환 |
| `postcheck` | G8 전환 후 검증 | 신규 쓰기·SLO 확인 후 후속 변경 |

게이트 통과는 해당 단계의 준비 조건일 뿐 전체 이전 성공이 아니다. `postcheck`에 속한 변경은 G8 결과가 있어야 실행할 수 있다. G8 근거를 수집하는 읽기 전용 probe는 이 변경 실행과 구분한다.

`application/migration_phases.py`의 컴파일러는 전체 프로그램의 검증 의무·revision·유효기간을 계획에 결합한다. 다음 단계 의무를 지우거나 선택 항목으로 바꾸지 않는다. 준비와 쓰기 정지, 트래픽 전환을 하나의 낮은 게이트 계획에 섞지 않는다.

## 신뢰 경계

- 동작 분류(`PhaseAction`)와 단계 바인딩은 서버의 신뢰된 정책이다. 업로드·AI 응답·HTTP 입력에서 실행 게이트나 동작 레지스트리를 받지 않는다.
- 단계 바인딩은 정확한 불변 계획에만 유효하다. 매개변수·범위·revision·의무가 바뀌면 새 계획과 승인이 필요하다.
- 재시작 때 인증된 프로그램·정책 저장소에서 바인딩을 복원해야 한다. `plan.reason` 문자열만 보고 단계를 신뢰하지 않는다. `PostgresMigrationProgramRepository`가 프로그램·계획·동작 레지스트리 digest의 불변 바인딩을 저장한다. `StoredMigrationPhaseExecutor`는 dispatch 직전 이를 다시 읽고 현재 정책·프로그램 인증을 수행한다. 기업 인증·중앙 환경 등록 서비스는 후속 연결 대상이다.
- 단계마다 승인 만료·폐기, 독립 보안 보류, 실행권과 효과 원장을 함께 검사한다. 낮은 게이트는 보안 보류를 해제하지 않는다.
- `ApprovedPlanExecutor`의 기존 기본값은 G7이다. 단계 바인딩을 명시적으로 주입하지 않은 보안 대응·복구 경로의 기준은 낮아지지 않는다.
- `StoredPlanExecutor`는 실행 직전 저장된 승인을 다시 읽으며, 단계 정책도 외부 변경 직전에 재검사한다.

## 불변 저장과 단계 워커

관리자는 제어 DB에 `postgres_migration_programs_v1.sql`을 명시적으로 적용한다. 프로그램 발행자는 프로그램·단계 바인딩에 SELECT/INSERT만 갖고, 워커는 해당 두 테이블에 SELECT만 갖는다. 앱·에이전트에는 이 제어 DB 자격을 전달하지 않는다. 테넌트 RLS는 인증된 서비스의 tenant 선택을 전제로 하며, 탈취된 공용 DB 자격의 임의 SQL까지 격리하는 수단은 아니다.

`MigrationPhaseRunner`는 접수된 `migration_phase` 목적의 계획만 실행한다. 앱 실행권을 얻고 단계별 승인·정책·근거를 재검사한 뒤 등록된 어댑터를 호출한다. 어댑터에 전달하는 변경 허가는 해당 명령 하나와 원장의 `in_flight` 상태에만 유효하다. 다른 단계나 완료된 명령의 허가로 재사용할 수 없다.

단계 상태는 `registered → phase_running → verifying → phase_verified`다. 마지막 상태는 전체 이전의 `service_moved`와 구분한다. 모든 단계의 최종 readback·현재 승인·보안 보류·실행권을 확인하고 완료 영수증, 상태 전이, 미발행 outbox 억제, 실행권 반환을 같은 DB 트랜잭션으로 기록한다. 최종 readback의 허용 나이는 현재 15초이며 장시간 검증을 지원했다고 주장하지 않는다.

완료 트랜잭션의 응답이 유실되거나 같은 메시지가 다시 전달되면 불변 영수증만 조회한다. 이미 완료한 외부 변경을 반복하지 않는다. 외부 결과가 불확실하거나 최종 검증에 실패하면 `recovery_required`로 남긴다. 독립 quiescence proof 없이 자동 재시도·실행권 인계를 열지 않는다.

실제 PostgreSQL 승인·실행권·효과 원장·단계 완료와 제한 역할의 DB 쓰기 제어를 통합 시험했다. 시험의 일부 정책/발급자 인증과 verifier 근거는 대체물이므로 기업 권한·전체 이전의 자격을 뜻하지 않는다. `adapters/sqs_operations.py`와 `application/operation_delivery.py`는 실제 SQS 수신을 불변 outbox 접수 및 PG 완료 영수증에 연결한다. 전용 큐 두 개를 사용한 실계정 시험에서 실제 쓰기 게이트 변경·중복 완료·poison 메시지 DLQ 이동·익명 발행 거부를 확인하고 큐를 삭제했다. 운영자 IAM 사용자의 시험이며 호스팅 워커 서비스 등록·역할 격리·운영 supervision과 DLQ 경보는 아직 연결하지 않았다.

## PostgreSQL 쓰기 제어 어댑터

`adapters/postgres_write_gate.py`는 협조적 쓰기 게이트를 갖춘 앱을 위한 고정 동작 어댑터다. `pause_writes`와 `resume_writes`를 별도 동작으로 구분하며 임의 SQL·식별자·비밀값을 명령으로 받지 않는다.

운영자는 앱 DB에 `control` 테이블을 설치하고 별도 실행 역할을 준비한다. 테이블에는 `singleton`, `writes_enabled`, `writer_epoch`, `execution_epoch`, `last_command_digest`가 필요하다. 실행 역할에는 스키마 USAGE, 테이블 SELECT, 네 상태 열의 UPDATE 및 `pg_control_system()` 조회만 부여한다. 소유자·관리자 역할을 전달하지 않는다. `examples/consultation/schema.sql`이 참조 구성이다.

어댑터는 DB 이름·OID·클러스터 ID·접속 역할·테이블 OID를 검증한다. 네트워크 연결에는 `verify-full` TLS가 필요하다. Unix socket 예외는 명시된 폐기용 시험 등록에만 사용한다. 트리거·규칙·상속·소유권·과도한 테이블/스키마 권한이 발견되면 거부한다.

쓰기 정지는 앱과 같은 advisory lock을 배타적으로 획득해 알려진 트랜잭션을 배출한다. 기대 writer 버전과 executor epoch를 CAS로 확인하고, 명령 digest를 같은 DB 트랜잭션에 저장한다. 현재 실행권·승인·근거·보안 보류에 결합된 별도 `ExecutionPermit`을 변경 직전과 쓰기 배출 후 다시 요구한다. DB 시각으로도 명령과 이 단기 허가 중 더 짧은 유효기간을 검사한다. 명령의 계획 유효기간만으로 실행권을 연장하지 않는다. 읽기 결과의 상태·버전·epoch·명령 digest가 모두 일치해야 해당 효과를 확인한다. 응답 유실은 UNKNOWN으로 남기고 실행권 복구 후 읽기 전용 대조로 해결한다.

앱의 모든 writer·직접 SQL·외부 worker·원격 스토리지 요청을 이 어댑터 하나로 봉쇄하지는 않는다. 결과에도 `all_writers_fenced=false`를 명시한다. 일반 이전의 G7은 별도의 전체 writer 조사·원격 fencing·최종 데이터 근거를 요구한다.

## 상담앱과 데이터 복구의 현재 경계

상담앱은 메시지·방 생성·세션 생성/폐기·첨부 저장을 같은 쓰기 게이트에 연결한다. 파일 저장과 메타데이터 확정이 끝나기 전에 정상적인 쓰기 정지가 완료되지 않는다. DB 연결이 끊긴 채 원격 저장 요청만 계속 실행되는 상황의 분산 fencing은 별도 자격 대상이다. 객체 쓰기 후 DB commit이 실패하면 미참조 객체가 남을 수 있으며, 같은 불변 키를 이용한 재시도로 수렴시킨다.

시험은 서로 다른 PostgreSQL 시스템 ID를 가진 두 임시 인스턴스에서도 수행한다. 정방향 동기화 후 원본 writer를 차단하고, 모든 등록 테이블·시퀀스·파일을 확인한다. 목적지 쓰기를 열기 전에 역방향 복제 슬롯을 준비한다. 목적지 신규 쓰기 후 다시 정지·최종 경계 대조·파일 복사·시퀀스 보정·역방향 구독 정지를 거쳐 원본에서 다시 쓸 수 있는지 확인한다.

이는 시험 운영자의 SQL과 ASGI 요청으로 수행한 참조 경로다. 실제 AWS→온프렘의 고정 공개 진입점, 원격 TLS publisher 신원, 일반 앱 변환, 전 과정 워커 실행, WebSocket 연결 무중단을 검증한 것으로 확대하지 않는다.

PostgreSQL의 시퀀스·DDL은 논리 복제 대상이 아니므로 별도로 검증한다. 역방향 구독의 `copy_data=false`는 이미 동등한 기준 데이터가 있다는 전제이며, `origin=none`은 이전 복제 변경의 재전송을 제한한다. [공식 복제 제약](https://www.postgresql.org/docs/17/logical-replication-restrictions.html), [CREATE SUBSCRIPTION](https://www.postgresql.org/docs/17/sql-createsubscription.html)을 따른다.
