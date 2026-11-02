# PostgreSQL 작업 접수와 outbox

승인된 계획의 실행 요청을 PostgreSQL에 기록하고, 같은 트랜잭션에서 상태 이력과 알림을 만든다. API는 저장된 접수 결과를 반환할 수 있고, 별도 relay가 outbox 알림을 발행한다. 현재는 저장소·relay 유스케이스와 시험용 publisher까지 구현했으며, 웹·실제 큐·배포 워커는 연결 전이다.

## 코드 경계

| 위치 | 책임 |
| --- | --- |
| `domain/operations.py` | 접수 입력·불변 fingerprint·저장 상태·내부 delivery·브로커 공개 event·receipt |
| `ports/operations.py` | 작업 저장소·publisher 계약 |
| `adapters/sql/postgres_operations_v1.sql` | 작업·상태 이력·outbox·키/FK·강제 RLS |
| `adapters/postgres_operations.py` | 원자적 접수·멱등성·상태 CAS·리스 claim/ack |
| `application/outbox.py` | DB 트랜잭션 밖에서 발행하고 해당 delivery만 ack |

`PostgresOperationRepository`는 기존 테넌트 범위 `PostgresLifecycleRepository`를 사용한다. 역할의 superuser/BYPASSRLS/소유권을 검사하고 각 트랜잭션에서 테넌트 문맥을 설정하는 경계도 유지한다. 마이그레이션은 lifecycle SQL 이후 별도 관리자 역할로 적용한다.

## 원자적 접수와 재접수

접수는 저장된 계획 해시와 승인 ID·revision·만료·취소 상태를 확인한다. 승인 행을 공유 잠금으로 읽어 접수 커밋과 동시 취소의 순서를 정한다. 접수 뒤 취소가 생길 수 있으므로 이 검사는 실행 직전 검사를 대체하지 않는다.

작업·첫 상태 이력·outbox는 한 번에 커밋한다. 이력 INSERT에 실패하면 작업과 outbox도 롤백한다. 승인·계획·수명은 영속 정보이며 호출자의 사용자 권한 검증은 별도 신뢰할 애플리케이션 경계에서 수행해야 한다. `requested_by` 문자열만으로 신원을 인증하지 않는다.

멱등 키는 테넌트·앱 범위다. fingerprint에는 계획·승인·승인 revision·요청자·멱등 키를 넣고, 요청 처리 중 새로 할당할 수 있는 operation ID는 제외한다. 같은 요청을 다시 보내면 원래 operation ID와 현재 상태를 반환한다. 같은 키의 다른 입력은 거부한다.

이미 취소된 요청의 재접수도 원래 취소 결과를 반환하며 새 알림을 만들지 않는다. 재시도 실행에는 새 접수 의도가 필요하다. 이 영수증 반환을 취소된 승인의 신규 사용으로 해석하지 않는다.

## 전달 리스와 재발행

relay는 `FOR UPDATE SKIP LOCKED`로 알림을 하나 가져오고 DB 시각으로 제한된 lease를 만든다. lease에는 소유자·새 난수 token·attempt·만료가 있다. 발행은 트랜잭션 밖에서 수행한다.

브로커에 전달할 `OutboxEvent`에는 event ID·topic·참조 payload만 있다. 내부 소유자와 lease token은 publisher 입력으로도 전달하지 않는다. payload는 저장된 작업 참조와 정확히 일치하는지 확인하고, lease·자격 증명·CLI·사용자 코드를 포함하지 않는다.

publisher가 반환한 event ID·publisher ID를 확인한 뒤 ack한다. 현재 owner/token·유효기간·미취소 상태가 맞는 delivery만 완료할 수 있다. 이전 워커의 늦은 응답은 `LeaseLost`로 거부한다.

발행 중 프로세스가 죽거나 응답을 잃으면 lease 만료 후 **같은 event ID**로 재발행할 수 있다. 따라서 전달 계약은 at-least-once다. 소비자는 테넌트·앱·event ID로 중복을 구분하고, 현재 작업·승인·보류·실행권을 조회한 뒤에만 실제 효과를 요청해야 한다. 발행 이력만 보고 효과를 다시 실행하면 안 된다.

publisher receipt는 큐 접수 확인이며 앱 배포·DB 전환·HTTP 검증 성공이 아니다. outbox ack로 operation 상태를 성공 처리하지 않는다. 실패 횟수 경보·재시도 정책·DLQ·실제 publisher connector는 운영 연결 단계에서 추가해야 한다.

## 상태·취소·권한

상태 변경은 현재 행을 잠그고 예상 revision과 도메인 상태 전이를 확인한 뒤 이력을 함께 저장한다. fencing 이후 일반 실패 종료 대신 `recovery_required`를 요구한다. 이 상태 값은 workflow의 진행 기록이며 그 자체로 실제 자원·단일 writer·검증 결과를 증명하지 않는다.

초기 단계의 취소·실패·차단은 미발행 알림을 억제하고 기존 claim도 무효화한다. 취소와 동시에 이미 브로커에 전달됐을 가능성을 없애지는 못하므로 소비자의 실행 직전 상태 확인이 필수다. 이미 보낸 provider 요청의 취소/복구는 별도 효과 계약이다.

런타임 역할은 작업 ID·계획/승인 참조·fingerprint와 outbox payload를 UPDATE할 수 없어야 한다. 작업 UPDATE는 `status,revision,updated_at`, outbox UPDATE는 lease·발행·억제 관련 열에 제한한다. 이력 UPDATE/DELETE는 부여하지 않는다. 보안 보류 해제·기업 역할 인가는 별도 권한 경계이며 이번 저장소가 구현하지 않는다.

## 검증과 남은 연결

PostgreSQL 17.11의 전용 임시 클러스터에서 기존 회귀 포함 **198개 통과·실패/오류/skip 0**을 확인했다. 이번 작업/outbox 시험은 실제 PG 20개이며, 접수 커밋 직후 별도 API 프로세스를 실제 종료하는 시험을 포함한다. publisher는 명시적 시험 대체물이다.

확인한 항목은 접수/이력/outbox 원자성, 중복 키·동시 접수, DB 재연결, 승인 취소, 동시 claim, 리스 만료·오래된 ack, 발행 응답 유실·같은 event ID 재전달, 취소 후 ack 거부, 잘못된 receipt·payload 차단, 상태 revision과 복구 전이, 테넌트/앱 격리다.

임시 서버 중지와 시험 데이터 삭제를 확인했다. 기존 VM·AWS·게임·앱 DB는 변경하지 않았다. 결과와 개발기록은 `.local-notes/postgres-outbox-20261031/`에만 보관한다.

후속으로 [PostgreSQL 실행 효과 원장과 앱 소유권](postgres-execution.md)을 추가했다. 실제 내구성 workflow/publisher·웹 접수/조회·외부 서비스의 fencing/종결 검증은 남아 있다. 기존 SQLite 프리뷰를 여러 워커가 각자 사용하는 형태로 확장해서는 안 된다.
