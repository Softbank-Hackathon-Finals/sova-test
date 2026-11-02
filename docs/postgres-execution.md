# PostgreSQL 실행 원장과 앱 소유권

새 PostgreSQL 실행 경로는 계획·승인·작업뿐 아니라 효과 의도·진행·관측·완료도 같은 제어 DB에 보존한다. 앱별 실행 소유권을 발급하고, 결과가 불명확한 효과가 남으면 리스 만료 뒤에도 다른 변경 실행을 막는다. 기존 로컬 시각화 프리뷰는 SQLite를 유지하며 자동 전환하거나 과거 기록을 옮기지 않았다.

## 코드 경계

| 위치 | 책임 |
| --- | --- |
| `domain/execution.py` | 실행 lease·모드·quiescence proof·미해결 효과 집합 해시 |
| `ports/execution.py` | 실행권 발급·갱신·해제와 복구 권한 계약 |
| `adapters/sql/postgres_execution_v1.sql` | 앱별 소유권·효과·효과 이력·실행권 이력·RLS |
| `adapters/postgres_execution.py` | DB 시각과 행 잠금에 따른 단일 소유자·epoch·barrier |
| `adapters/postgres_effects.py` | 소유권을 확인한 의도/claim/결과 CAS·원장·관측 |
| `application/execution_recovery.py` | 신뢰할 proof 인증 후 조회 전용 복구권 발급 |

마이그레이션은 lifecycle → operations → execution SQL 순서로 별도 관리자 역할이 수행한다. 기존 테넌트 RLS·런타임 superuser/BYPASSRLS/소유권 거부를 유지한다. 새 표준 실행 경로는 `StoredPlanExecutor → ApprovedPlanExecutor → EffectExecutor + PostgresEffectJournal`이다. 효과 원장의 기본 guard만으로 전체 업무 검증이나 사용자 인가를 대체하지 않는다.

보안 대응의 원자 완료를 사용하는 구성은 `postgres_lifecycle_v2.sql`도 적용한다. 승인 행 잠금에 필요한 워커 권한은 `UPDATE(lock_guard)`로 제한한다. `revision`·`revoked_at`·`document`의 UPDATE나 승인 INSERT를 워커에 주지 않는다. 보안 대응·보호 비교·발행자 신뢰의 추가 마이그레이션과 범위는 [보안 실행 계약](security-governance.md)을 따른다. 아래 226개 결과는 최초 실행 원장의 과거 체크포인트이며 최신 회귀 수는 [구현 현황](implementation-status.md)을 따른다.

## 실행권과 알림 전달권의 차이

outbox lease는 알림을 발행할 워커의 권한이다. 앱 실행 lease는 해당 앱을 변경할 제어 실행기의 권한이다. outbox를 수신했다는 사실만으로 실행권을 얻지 않는다.

앱 실행권은 테넌트·앱·작업·owner·난수 token·단조 증가 epoch·DB 기준 만료에 결합된다. 앱 하나에는 한 실행 소유자만 존재한다. 같은 앱의 다른 작업도 현재 소유자를 우회할 수 없다. 다른 앱은 다른 행으로 관리한다.

갱신·해제·효과 저장은 현재 token과 epoch를 확인한다. 만료된 소유자는 갱신하거나 결과를 확정할 수 없다. 실행권 갱신은 같은 token/epoch를 유지하며, 새 인계는 epoch를 증가시킨다.

## 외부 호출과 원장

의도·`in_flight`를 먼저 커밋한 뒤 외부 호출을 수행한다. 원장과 소유권 행의 잠금은 외부 호출 전에 해제한다. callback 안에서 다른 연결이 `FOR UPDATE NOWAIT`로 행을 잡을 수 있는지 시험했다.

실제 호출 직전에는 소유권·작업 상태·보안 보류·승인을 다시 확인한다. 승인 만료는 DB 시각으로도 검사하므로 느린 앱 시계로 수명을 연장할 수 없다. 저장된 계획 단계로 명령을 재구성해 인자·자원·action·멱등 키·만료까지 fingerprint를 비교한다. 계획 해시만 복사한 변조 명령은 실행하지 않는다.

완료·실패 기록은 새 provider 호출이 아니다. 아직 유효한 소유자는 승인 취소 이후에도 이미 발행한 효과의 관측을 기록할 수 있다. 그러나 실행권 자체가 만료됐거나 변경되면 완료 기록도 거부하고 미해결 상태를 보존한다. 새 호출과 기존 호출의 결과 기록을 구분한다.

같은 실행 소유자의 중복 명령은 원장 CAS로 막는다. 새 epoch에서 동일한 계획의 완료 단계를 재조회할 때는 epoch 이외의 의도가 정확히 같고 기존 결과가 `confirmed_applied`인 경우에만 옛 영수증을 반환한다. 원본 command와 epoch를 바꾸지 않으며 호출을 반복하지 않는다. 이는 역사적 완료 결과이지 현재 자원 health 확인이 아니다.

## 만료와 복구 barrier

`prepared`, `in_flight`, `unknown` 중 하나라도 앱에 남으면 일반 실행권 인계를 거부한다. 준비된 의도가 있더라도 먼저 조정해야 한다. 만료된 리스나 새 프로세스 기동만으로 barrier를 지우지 않는다.

복구는 이전 실행자와 그 외부 요청이 더 이상 늦은 변경을 만들지 않는다는 근거가 필요하다. `QuiescenceProof`는 테넌트·앱·원래 작업·이전 epoch·현재 미해결 효과 집합·관측/만료·artifact digest를 포함한다. `ExecutionRecovery`의 필수 인증 callback이 발급자와 내용을 검증한 뒤 저장소가 현재 DB 상태와 대조한다. artifact 해시나 타입 선언만으로 인증했다고 판단하지 않는다.

이 근거로 발급되는 권한은 `reconcile` 모드다. 새 `apply`와 새 `in_flight` 전이는 허용하지 않는다. 증거에 포함된 효과의 readback 또는 아직 claim되지 않은 의도의 취소만 허용한다. 복구 리스와 갱신은 proof의 유효기간을 넘지 못한다.

모든 미해결 효과가 안전하게 조정돼야 복구권을 해제하고 일반 실행권을 다시 받을 수 있다. 현재 관측이 원래 요청 상태를 확인하지 못하면 `unknown`을 유지한다. 자동으로 “실행되지 않았다”고 바꾸거나 barrier를 강제로 해제하지 않는다. 불명확한 결과를 관리자가 검토·종결하는 운영 절차와 화면은 후속 과제다.

## 검증과 보장 범위

전용 임시 PostgreSQL 17.11에서 전체 **226개 통과·실패/오류/skip 0**을 확인했다. 이번 실행권/효과 원장 관련 실제 PG 시험은 28개다. 기존 실제 PG 36개와 이전 회귀를 함께 실행했다.

시험은 동시 소유권, 다른 작업의 우회 거부, 갱신·만료·늦은 완료 거부, 모든 미해결 상태의 인계 차단, proof 범위·최신성·인증, 조회 전용 복구, 동일 의도의 과거 영수증 재사용, 인자 변조, 감사 실패 rollback, 저장된 계획부터 PG 효과 기록까지의 실행 경로를 포함한다.

별도 워커 프로세스가 임시 파일 효과를 fsync한 직후 실제 종료하도록 했다. DB의 `in_flight`와 기존 실행권은 남았고, 만료 뒤에도 일반 인계를 거부했다. 해당 테스트 프로세스와 동기 파일 작업이 끝났음을 확인한 시험 verifier로 조회 전용 복구를 수행해 재호출 없이 완료했다.

provider는 시험 대체물이며 AWS에 실제 변경을 수행하지 않았다. 이번 구현은 **프로토콜을 따르는 신뢰할 제어 실행기 사이의 DB barrier**다. AWS API 자체가 epoch를 검사하는 원격 fencing이나 악성 DB 런타임의 임의 SQL을 방어하는 인증 경계가 아니다. 외부 서비스의 요청 종결을 검증하는 실제 collector는 아직 없으므로 근거 없는 자동 복구·인계 경로를 열지 않는다.

앱 코드·AI·빌드 sandbox에 이 제어 DB 역할을 전달해서는 안 된다. 테스트용 하나의 역할 구성을 프로덕션의 API·실행·보안·복구 역할 분리 완료로 간주하지 않는다. 기업 인증·proof 서명/발급·최소 권한 실행 broker·소비자 dedup·실제 workflow/큐·웹은 운영 연결 단계에서 구현해야 한다.

임시 서버는 종료했고 데이터도 삭제했다. 기존 VM·게임·AWS·운영 DB는 변경하지 않았다. 로그와 개발기록은 `.local-notes/postgres-execution-20261031/`에만 남긴다.
