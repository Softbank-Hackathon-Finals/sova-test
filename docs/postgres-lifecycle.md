# Lifecycle의 PostgreSQL 저장

계획·조사 snapshot·승인을 PostgreSQL에 보존하고, 저장된 계획과 승인을 읽어 기존 실행 계층에 전달한다. 현재 실행 효과 원장은 프리뷰의 SQLite를 유지한다. 웹 화면·기업 로그인·작업/outbox 전체를 PostgreSQL로 옮긴 단계는 아니다.

## 코드 경계

| 모듈 | 책임 |
| --- | --- |
| `ports/plans.py` | 테넌트 범위 저장소, 저장된 승인 revision·취소 상태 |
| `adapters/plan_codec.py` | 저장 문서의 엄격한 복원·해시 계산 |
| `adapters/sql/postgres_lifecycle_v1.sql` | 테이블·키·FK·강제 RLS·PUBLIC 권한 회수 |
| `adapters/postgres_plans.py` | 불변 저장, 승인 취소 CAS, 트랜잭션 감사 |
| `application/stored_plans.py` | 저장된 승인 재조회와 실행 직전 취소 확인 |

계획 ID와 snapshot ID는 테넌트·앱 범위다. 같은 ID와 같은 내용의 저장은 멱등이고, 다른 내용으로 바꾸려 하면 충돌이다. 승인 ID도 대체하거나 취소 이후 재활성화할 수 없다. 변경된 계획에는 새 ID와 새 승인을 사용한다.

승인 취소는 예상 revision이 일치할 때만 적용하며, 동시에 요청하면 하나만 성공한다. 계획 생성·승인 생성·취소의 감사 행은 해당 변경과 같은 트랜잭션으로 저장한다. 감사 저장에 실패하면 변경도 롤백한다. 이 감사 테이블을 외부 WORM 감사 저장소라고 표현하지 않는다.

## 신뢰와 DB 권한

저장소의 테넌트는 신뢰할 인증 계층이 생성할 때 선택해야 한다. 요청 본문에서 받은 `tenant_id`로 저장소를 만들지 않는다. 모든 쿼리는 테넌트·앱 조건을 사용하며, DB에서도 RLS를 적용한다. 트랜잭션마다 `SET LOCAL`에 해당하는 `set_config(..., true)`로 문맥을 설정해 연결 재사용 시 잔류하지 않도록 한다.

런타임 역할은 superuser·BYPASSRLS·`sova_control` 객체 소유자가 될 수 없다. 저장소가 매 트랜잭션에서 이 조건을 확인한다. 마이그레이션은 별도의 관리 역할로 명시적으로 수행한다. API 시작 시 마이그레이션이나 관리자 접속으로 자동 우회하지 않는다.

런타임에 필요한 권한은 schema `USAGE`, 네 테이블의 `SELECT/INSERT`, 감사 identity sequence `USAGE`, 승인 테이블의 `UPDATE(revision, revoked_at)`이다. 계획·snapshot·승인 문서의 UPDATE와 감사 DELETE는 부여하지 않는다. 운영 배치에서는 감사 조회·승인 작성 등 역할을 추가로 분리해야 한다.

RLS의 테넌트 문맥은 신뢰할 애플리케이션이 설정한다. 임의 SQL을 실행할 수 있는 런타임 침해까지 방어하는 테넌트별 DB 로그인 분리는 이번 구현이 아니다. 사용자별 앱 접근 권한·승인 권한은 별도 인증/인가가 필요하다.

문서 해시와 복원 시 scope 검사는 잘못된 저장·변경을 감지한다. DB 관리자가 문서와 해시를 함께 바꾸는 공격까지 막는 서명은 아니다. 원문 Secret·운영 키는 이 저장소의 입력으로 전달하지 않아야 하며, 임의 문자열에서 비밀값을 자동 식별하는 기능은 없다.

연결은 호출자가 제공하는 connection factory를 사용하며, 접속 실패 시 SQLite로 대체하지 않는다. 원격 운영 DB는 배치 계층에서 인증서·hostname을 검증하는 TLS와 Secret 참조를 구성해야 한다. 이번 시험은 임시 Unix socket이므로 원격 TLS 검증 결과는 아니다.

## 저장된 승인과 실행

`StoredPlanExecutor`는 저장된 계획·승인부터 읽는다. 기존 `ApprovedPlanExecutor`의 승인·정책·근거 검사를 유지하고, 실행 직전 검사마다 승인 revision·내용·취소 상태를 다시 조회한다. claim 이후 취소가 확인되면 실제 어댑터 호출 없이 `confirmed_not_applied`를 기록한다.

이미 provider 요청을 보낸 뒤의 취소가 그 요청을 취소하거나 되돌리는 것은 아니다. 실행 중 결과 조회·fencing·보상 계획은 기존 효과 계약과 후속 workflow 조정의 책임이다.

## 실제 DB 시험

시험에는 PostgreSQL 17.11 임시 클러스터를 사용했다. 기존 VM·Docker·AWS·서비스 DB를 시작하거나 변경하지 않았다. 서버는 소유한 임시 디렉터리의 Unix socket으로만 수신했고, 종료 후 서버 중지와 시험 데이터 삭제를 확인했다. 시스템 PostgreSQL 서비스는 설치하지 않았다.

`tests/integration/test_postgres_plans.py`는 `SOVA_TEST_POSTGRES_DSN`이 있어야 실제 DB 시험을 실행한다. 대상의 `cluster_name=sova-persistence-test`와 DB 이름 `sova_test`를 확인한 뒤에만 시험 schema·역할을 생성한다. 개인/운영 DB의 DSN을 넣지 않는다. 시험용 클러스터의 관리 DSN이며 제품 런타임에는 사용하지 않는다.

```sh
cd sova
# 격리된 시험 클러스터에만 연결한다. pytest와 psycopg 3가 필요하다.
SOVA_TEST_POSTGRES_DSN='<isolated-test-cluster>' python -m pytest -q
```

실제 DB 프로필에서는 계획·승인·snapshot 재조회, 다른 테넌트·앱 거부, DB RLS 자체 검사, 런타임 문서 수정·감사 삭제 거부, superuser/소유자 거부, 동시 요청, 승인 취소, 인가 중 취소 확인, 감사 실패 롤백, 연결 재사용, 저장 문서 해시 불일치를 확인했다. DSN이 없으면 PostgreSQL 시험은 skip이므로 DB 검증 성공으로 해석하지 않는다.

이번 전체 결과는 178개 통과·실패/오류/skip 0이다. 상세 로그·Junit·서버 정리 확인·개발기록은 `.local-notes/postgres-plans-20261031/`에 보관한다.

후속으로 [작업·이벤트/outbox PostgreSQL 저장](postgres-outbox.md)을 추가했다. 기존 웹 요청·실제 사용자/조직 인가·실행 원장 이전과 워커 연결은 남아 있다. DB 어댑터 추가만으로 호스팅 서비스의 동시 실행·운영 인수가 끝난 것은 아니다.
