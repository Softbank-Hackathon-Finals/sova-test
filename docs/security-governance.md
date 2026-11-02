# 보안 거버넌스 실행 계약

2026-11-01 · 보안 담당 구현 계약. Harbor 실행 연동은 팀원 담당으로 유지한다.

## 구현 범위

| 영역 | 구현 |
| --- | --- |
| 공통 보호 목적 | 신원·Secret·네트워크·암호화·감사·정책·백업의 통제 분류 |
| 정책 | tenant/app·정확한 자원 scope·필수 검증 의무·verifier 버전·revision·유효기간·내용 digest |
| 판정 | 충족·위반·미확인. 최신 근거의 범위·revision·만료·중복 모호성 확인 |
| 독립 보류 | 앱 전체의 변경을 차단하는 PostgreSQL 보안 보류 이력 |
| 해제 | 별도 권한·보류 이후 재검증·분리 승인·정확한 scope/revision·기한 |
| 실행 연결 | 계획 검사와 외부 효과 apply 직전 재검사, 저장 계획 경로에서도 유지 |

provider 기능이 있다는 사실, Sova 어댑터가 구현됐다는 사실, 해당 자원의 보호가 검증됐다는 사실은 서로 다르다. 이 모듈은 **인증된 근거를 판정하는 계층**이다. Kubernetes의 제한된 설정 수집과 RDS 메타데이터 수집 어댑터를 구현했으며, 전체 provider 보안 조사는 지원하지 않는다. [보호 수준 비교](protection-parity.md)와 [RDS 읽기 전용 조사](aws-rds-security.md)의 검증 범위를 따른다.

## 정책과 판정

`GovernancePolicy`는 신뢰된 정책 공급자가 제공한다. 정책 내용 digest는 `plan.revisions.policy`와 같아야 한다. 빈 정책, 선택 항목으로 약화한 통제, 실행 후 게이트로 미룬 통제는 거부한다. 계획의 모든 실행 자원에 보안 통제가 있어야 하며 정책 의무가 계획에서 누락되면 실행을 막는다.

각 `SecurityControl`은 기존 `VerificationObligation`과 연결한다. 정확한 scope·source/config/policy/environment revision·verifier 버전이 같은 `EvidenceRecord`만 사용한다. 최신 관측의 실패를 옛 성공으로 덮지 않는다. 같은 시각의 복수 근거는 미확인으로 남긴다.

| 상태 | 판정 |
| --- | --- |
| satisfied | 유효하고 정확히 결합된 PASS |
| violated | 유효한 최신 FAIL |
| unknown | 근거 없음·만료·미래·scope/revision/version 불일치·모호성·UNKNOWN |

현재 `NOT_APPLICABLE`도 필수 보안 통제를 통과시키지 않는다. 일반 승인자 이름이나 사유를 넣어서 예외를 만들 수 없다. 공식 예외·보완 통제·만료·별도 승인 모델은 후속 구현이며 현재 자동 예외 승인은 지원하지 않는다.

정책·근거를 읽는 동안 시간이 경과할 수 있으므로 조회 후 신뢰된 clock으로 다시 판정한다. 보안 유효기간은 정책과 선택된 근거의 가장 짧은 기한이며 실행 permit 기한에 포함한다. 인가 조회 도중 만료된 실행은 거부한다.

## 독립 보안 보류

`SecurityHold`는 원인 자원의 scope를 보존하지만 **동일 tenant/app의 모든 환경에 대한 변경**을 차단한다. 다른 환경으로 이동하거나 새 배포 승인을 받는 것으로 우회하지 못하게 한다. 시간 경과·근거 PASS·새 계획·일반 승인으로 자동 해제되지 않는다.

보류는 `security_hold_events`에 opened/released 이벤트로 추가한다. 공개 API의 단순 boolean 변경으로 처리하지 않는다. 같은 ID를 다른 내용으로 바꾸거나 해제한 ID를 재활성화하지 않는다. 새 사고는 새 hold ID를 사용한다.

- 강제 tenant RLS와 명시적 app 범위 조회
- 기본 권한 제거, 비소유·비슈퍼유저·NOBYPASSRLS 역할
- append-only runtime 권한: SELECT/INSERT, UPDATE/DELETE 금지
- 앱별 보류 집합 잠금·보류별 직렬화·revision CAS. v2 DB 트리거는 직접 SQL INSERT도 같은 앱 잠금에 참여시킨다.
- 운영 DB 시각으로 보류·해제 기한 재확인
- 재시작 후 활성 보류와 해제 이력 조회

배포 실행기는 이 테이블에 **SELECT만**, 별도 보안 관리 서비스는 필요한 SELECT/INSERT만 갖게 한다. 테스트의 일반 repository 역할은 편의를 위해 더 많은 테이블을 읽고 쓴다. 운영 권한 전체를 그대로 복제해서는 안 된다. 마이그레이션은 운영자가 별도로 적용하며 시작 시 자동 실행하지 않는다.

공유 DB 계정 자체를 탈취한 공격자가 tenant 설정을 바꾸거나 INSERT 권한을 악용하는 경우까지 RLS가 방어한다고 주장하지 않는다. 정책·서명 검증·서비스 역할 분리·감사 저장의 추가 경계가 필요하다.

## 해제 절차

1. 신뢰된 인증 경계에서 요청자를 식별한다. actor 문자열 자체는 인증 증거가 아니다.
2. 해당 보류를 tenant/app 범위로 조회하고 아직 활성인지 확인한다.
3. `security:release-request` 권한을 확인한다.
4. scope·source/config/policy/environment revision·expected hold revision·재검증 자료 digest·기한에 결합된 `HoldRelease`의 승인 출처를 인증한다.
5. 별도 승인자의 `security:release-approve` 권한을 확인한다. 요청자 자기 승인과 보류를 올린 당사자의 해제 승인은 거부한다.
6. 인증된 `security-revalidation-v1` 근거를 확인한다. obligation ID는 `security-release:<hold_id>`이며 같은 자원·현재 revision·보류 이후 관측·유효한 PASS여야 한다. 이전 배포 근거·N/A·다른 앱의 근거는 거부한다.
7. 승인한 근거와 현재 근거의 ID·artifact digest·revision·기한을 대조한다. 승인 후 revision이 달라지면 새 승인이 필요하다.
8. PostgreSQL에서 현재 revision과 DB 시각을 다시 확인하고 released 이벤트를 추가한다. 경쟁 해제·재전송은 기존 해제 사실을 지우거나 재활성화하지 않는다.

해제는 provider의 SG·NetworkPolicy를 복원하는 동작이 아니다. 실제 격리 복원은 새 계획·권한·readback 검증이 필요한 별도 외부 효과다.

## 실행 경계

`ApprovedPlanExecutor`에 `governance_guard=GovernanceGuard(...)`를 주입한다. `StoredPlanExecutor`도 같은 guard를 보존한다. 정책·근거 인증기와 공급자, 현재 보류 저장소는 서버가 정하며 요청자가 선택하지 않는다. 조회 실패는 예외로 중단하고 빈 정책·빈 보류로 바꾸지 않는다.

기존 프리뷰·기존 executor의 호환성을 위해 guard 없는 경로는 남아 있다. 그 경로를 거버넌스가 적용된 운영 경로로 표시하지 않는다. 호스팅 조립 단계에서는 guard가 없는 설정을 거부하고 배포 역할의 보안 이벤트 쓰기를 차단해야 한다. Ed25519 근거 인증과 PG 발행자 등록·폐기는 구성 요소로 검증했다. 기업 OIDC·독립 signing 서비스·실제 provider 권한 broker는 아직 연결하지 않았다.

현재 게이트는 dispatch 전 재검사를 제공한다. **보류 기록과 원격 provider 변경이 원자적이라는 보장은 없다.** 최종 검사와 provider 요청 사이에 새 보류가 생기거나 이미 시작한 요청을 취소해야 하는 문제는 broker의 보안 revision 결합·단기 권한 폐기·원격 fencing·불명확 효과 조회로 해결해야 한다. 이 단계만으로 모든 진행 중 변경을 즉시 차단한다고 주장하지 않는다.

읽기 전용 조사·불명확 효과의 조회 복구는 별도 인가 경로다. 보류가 있다는 이유로 관리·관측·증거 보존까지 끊지 않는다. 제한된 `security_response` 경로는 등록된 무상태 앱·정확한 사고 보류·원본/대상·이미지·설정·정책·기한에 결합된 네 동작만 허용한다. 새 보류나 다른 자원이 발견되면 중단한다. 일반 배포가 목적 문자열만 바꿔 우회할 수 없으며, 대응 완료 후에도 원본 보류를 유지한다. 범용 긴급 예외 정책은 미구현이다.

## 대응 완료의 원자 기록

`SecurityResponseRunner`는 각 상태 전이를 현재 앱 실행권에 결합한다. 최종 경로 readback 후에도 저장된 승인·필수 근거·보류를 다시 검사한다. PostgreSQL의 `finish_response`는 다음을 한 트랜잭션으로 처리한다.

1. 현재 owner·epoch·lease, 작업 revision, 승인 revision·기한, 정확한 사고 보류 집합을 재확인한다.
2. 같은 epoch의 네 효과가 모두 APPLIED인지 확인한다.
3. 마지막 효과 이후의 정확한 경로 readback과 15초 이내의 검증 유효기간을 확인한다.
4. 불변 완료 영수증, 완료 상태, outbox 억제, 실행권 반환을 함께 저장한다.

하나라도 실패하면 모두 롤백한다. COMMIT 응답만 유실됐을 때는 저장된 완료 영수증을 조회해 복구하며 provider 변경을 반복하지 않는다. 일반 상태 변경 API로 완료 상태를 직접 만들 수 없다. 완료 영수증은 당시 결과의 이력이며 현재 보안 통과권이 아니다.

이 원자성은 **제어 DB의 완료 처리**에 한정한다. Kubernetes·AWS 변경과 DB가 분산 트랜잭션으로 묶인다는 뜻이 아니다. 과거 완료 작업에 v2 영수증이 없다면 새 형식으로 자동 재자격 처리하지 않는다.

완료 워커가 승인 행을 `FOR SHARE`로 잠그려면 PostgreSQL의 UPDATE 권한이 일부 필요하다. 이를 위해 승인 revision·폐기 시각 수정 권한을 주어서는 안 된다. `postgres_lifecycle_v2.sql`의 생성 상수 열 `lock_guard`에만 `UPDATE(lock_guard)`를 부여한다. 이 열은 승인 내용·기한·폐기 상태를 바꾸지 못한다. 실제 PG에서 이 권한만으로 완료가 성공하고 승인 생성·폐기·재활성화·내용 수정이 거부됨을 확인했다. 별도 승인 관리 역할만 승인 상태를 변경한다.

v2는 운영자가 실행기 배포 전에 적용하는 schema 변경이다. 기존 운영 DB에서의 DDL 잠금·테이블 재작성 시간은 시험하지 않았다. 운영 적용 전 별도 복제본 리허설·잠금/실행 시간 제한·유지보수 계획이 필요하며 서비스 시작 중 자동 적용하지 않는다.

## 관련 코드

- `domain/governance.py`: 정책·공통 통제·판정·보류·해제 계약
- `application/governance.py`: 신뢰된 근거 공급·독립 보류 게이트·해제 인가
- `adapters/postgres_governance.py`: 보류의 추가 전용 저장·CAS·RLS
- `adapters/sql/postgres_governance_v1.sql`, `postgres_governance_v2.sql`: 운영자 적용 마이그레이션
- `domain/response_completion.py`, `adapters/postgres_operations.py`: 완료 영수증·원자 완료
- `adapters/sql/postgres_security_response_v2.sql`: 완료 영수증 RLS·추가 전용 저장
- `adapters/sql/postgres_lifecycle_v2.sql`: 승인 상태 변경 권한 없는 행 잠금 지원
- `application/plans.py`, `application/stored_plans.py`: 실행 직전 검사의 연결과 보존

## 검증과 다음 단계

실제 임시 PostgreSQL로 재시작·tenant/app 격리·RLS·UPDATE/DELETE 거부·동시 생성/해제·읽기 전용 배포 역할·실행 직전 새 보류를 시험한다. 외부 provider와 신원 인증은 시험 대체물이다. 이 결과는 실계정 보안 자격이 아니다.

다음은 독립 권한 broker와 기업 인증 연결, 더 넓은 provider 보호 시험, 중앙 정책 운영·알림·명시적 예외, 실제 외부 환경 장애 시험이다. 로컬 k3s 및 DB 시험 결과는 [검증 현황](security-workload-validation.md)에 구분한다.
