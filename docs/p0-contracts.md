# P0 실행 계약과 프리뷰 연결

Sova의 도메인 모델과 외부 변경 경계를 독립 Python 패키지로 분리했다. 현재 어댑터 연결은 단일 운영자 프리뷰 범위다. PostgreSQL·기업 인증·분산 워커·고객 환경 agent를 구현한 상태는 아니다.

## 모듈 책임

| 위치 | 책임 |
| --- | --- |
| `src/sova/domain/contracts.py` | 불변 명령·자원 범위·permit·관측·효과 상태 |
| `src/sova/domain/environments.py` | 앱 revision, provider/backend, 공급자 기능·Sova 구현·경로 자격·실행 준비 분리 |
| `src/sova/domain/workflows.py` | 이전 단계·실패/복구 전이, 프리뷰 단계의 재실행 금지 |
| `src/sova/domain/evidence.py` | revision·대상·검증기에 결합된 근거와 G0~G8 의무 이관 |
| `src/sova/domain/plans.py` | 조사 snapshot·계획 DAG·계획 해시·용도별 승인 |
| `src/sova/ports/effects.py` | 변경 어댑터와 효과 원장 인터페이스 |
| `src/sova/ports/lifecycle.py` | 조사·계획·검증·복구 계획·정리 계획의 읽기/계획 port |
| `src/sova/application/effects.py` | 실행 직전 검사, 의도 기록, 변경, readback, 불명확한 효과 조정 |
| `src/sova/application/plans.py` | 승인·필수 검증·선행 작업을 확인해 계획 단계를 기존 실행 원장으로 전달 |
| `src/sova/adapters/sqlite_effects.py` | 프리뷰용 SQLite 원장·CAS·자원별 미해결 효과 제한 |
| `src/sova/adapters/preview.py` | 등록된 SG 변경·로컬 경로 전환을 제한 명령으로 연결 |
| `preview/server.py` | 기존 HTTP/UI·제어 시험의 진입점과 로컬 정책 |

도메인은 클라우드 SDK·프리뷰 서버·DB를 import하지 않는다. 형제 Sky·OneDeploy 디렉터리 없이 별도 디렉터리에서 핵심 모듈을 import하는 시험도 수행했다. 프리뷰의 실제 자원 준비·터널은 기존 운영자 경로를 계속 사용하므로 제품 전체의 독립 설치가 완료됐다는 의미는 아니다.

## 외부 변경 절차

1. 서버가 명령과 permit의 앱·환경·자원·작업·계획 해시·명령 해시·epoch·만료를 확인한다.
2. 어댑터가 등록된 action과 공개 인자 schema만 허용한다. 임의 CLI·Secret 원문을 받지 않는다.
3. SQLite에 `prepared`를 기록한다. 같은 키에 다른 입력은 충돌이며, 다른 미해결 효과가 같은 자원을 사용 중이면 막는다.
4. revision CAS로 `in_flight`를 기록하고 커밋한다. 실제 호출 직전에 정책·만료를 다시 확인한다.
5. 어댑터가 한 번 호출한다. 성공 응답 뒤에도 실제 자원 readback을 수행한다.
6. 명령에 결합된 관측이 맞으면 `confirmed_applied`를 기록한다. 예외·불일치는 `unknown` 또는 미완료 `in_flight`로 남으며 자동 재호출하지 않는다.

`confirmed_not_applied`는 호출 전 거부 또는 아직 claim되지 않은 의도의 명시적 취소에서만 사용한다. 현재 자원 값이 예상과 다르다는 이유만으로 과거 호출이 실행되지 않았다고 판단하지 않는다.

동일한 완료 명령을 다시 실행하면 기존 영수증을 반환한다. 이는 역사적 완료 기록이고 새 health check가 아니다. 진행 중·결과 불명인 명령은 재실행하지 않는다. 원장 저장 실패도 외부 호출의 중복 실행 근거가 되지 않는다.

## 조사·계획·복구 경계

`LifecycleAdapter`의 `inspect`, `plan`, `verify`, `plan_recovery`, `plan_finalization`은 자원을 변경하지 않는 계약이다. 복구·정리는 새 `LifecyclePlan`을 만들며 원본 계획 해시와 사유를 기록한다. 실제 변경은 모든 용도에서 같은 `EffectExecutor`를 사용한다. 이 port 선언 자체가 플러그인 코드의 무해성을 보증하는 sandbox는 아니다.

계획의 해시는 앱·테넌트·작성자·용도·입력 revision·단계 인자·선행 관계·의무·유효기간을 포함한다. 실행 시점의 operation ID·epoch는 별도 결합하므로 plan digest와 command digest의 순환 참조가 없다. 단계는 유일한 ID와 먼저 정의된 선행 작업만 참조할 수 있다.

`ApprovedPlanExecutor`는 작성자와 다른 승인자, 정확한 계획 해시·용도·유효기간, 신뢰할 정책이 요구하는 필수 의무, 근거 발급자, G7 판정과 선행 단계의 실제 완료 기록을 확인한다. 계획 자체가 필수 의무를 삭제하거나 선택 사항으로 완화할 수 없다. 빈 필수 정책도 실행 허가가 아니다.

승인·정책·근거는 실제 호출 직전 다시 검사한다. permit 수명을 승인·계획·사용한 필수 근거의 가장 이른 만료로 제한하고, 인가 조회 중 시간이 경과한 경우에도 만료된 권한으로 dispatch하지 않는다. 승인 철회나 근거 만료가 claim 이후 확인되면 실제 호출 없이 `confirmed_not_applied`로 남긴다.

이번 연결은 공통 실행 계층과 테스트용 어댑터까지다. 기존 웹 화면의 계획 생성 전체를 이 계층으로 전환하거나 실제 AWS 복구·삭제를 구현한 것은 아니다. 실제 사용자 인증·승인·근거 서명은 주입한 인증 경계에서 구현해야 하며, 값 객체의 승인자 이름을 인증 증거로 믿지 않는다.

## 조정과 중단

`reconcile()`은 `apply()`를 부르지 않고 조회만 한다. 오래된 실행자와 그 외부 요청이 더 이상 늦은 변경을 수행하지 않는지 확인하는 책임은 실행 인가 경계에 있다. 리스 만료나 현재 값이 맞다는 사실만으로 이 조건을 충족하지 않는다.

현재 프리뷰에서 응답이 유실된 SG 효과는 사용자가 명시적으로 시험 격리 해제를 요청했을 때 이전 완료 작업의 상태를 읽어 조정한다. 이전 작업의 종료가 확인되지 않으면 새 변경을 거부한다. 이전 workflow의 실패 이력을 성공으로 고쳐 쓰지 않는다.

일반 코어의 조정은 도구 계약까지 구현했으며, 프리뷰에는 모든 효과를 조정하는 운영 화면이 없다. 특히 프로세스 종료 뒤 `completed`가 없는 작업이나 로컬 경로 효과는 자동 해제하지 않는다. 이를 운영자가 안전하게 검토·해제하는 흐름과 분산 실행자의 실제 fencing은 P1 이후 과제다.

프리뷰 경로 변경은 DB revision과 효과 digest를 함께 저장한다. 목적지·revision·digest를 모두 읽어 확인해야 해당 변경의 성공으로 판단한다. 새 서버가 예전 route 테이블을 읽을 때는 현재 경로와 이력을 보존한 채 marker 열을 추가한다. 테스트용 복사본으로 이전 schema 호환을 검증했다.

## 상태와 검증 의무

일반 이전 모델에서 fencing 이후의 실패는 평범한 `failed/cancelled`로 종료하지 않고 `recovery_required`로 전환한다. 보안 보류는 별도 속성이며, 보류 상태를 기록할 수 있어도 다음 변경을 진행할 수 없다. 이 모델을 현재 프리뷰가 일반 DB 이전에 사용하는 것은 아니다.

근거는 테넌트·앱·환경·자원, source/config/policy/environment revision, 검증기 버전, 관측/만료, artifact 참조·해시에 결합된다. 최신 근거가 실패하면 과거 성공으로 덮지 않는다. 근거가 누락·만료됐거나 미래 시각이거나 최신 결과가 모호하면 `unknown`이다.

게이트 결과에는 전체 의무 판정과 다음 게이트로 이관할 의무 ID가 포함된다. 이후 단계의 의무는 지금 통과 근거가 있더라도 이관해 다시 최신성을 검사한다. `not_applicable`은 설명·승인자·유효기간이 필요하다. 이 문자열과 해시 자체가 인증·서명·승인 증명은 아니며 신뢰할 발급자 검증은 제어면에서 구현해야 한다.

## 시험과 한계

개발 환경에서 다음 명령을 사용한다. Python 3.11 이상, pytest가 필요하며 프리뷰 시험에는 boto3 import가 필요하다. HTTP 통합 시험은 임시 localhost 포트를 사용한다.

```sh
cd sova
python -m pytest -q
ruff check src tests preview/server.py preview/test_security.py
```

시험은 실제 SQLite·로컬 HTTP API·별도 DB 연결·자식 프로세스 종료를 사용한다. 프리뷰 연결 시험의 AWS·TLS 경계는 명시적인 fault injection이다. 등록된 클라우드 자원·기존 앱·DB를 변경하지 않는다.

| 확인한 경계 | 시험 |
| --- | --- |
| 의도 기록 선행 | 다른 DB 연결에서 `in_flight` 커밋을 확인한 뒤에만 effect 호출 |
| 응답 유실·재시작 | 실제 프로세스가 임시 파일 효과 후 종료; 재시작이 효과를 재실행하지 않음 |
| 동시 실행 | 서로 다른 SQLite 연결에서 같은 명령의 apply 1회 |
| 저장 실패 | claim 감사 저장 실패 시 rollback, 완료 저장 실패 뒤 재실행 거부 |
| 범위·순서 | 다른 tenant/plan/epoch·중복 단계·완료 단계 재실행·대상 변경 거부 |
| 입력 | 중복 JSON 키·NaN·잘못된 Unicode·타입·초과 크기 거부 |
| 근거 | 다른 환경/revision·만료·최신 실패·모호한 최신 시각에서 차단 |
| 프리뷰 호환 | 기존 202 접수·상태 조회·격리/해제·세션/Origin 계약 유지 |

이것은 운영 시스템의 분산 정확히 한 번 실행, 실제 AWS 재검증, 기업 인가, WORM 감사, 악성 코드 sandbox, DB writer fencing, 실데이터 이전의 완료를 뜻하지 않는다. 기존 시험 등록은 유효기간이 지났으며 이 작업에서 연장·재생성하지 않았다.

## P1로 넘길 작업

- lifecycle 계획·승인·snapshot의 PostgreSQL 저장과 승인 재조회 실행 연결을 추가했다. 범위와 실DB 시험은 [PostgreSQL 저장 설명](postgres-lifecycle.md)을 따른다. 기존 웹 요청·작업 흐름 연결은 남아 있다.
- PostgreSQL 도메인 저장소와 제약·테넌트 인가/RLS, Secret 참조 및 outbox.
- 기업 인증·실시간 멤버십·분리 승인·서명된 명령 신원.
- workflow와 도메인 상태의 정합성, 앱 단위 상충 작업 제어, 외부 효과의 소유자·실제 fencing.
- 미완료 작업·효과를 현재 자원과 비교하는 조정 화면과 안전한 운영자 복구 절차.
- 실제 AWS·원격 VM의 어댑터 자격 및 이후 데이터 이전·복구 계약 연결.

개발기록·시험 결과·실행 시각은 `.local-notes/p0-20261031/`에 보관한다. 목표 전체는 [프로덕션 설계 명세](sova-production-spec-v1.md)를 따른다.
