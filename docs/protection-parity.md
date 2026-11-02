# 출발지·목적지 보호 수준 비교

2026-11-01 · 구현 계약과 검증 한계.

## 비교 단위

IAM과 Kubernetes RBAC를 같은 설정으로 취급하지 않는다. 공통 보호 목적 하나에 출발지·목적지의 구현과 실제 근거를 각각 연결한다.

```text
보호 목적 → 출발지 구현·근거 / 목적지 구현·근거
         → 유지·개선·퇴보·미충족·미검증
```

`ProtectionEndpoint`는 정확한 tenant/app/environment/resource, provider, 구현 방식, provider 지원 여부, Sova 어댑터 구현 여부, 소스·설정·환경 digest, verifier 버전을 가진다. provider 지원과 어댑터 구현만으로 PASS가 되지 않는다. 다른 환경 이름이 같은 물리 자원을 가리키는 비교도 거부한다.

`ProtectionPolicy`는 요구사항·revision·유효기간과 내용 digest를 고정한다. 빈 정책과 필수 항목이 없는 정책은 거부한다. 필수 목적지 근거가 유효한 PASS여야 하며 출발지도 비교 가능한 PASS 또는 FAIL이어야 한다. 누락·만료·미래 관측·revision 불일치·동시각 모호성·N/A는 필수 검증을 통과시키지 않는다.

## 최소 보호 프로필

`ProtectionProfile`은 정책 작성자가 필수 목적을 삭제하거나 설정 검사로 대체하는 것을 막는다. 프로필 digest를 정책에, 정책 digest를 계획에 결합한다. 실행 guard에는 신뢰된 `profile_provider`가 필수다.

`production_protection_profile()`에는 다음 **필수 증거 계약**을 정의했다.

| 보호 목적 | 필요한 시험 |
| --- | --- |
| 앱 간 접근 거부 | 다른 앱의 권한으로 보호 자원 접근 거부 |
| Secret 회전·폐기 | 새 인증정보 성공, 폐기한 인증정보 거부 |
| egress·관리 경계 | 금지한 외부·관리 경로 접근 거부 |
| TLS 상대 검증 | 올바른 CA·상대 신원 성공, 신뢰하지 않는 상대 거부 |
| 저장 암호화 키 | 허가한 키 접근과 비인가 키 접근 거부 |
| 감사 전달·무결성 | 실제 감사 이벤트 도착과 변경 탐지 |
| 백업 복원·무결성 | 격리된 복원과 데이터 무결성 확인 |

이 목록은 구현된 provider probe 목록이 아니다. 아직 이 전체 프로필의 운영 자격을 통과하지 않았으며, 이름이 맞는 임의 근거를 발행해 통과시키면 안 된다. 시험용 단일 목적 프로필도 전체 프로덕션 프로필과 구분한다.

## 실행 연결

`ProtectionParityGuard`는 서버가 제공한 정책·프로필·현재 revision·발행자 인증·활성 보류로 판정한다. 요청자는 공급자나 인증 함수를 고를 수 없다. 근거 인증 후 정책과 revision을 다시 읽고, 감사 기록 후에도 기한·보류·revision 변경을 검사한다. 등록되지 않은 실행 자원은 차단한다.

이 guard를 `ApprovedPlanExecutor`의 `governance_guard`에 연결해 실제 임시 PostgreSQL·서명 근거와 함께 시험했다. 외부 배포 어댑터와 권한 주체는 해당 통합 시험에서 대체물이다. 모든 호스팅 실행 경로에 자동 적용된 상태는 아니다.

정책과 판정 이력은 `postgres_protection_parity_v1.sql`로 저장한다. 정책 revision은 불변이며, 판정은 계획·정책·근거 digest에 연결된다. 오래된 PASS 보고서는 이력이며 새 실행 허가가 아니다.

## 발행자 신뢰

Ed25519 공개키 등록·폐기 이력을 PostgreSQL에 추가 전용으로 저장한다. tenant/app 범위·허용 자원·verifier 버전·신뢰 기한을 매번 확인한다. 같은 key ID의 키 교체와 폐기한 key ID의 재활성화를 막는다. 새 키는 새 ID로 등록한다.

등록·폐기는 요청자와 별도 승인자의 인가 및 승인 출처 인증을 요구한다. 검증자는 공개 신뢰 이력만 읽고 자신을 등록할 수 없다. 실제 k3s 근거 서명·저장·폐기와 DB 권한 거부를 시험했지만, 기업 승인 신원·키 보관 서비스·독립 signer 배치는 아직 연결하지 않았다.

## 화면과 실행 권한 구분

로컬 보안 콘솔의 비교표는 실제 k3s Pod template의 12개 **설정 검사**를 비교한다. 누락된 검사는 미검증으로 남긴다. 결과에는 `basis=configuration_only`, `execution_authority=False`를 표시한다. Kubernetes를 cloud provider라고 추정하지 않으며 등록이 없는 provider는 `unclassified`다.

이 표를 위 프로덕션 프로필의 실행 승인으로 사용할 수 없다. 설정 일치, 통신 차단, 기업 권한 검증, 백업 복원, 서비스 이전 자격은 각각 별도 근거가 필요하다.

## 주요 코드

- `src/sova/domain/protection_parity.py`, `protection_profiles.py`: 비교·최소 목적 계약
- `src/sova/application/protection_parity.py`: 실행 guard
- `src/sova/adapters/postgres_protection_parity.py`: 정책·판정 이력
- `src/sova/domain/verifier_registry.py`, `application/verifier_registry.py`: 신뢰 변경·분리 승인
- `src/sova/adapters/postgres_verifier_registry.py`: 공개 신뢰 등록·폐기
- `src/sova/application/protection_projection.py`: 읽기 전용 콘솔 비교

범위별 실제 시험은 [보안·워크로드 검증 현황](security-workload-validation.md)을 따른다.
