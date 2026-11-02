# 담당 경계와 보안 근거 연동

2026-11-01 결정: **Harbor 실행 연동은 팀원**, 현재 작업은 **보안 거버넌스**를 담당한다.

| 담당 | 책임 |
| --- | --- |
| Harbor | 일회성 실행 환경·agent 도구·독립 verifier·테스트 실행·산출물 수집·환경 정리 |
| 보안 거버넌스 | 필수 보호 통제·정확한 scope/revision·근거 수용·보류·별도 해제·실행 게이트 |
| 공유 계약 | source/patch/image/tests digest, tenant/app/environment/resource, 정책 revision·검증 의무·발행자·버전·시각·만료·결과 |

Harbor의 성공 응답을 곧바로 운영 승인으로 사용하지 않는다. 신뢰된 수신 경계가 발행자·작업·산출물 출처를 검증한 뒤 기존 `EvidenceRecord`로 정규화한다. 정책이 기대한 obligation ID·verifier 버전·scope·revision이 일치해야 한다. 원문·키·민감 실행 로그는 근거 본문에 넣지 않고 허용된 artifact 참조와 digest를 사용한다.

보안팀이 PASS를 만드는 권한을 agent에 주지 않는다. agent는 source·독립 tests·verifier 정책을 바꿔 자기 결과를 승인할 수 없다. 보안 보류는 Harbor 재실행 성공·일반 배포 승인으로 해제되지 않는다.

`HoldRelease`는 별도의 보안 승인·재검증 계약이다. Harbor가 재검증 자료를 제공할 수 있지만 해제 권한이나 승인을 대신하지 않는다. 운영자는 서명·신원·단기 자격 증명과 전송 경계를 연결해야 한다.

현재 구현은 신뢰된 공급자·인증 callback을 주입하는 port 방식이다. 실제 Harbor 결과 수신·기업 인증·서명 검증은 아직 연결하지 않았다. 담당 경계를 맞추는 과정에서 각자 다른 보류 boolean·승인 상태 머신을 만들지 않는다.

## 추가된 결과 binding

산출물에는 원래 `SandboxRequest.fingerprint`인 `request_digest`를 포함한다. source/tests뿐 아니라 scope·agent/verifier digest·timeout·만료의 변경도 구분한다. Harbor 준비 응답의 binding에도 같은 필드를 제공한다. 수용 경계는 이 fingerprint와 별도 인증된 근거를 요구하며 runner 구현은 담당 팀원이 연결한다.
