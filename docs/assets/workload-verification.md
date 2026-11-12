# README 썸네일 · 실제 실행 범위

## 현재 썸네일 · 2026-11-13 하이브리드 실제 실행 전체 페이지

README 썸네일은 **2026년 11월 13일 오전 4시 16분(KST), Sova 워크로드 대응 콘솔에서 「연관 구간 부분 격리」를 실제로 실행하던 중 저장한 전체 페이지**다. 작업 공간 메뉴, 요약 지표, 대응 유형, 운영 콘솔, 워크로드 지도, 구성 요소 상세, 범위·승인, 대응 타임라인을 자르지 않고 담았다.

- 실행 환경: 개인 AWS 계정의 실행 전용 EKS(출발지, ap-northeast-2)와 이 Mac의 RKE2(목적지·제어 probe). 두 환경은 IAM 인증 SSM 터널로만 연결한다.
- 실행 경로: 브라우저의 운영 콘솔에서 제안 명령 `inject` → `response plan` → `response submit` → `response approve` → `response verify`를 차례로 실행했다. 화면의 단계·지도·검사 결과는 서버가 실제 Kubernetes·HTTP·DB를 관측해 내려준 값이다.
- 촬영 시점: 「결과 확인」 단계(독립 검증 통과 후, 최종 명령 전). 서버 관측이 유효한(20초 이내) 동안에만 촬영했다. API·작업자는 격리 구역에 0 Pod로 표시되고, 주변 자원은 정상이며, 검사 10개가 PASS다.
- 서명 증거: `097d0c9e750c6c53.segment.verify.r954`·`…finalize.r955` 모두 pass. 지원 기록 `sq-ffb851b452105571`(aws/eks → on-prem/rke2).
- 가림: 페이지 텍스트의 12자리 AWS 계정 번호를 그리기 전에 `<AWS 계정 가림>`으로 바꾸도록 했다. 이 화면에서 보이는 영역에는 해당 번호가 없었고, 그 밖의 화면 요소는 바꾸지 않았다.
- 촬영 조건: 헤드리스 Chrome, CSS 너비 1440px·배율 2, 창 높이를 페이지 길이에 맞춤.
- 공개 전 확인: 촬영된 페이지 텍스트에 개인 경로·이메일·12자리 계정 번호·Pod UID가 없음을 확인했다.
- 실행 코드: `22ce74df1cb13293aeb24e36c90a51c2b0da4a15`(촬영 당시 서버). 실행 방법은 [워크로드 대응 실제 실행기](../workload-response-runtime.md)를 따른다. 해시·크기는 [thumbnail.json](thumbnail.json)에 있다.

이 화면은 단일 시험 앱에 대한 실행 기록이다. 팀 운영 환경 이전, 무중단 운영, 제품 T10 승인 완료를 뜻하지 않으며 현재 실시간 상태도 아니다.

## 이전 썸네일 · 2026-11-08 온프렘 지도 crop

이전 썸네일은 **2026년 11월 8일 실제 온프렘 Kubernetes 전용 시험 중 저장한 UI 화면**의 워크로드 지도 부분이다. 브라우저에서 만든 9종 대응 시나리오 화면을 사용하지 않았다. 당시 화면의 지도 좌표·노드·상태는 변경하지 않고 해당 영역만 잘라 브랜드·검증 날짜·범위 설명을 붙였다. 현재 클러스터를 다시 실행하거나 실시간으로 조회한 결과는 아니다.

### 확인한 실제 동작

- 같은 온프렘 클러스터의 별도 소유 namespace에서 고정 무상태 시험 API·이웃 서비스·Green API·독립 probe를 실행했다.
- 원본 Pod에서 보호된 이웃으로 보낸 비인가 HTTP 요청이 실제 403으로 거부됐고, 주체 신원과 독립 감사를 대조했다.
- 사건 후 별도 승인으로 원본 새 연결 차단, 이웃 정상 응답, Green 기동·HTTP 응답, 시험 진입점 전환과 readback을 확인했다.
- 화면의 8단계가 근거로 표시되는 것을 확인했다. 시험 종료 후 소유 namespace 세 개의 부재와 세션 회수 시 자료 철회도 확인했다.

이 실행은 단일 시험 API에 대한 검증이다. 임의 앱·일반 공격 탐지·공유 채팅 앱 대응·AWS→온프렘 데이터 이전·무중단 운영·제품 T10 승인 완료를 증명하지 않는다. 그림의 화살표는 시험 요청·probe·격리 관계이며 실제 트래픽량을 나타내는 계측 차트가 아니다. 현재 시험 자원 가동을 의미하지 않는다.

### 코드와 실행 근거 구분

| 구분                         | 기준                                                                           |
| ---------------------------- | ------------------------------------------------------------------------------ |
| 실제 시험 실행 생산자        | `3ab5dd3aa2aaf4bc2169526f67e9de3f1d4cf7ba`                                     |
| 검토한 플랫폼 UI 코드        | `fc1125d2d59d215cc1310ab462b1ae534384137a`의 기존 터미널 시험 UI·지도 renderer |
| 원본 캡처                    | 비공개 보존. 전체 화면의 개인 경로·시험 식별자는 공개하지 않음                 |
| 공개 캡처                    | [원본 지도 영역](workload-verified-capture.png)                                |
| 공개 결과 요약               | [선별한 실제 인수 결과](workload-verification.json)                            |
| 원본 해시와 crop 좌표        | git 이력의 `docs/assets/thumbnail.json` v2(`619fb6e`)                         |

- 실제 실행 코드: [터미널 실행기](https://github.com/Softbank-Hackathon-Finals/sova-test/blob/3ab5dd3aa2aaf4bc2169526f67e9de3f1d4cf7ba/demo/onprem_response/terminal.py), [관측→지도 변환](https://github.com/Softbank-Hackathon-Finals/sova-test/blob/3ab5dd3aa2aaf4bc2169526f67e9de3f1d4cf7ba/demo/onprem_response/terminal_projection.py).
- 확인한 기존 UI: [터미널 시험 화면](https://github.com/Softbank-Hackathon-Finals/platform/blob/fc1125d2d59d215cc1310ab462b1ae534384137a/services/console/testing/terminal_trial_assets/client.js). 이 검토용 플랫폼 커밋을 실제 시험 실행 생산자 SHA로 대체하지 않는다.

### 변경·확인 기록 · 2026-11-09

이전 README 썸네일의 브라우저 시나리오를 실제 검증 화면으로 교체했다. 보존한 원본 PNG와 인수 결과를 대조하고, 기존 UI가 실제 관측을 지도 renderer에 전달하는 경로를 확인했다. crop 영역에는 개인 경로·Pod UID·접속 정보가 없음을 시각적으로 확인했다. 두 PNG의 규격·SHA-256, 상대 링크와 공개 요약을 검증했다. 이미지·문서만 변경했으며 실제 자원이나 애플리케이션 코드는 수정하지 않았다.
