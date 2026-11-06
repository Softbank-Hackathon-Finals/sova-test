# T14·T33 맥 인수 도구 소비

- 요구: 기존 platform 보안 계약에 맞는 로컬 보강, 맥 실행 준비, 기능별 커밋·푸시.
- platform 기준: `c364e6284d2e635ff86001e2feac88560ed23ebc`.
- security 생산자: `27e6e85514a7cbb3e43d216464b72d9bd78f3fcf`, 패키지 0.11.1.
- 구현: `interfaces/security_intake.py`, 기존 CLI dispatcher와 owner-checked private reader 재사용.
- 진단: `platform-security-intake.v1`. 기존 `security-program-input.v1`와 별개이며 게이트 입력이 아니다.

입력 없이 full 시험 20개의 준비 목록을 생성한다. private ControlRun·SourceStatus는
선택적으로 읽고 stdout으로 정리한다. 클라우드·shell subprocess를 호출하지 않는 시험을
추가했고 Windows 2 PASS·POSIX private-file 시험 1 SKIP를 확인했다. Linux CI에서는
설치된 producer wheel로 같은 시험과 기존 process/container 실행·T28 회귀를 검증한다.

기존 T28의 접수·effect journal·실행 경로는 변경하지 않는다. 기존 0.11.0 이미지 source와
새 0.11.1 source를 혼동하지 않도록 manifest의 exact source·version·13개 플랫폼 계약을
갱신했다. 실제 AWS/GCP/온프렘 로그인·수집·보안 인수는 수행하지 않았다.

최종 검토에서 T10이 발급한 workload ID를 카탈로그의 표시 이름 demo-chat으로 바꾸지
않도록 보강했다. 양쪽 workload는 같고 환경·run ID는 달라야 한다. 보류 권한 자체의
인증 중 철회도 효과 직전에 재검사한다. 현재 생산자는 이 두 수정을 포함한다.
