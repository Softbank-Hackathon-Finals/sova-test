# AI 에이전트와 Harbor 샌드박스

상태: 작업 요청·Harbor 설정 준비·요청 전체에 결합한 산출물 수용을 구현했다. 실제 Harbor runner·모델 gateway·독립 verifier 실행은 아직 연결하지 않았다.

## 책임 분리

Sova는 승인 가능한 작업을 생성하고 실행권·비용·정책·자료 출처를 관리한다. Harbor Framework는 격리 작업과 평가를 실행하는 교체 가능한 어댑터다. OCI registry 제품 Harbor와 구분한다. guest 격리 backend는 데이터 등급·위치·적대성·운영 조건에 따라 선택하고 자격 시험을 통과해야 한다. 직접 Firecracker 제어기를 만드는 것을 첫 구현의 필수 전제로 두지 않는다.

AI는 조사·코드 변경·시험 도구를 사용하지만, 배포 승인·보안 보류 해제·운영 자격 발급·서명 키 접근은 할 수 없다. 코드·문서·도구 출력의 지시는 불신 데이터로 처리한다.

## 입력·실행 경계

작업은 scope, source/test digest, 고정 agent/verifier 이미지, 시간·용량·network·도구 한도, 정책·환경 revision과 만료에 결합한다. 작업 기록에는 Secret 값을 저장하지 않는다. 원문·민감 데이터는 허용된 경계 밖으로 보내지 않는다.

빌드·리허설에는 운영 자격 증명·Docker 호스트 소켓·운영 파일 마운트를 주지 않는다. 다운로드와 실행 단계를 분리하고 잠긴 의존성·검증된 이미지·통제된 mirror를 사용한다. 기본 egress는 차단한다. 패키지 준비·agent setup 단계에서도 넓은 네트워크를 허용하지 않는다. 모델 호출은 외부 정책 gateway를 경유하도록 별도 통합한다.

현재 준비기는 digest 고정 이미지와 `no-network` 초기 설정, 분리 verifier를 출력한다. 이것은 provider의 실제 차단·digest 출처·테스트 내용을 증명하지 않는다. AI 실행에 필요한 gateway와 offline agent 구성도 미연결이므로 출력은 `prepared-not-executed`, `executable=false`다.

## 변경·독립 검증·승격

1. 읽기 전용 소스 기준본과 독립 테스트 기준을 고정한다.
2. 작업 복사본에서 변경·빌드·단위·업무 시험을 수행한다.
3. patch 허용 경로·diff·문법·의존성·라이선스·보안·행동 변화를 검사한다.
4. 승인한 산출물만 경로·크기·유형·symlink·특수 파일 검사를 거쳐 분리 검증기로 전달한다. agent가 테스트·reward·검증기 설정을 수정하지 못하게 한다.
5. 출발 cloud SDK·endpoint·관리형 기능에 대한 실제 접근을 막아 탈출 리허설을 수행한다. 관리·관측 경로는 별도로 보존한다. 필요한 잔류 연결은 명시하고 완전 탈출로 표시하지 않는다.
6. source·patch·tests·image·환경·정책 revision과 실제 결과를 묶는다.
7. 독립 서명·승인 후 검증한 동일 이미지 digest를 배포한다. 변경한 설정·DB·Secret도 별도 검증한다.

서명은 기록의 발행·변경 탐지를 돕고 검증 내용의 진실을 자동 보장하지 않는다. 빌드가 끝난 작업의 유출 흔적·이미지 취약점·테스트 한계를 기록하고 실행 환경·임시 키·저장 자료를 정책에 따라 정리한다.

## 운영 자격 시험

prompt injection, 악성 archive/path, fork·디스크·메모리 고갈, egress·metadata 우회, DNS/redirect, sandbox 탈출 경계, verifier 변조, 응답 유실·중복, 종료·정리 실패를 시험한다. guest 실패가 제어면·다른 테넌트·서명 자격에 영향을 주면 자격 실패다. version 고정 후 provider별 회귀를 재실행한다.

## 외부 문서 기준

설정 생성은 Harbor [작업 설정](https://docs.harborframework.com/tasks/configuration)의 schema 1.4를 참고한다. 독립 환경과 산출물 전달은 [분리 verifier](https://docs.harborframework.com/tasks/separate-verifier), 초기·단계별 통신 경계는 [network 정책](https://docs.harborframework.com/tasks/network-policies)을 기준으로 검토한다. 이는 2026-11-01 조회 기준이며 Harbor 런타임 버전 고정·schema 검사·실행 회귀는 별도 완료 조건이다.

## 2026-11-02 산출물 수용 계약

`SandboxRequest.fingerprint`는 scope·source/tests·agent/verifier 이미지·timeout·만료 전체를 결합한다. 반환 artifact는 `request_digest`와 source/patch/tests/image digest를 포함해야 한다. 저장소 이름이 달라도 agent/verifier의 image digest가 같으면 거부한다. 요청·patch·산출물·테스트 변경은 이전 근거를 무효화한다.

허용/거부 근거의 발행자와 폐기는 별도 callback이 인증한다. `eligible_for_approval`는 실행 권한이 아니다. Harbor runner는 계속 팀원 담당이며 이 계약을 runner 성공 코드나 실제 egress 시험 완료로 대체하지 않는다.
