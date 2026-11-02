# 보안 거버넌스·워크로드 대응 검증 현황

2026-11-01 · 독립 로컬 k3s 검증 경로. Harbor 실행 연동은 팀원 담당이다.

## 이번에 연결한 흐름

`등록한 Kubernetes API → 값 제거 보안 설정 수집 → PostgreSQL 관측·이벤트 → 독립 보류 → 정확한 대응 계획·승인 → 원본 격리 → 깨끗한 대상 기동·검증 → gateway 경로 전환`

- 실제 k3s 1.35.9의 **같은 클러스터 안 두 namespace**를 서로 다른 등록 환경으로 사용했다. AWS·VM·클라우드 간 이동을 검증한 결과가 아니다.
- 앱은 데이터·장기 세션·background writer가 없는 고정 시험 앱이다. 일반 앱·DB·게임 세션 이전을 지원한다고 주장하지 않는다.
- 실제 Pod template에서 권한·호스트 접근·이미지 digest·자원 한도 등 12개 검사를 수행한다. 설정상 충족과 런타임 보안 검증을 구분한다. 암호화·감사·백업·전체 IAM 검증은 남아 있다.
- 알려진 민감 env 값, 원본 env 이름·내용, Secret payload를 결과에 복사하지 않는다. 제한된 정규식 검사는 모든 비밀값의 탐지를 보장하지 않는다.
- 실제 API의 깊은 managedFields와 항목 GVK 생략을 처리하되, 공개 계약의 엄격한 입력 검증은 유지한다.

## 대응의 경계

목적이 `security_response`인 계획만 현재 지원하는 네 동작을 사용할 수 있다. 일반 배포가 목적 문자열만 바꿔 보류를 우회할 수 없다. 등록한 원본·대상·보류·이미지·불변 설정·정책·기한과 일치하는 계획을 다시 구성해 대조한다.

원본의 등록된 Deployment selector에만 새로운 NetworkPolicy를 생성한다. selector와 Service는 **앱 ID와 구성 요소 이름을 함께** 지정해야 하며 이름만 있는 기존 시험 등록은 거부한다. 앱 ID 없이 범위를 자동 확대하지 않는다. 다른 additive 정책이 있으면 자동 격리를 거부한다. 정책의 실제 readback, 독립 probe의 생존, **새 TCP 연결 거부**를 함께 확인한다. HTTP 오류·응답 신원 불일치·probe 장애를 차단 성공으로 취급하지 않는다. 기존 연결의 강제 종료나 모든 공격 차단을 보장하지 않는다.

깨끗한 대상은 고정 이미지와 불변 ConfigMap·template digest를 사용한다. namespace·Service·Deployment UID, 앱·구성 요소·환경·요청 ID의 응답 결합을 검사한다. 이 fixture의 코드·설정이 고정됐다는 뜻이며 범용 취약점 검증은 아니다.

실제 앱 접속은 로컬 gateway와 독립 Pod probe를 거친다. PostgreSQL CAS로 gateway 목적지를 전환하고 실제 대상 응답을 확인한다. ALB·DNS 전환이 아니며, 물리적 컨테이너를 옮기지 않는다. 원본을 격리 상태로 유지하고 별도 환경의 실행본을 기동하는 방식이다.

실행에는 기존 PostgreSQL 계획·승인·operation·app 실행권·효과 원장을 재사용한다. 보안 대응 상태는 일반 마이그레이션과 분리된 profile을 사용한다. 불확실한 외부 효과는 재실행하지 않고 복구 검토로 남긴다. 경로 전환 후에도 독립 보류를 유지한다.

## 발행자 검증

Ed25519 envelope는 근거의 전체 scope·revision·결과·artifact digest·발행자·key ID·발행 시각을 서명한다. 수신자가 등록한 공개키·정확한 자원·verifier 버전·기한·폐기를 매번 검사한다. 요청 본문의 공개키와 임의 알고리즘은 사용하지 않는다. 근거의 유효기간은 발행자 신뢰 기한을 넘을 수 없다.

서명은 발행자와 무결성을 확인하며 검사 결과의 진실을 자동 보장하지 않는다. 실제 수집 근거 12개의 서명·DB 저장·PASS 변조 거부·발행자 폐기를 시험했다. 개인 키는 해당 시험 프로세스 메모리에만 두었다. **기업 PKI·키 관리 서비스·Harbor 결과 수신·실제 승인 서명은 아직 연결하지 않았다.**

## 화면과 확인 결과

검증용 화면은 `preview/security_console.py`와 `preview/security_web/`에 있다. 임의 ZIP·kubeconfig·URL·명령을 받지 않는다. 운영자가 준비한 전용 시험 등록만 사용한다.

실제 브라우저에서 다음을 확인했다.

- 통제된 설정 위반 → 실제 보류 → 계획 검토·승인
- 실제 네트워크 차단 → 대체 기동·HTTP 검증 → 동일 시험 URL의 Green 응답
- 모바일 레이아웃, 브라우저 오류 없음, 연결 단절 시 성공 표시를 미확인으로 변경
- 재시작 후 기존 계획·효과 영수증·경로를 읽기 전용으로 복구하고 외부 변경을 재실행하지 않음
- 실제 읽기 RBAC 폐기 시 보안 수집은 미확인이 되지만 Green 응답·보류는 유지, 명시 복원 후 수집 회복
- 별도 namespace의 동일 이름 재생성 시 UID 불일치 거부와 시험 자원 정리

## 운영자 인증과 요청 경계

소유 OS 사용자만 읽는 0600 파일에 5분 유효한 일회용 bootstrap URL을 만든다. 토큰은 URL fragment로만 전달하고 HTTP 요청 경로·로그에 남기지 않는다. 최초 교환은 원자적으로 한 번만 허용한다. 실제 브라우저에서 최초 fragment와 같은 페이지의 fragment 변경을 모두 확인했다.

교환한 세션은 최대 30분, 전체 시험 기한 이내로 제한한다. HttpOnly·SameSite 쿠키와 별도의 origin 전용 proof를 함께 사용한다. localhost의 다른 포트로 쿠키가 전달돼도 그 쿠키만으로 제어 API를 사용할 수 없다. 읽기 요청에도 proof를 요구한다. 로그아웃·기한 만료 후 제어 요청을 거부한다. 기업 SSO, 공개 TLS 서비스, OS 소유자 계정 침해 방어를 대신하지 않는다.

HTTP 서버는 loopback 전용이며 동시 연결·대기열·읽기 시간을 제한한다. Host/Origin/Fetch Site·중복 헤더·짧은 body·잘못된 길이·Transfer-Encoding·중복 JSON 키·과대 요청을 검사한다. 종료 시 새 제어 요청을 차단하고 실행 중 수집·동작을 제한된 시간 동안 기다린다. 이 서버는 공개 운영용 웹 서버가 아니다.

## 최소 권한 실행 자격 시험

별도 시험 namespace에서 계획별 ServiceAccount·RoleBinding과 fail-closed ValidatingAdmissionPolicy를 실제 k3s API에 적용했다.

- 등록한 Deployment의 0→1 기동과 정확한 deny-all 격리 정책 생성 성공
- Secret 읽기·다른 환경 조회·Pod/exec·token 발급·RBAC/정책 관리 거부
- 이미지 변경·replica 2·허용 네트워크 규칙·다른 계획/앱 selector·격리 해제 거부
- 같은 namespace에서 구성 요소 이름이 같은 다른 앱은 계속 응답
- RoleBinding 폐기 후 새 조회 거부

Kubernetes RBAC는 CREATE의 내용 제한을 대신하지 못하므로 admission에서 실제 본문을 검증한다. CEL에서 UID에 직접 접근할 수 없어 운영자가 고정한 신원 label을 사용하며, 실제 UID는 어댑터가 별도로 읽어 확인한다. 관리자 label 변경까지 막는 물리적 경계는 아니다.

이것은 **자격 시험용 manifest 생성기**다. 현재 콘솔 실행기는 전용 시험 관리 kubeconfig를 사용하며, 위 권한을 발급하는 운영 broker로 교체된 상태가 아니다. TokenRequest의 최소 TTL과 계획 기한의 차이는 독립 broker·권한 회수기로 처리해야 한다. [Kubernetes RBAC](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)와 [ValidatingAdmissionPolicy](https://kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/)의 제약을 따른다.

추가 시험에서는 관리 토큰으로 준비만 수행한 뒤 **실제 대응 어댑터의 네 효과를 제한 토큰으로 모두 실행**했다. 준비 확인에는 넓은 watch/list 대신 등록한 Deployment 하나의 유한 GET을 사용한다. 같은 namespace에서 구성 요소 이름이 같은 다른 앱의 전후 HTTP 응답과 원본 격리·Green 응답을 확인했다. DB 워커도 승인 상태를 변경할 권한 없이 완료를 기록했다. 시험 발급자는 여전히 같은 로컬 운영자 경계에 있으므로 독립 broker·별도 신뢰 도메인 격리 완료로 표현하지 않는다.

## 완료 기록과 장애 시험

최신 코드로 별도 PostgreSQL·namespace에서 실제 브라우저 흐름을 다시 실행했다. 네 효과의 APPLIED 영수증, 하나의 불변 완료 영수증, 완료 상태, 실행권 반환을 확인했다. 시험 앱의 실제 격리·대체 기동·HTTP 응답·경로 전환과 연결했다. 별도 fixture 자원은 정리했다.

회귀 시험에서는 완료 COMMIT의 응답 유실을 조회 복구하고 효과를 반복하지 않음을 확인했다. 실행권 반환 실패는 완료 상태·영수증·outbox 변경까지 롤백한다. 완료 직전 승인 폐기·새 보류·실행권 만료를 주입해 완료 승격을 차단했다. 이 원자성은 제어 DB에 한정하며 원격 변경과의 분산 트랜잭션은 아니다.

별도 실제 k3s 시험에서는 Green 기동이 끝난 직후 응답 유실을 주입했다. 앱은 실제로 응답하지만 효과는 UNKNOWN, 작업은 복구 필요 상태로 남았고 같은 작업의 자동 재실행과 완료·경로 승격을 거부했다. 원본 보류·격리와 다른 앱의 응답은 유지했다. 이는 **불확실한 변경을 성공으로 꾸미지 않는 동작**의 검증이며 자동 복구 완료의 검증은 아니다.

다른 실제 시험에서는 원본 격리 직후 대상 RoleBinding을 회수했다. 후속 기동·경로 승격·완료를 거부하고 복구 필요 상태로 남았다. 완료한 격리 효과·보류는 지우지 않았으며 다른 앱의 응답은 유지했다.

재시작 시험에서는 원자 완료 영수증을 읽고 외부 효과를 재실행하지 않음을 확인했다. 검증 도구의 관리자 권한으로 영수증을 잠시 제거해 과거 형식을 재현했을 때도, 완료 상태 문자열만으로 새 영수증을 만들지 않고 검토 필요 이력으로 표시했다. 원본 영수증은 도구가 복원했다. 이는 DB 관리자 침해 방어가 아니라 복원·버전 호환 경계의 시험이다.

현재 대응 순서는 원본 격리를 먼저 수행한다. 중간 실패 시 원본을 자동 공개하지 않으므로 서비스 중단이 생길 수 있다. 보안 봉쇄와 연속 서비스의 우선순위·준비된 대체 실행본·안정 진입점 정책은 운영 자격에서 별도로 정해야 한다. 이 경로를 무중단 대응이라고 부르지 않는다.

추가 허용 NetworkPolicy를 잠시 주입한 실제 시험에서는 원본에 다시 연결됐을 때 격리 증거가 미확인으로 바뀌었다. 원본 보류·이전 완료 이력은 유지했고 잘못된 현재 성공 표시로 덮지 않았다. 시험 정책을 제거한 뒤 새 연결 거부가 회복됐다.

## 제어 메타데이터 복원

별도 PostgreSQL DB에 동일 snapshot의 제어 메타데이터를 dump/restore했다. 전체 테이블 내용 hash·행 수, FORCE RLS, 발행자 폐기 상태를 비교했다. 실행권을 자동 재활성화하거나 외부 효과를 반복하지 않았다. 원본 DB와 별도로 만든 복원 DB는 삭제했다.

이 시험은 로컬 제어 기록 복원이다. 앱 DB 이전, 암호화된 원격 백업, 다중 장애 영역 복구, 프로덕션 RPO/RTO를 검증한 결과가 아니다. snapshot 경계는 [PostgreSQL exported snapshot](https://www.postgresql.org/docs/17/functions-admin.html)과 [pg_dump](https://www.postgresql.org/docs/17/app-pgdump.html)를 따른다.

장시간 관측은 실제 읽기 전용 요청을 기록하며 미확인·실패도 보존한다. 이번 2시간 작업 중에는 제어 세션 만료 이후에도 독립 Green Pod probe를 계속했다. 이 수치는 **Green 실행본의 응답**이며 인증 만료 이후의 공개 안정 진입점·보류 연속 검증을 뜻하지 않는다. 전환 중 연속 업무 요청의 가용성 측정은 별도 완료 조건이다. 현재 결과를 무중단 자격·전체 프로덕션 완료로 표현하지 않는다.

## 중지·재개 기준

최초 일시 중지 체크포인트는 `.local-notes/security-workload-session-20261101/`에 보존했다. 이어진 2시간 작업은 `.local-notes/governance-resume-20261101/`, 최신 코드의 원자 완료 E2E는 `.local-notes/governance-atomic-e2e-20261101/`에 기록한다. 결과·화면·정제한 DB 이력은 비공개 개발기록이며 게시하지 않는다. 시험 서버·자원·잠자기 방지는 기한 종료 시 정리한다. 커밋·푸시는 하지 않는다.

최종 제한 토큰·승인 권한 분리 E2E 기록은 `.local-notes/governance-scoped-e2e-final-20261101/`에 있다. 이 fixture의 namespace·RBAC/admission 객체·임시 DB·토큰 파일은 검증 직후 정리했다.

실제 기동 후 응답 유실 시험 기록은 `.local-notes/governance-lost-ack-e2e-20261101/`에 따로 보존한다.

실행 중 권한 회수는 `.local-notes/governance-revocation-e2e-20261101/`, 재시작·옛 영수증 처리는 `.local-notes/governance-restart-e2e-20261101/`에 기록한다. 각 fixture는 독립 namespace·임시 제어 DB를 사용하고 종료 후 정리했다.

다음 재개 작업은 아래와 같다.

1. 기업 OIDC·tenant 인가, 독립 signing/credential broker, 계획 기한에 맞춘 실제 권한 회수.
2. 중앙 정책·발행자 등록/폐기의 기업 승인 경계와 운영 API 연결. 구성 요소 PG 시험과 분리한다.
3. RDS SDK 수집의 실계정 읽기 자격, provider별 보호 profile의 실제 probe, 공유 자원 영향·일반 앱·외부 환경 시험.
4. 전환 중 연속 업무 요청·세션·데이터·가용성, 실제 환경 crash·응답 유실·복구 자격. 로컬 DB 대체물 시험만으로 완료하지 않는다.

검증용 UI·kubectl 어댑터는 운영자가 통제하는 로컬 시험 도구다. 일부 동작은 전용 시험 kubeconfig를 사용하며, 이를 최소 권한 production broker가 완성된 것으로 표시하지 않는다. sourcecode/Secret·업무 데이터의 보존·이전은 이번 경로에 포함하지 않는다.

암호 API 기준: [cryptography Ed25519 문서](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519/). 네트워크 의미 기준: [Kubernetes NetworkPolicy](https://kubernetes.io/docs/concepts/services-networking/network-policies/). 실제 시험 dependency 버전과 공개 이미지 digest는 로컬 검증 기록을 따른다.
