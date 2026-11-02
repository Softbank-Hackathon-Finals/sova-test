# Sova 운영 콘솔

React·TypeScript·Vite·React Flow 기반의 로컬 운영자 화면이다. 기존 Python의 인증·정책·실행 판정을 사용한다.

## 실행 경로

현재 첫 화면은 **보안·대응**이다. 팀 공유용 6단계 안내에서 실제 관측,
승인·실행 이력, 현재 응답과 격리 근거를 구분한다. 화면의 완료 영수증만
남아 있어도 현재 근거가 만료되거나 연결이 끊기면 현재 성공 표시를 철회한다.

| 화면 | 실제 backend | 변경 동작 |
| --- | --- | --- |
| 환경 이전 | 기존 AWS·Lima VM 프리뷰, 고정 loopback 8790 | 실행본·경로 revision 재검사 후 요청 경로 전환/복귀, 단일 업무 요청 |
| 워크로드 지도 | 등록된 로컬 프로세스·HTTP·SQLite 실험 | 선택 프로세스 종료/복원, 통제된 HTTP 오류 |
| 보안·대응 (첫 화면) | 로컬 k3s·PostgreSQL 보안 콘솔 | 승인한 네트워크 격리·대체 기동·시험 경로 전환 |

세 경로를 같은 화면에서 선택한다. 같은 앱이나 동일한 이전 작업으로 병합한 것은 아니다. 설정 검사, 실제 응답, 과거 완료 이력 및 미확인을 구분한다. 환경 이전은 미리 실행된 무상태 HTTPS 앱의 시험 요청 경로 변경이다. DB·세션·ALB/DNS 이전은 포함하지 않는다.

## 빌드·시험

```sh
cd console
npm ci --ignore-scripts
npm test
npm run format:check
npm run build
```

Python과 준비된 소유자 전용 시험 등록이 있는 프로젝트 루트에서 실행한다.

```sh
.local-notes/venv/bin/python demo/security_console.py \
  --session-root /absolute/path/to/operator-private-session \
  --ui-root console/dist \
  --dependency-port 8791 \
  --migration-port 8790 \
  --port 8792
```

이 명령은 클러스터나 DB를 준비하지 않는다. Dependency Lab도 별도로 실행되어 있어야 한다. 준비되지 않은 경로는 미확인으로 남기며 가짜 결과로 채우지 않는다. 기존 보안 HTML은 `/legacy`, 시험앱 응답 화면은 `/workload`에 유지한다.

AWS·VM 프리뷰의 등록 만료·서버 정지·응답 미검증 시 환경 이전 화면은 미연결로 표시하고 변경을 차단한다. 자원을 자동 생성하거나 기존 등록을 연장하지 않는다. upstream 쿠키는 운영자 쿠키와 별도로 서버에서 보관한다. 전환 접수는 완료가 아니며 실제 단계와 새 응답을 확인한다.

## 팀 공유 시연 준비

프로젝트 루트에서 `demo/security_demo.py`를 사용하면 과거 비공개 준비
스크립트 없이 새 회차를 구성한다. Docker Desktop(또는 동등한 로컬 Docker),
kubectl, PostgreSQL 17의 `initdb`/`pg_ctl`과 share 디렉터리,
`.[dev]` Python 의존성과 위에서 빌드한 UI가 필요하다.
캐시된 k3s와 Python 이미지 digest를 검사하며 다른 버전으로 자동 대체하지 않는다.

```sh
python demo/security_demo.py start \
  --pg-bin /absolute/path/to/postgresql-17/bin \
  --pg-share /absolute/path/to/postgresql-17/share \
  --minutes 110 --port 8792
```

출력된 private run directory를 다음 명령의 `<run-directory>`에 넣는다.

```sh
python demo/security_demo.py status --root <run-directory>
python demo/security_demo.py login --root <run-directory> --open
python demo/security_demo.py login --root <run-directory> --renew --open
python demo/security_demo.py stop --root <run-directory>
```

`--open`은 macOS 기본 브라우저를 연다. 다른 OS에서는 소유자 전용
`operator-access.json`을 로컬에서 확인한다. URL을 공개 채널에 공유하지 않는다.
5분 일회용 로그인 또는 30분 브라우저 세션 만료 시 `--renew`로 콘솔을 재시작한다.
진행 중 작업의 종료를 확인한 뒤에만 재시작하며 완료 효과는 다시 실행하지 않는다.
기본 실행은 프로세스 의존성 실험(8791)과 Kubernetes 보안 대응(8792)을 함께
준비한다. 하나의 운영자 로그인으로 `워크로드 지도`와 `보안·대응`을 전환한다.
의존성 실험에는 프로세스별 HTTP 장애 주입·해제, 여러 프로세스의 선택 격리,
복원·재검증, 실제 업무 요청, 등록 예제 선택이 포함된다.
`--dependency-port`로 전용 포트를 바꿀 수 있고, `--security-only`를 명시하면
프로세스 실험을 제외한다. AWS/VM 환경 이전은 별도 실행 등록이 필요하므로
이 도구에서 자동 활성화하지 않는다.

준비에는 전용 privileged k3s 컨테이너가 필요하며 앱은 고정 시험 코드다.
사용자가 업로드한 코드를 실행하는 샌드박스로 사용하지 않는다.
제어 DB는 소유자 전용 디렉터리의 Unix socket만 사용하고 TCP 수신을 열지 않는다.
AWS API·기존 Kubernetes context·다른 VM은 사용하지 않는다.

회차마다 전용 클러스터와 DB가 생긴다. 과거 보류·승인·효과를 지우는 웹 초기화는
제공하지 않는다. 재시연은 기존 회차를 종료하고 새 회차를 시작한다.
종료·기한 만료 시 전용 프로세스·소유권 확인 컨테이너·DB를 정리하고
`cleanup.json`에 결과를 남긴다. 기록과 정지된 DB 파일은 비공개로 보존한다.
macOS 화면·시스템 잠자기 방지는 해당 회차가 실행되는 동안에만 적용한다.
프로세스 실험의 상태·종료 확인도 회차의 `dependency/`에 따로 기록한다.
운영자 로그인 갱신은 프로세스 실험을 초기화하지 않으며 격리·장애 상태를 유지한다.

### 프로세스 의존성 실험

1. `워크로드 지도`에서 기본 업무 서비스의 7개 실제 프로세스와 호출 관계를 확인한다.
2. `실제 업무 요청 확인`으로 새 요청을 보내 응답·지연·선택 경로 영향을 확인한다.
3. 후처리 서비스에 `장애 주입`을 적용하고 선택 의존성의 영향을 확인한다.
4. `장애 해제` 후 후처리 서비스·결과 보관을 선택해 `선택 구간 격리`한다.
5. 선택한 PID의 종료와 연결 차단 표시를 확인하고 `복원·재검증`한다.
6. 문서 처리 서비스로 바꾸면 필수 분석 경로의 장애가 전체 요청에 미치는 영향을
   비교할 수 있다. 이 전환은 시험 프로세스를 다시 구성한다.

프로세스 격리는 시험 프로세스 종료다. Kubernetes NetworkPolicy와 같다고
표현하지 않는다. SQLite 데이터와 프로세스는 별도 시험앱의 것이며 k3s 앱·DB와
동일한 워크로드로 병합된 것은 아니다.

### 약 5분 발표 순서

1. Blue 응답과 지도 관계 확인. 선언 관계와 실제 HTTP 응답을 구분한다.
2. `통제된 설정 위반`을 선택하고 변경 범위를 확인·실행한다.
3. `read-only-root` 위반과 독립 보류, 원본·대상 비교를 확인한다.
4. `대응 계획 검토` 후 digest·유효기간·동작을 읽고 사람이 `계획 승인·실행`한다.
5. 원본의 새 연결 차단, Green 기동·응답, 시험 경로 전환을 확인한다.
6. 네 효과·완료 영수증·유지되는 보류를 확인하고 미검증 범위를 설명한다.

같은 로컬 클러스터의 무상태 시험앱 대응이다. 실제 공격 탐지·AWS→온프렘 이전·
DB/파일/세션 이전·무중단 운영을 시연한 것으로 설명하지 않는다.
팀 공유는 같은 PC에서의 시연 또는 화면 공유 기준이며 공개 호스팅 인증은 별도다.

## 인증·전송 경계

- Python이 빌드한 정적 파일과 API를 같은 origin에서 제공한다. 별도 개발 서버의 인증 프록시는 구성하지 않았다.
- 일회용 운영자 로그인, HttpOnly 쿠키, origin별 proof, 세션 기한을 유지한다. 키나 kubeconfig를 브라우저로 보내지 않는다.
- 로컬 실험 연결은 서버 설정의 고정 loopback 포트만 사용한다. 요청자가 URL·포트·임의 명령을 지정할 수 없다.
- 브리지는 자체 Dependency Lab 쿠키만 사용한다. 운영자 쿠키·proof를 upstream으로 전달하거나 upstream 쿠키를 브라우저로 반환하지 않는다.
- 스크립트는 self만 허용한다. React Flow의 동적 위치를 위해 새 UI 문서에만 inline style을 허용하며 기존 API·HTML의 정책은 유지한다.
- 상태가 오래되거나 연결이 끊기면 현재 성공 표시·트래픽·변경 동작을 비활성화한다. 변경 요청은 자동 재시도하지 않는다.
- 승인 요청은 검토한 plan digest를 그대로 보낸다. 만료·폐기·범위 변경의 최종 판단은 Python이 수행한다.

## 검증 경계

브라우저에서 실제 기존 데이터로 지도·화면 전환·확인창·모바일·오프라인·로그아웃을 검증한다. 실행 버튼을 누르는 변경 시험은 격리된 fixture나 대체 backend에서 수행하고 사용 중인 앱 상태를 임의로 초기화하지 않는다.

이번 UI 통합은 기업 인증·독립 권한 broker·일반 앱의 클라우드 간 이전을 완성하지 않는다. 상세 개발기록과 화면 자료는 `.local-notes/`에 보존한다.
