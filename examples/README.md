# 입력 예제

` sova example `은 가상 주문 서비스의 등록 파일을 생성한다. 실제 자원·가격·이전 성공을 나타내지 않는다. 현재 시각 기준 1시간 후 만료한다.

```sh
.local-notes/venv/bin/sova example > .local-notes/example.json
.local-notes/venv/bin/sova assess .local-notes/example.json --target-environment customer-k3s --target-backend kubernetes
```

제공된 `kubernetes/orders.json`은 비밀값 없는 수동 예제다. `import-kubernetes`는 로컬 파일만 정규화하며 클러스터에 접속하지 않는다. scope 매개변수는 운영자 주장이고 인증·권한의 증거가 아니다.

```sh
.local-notes/venv/bin/sova import-kubernetes examples/kubernetes/orders.json --tenant example-tenant --application orders --environment test-k3s --namespace orders --location local-test > .local-notes/kubernetes-registration.json
.local-notes/venv/bin/sova inspect .local-notes/kubernetes-registration.json
```

지원 입력은 Deployment·StatefulSet·Service·PVC의 범위가 지정된 Kubernetes List다. Secret·다른 앱/namespace·누락 PVC는 거부한다. Service selector는 선언 관계이며 관측한 트래픽이 아니다. env 값·Secret 내용은 출력하지 않는다. 이 입력은 전체 의존성 조사나 보안 감사가 아니다.

## 상담 reference workload

`consultation/`은 합성 데이터로 이전을 시험하는 작은 웹앱이다. PostgreSQL, WebSocket, 비공개 첨부, 고객/상담원 권한, 멱등 요청, OTel을 사용한다. 기업 로그인이나 실제 금융 업무용 서비스는 아니다.

현재는 독립 앱과 통제된 DB 전환 시험으로 연결돼 있다. Sova의 일반 ZIP 업로드·자동 이전 경로에 연결하는 작업은 남아 있다.

### 준비와 실행

Python 개발 실행에는 다음 extra를 사용한다. S3를 선택할 때 `aws`가 필요하다.

```sh
.local-notes/venv/bin/python -m pip install -e '.[postgres,demo,aws]'
```

운영자는 별도 앱 DB와 최소 권한 runtime role을 먼저 준비한다. 앱 role에 superuser·createdb·createrole·replication·bypassrls 또는 그 역할의 멤버십을 주지 않는다. 연결 수는 DB 예산에 맞춰 제한한다. Sova 제어 DB의 자격 증명을 사용하지 않는다.

DSN은 소유자 전용 파일에 저장한다. TCP 연결은 `sslmode=verify-full`과 신뢰할 CA를 사용한다. 비밀번호는 명령행·README·Git에 넣지 않는다.

```sh
.local-notes/venv/bin/python -m examples.consultation.manage prepare \
  --owner-dsn-file /private/path/migration-owner.dsn \
  --runtime-role consultation_runtime \
  --private-output .local-notes/consultation-invites.json
```

관리 도구는 schema·권한·세 시험 사용자를 만든다. 초대코드는 지정한 0600 파일에만 쓴다. 기존 출력 파일은 덮어쓰지 않는다. 앱 서버는 schema를 만들지 않는다.

```sh
DATABASE_URL_FILE=/private/path/runtime.dsn \
CONSULTATION_ORIGIN=http://127.0.0.1:8794 \
CONSULTATION_ENVIRONMENT=source-local \
CONSULTATION_OBJECT_DIR=/private/path/consultation-objects \
.local-notes/venv/bin/python -m uvicorn examples.consultation.service:create_app \
  --factory --host 127.0.0.1 --port 8794 --no-access-log --no-proxy-headers
```

앱 연결 파일도 앱 실행 UID의 0600/0400 일반 파일이어야 한다. 실제 공개 서비스는 별도로 검증한 HTTPS 진입점을 사용한다. 초대 관리의 `issue-invites`, 제한된 `pause`/`resume` 명령은 `manage --help`로 확인한다. 이 명령은 해당 시험앱의 writer 제어이며 임의 외부 writer 봉쇄가 아니다.

### 컨테이너와 저장소

빌드 컨텍스트는 `examples/consultation/`이다. Python 3.12 Linux ARM64·AMD64 의존성을 `requirements.lock`에 해시로 고정한다. 서비스는 UID 10001로 실행한다. runtime DSN·CA를 읽기 전용으로 전달하고, 파일 volume은 UID 10001의 0700 디렉터리로 준비한다.

`--read-only`, `--cap-drop ALL`, `--security-opt no-new-privileges`, 유한한 CPU·메모리·PID 한도와 전용 volume을 적용한다. 앱 이미지에는 관리 도구·schema·Docker CLI·호스트 소켓을 넣지 않는다. 실제 환경의 보안 설정은 Sova의 별도 검증 의무다.

객체 저장소 선택은 `CONSULTATION_OBJECT_BACKEND=local|s3`다. S3는 `CONSULTATION_S3_REGION`, `CONSULTATION_S3_BUCKET`, `CONSULTATION_S3_PREFIX`, `CONSULTATION_S3_OWNER_ACCOUNT`, `CONSULTATION_S3_KMS_KEY_ARN`을 요구한다. SDK는 workload role을 사용하며 임의 endpoint와 실패 후 local fallback을 허용하지 않는다. S3/KMS 실계정 자격과 local volume 암호화는 별도 검증이다.

### API와 검증

- `/api/session`, `/api/me`, `/api/logout`: 일회용 시험 초대와 서버 세션.
- `/api/rooms`, `/api/rooms/{id}/messages`: 접근 가능한 방과 멱등 메시지.
- `/api/rooms/{id}/stream`: 인증·origin·CSRF를 확인하는 WebSocket과 재접속 커서.
- `/api/rooms/{id}/attachments/{id}`: 권한·크기·무결성을 확인하는 첨부.
- `/api/rooms/{id}/summary`: 등록된 gateway callback이 없으면 503.

64bit 메시지 ID·순번·커서는 JSON 문자열이다. 브라우저 안전 정수 범위를 넘는 값을 반올림하지 않는다. 고객 데이터·초대코드·인증 헤더는 OTel span에 넣지 않는다.

```sh
node --test examples/consultation/web/app.test.mjs
```

실제 PG 시험은 `tests/integration/test_consultation_*.py`와 `test_postgres_*.py`에 있다. [격리 DB 시험 조건](../docs/postgres-execution.md)을 따른다. 논리 복제 시험에는 해당 임시 클러스터의 `wal_level=logical`이 필요하다. 컨테이너·Collector 시험은 별도 명시적 opt-in이며 운영 DB에 실행하지 않는다.
