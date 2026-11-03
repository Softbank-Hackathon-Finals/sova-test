# 등록된 보안 감시 워커

`python -m sova.monitoring.worker --config /private/monitor.json`은 한 번 실행하고 종료한다. 예약 실행은 Kubernetes CronJob 또는 운영체제 서비스 관리자가 담당한다. 별도 배포 엔진이나 자체 시간 스케줄러를 만들지 않는다.

## 실행 경계

- 서명된 작업 등록은 한 서비스 신원·앱·환경·자원·기준선과 실행 주기, 만료를 지정한다.
- PostgreSQL 행 잠금과 기한이 있는 토큰으로 동시 실행을 제한한다. 만료된 실행자가 새 실행자의 결과를 덮어쓸 수 없다.
- 최신 입력 묶음은 순번·이전 해시를 가진 append-only CAS 기록이다. 과거의 유효한 서명도 최신 입력을 되돌리는 권한은 아니다.
- 입력 묶음과 각 자산·취약점·노출·정책 문서를 각각 인증한다. 기준선·발행자 키·등록이 바뀌거나 폐기되면 정상 결과를 반환하지 않는다.
- 판정은 기존 `ContinuousSecurityMonitor`가 수행한다. 새 판정기·배포·격리·보류 해제 권한을 만들지 않는다.
- 실패와 주의 결과는 실행 기록과 같은 트랜잭션으로 경보 outbox에 남긴다. 예외 본문·DSN·임의 수집 문자열은 경보에 저장하지 않는다.
- 경보 relay는 등록한 sink의 같은 alert ID에 대한 수신 확인만 기록한다. 전달 결과가 불명확하면 기한 뒤 같은 ID로 재전달될 수 있다. sink도 그 ID로 중복 제거해야 한다. 8회 실패한 경보는 삭제하지 않고 운영자 확인 대상으로 남긴다.

## 배치

[최소 CronJob 구성](../examples/monitoring/cronjob.yaml)은 연결 예제다. 이미지 digest·DB Secret·접속 정책을 채우지 않은 상태로 운영에 적용하지 않는다. 예약은 1분 단위이며 실제 실행 주기는 등록된 DB의 `next_due`를 따른다. `concurrencyPolicy: Forbid`, 재시도 0회, 90초 작업 제한과 별도로 DB 리스를 사용한다.

워커에는 DB 접근만 제공한다. AWS 배포 역할·사용자 코드·Docker 소켓·운영 변경용 서명 개인 키는 제공하지 않는다. 원격 PostgreSQL은 `sslmode=verify-full`과 명시적 CA가 필수다. DB 역할은 테이블 소유자·superuser·BYPASSRLS가 아니어야 한다. `adapters.monitor_permissions.create_monitor_role`은 migration 소유자가 새 NOLOGIN 역할을 한 작업·자원에 고정하도록 만든다. 기존 tenant 정책 위에 역할별 restrictive RLS를 적용하고, 보류는 opened/첫 revision만 INSERT하도록 제한한다. 워커는 보류 해제·산출물 폐기·키 발급·다른 작업 비활성화 권한을 받지 않는다. 로그인/서비스 신원 연결은 운영자가 별도로 수행한다. tenant 설정만으로 공유 DB 자격 증명 침해까지 격리되는 것은 아니다.

Kubernetes Secret projected volume은 심볼릭 링크·소유권 형태가 운영자 개인 파일과 다르다. 예제의 비루트 init 컨테이너는 알려진 파일 3개만 메모리 볼륨에 0600으로 복사한다. 실행 컨테이너는 그 사본만 읽는다. `monitor.json`의 `dsn_file`과 DSN의 CA 경로는 각각 `/private/monitor.dsn`, `/private/ca.pem`으로 지정한다.

설정 파일 필드:

| 필드 | 의미 |
| --- | --- |
| `schema_version` | 정수 `1` |
| `scope` | tenant/application/environment/resource의 정확한 등록 |
| `job_id`, `actor_id` | 서명된 작업과 일치하는 서비스 신원 |
| `dsn_file` | 0600 파일의 DB 연결 문자열. 로그로 출력하지 않음 |
| `revisions` | source/configuration/policy/environment의 승인된 근거 revision |
| `issuers` | `sova.monitor-input.schedule.v1`, `.baseline.v1`, `.inputs.v1`와 assessment input kind별 허용 발행자 목록 |

설정은 임의 실행 모듈·명령·URL을 받지 않는다. 파일 변경·서명 역할 불일치는 작업을 거부한다. 새 관측은 인증된 수집자가 산출물 저장소와 `RegisteredMonitoring.publish_inputs`에 게시해야 한다. 수집 중단으로 입력이 만료되면 정상으로 표시하지 않는다.

## 확인 범위와 운영 조건

실제 임시 PostgreSQL·Ed25519·독립 CLI 프로세스로 중복 실행, 입력 CAS, 키 폐기, 변경 탐지, 보류와 경보 저장, 재시작·리스 만료를 검증한다. 합성 관측을 사용한 조립 시험이며 실제 외부 공격 탐지나 상시 수집 운영의 완료를 뜻하지 않는다.

DB에 접속하기 전 설정·인증이 실패하거나 예약기 자체가 중단되면 해당 워커가 DB에 실패를 기록할 수 없다. 따라서 Job 실패·미실행과 DB/수집자 가용성은 독립된 외부 감시가 필요하다. 이 문서와 outbox가 외부 알림 채널의 운영 연결 완료를 뜻하지 않는다. Slack·메일로 실제 메시지를 보내지 않는다.
