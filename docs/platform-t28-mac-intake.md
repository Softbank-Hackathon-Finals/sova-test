# T28 Mac 인수: 검증된 포트와 실제 플랫폼 연결의 차이

2026-11-07 KST. 인계 source `ed1a9ad4e05325cfc7013692f63c973165980e36`.
기존 [T28 재시작 계약](platform-t28-restart.md)을 유지한다. 이번 변경은 문서이며 원본
platform CLI, 개인 어댑터, 허용 SHA, 운영 권한을 수정하지 않는다.

## 재확인한 상태

- 최종 security producer: `546f6e0482cc06fa32f00ea8d554522551a84beb`.
- 플랫폼 인계 계약: `0795f65e24f58e43545b16b97757efcc0923fd4a`.
- 이번에 읽은 최신 develop: `c364e6284d2e635ff86001e2feac88560ed23ebc`.
- GitOps 호스트·Reader source 선언: `445848d2ed9878e31eb6f5aabad0575c61739b47`.
- 실제 runtime source: **미관측**. 사용자는 일괄 배포 시점 미확인으로 로컬 준비만 허용했다.

기존 `tests/integration/test_platform_t28_restart.py`와 `test_effect_executor.py`를
Mac의 Python 3.12.16에서 재현했다. **34 passed / 2.13초**다. 고정 플랫폼 소스는 `0795f65`이며
로컬 SQLite, 자식 프로세스 종료, 합성 파일 효과와 loopback 지연 HTTP를 사용했다.
실제 cloud/operator 명령은 0회다. PostgreSQL 2개는 이번에 실행하지 않았으므로
Windows/CI의 36개 결과와 동일하게 표현하지 않는다.

## source 자격은 자동으로 이어지지 않음

`load_driver`를 실제 소스 사본에 적용하되 driver를 실행하지 않고 결과를 확인했다.

| source | 결과 |
|---|---|
| `0795f65e24f58e43545b16b97757efcc0923fd4a` | import 허용 |
| `445848d2ed9878e31eb6f5aabad0575c61739b47` | `Unqualified T28 platform commit` |
| `c364e6284d2e635ff86001e2feac88560ed23ebc` | `Unqualified T28 platform commit` |

세 소스의 `scripts/happy_path.py` Git blob은 `8a3e3993682f31ce262e1a82e21c4f11d60e75c5`,
SHA-256은 `e4bc607112512361d4bde4c6022bc59eb21191fdc139ade77b52f50bb013a355`로 같다.
그러나 `DRIVER_HASHES`는 전체 source SHA까지 제한한다. 같은 파일이라는 이유로
호스트의 `445848d`를 기존 `0795f65`로 표시하거나 허용 목록을 자동 확장하지 않는다.
security bridge의 12개 허용 기준과 T28 driver의 두 기준도 별도다.

## 플랫폼 인계할 접점

| 연결할 곳 | 재사용할 기존 기능 | 실제 인수 조건 |
|---|---|---|
| operator entrypoint | `DurableT28Port.run`과 기존 `cmd_run(run=...)` | 실제 entrypoint source를 정하고 exact SHA/hash로 자격 시험. 범용 subprocess adapter를 새로 노출하지 않음 |
| 승인·현재 권한 | T10 현재 승인/계획 잠금, 기존 operation 접수 | 사용자 JSON이 아닌 서버 등록 command/permit/adapter. diff/image/plan/환경 revision/epoch/profile 결속 |
| 재시작·경쟁 | 기존 PostgreSQL execution ownership/effect journal | 여러 host가 같은 원장 사용. 이전 호출의 UNKNOWN을 새 JSONL/operation으로 우회하지 못함 |
| 상태 조회 | 기존 T10 읽기 callback | `--plan-state-command`, `--platform-context`의 직접 subprocess 경로를 개인 포트에 연결하지 않음 |
| 직접 실행 제한 | T7/T9의 역할·자격, T31/T12 기존 실행 경계 | 원본 CLI/하위 명령 호출자가 실제 실행 자격을 따로 보유해 우회하지 못함. 관리자 break-glass 범위는 명시적으로 구분 |
| 결과 불명확·복구 | T31/T12 provider readback와 기존 recovery authority | 호출자 종료/lease 만료/현재 GET만으로 미실행을 단정하지 않음. terminal/cancel/fencing 후 별도 복구 권한으로 조정 |

기존 security 인수 계획과 source 대조는
[Mac 인수 준비](https://github.com/Softbank-Hackathon-Finals/security/blob/feature/security-service-integration/docs/development/mac-acceptance-preparation-2026-11-07.md)에 있다.
팀 플랫폼 변경은 별도 검토 대상이다. 현재 이 문서는 T28 보호 경로의 실제 채택이나
운영 IAM/RBAC 거부·복구 시험 완료를 의미하지 않는다.
