# T28 재시작 경계: 기존 실행 원장에 연결

기준 플랫폼 `42811da4cf19ce941491d4794ab49790881dc409`의 `scripts/happy_path.py`는
이전 재현 기준과 동일한 원문 SHA-256
`edac61dcc4ec0f0bf26e5e7583f33fb3137c544836d9d1c6441453724210d14c`다.
효과와 JSONL 결과 기록 사이의 중단 창이 남아 있다.

## 구현

`src/sova/adapters/platform_t28.py`의 `DurableT28Port`를 원본 `cmd_run(run=...)`에 연결한다.
T28의 순서·콘솔 승인·상태 조회는 그대로 사용하고, operator 호출은 Sova의 기존
`EffectExecutor` 및 `EffectJournal`을 통과시킨다. 별도 승인기나 새 JSONL 실행 원장은 없다.

- 신뢰된 서버가 등록한 command/permit/adapter만 입력한다. 사용자 JSON을 그대로 등록하지 않는다.
- command fingerprint는 argv, 플랫폼 SHA, plan/application, diff/image, 환경 revision과 fencing epoch를 포함한다.
- 기존 원장의 PREPARED → IN_FLIGHT CAS를 효과 전에 commit하고 현재 승인을 다시 확인한다.
- IN_FLIGHT/UNKNOWN은 재호출하지 않는다. 종료 코드나 stdout만으로 APPLIED를 만들지 않고
  기존 adapter의 결속된 readback을 요구한다.
- APPLIED 영수증을 잃어도 이전 영수증을 반환한다. 새로운 상태 진단으로 표시하지 않는다.
- JSONL의 완료 표시는 원장의 APPLIED와 대조한다. 다른 JSONL 경로로 바꿔도 같은 원장을 사용한다.
- 복구는 `EffectExecutor.reconcile`과 기존 복구 권한 경로를 사용한다. 늦게 도착할 이전 실행이
  더 이상 변경할 수 없다는 확인 없이 단순 GET이나 만료된 lease만으로 복구를 승인하면 안 된다.

`load_driver`는 clean checkout·정확한 플랫폼 SHA·원문 hash를 확인한다.
원래 `happy_path.py`를 직접 실행하는 경로는 아직 플랫폼에 존재한다. 개인 어댑터를 만들었다는
이유만으로 해당 경로가 보호됐다고 주장하지 않는다. 플랫폼 채택 시 실행 권한을 가진 operator
entrypoint에서 이 포트를 구성하고 기존 직접 실행 경로를 권한으로 제한해야 한다.

## 검증과 인수 한계

`tests/integration/test_platform_t28_restart.py`는 실제 고정 플랫폼 코드를 읽고 STEPS 전체를
**한 개의 합성 파일 효과**로 교체한다. 실제 클라우드·operator 명령은 0회다.
효과 전/효과 후/원장 APPLIED 후 각각 자식 프로세스가 `os._exit`로 종료되며,
재시작·계획/diff/image 변경·권한 철회·위조 JSONL·동시 두 프로세스를 검사한다.

최초 실행은 sparse checkout에 scripts 경로가 없어 실패했다. 원문·GitOps pin 경로를 추가한 뒤
10개 T28 시험과 기존 원장 12개 시험이 **22 PASS / 2.72초**였다.
추가 동시성/다른 기록 경로 시험까지 **24 PASS / 2.81초**였다 (Python 3.14.10, WSL).
동일 시험을 Linux CI에도 연결했다. 운영 클러스터 시험으로 확대하지 않는다.

```sh
SOVA_T28_PLATFORM_SOURCE=/absolute/clean/pinned-platform \
python -m pytest -q tests/integration/test_platform_t28_restart.py tests/integration/test_effect_executor.py
```

SQLite는 개인 검증용이다. 실제 다중 host에서는 기존 PostgreSQL 실행 소유권·fencing·복구 권한과
현재 T10 승인/잠금/application 원장을 주입해야 한다. 이 어댑터는 그 권한을 발급하지 않는다.
따라서 현재 상태는 **개인 환경 구현·프로세스 검증**, 실제 플랫폼 반영/운영 인수는 별도다.
