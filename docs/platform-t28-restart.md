# T28 재시작 경계: 기존 실행 원장에 연결

Mac 인수 후속은 [현재 source 차이와 연결 조건](platform-t28-mac-intake.md)을 참고한다.
기존 개인 검증과 실제 플랫폼 적용을 구분하며 허용 SHA를 자동 확장하지 않는다.

후속 기준 `0795f65e24f58e43545b16b97757efcc0923fd4a`의 새 driver도 별도로 고정한다.
원문 SHA-256은 `e4bc607112512361d4bde4c6022bc59eb21191fdc139ade77b52f50bb013a355`이며
Git blob `8a3e3993682f31ce262e1a82e21c4f11d60e75c5`와 대조했다. 기존 42811da 시험도 유지한다.

현재 검증: 최종 producer 546f6e0을 사용하는 [a177276 CI](https://github.com/Softbank-Hackathon-Finals/sova-test/actions/runs/42266814087)에서
최신 driver **36 PASS / 2.16초**, 이전 driver **32 PASS / 4 SKIP / 2.02초**다.
skip 네 개는 이전 driver에 없는 initial-proposal 인자 시험이다. 아래 실패·추가 과정은 이력으로 보존한다.

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

## PostgreSQL 실행 소유권 시험 추가

`31fc071`의 [원격 CI](https://github.com/Softbank-Hackathon-Finals/sova-test/actions/runs/42253531892)는
기존 소비 시험 process/container 각각 44개와 T28/원장 **24 PASS / 2.36초**를 통과했다.
이어 `test_platform_t28_postgres.py`에서 동일한 T28 포트를 기존 PostgreSQL 승인·operation·
실행 lease·effect journal에 연결한다. 실제 자식 종료 후 lease 만료만으로 takeover하지 못하고,
별도 quiescence 확인으로 발급된 reconcile lease만 readback을 수행하는지 확인한다.
현재 승인 철회 시 효과 0회도 검사한다. 원격 CI 실행 전이며 결과는 후속 기록한다.
quiescence는 합성 파일 효과를 낸 로컬 child의 종료를 확인한 것으로, 원격 클라우드 요청 취소
증거까지 검증했다는 뜻은 아니다. 로컬 C: 용량 guard 때문에 추가 PG 시험은 CI에서 수행한다.

`6e000ff`의 [CI](https://github.com/Softbank-Hackathon-Finals/sova-test/actions/runs/42255522327)는
기존 소비 44개와 T28/원장/PG **26 PASS / 0.96초**를 통과했다.

## 후속 검토: 상태 조회 subprocess도 우회 경로가 될 수 있음

원본 T28은 `--plan-state-command`를 읽기 전용 명령으로 간주하지만 실제로는 임의 subprocess다.
operator 포트만 보호하면 이 경로가 영속 접수 밖에서 실행될 수 있다. 개인 연결부는 해당 CLI
옵션을 거부하고, 호스트가 구성한 기존 T10 읽기 callback만 받도록 바꿨다.
새 상태 조회 구현이나 권한 발급기는 만들지 않는다. original CLI 자체는 아직 팀 플랫폼에 남아 있다.

같은 이유로 `real/local/mock` profile도 command fingerprint에 포함하고 기존 JSONL header의
profile/plan/platform SHA를 대조한다. 모의 실행을 real로 이름만 바꾸거나 다른 기준의 기록을
이어 사용하는 경로는 거부한다. 등록 변경·기록 변조·상태 조회 우회 시험 3개를 추가했다.
이 추가 변경은 lint를 통과했고 원격 CI 결과를 기다린다.

`e047e42`의 [CI](https://github.com/Softbank-Hackathon-Finals/sova-test/actions/runs/42257416125)는
기존 소비 44개와 T28/원장/PG **29 PASS / 1.05초**를 통과했다.

## 호출자 종료 뒤 원격 효과가 늦게 생기는 경계

별도 localhost HTTP 서버 프로세스가 요청을 접수한 뒤 호출자 프로세스를 강제 종료한다.
서버는 계속 살아 있고 초기 효과는 아직 없다. 재시작한 T28이 다시 요청하지 않으며,
호출자 종료만을 근거로 reconcile하지 못하는지 검사한다. 이후 원격 서버를 해제하여
효과가 늦게 1회 생성되면 terminal 확인 후 readback으로만 조정한다.

실제 TCP와 두 프로세스를 사용하지만 효과·terminal 증거는 개인 시험 파일이다.
운영 공급자의 지연 요청 취소·fencing 계약을 증명하지 않는다. 그 증거를 인증하는 책임은
기존 호스트의 recovery authority에 남긴다. 추가 원격 CI 결과는 후속 기록한다.

## 작업 중 플랫폼 갱신 대응

0795f65는 새 `--platform-context`에서 `kubectl exec` 상태 조회를 직접 구성한다.
이 경로도 영속 operator 포트 밖 subprocess이므로 개인 어댑터에서는 거부하고 호스트 reader
callback을 요구한다. 새 initial-proposal `start/collect`의 `--initial-args`는 실제 호출 argv에
덧붙는 값이므로 등록 fingerprint와 함께 대조한다. 인자를 바꾸면 효과 전에 거부한다.
file 경로 결속만으로 그 파일 내용을 인증하지 않는다. 실제 공급자 adapter의 `validate`가
현재 등록된 입력·계획·diff·이미지와 파일 내용을 대조해야 하며 일반 subprocess adapter는 제공하지 않는다.

원본의 exit 10 대기는 별도 정책이다. 이 포트는 승인된 효과를 확인하는 APPLIED 영수증만 0으로
반환하며 불명확한 비동기 작업을 다시 apply하지 않는다. 공급자 terminal/readback 후 기존 원장에서
조정한다. 이 보수적인 경계를 원본의 자동 재호출로 우회하지 않는다.
