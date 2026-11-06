# 보안 서비스 소비 개발 기록

2026-11-06 · security 0.11.0 · platform `f602b39a949b99f3e2e7be901103063e78a52a70`

- 요구: SEC-PATCH-05·06·07·08, POL-09·11, SG-2·3.
- 기반 Sova: `7d79d6517730e408d3663815e91e70e626806c88`.
- 수정: `src/sova/security/application/remote_program.py`,
  `tests/integration/test_security_patch_execution.py`, pyproject의 정확한 패키지 버전.
- 이유: 기존 effect 원장·승인·사후 검사 조합을 유지하며 판정 공급자만 선택적으로 원격화한다.
  패키지 코드를 복제하거나 서비스가 실행 권한을 가져가는 구조를 피한다.
- 시험: `python -m pytest tests/integration/test_security_patch_execution.py -q` 31 PASS.
  실제 SQLite 원장을 사용하되 권한/측정/전송은 합성이다. 신규 효과 전 서비스 장애·승인 철회는
  효과 0회, 효과 후 서비스 장애·철회·만료는 APPLIED 유지와 hold, 재시도 중복 효과 0회를 확인한다.
- 전체 Linux 실제 PostgreSQL 17.11·OPA 1.22 회귀: 1,102 PASS, 3 SKIP.
  skip은 실제 컨테이너 이미지/Collector/AWS SQS 등록이 필요한 세 시험이다.
- 미검증: Sova 실행 actor와 workload 신원의 실제 매핑, T7 서비스 audience,
  운영 verifier/클라우드 거부/복구 근거. 명시적 사용자 위임 없이 actor를 바꾸지 않는다.
- 상태: 구현·소비 모의 검증·로컬 SQLite/PG 원장 실측. 플랫폼 적용/운영 인수는 보류.

상세 설계·소스 SHA·실패 실험·서비스 실행 결과는 security의
`docs/development/security-service-2026-11-06.md`와 ADR을 정본으로 참조한다.
