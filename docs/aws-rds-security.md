# RDS 읽기 전용 보안 조사

2026-11-01 · 코드·계약·AWS SDK 응답 대체물 검증 완료. 실제 AWS 계정 호출은 이번 작업에 포함하지 않았다.

## 등록과 권한

`RdsReadRegistration`에는 계정·리전·DB ARN·불변 `DbiResourceId`·tenant/app/environment·revision·기한을 고정한다. 등록은 최대 하루이며 임의 endpoint·명령·Secret을 받지 않는다.

| 관계 | 검증 |
| --- | --- |
| `sova_managed` | 정확한 계정·DB ID와 Sova 관리·tenant·app 태그 확인 |
| `registered_read_only` | 운영자가 명시 등록한 기존 DB의 계정·DB ID 확인. Sova 소유라고 주장하거나 태그를 변경하지 않음 |

기존 schema 1은 관리 자원으로만 해석한다. schema 2는 관계를 명시하며 필드 생략으로 관리 검사를 끌 수 없다. 등록 자체의 신뢰는 운영자 경계에서 보장해야 하며 임의 사용자 JSON을 승인된 등록으로 받아서는 안 된다.

SDK 클라이언트를 만들기 전과 각 호출 전에 인가한다. 고정된 AWS STS/RDS HTTPS endpoint와 인증서 검증을 사용하고, 사용자 endpoint override·proxy 설정을 사용하지 않는다. 연결 2초·읽기 3초·1회 시도·전체 경과 12초 예산을 적용한다. 이는 SDK와 직렬 호출의 시간 예산이며 DNS·OS까지 강제 종료하는 별도 프로세스 샌드박스가 아니다.

필요한 읽기는 STS `GetCallerIdentity`, RDS `DescribeDBInstances`, 관리 자원인 경우 `ListTagsForResource`다. 자원 생성·수정·Secret 읽기·DB SQL 실행 권한을 요구하지 않는다. AWS IAM에서 action별 resource scope 지원 차이를 확인해 별도 읽기 역할로 제공한다.

## 수집 항목

| 검사 | 이 결과가 증명하지 않는 것 |
| --- | --- |
| 저장 암호화 설정 | 비인가 KMS 접근 거부 |
| 백업 보존 기간 | 실제 복원 성공·RPO·RTO |
| 비공개 endpoint 설정 | 모든 네트워크 경로 차단 |
| 삭제 보호 설정 | 운영자 전체 권한의 안전성 |
| PostgreSQL 로그 export 설정 | 감사 로그 도착·무결성 |
| Multi-AZ 설정 | 장애 전환 성공·업무 가용성 |

없는 필드를 안전한 기본값으로 채우지 않는다. 전환 중 상태와 대기 중 변경이 있으면 미검증으로 처리한다. DB engine·ARN·불변 ID가 다르면 거부한다. 결과에는 계정·scope와 정제한 사실만 남기며 endpoint·사용자명·Secret payload·원본 태그를 복사하지 않는다.

수집 결과의 설정 digest·등록 digest·verifier 버전은 정책 근거와 정확히 연결한다. 이 결과를 런타임 보호 시험 대신 사용할 수 없다.

## CLI

운영자가 검토한 비밀값 없는 등록 파일과 최소 권한 AWS 프로필을 준비한 후 실행한다.

```sh
.local-notes/venv/bin/python -m pip install -e '.[aws]'
.local-notes/venv/bin/sova discover-rds-security \
  --registration /absolute/path/to/operator-approved-registration.json \
  --aws-profile sova-readonly
```

정확한 인자는 `sova discover-rds-security --help`로 확인한다. 자격 증명을 등록 파일이나 CLI 인자로 넣지 않는다. 전체 계정 DB를 탐색하지 않고 등록한 DB 하나만 조회한다.

## 검증 범위와 코드

실제 boto3/botocore `Stubber`로 호출 이름·인자·미호출·오류·시간 예산·출력 제거를 시험했다. 실제 AWS 권한, 태그, RDS 상태, 운영 TLS/감사/복원은 별도 실계정 시험이 필요하다.

- `src/sova/domain/aws_security.py`: 등록·스냅샷 계약
- `src/sova/adapters/aws_security_codec.py`: 엄격한 입력 schema
- `src/sova/adapters/aws_rds_security.py`: 읽기 전용 SDK 수집
- `tests/unit/test_aws_rds_security.py`: SDK 응답 대체물 시험

설정 의미는 [AWS DescribeDBInstances](https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DescribeDBInstances.html), TLS는 [RDS PostgreSQL SSL 안내](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/PostgreSQL.Concepts.General.SSL.html)를 기준으로 한다.
