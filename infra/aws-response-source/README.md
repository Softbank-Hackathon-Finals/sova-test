# 워크로드 대응 하이브리드 출발지 (EKS)

실행 전용 EKS 출발지다. VPC, EKS, 노드 2대, NetworkPolicy가 켜진 VPC CNI, Pod Identity 기반 EBS CSI, 태그 변경 불가 ECR로 이루어진다. 실행 순서, 경계, 비용, 정리 방법은 [워크로드 대응 실제 실행기](../../docs/workload-response-runtime.md)에 있다.

- 상태와 변수 파일(`run.auto.tfvars.json`)은 레포 밖 개인 상태 폴더에 둔다. `TF_DATA_DIR`와 `-backend-config=path=`로 지정한다.
- 애드온과 노드 AMI 버전은 고정한다. 바꾸면 자격 기록이 `NEEDS_EVIDENCE`가 되므로 다시 검증한다.
- EKS API 공개 접근은 운영자 /32 하나만 허용한다.
