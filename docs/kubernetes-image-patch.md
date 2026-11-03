# 검증된 이미지의 제한적 Kubernetes 교체

`KubernetesImagePatchAdapter`는 등록된 Deployment 한 개의 컨테이너 이미지 한 개만 교체한다. 임의 매니페스트·셸·태그·대체 목적지를 받지 않는다. 기존 저장 승인·실행 리스·효과 원장을 거친 호스트 실행 경로에 연결하는 provider 포트이며, 어댑터 자체가 승인을 발급하지 않는다.

## 변경 조건

등록에는 tenant/app/environment/resource, namespace UID, Deployment UID, container, 불변 OCI digest, 기존 설정 hash, opaque resourceVersion과 리허설 산출물 참조를 고정한다. 변경 전 전체 pod template과 UID·resourceVersion을 JSON Patch의 원자적 `test`로 확인한다. 일치하는 경우에만 이미지와 이 명령의 marker를 한 번 변경한다. 권한·등록·유효기한은 API 호출 직전에 다시 확인한다.

현재 지원 범위는 1~10개 복제본의 단일 컨테이너 Deployment, 이미지 단독 변경이다. 설정·init/ephemeral container 변경, DB 이전·스키마 변경·트래픽 전환·카나리·블루그린은 이 포트의 책임이 아니다.

## 응답 유실과 사후 검증

API 응답을 잃어도 자동으로 PATCH를 다시 보내지 않는다. 같은 명령 marker·정확한 이미지·설정을 읽어 실제 반영 여부를 확인한다. 다른 작업이 같은 이미지를 쓴 것만으로 해당 명령의 성공을 인정하지 않는다.

실행 허용 기한과 조회 허용 기한을 별도로 등록할 수 있다. 조회 기한은 기존 API 등록과 최대 24시간 안에 제한되며, 실행 기한·사용자 승인·서명된 증거의 유효기간을 연장하지 않는다. 폐기된 등록과 권한은 조회에도 사용할 수 없다.

`confirmed_applied`는 원하는 spec이 저장됐다는 의미다. `KubernetesRuntimeCollector`는 별도 읽기 전용 주체로 Deployment 관측 generation·복제본 수, ReplicaSet/Pod 소유권 체인, 실제 실행 imageID의 manifest digest, Pod Ready를 확인한다. 컨트롤러 숫자나 Docker config ID만으로 런타임을 인정하지 않는다. 이후 실제 HTTP·기능·보안 수정·데이터 보호 검증과 재평가는 기존 독립 postflight 경계에서 수행한다.

## 검증 범위

전용 로컬 kind 클러스터의 제한된 서비스 계정으로 v1 → v2 한 번의 실제 조건부 변경, 독립 런타임 digest와 HTTP 응답·보안 헤더를 확인했다. 읽기 주체의 PATCH, 쓰기 주체의 Secret 조회·다른 Deployment 변경, 다른 namespace 조회는 실제 403으로 거부됐다. 이 시험은 고정된 제어용 HTTP 앱이며 Harbor·AI·기업 승인 E2E를 의미하지 않는다. kind의 기본 CNI에 NetworkPolicy 강제력을 가정하지 않는다.

로컬 TLS 시험은 고정 경로·JSON Patch 형식·CA/호스트명·리다이렉트 거부·403/422·응답 유실 시 재전송 없음도 검증한다. 운영 배치에는 전용 최소 RBAC, 짧은 토큰 발급·폐기, 등록 서명과 기존 실행 조정기의 결합, 독립 postflight가 필요하다. 실환경 검증 결과를 개별 등록과 버전에 한정하며 일반 클러스터 전체의 운영 자격으로 확대하지 않는다.
