# 등록된 Kubernetes 환경의 읽기 전용 조사

2026-11-01 · S1의 첫 구현. 로컬 운영자 CLI와 외부 인증 경계를 주입하는 유스케이스를 제공한다. 기업 OIDC·중앙 등록 저장소·실제 클러스터 자격 시험은 아직 연결하지 않았다.

## 범위와 권한

운영자가 서버 endpoint·접속 IP·CA digest·namespace UID·tenant/app/environment·등록 revision·유효기간을 사전에 등록한다. 등록 파일은 현재 OS 사용자 소유의 비공개 일반 파일이어야 한다. 사용자 ZIP이나 업로드된 kubeconfig를 실행하지 않는다. 파일의 소유권이 기업 로그인·조직 인가를 대신하지 않는다. 이 CLI는 로컬 운영자 모드에 한정한다.

유스케이스는 매 요청과 결과 반환 전에 주입한 인가기를 호출한다. 호스팅 경계는 여기서 실제 인증된 신원·tenant·앱·환경 권한·폐기 상태를 검증해야 한다. actor 문자열이나 등록 데이터 자체를 인증 증거로 사용해서는 안 된다. CLI는 OS 신원과 등록 파일 소유권·동일 revision을 재확인한다.

실제 Kubernetes 인증에는 운영자가 제공한 짧은 수명의 service account bearer token을 사용한다. 토큰은 비공개 파일에서 요청마다 읽고 결과·등록·로그에 저장하지 않는다. 토큰 발급·갱신은 이 클라이언트가 수행하지 않는다.

## 통신과 수집

- 등록한 숫자 IP로만 직접 연결하고 TLS SNI·hostname·등록 CA digest를 검증한다. 환경 proxy·DNS 변경·redirect로 다른 서버에 토큰을 보내지 않는다. 현재는 등록 IP 중 첫 주소를 사용하며 자동 failover는 하지 않는다.
- 등록 namespace의 UID를 수집 전후 확인한다. 같은 이름으로 삭제·재생성된 namespace는 거부한다.
- Deployment·StatefulSet·Service·PVC만 앱 label selector로 조회한다. Secret·Pod exec·watch·변경 API는 호출하지 않는다.
- 32개 단위 pagination, 종류별 최대 8페이지, 전체 128개 자원, 응답별 2MiB, 호출당 최대 5초의 절대 제한과 전체 수집 30초 예산을 적용한다. 인가기·토큰 공급자의 실행 시간은 해당 신뢰 경계에서 별도 제한해야 한다.
- 계속 토큰의 반복·누락된 resourceVersion·페이지 사이 버전 변경·권한 거부·만료·부분 수집은 실패다. 한 종류라도 실패하면 성공 그래프를 반환하지 않는다. 비어 있는 앱 목록도 현재는 성공 등록으로 처리하지 않는다.
- 자원 종류별 collection resourceVersion을 따로 보존한다. 서로 다른 종류를 하나의 원자적 시점으로 수집했다고 주장하지 않는다.
- env 값과 Secret 내용은 정규화 그래프에 복사하지 않는다. API 원문은 메모리에서 처리하며 디스크에 기록하지 않는다. Pod·Ingress·외부 DB·네트워크 정책 등의 전체 조사는 아직 포함하지 않는다.

## 결과와 한계

출력은 `graph`, 등록 digest·namespace UID·collection version·수집 시작/완료·graph digest를 연결한 `collection`, 그 문서의 digest다. 서명된 자격 증거가 아니며 실제 트래픽·readiness·업무 성공·보안 정책 준수를 증명하지 않는다. `executable=false`를 유지한다.

Kubernetes 입력만으로 애플리케이션 이식성을 확정하지 않는다. 자원별 이식성은 unknown으로 시작하며 호스트 의존·외부 서비스·데이터·Secret·이미지·runtime 조사가 뒤따라야 한다. Service selector 관계는 선언된 연결이다.

## 등록 스키마와 실행

비밀값 없는 등록 JSON의 필드는 다음과 같다.

```text
schema_version: 1
tenant_id / application_id / environment_id / location
endpoint: https://<registered-host>:<port> (path·사용자정보·query 없음)
approved_addresses: [<operator-approved-numeric-IP>]
ca_digest: <CA PEM bytes SHA-256>
namespace / namespace_uid
revision: positive integer
registered_at / valid_until: timezone-aware ISO timestamps
```

앱 ID는 안전한 Kubernetes label 값, namespace는 DNS label이어야 한다. CA 파일의 원시 bytes digest가 등록값과 일치해야 한다. 등록·토큰 파일은 0600 등 현재 사용자만 읽을 수 있는 권한으로 준비한다. Secret 값은 명령행에 직접 넣지 않는다.

```sh
.local-notes/venv/bin/sova discover-kubernetes --registration .local-notes/cluster-registration.json --ca-file .local-notes/cluster-ca.pem --token-file .local-notes/cluster-token > .local-notes/inventory.json
```

입력이 잘못됐거나 만료됐으면 일반 오류로 종료하며 토큰·서버 응답 본문을 출력하지 않는다. 결과를 장기 저장할 때는 관측 유효기간과 등록 revision을 다시 검증해야 한다. 현재 결과는 새 PostgreSQL 등록 저장소나 웹 지도에 자동 저장되지 않는다.

## RBAC 예제

[orders-reader.yaml](../examples/kubernetes/rbac/orders-reader.yaml)은 운영자 검토용 예제이며 자동 적용하지 않는다. namespace가 미리 준비되어 있어야 한다. 네 가지 resource의 namespace list와 정확한 namespace 이름의 get만 요청한다. Secret 조회·변경·cluster 전체 list 권한은 없다.

**label selector는 RBAC 보안 경계가 아니다.** 해당 service account는 namespace 안의 이 네 종류를 모두 list할 수 있다. 신뢰 경계가 다른 테넌트에 namespace를 공유하지 않으며, 더 강한 격리는 별도로 설계·시험해야 한다. 앱 label은 조회 범위·결과 일치 검사에 사용한다.

## 시험과 남은 작업

계약 대체물로 인가 철회·namespace 재생성·페이지/범위 오류를 시험하고 실제 localhost HTTPS 서버로 CA/hostname·토큰·proxy 무시·redirect 거부·읽기 제한을 시험한다. localhost 서버는 Kubernetes API 형태의 시험 서버이며 실제 k3s 클러스터가 아니다.

다음 검증은 전용 k3s의 실제 RBAC·토큰 만료·namespace 재생성·크기/페이지 경계·현재 자원 상태다. 그 후 기업 OIDC, 중앙 등록 revision·폐기 저장, PostgreSQL snapshot 연결, watch·인벤토리 변경 반영으로 이어간다.

## 별도 Linux VM의 실제 자격 시험

2026-11-02에는 기존 Sky VM과 분리한 Sova 전용 Lima VM에 고정 버전 k3s를 구성했다. 호스트 디렉터리·Docker 소켓·AWS 자격 증명을 앱에 마운트하지 않는다. 이 VM은 단일 노드 시험 환경이며 HA 또는 금융 운영 인증을 의미하지 않는다.

- [VM 구성](../infra/lima/sova-target.yaml)과 [고정 binary 설치](../infra/lima/bootstrap-k3s.sh)는 운영자가 별도로 검토·실행한다. Kubernetes 서버를 외부 공개하지 않으며 호스트의 명시적 loopback 포트만 사용한다.
- [대상 시험](../infra/lima/qualify_target.py)은 `SOVA_QUALIFY_LINUX_VM=1`과 비공개 `--state-dir`, 새 `--output`을 명시해야 한다. 등록의 기한·machine ID·node UID·Lima 설정 digest를 확인한 뒤 매번 고유 namespace를 만든다. 기존 namespace나 Sky VM을 수정하지 않는다. `--soak-seconds`는 0~1800초의 무상태 시험 서비스 갱신 측정을 선택한다.
- 실제 인벤토리 수집에는 짧은 ServiceAccount 토큰과 제한 RBAC를 사용한다. 설정된 label만으로 테넌트를 분리했다고 주장하지 않는다. 별도 namespace에서 실제 접근 거부를 시험한다.
- [Secret 시험](../infra/lima/qualify_secrets.py)은 `SOVA_QUALIFY_SECRET_ROTATION=1`을 별도로 요구한다. 전용 **단일 노드 시험 클러스터 전체의 암호화 키를 회전**하므로 다른 환경에 적용하지 않는다. 키·Secret·토큰을 출력하지 않고 암호문 hash·새 계정/폐기 계정의 접근 결과·선택한 감사 메타데이터의 digest만 남긴다.
- 두 도구는 운영자 권한으로 시험 자원을 준비하고, 실행 식별 label과 UID가 맞는 시험 자원만 정리한다. 호스팅 실행기·기업 인증·독립 verifier·운영 권한 broker가 아니다. 결과는 과거 시험 기록이며 현재 실행 권한으로 사용할 수 없다.

실제 Secret 저장 암호문, 키 회전 후 재암호화와 값 보존, ServiceAccount 재생성 후 이전 토큰 거부·새 토큰 성공 및 본문 없는 감사 이벤트를 확인했다. AES-CBC 키가 같은 호스트에 있으므로 호스트 root로부터의 키 격리나 외부 KMS 동등성을 검증한 것은 아니다. 감사 외부 전달·변조 탐지·복원·전체 보호 프로필은 후속 자격으로 남는다.

같은 VM의 무상태 HTTP 시험 서비스에 30분간 요청하며 롤링 갱신 6회를 수행했다. 35,137개 요청이 모두 HTTP 200으로 완료됐고, 갱신 후 다른 namespace 접근 거부와 허용 링크 회수 후 접속 거부도 확인했다. 이는 **단일 VM 내부의 정적 HTTP 시험 서비스** 결과다. 실제 상담앱의 DB·WebSocket·파일 이전, 외부 접속 SLO, 클라우드 간 무중단 운영 또는 일반 앱의 무오류 보장으로 확대하지 않는다.

키 회전은 K3s의 [단일 서버 공식 절차](https://docs.k3s.io/cli/secrets-encrypt#encryption-key-rotation)를 따른다. 설정 flag만으로 저장 암호화를 입증하지 않고 실제 저장 값을 대조했다.

## 기준 자료

통신·인증은 Kubernetes [인증 문서](https://kubernetes.io/docs/reference/access-authn-authz/authentication/), 범위 권한은 [RBAC 문서](https://kubernetes.io/docs/reference/access-authn-authz/rbac/), 목록 version과 pagination은 [API 개념](https://kubernetes.io/docs/reference/using-api/api-concepts/)을 참고했다. 조회일은 2026-11-01이다.
