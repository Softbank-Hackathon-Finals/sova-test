# 비용 통합과 OpenTelemetry 횡단 관측

상태: 비용 비교 계약과 실제 Collector·SDK 경로의 첫 구현이다. 전체 관측 backend·청구 수집은 남아 있다.

## 공통 신원과 관측

클라우드·온프레미스에 로컬 OTel Collector를 배치하고 승인된 경계의 gateway로 전달한다. tenant/app/environment/resource/deployment/revision/operation/trace 식별자를 연결한다. 지표·로그·trace는 Prometheus 계열 저장소, Loki, Tempo 등의 교체 가능한 backend로 보낸다. 실제 선택과 HA·보존·부하는 자격 시험에서 고정한다.

Collector는 workload identity·mTLS·tenant 인가를 적용한다. 토큰·DB URL·prompt·원문·고카디널리티 필드를 제거·제한하고 제한된 큐·재시도·디스크 buffering·수집 손실 지표를 둔다. 제어면 또는 수집 서버 단절 시 정상 앱 운영이 중단되지 않아야 한다. 관측이 오래되면 unknown으로 표시하고 자동 이전 근거로 쓰지 않는다.

trace는 샘플링되고 일부 요청은 계측되지 않을 수 있다. 관측 span을 전체 트래픽·청구 정본·감사 WORM 기록으로 취급하지 않는다. 실제 호출·구성상 의존·잠재 영향은 지도에서 구분한다.

## 비용 모델

| 값 | 의미 |
| --- | --- |
| billed | provider의 확정 청구·정산 |
| provisional | 아직 조정될 수 있는 사용·청구 자료 |
| estimated | 가격 출처와 측정 사용량에 근거한 계산 |
| forecast | 예측한 부하·기간·가정에 따른 전망 |

통화·환율일·세금·할인·약정·미배분 비용과 공유 자원 배분식을 함께 보인다. 관측 부하만으로 확정 요금을 만들지 않는다. 가격·사용량의 출처·유효기간·누락 범위를 보존한다. 앱별 비용 배분과 계정 총액을 중복 합산하지 않는다.

온프레미스는 장비·전력·지원·운영 인력·감가상각의 TCO와 실제 추가 현금 비용을 분리한다. 남은 약정·잔류 저장·backup·공인 주소·회선·출발 egress·데이터 복사·동시 운영 기간도 이전 경제성에 포함한다.

## 배치 제안과 폐쇄 루프

보안·레지던시·가용성·기능·지연·용량을 필수 조건으로 먼저 평가한다. 통과한 후보만 동일 기간·부하·서비스 수준으로 비용을 비교한다. 절감액 범위·가격 신뢰도·전환 비용·회수 기간·감도와 탈락 이유를 제시한다.

`관측 → 조건 충족의 지속 확인 → 후보 비교 → 비용/위험 검토 → 승인 → 이전 → 효과 검증`을 따른다. hysteresis·최소 유지 시간·cooldown·횟수/금액/범위 한도로 왕복 이동을 막는다. 비용 지표만으로 쓰기 이전을 즉시 실행하지 않는다. 자동 실행은 정확한 정책·기한·한도 내 사전 승인된 경로만 허용한다.

## 시험

수집 지연·중복·누락·clock skew·tenant 위조·수집기 과부하·고카디널리티·위치 위반·청구 지연·환율·공유 배분 오류를 주입한다. 대시보드의 수치가 어떤 시각과 범위를 나타내는지 추적 가능해야 한다. 이전 후 비용·SLO가 개선되지 않으면 새 계획을 제안하며 데이터 손실을 동반한 자동 복귀를 하지 않는다.

## 2026-11-02 구현 경계

공식 Collector 0.164.0 이미지를 digest로 고정한 구성 생성기와 최소 OTLP projection을 추가했다. 별도 생산자 listener·mTLS·bearer를 사용하고 자원 신원은 등록값으로 덮어쓴다. HTTP server span만 허용하며 알려진 route/method/status 외 속성·이름·scope 정보는 정리한다. event/link가 있거나 등록되지 않은 경로인 span은 버린다. 실제 컨테이너와 상담앱 SDK 전송·인증 거부를 시험했다.

projection은 인증된 Collector 전송만 수용한다. raw OTLP는 디스크에 저장하지 않는다. 수집 손실이 미확인일 때 0으로 가정하지 않으며 sampled window는 전체 트래픽·청구·불변 감사가 아니다. 등록 만료는 수신 projection에서도 검사한다. 공급자가 허용 필드에 숨긴 데이터를 포함한 범용 DLP나 metrics/logs/trace 저장 backend·HA까지 자격을 부여한 것은 아니다.

비용은 같은 app·통화·기간·workload/SLO의 6개 운영비와 3개 이전비(migration/overlap/egress)를 각각 명시해야 한다. 이전비도 scope·입력·관측 시각·만료에 결합한다. authorized quote provider와 출처 인증 경계를 추가했다. 추정 절감액은 비용 한도나 이전 승인으로 쓰지 않는다.

### 실제 공개 단가 수집의 첫 범위

`adapters/aws_public_prices.py`에서 AWS Price List Query API의 정확한 RDS PostgreSQL·Single-AZ·current-generation·region·instance class 프로필을 읽는다. 인증·등록 확인 callback을 외부 경계에서 주입하며, 표준 TLS endpoint와 제한된 timeout/retry·3페이지·페이지당 20개 응답만 허용한다. 같은 SKU의 충돌, 복수 SKU, 조건부/계층/비시간 단가, USD 외 통화, 미래 발행, 불완전 pagination은 거부한다.

응답은 SKU·rate code·catalog version·적용일·관측일·문서 digest·최대 6시간의 유효기간에 결합한다. 정수 시간의 가정을 곱해 `compute` 항목 하나만 만들 수 있다. 누락된 storage/network/backup/operations/shared 항목을 0원으로 채우지 않으며 `CostEstimate` 전체로 승격할 수 없다. CPU credit·할인·세금과 공유 배분도 별도다.

정확한 한 프로필로 실제 API 수집을 확인했지만 전체 사용량·청구·온프레미스 TCO·여러 환경의 비용 비교는 미완료다. 운영자 로컬 인증으로 시험했으며 호스팅된 quote provider의 기업 인가는 별도 연결 대상이다.

AWS는 [Price List](https://docs.aws.amazon.com/awsaccountbilling/latest/aboutv2/price-changes.html)를 정보성 가격 카탈로그로 설명한다. API를 호출하는 endpoint의 리전과 조회 제품의 리전은 구분한다. 이 결과를 실제 청구액이나 지출 상한으로 표시하지 않는다.
