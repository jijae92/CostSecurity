# Runbook

## 장애 대응 한줄요약
CloudWatch Logs 확인 → 수집기 재시도 → FP suppress 등록(기간 한정) → 권한/키 점검

## 1. 관찰 (Observe)
- **로그 위치**
  - Cost Collector: `/aws/lambda/CostCollectorFunction`
  - Security Collector: `/aws/lambda/SecCollectorFunction`
  - Correlate: `/aws/lambda/CorrelateFunction`
  - Reporter: `/aws/lambda/ReporterFunction`
- **지표**
  - `CostSecurity/CollectedRecords`
  - `CostSecurity/CorrelatedSignals`
  - `CostSecurity/NotificationsSent`
- **알람**
  - EventBridge 미실행 알람 (500/주기 1회 이상)
  - Lambda 오류 비율 > 5%
  - SNS 전송 실패 (Reporter 단계)

## 2. 안정화 (Stabilize)
1. 최근 배포/구성 변경 확인.
2. 개별 수집기 Lambda를 **수동 재시도** (AWS Console → Lambda → `Test` 또는 `sam remote invoke`).
3. 필요한 경우 `DRY_RUN=true`로 로컬 재현 (`python -m src.correlate.handler --dry-run`).

## 3. 원인 분석 (Diagnose)
- **비용 API RateLimit 발생 시**
  - 로그 메트릭: `ThrottlingException` 또는 `Rate exceeded` 확인.
  - Cost Explorer 호출 재시도 간격을 늘리고, `COST_LOOKBACK_DAYS`/그룹 단위를 축소하여 요청량을 줄임.
  - 충돌이 빈번하면 요청을 주간 단위로 분할하거나 비경쟁 시간대(야간 UTC)로 스케줄 조정.
- **보안 이벤트 부족 시**
  - Security Hub/GuardDuty 활성화 여부 및 필터(Severity/Status) 재검토.
  - 멀티계정 환경이면 Organization 관리자 계정 권한을 확인하고, 필요한 `ListFindings/GetFindings` 권한이 있는지 검증.
  - CloudTrail@Athena가 비활성 상태이면 테이블/데이터 소스 구성 확인.

## 4. 완화 (Mitigate)
- False Positive가 반복되면 `SUPPRESS_CONFIG_URI`가 가리키는 `.falsepositives.json`에 주간 한정 suppress 항목 추가.
- SNS/Slack 전송 실패 시 토픽/웹훅 권한 재설정 후 Reporter Lambda 재호출.

## 5. 복구 & 사후 처리 (Recover)
1. 모든 Lambdas가 정상 실행되는지 확인 (다음 스케줄 전 수동 실행 권장).
2. CodePipeline `Release` 재실행으로 최신 코드 재배포.
3. Incident 기록에 이벤트 타임라인, 적용한 suppress, 권한 변경 사항을 남김.
4. 필요 시 API 쿼터 증설(AWS Support) 또는 비용 분석 워크로드 최적화 계획 수립.
