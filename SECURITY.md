# Security Policy

## 취약점 신고
- 신고 이메일: security@example.com (예시)
- 포함 정보: 영향 범위, 재현 단계, 관련 로그(민감정보 마스킹), 제안 대응 방안

## 공개 전 점검
- 비밀키/토큰이 저장소에 포함되지 않았는지 사전 검사
- PR 제출 전 `git secrets`, `trufflehog` 등 비밀 탐지 도구 실행 권장

## 키/인증정보 노출 시 대응 절차
1. 노출된 키 즉시 폐기 또는 회수 (AWS 콘솔/CLI)
2. `git filter-repo` 또는 BFG Repo-Cleaner로 히스토리에서 완전 제거
3. `git push --force`로 원격 저장소 갱신
4. 협업자에게 노출 사실과 조치 내용을 공지
5. CloudTrail/로그를 확인하여 악용 징후를 조사하고 필요한 추가 대응 수행

## 서드파티 의존성 모니터링
- Dependabot/Security Hub로 CVE 모니터링
- 심각도 HIGH 이상 취약점은 즉시 패치 및 재배포
