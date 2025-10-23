# Contributing Guide

## 브랜치 전략
- `main` : 보호 브랜치
- 기능 개발: `feature/<short-description>`
- 버그 수정: `fix/<issue-id>-<short-description>`

## 커밋 규칙
- Conventional Commits 사용 (`feat:`, `fix:`, `docs:`, `chore:` 등)
- 하나의 커밋은 하나의 변경 사항에 집중
- 커밋 메시지에 테스트 여부/관련 이슈 표기 권장

## 코드 스타일 & 테스트
- Python: PEP8 준수, type hints 및 docstring 권장
- 테스트: `pytest -q` 필수 통과, 커버리지 80% 이상 권장
- 로컬 검증: `make dry-run`으로 리포트 생성 확인

## Pull Request 체크리스트
- [ ] 테스트 통과 (`pytest -q`)
- [ ] 문서/README 갱신 (필요 시)
- [ ] 린터/포매터 적용 (적용 대상인 경우)
- [ ] 리뷰어 1명 이상 승인
- [ ] CHANGELOG 또는 릴리스 노트 업데이트 (필요 시)

## 이슈 & 피드백
- 버그/기능 제안: GitHub Issues 활용
- 긴급 지원: 저장소 관리자가 지정한 연락 경로 이용
