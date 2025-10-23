"""Rule engine for correlation alerts."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List


@dataclass(slots=True)
class RuleContext:
    """Context passed to rule evaluators."""

    account_id: str
    region: str
    service: str
    cost_delta_pct: float
    cost_anomaly_score: float
    severity_counts: Dict[str, int]
    provider_counts: Dict[str, int]
    guardduty_high_count: int
    new_service_count: int
    delta_threshold: float
    zscore_threshold: float


@dataclass(slots=True)
class RuleMatch:
    """Matched rule with recommendation."""

    name: str
    recommendation: str


class RuleEngine:
    """Evaluate correlation contexts against predefined heuristics."""

    def __init__(self, *, service_diversity_threshold: int = 3):
        self.service_diversity_threshold = service_diversity_threshold

    def evaluate(self, context: RuleContext) -> List[RuleMatch]:
        matches: List[RuleMatch] = []
        if self._rule_cost30_sec_high(context):
            matches.append(
                RuleMatch(
                    name="RULE_COST30_SEC_HIGH",
                    recommendation="비용 급등과 보안 이벤트가 동시에 발생했습니다. 액세스 키 남용, 권한 오용, 자동화 도구 남용 여부를 점검하세요.",
                )
            )
        if self._rule_gd_threat_costspike(context):
            matches.append(
                RuleMatch(
                    name="RULE_GD_THREAT_COSTSPIKE",
                    recommendation="GuardDuty 고위험 탐지와 비용 급등이 함께 관측되었습니다. 위협 행위자에 의해 리소스가 악용되는지 조사하세요.",
                )
            )
        if self._rule_account_drift(context):
            matches.append(
                RuleMatch(
                    name="RULE_ACCOUNT_DRIFT",
                    recommendation="신규 서비스가 대량으로 사용되면서 Security Hub 경보가 발생했습니다. 계정 내 서비스 드리프트와 거버넌스 위반을 검토하세요.",
                )
            )
        return matches

    def _rule_cost30_sec_high(self, context: RuleContext) -> bool:
        threshold = max(30.0, context.delta_threshold)
        high_or_critical = context.severity_counts.get("HIGH", 0) + context.severity_counts.get("CRITICAL", 0)
        return context.cost_delta_pct >= threshold and high_or_critical >= 1

    def _rule_gd_threat_costspike(self, context: RuleContext) -> bool:
        return context.guardduty_high_count >= 2 and context.cost_anomaly_score >= max(2.0, context.zscore_threshold)

    def _rule_account_drift(self, context: RuleContext) -> bool:
        securityhub_count = context.provider_counts.get("SecurityHub", 0)
        return context.new_service_count >= self.service_diversity_threshold and securityhub_count >= 1


__all__ = ["RuleContext", "RuleMatch", "RuleEngine"]
