"""复现服务：用审计条目中的快照 + 历史规则版本重放判定，验证结论一致。"""

from __future__ import annotations

from .audit import AuditLog
from .decision import decide
from .models import AccessDecision, ClearanceLevel, Grant, Record
from .rules import RuleRegistry


class ReplayService:
    def __init__(self, audit: AuditLog, rules: RuleRegistry) -> None:
        self._audit = audit
        self._rules = rules

    def replay(self, decision_id: str) -> AccessDecision:
        """按审计快照与当时规则版本重放判定。"""
        entry = self._audit.get(decision_id)
        if entry is None:
            raise KeyError(f"unknown decision_id {decision_id}")
        snapshot = self._rules.snapshot_of(entry.rule_version)

        record: Record | None = None
        if entry.record_required_level >= 0:
            record = Record(
                record_id=entry.record_id,
                record_type=entry.record_type,
                required_level=ClearanceLevel(entry.record_required_level),
                data=dict(entry.record_snapshot),
            )
        grant: Grant | None = None
        if entry.grant_level is not None:
            grant = Grant(
                subject_id=entry.subject_id,
                record_id=entry.record_id,
                level=ClearanceLevel(entry.grant_level),
                expires_at=entry.grant_expires_at,
            )
        return decide(
            decision_id=entry.decision_id,
            subject_id=entry.subject_id,
            record=record,
            grant=grant,
            snapshot=snapshot,
            now=entry.decided_at,
        )

    def verify(self, decision_id: str) -> bool:
        """重放结果与审计条目中的结论逐字段比对。"""
        entry = self._audit.get(decision_id)
        if entry is None:
            raise KeyError(f"unknown decision_id {decision_id}")
        replayed = self.replay(decision_id)
        if replayed.result != entry.result or replayed.deny_reason != entry.deny_reason:
            return False
        for name, pf in replayed.presented.items():
            saved = entry.presented.get(name)
            if saved is None:
                return False
            if (
                saved["value"] != pf.value
                or saved["strategy"] != pf.strategy.value
                or saved["visible"] != pf.visible
            ):
                return False
        return True
