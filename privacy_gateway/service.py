"""访问服务：编排 规则快照 -> 判定 -> 审计写入 的一致性流程。

一致性语义：
- 整次请求只使用请求开始时抓取的一个规则快照；
- 审计在返回任何数据之前同步写入；写失败则整个访问失败（AuditWriteError），
  既不静默放行，也不留下“有访问无审计”的不完整状态。
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone

from .audit import AuditLog, AuditLogError
from .decision import decide
from .errors import (
    AuditWriteError,
    ClearanceInsufficientError,
    GrantExpiredError,
    ResourceNotFoundError,
    UnauthorizedError,
)
from .models import AccessDecision, AuditEntry, DecisionResult, Grant, Record, RuleSnapshot
from .rules import RuleRegistry
from .store import GrantStore, RecordStore

logger = logging.getLogger("privacy_gateway.service")

_DENY_ERRORS = {
    "resource_not_found": ResourceNotFoundError,
    "unauthorized": UnauthorizedError,
    "grant_expired": GrantExpiredError,
    "clearance_insufficient": ClearanceInsufficientError,
}


class AccessService:
    def __init__(
        self,
        records: RecordStore,
        grants: GrantStore,
        rules: RuleRegistry,
        audit: AuditLog,
    ) -> None:
        self._records = records
        self._grants = grants
        self._rules = rules
        self._audit = audit

    def access(
        self,
        *,
        subject_id: str,
        record_id: str,
        now: datetime | None = None,
    ) -> AccessDecision:
        """执行一次敏感访问：判定 + 审计同成败。"""
        now = now or datetime.now(timezone.utc)
        # 1. 请求开始时抓取唯一规则快照，整次判定不混用其他版本
        snapshot = self._rules.current_snapshot()
        record = self._records.get(record_id)
        grant = self._grants.get(subject_id, record_id)
        decision_id = uuid.uuid4().hex

        logger.info(
            "access input: subject=%s record=%s now=%s rule_version=%s",
            subject_id, record_id, now.isoformat(), snapshot.rule.version,
        )

        # 2. 纯函数判定
        decision = decide(
            decision_id=decision_id,
            subject_id=subject_id,
            record=record,
            grant=grant,
            snapshot=snapshot,
            now=now,
        )
        logger.info(
            "decision basis: id=%s result=%s reason=%s basis=%s",
            decision.decision_id, decision.result.value,
            decision.deny_reason, decision.basis,
        )

        # 3. 审计先行：写失败则整个访问失败
        entry = self.build_audit_entry(decision, record, grant, snapshot)
        try:
            self._audit.write(entry)
        except AuditLogError as exc:
            logger.error("audit write failed: %s", exc)
            raise AuditWriteError(f"audit write failed: {exc}") from exc

        # 4. 拒绝时抛出可区分原因
        if decision.result is DecisionResult.DENY:
            raise _DENY_ERRORS[decision.deny_reason](
                f"{decision.deny_reason}: subject={subject_id} record={record_id}"
            )
        return decision

    def build_audit_entry(
        self,
        decision: AccessDecision,
        record: Record | None,
        grant: Grant | None,
        snapshot: RuleSnapshot,
    ) -> AuditEntry:
        """根据判定结果构造可复现的审计条目（含记录/策略/授权快照）。"""
        rule = snapshot.rule
        policies_snapshot: dict[str, dict[str, object]] = {}
        if record is not None:
            for fname, pol in rule.field_policies.get(record.record_type, {}).items():
                policies_snapshot[fname] = {
                    "min_level": pol.min_level.name,
                    "strategy": pol.strategy.value,
                    "full_level": pol.full_level.name if pol.full_level else None,
                }
        return AuditEntry(
            decision_id=decision.decision_id,
            subject_id=decision.subject_id,
            record_id=decision.record_id,
            result=decision.result,
            deny_reason=decision.deny_reason,
            rule_version=rule.version,
            rule_published_at=rule.published_at,
            decided_at=decision.decided_at,
            basis=dict(decision.basis),
            record_type=record.record_type if record else "",
            record_snapshot=dict(record.data) if record else {},
            record_required_level=int(record.required_level) if record else -1,
            policies_snapshot=policies_snapshot,
            grant_level=int(grant.level) if grant else None,
            grant_expires_at=grant.expires_at if grant else None,
            presented={
                name: {
                    "value": pf.value,
                    "strategy": pf.strategy.value,
                    "visible": pf.visible,
                }
                for name, pf in decision.presented.items()
            },
        )
