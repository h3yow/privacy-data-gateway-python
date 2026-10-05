"""网关服务：编排授权判定、脱敏呈现与审计落痕。"""
from __future__ import annotations

import itertools
import threading
from datetime import datetime

from .audit import AuditSink
from .authz import SubjectStore
from .decision import Evaluation, evaluate, mask_value
from .models import AuditEvent, Decision, DenyReason
from .rules import RuleRegistry

__all__ = ["RecordStore", "GatewayService", "mask_value"]


class RecordStore:
    """记录仓库（内存实现）。"""

    def __init__(self, records: dict | None = None) -> None:
        self._records: dict = dict(records or {})

    def get(self, record_id: str):
        return self._records.get(record_id)

    def upsert(self, record) -> None:
        """写入/替换记录（供演示与测试构造数据漂移场景）。"""
        self._records[record.record_id] = record

    def delete(self, record_id: str) -> None:
        """删除记录（供测试构造记录缺失场景）。"""
        self._records.pop(record_id, None)


class GatewayService:
    """访问入口：一次请求只使用一个规则版本快照，审计与访问成败一致。"""

    def __init__(
        self,
        subjects: SubjectStore,
        records: RecordStore,
        rules: RuleRegistry,
        audit: AuditSink,
    ) -> None:
        self._subjects = subjects
        self._records = records
        self._rules = rules
        self._audit = audit
        self._seq_lock = threading.Lock()
        self._seq = itertools.count(1)

    @property
    def rules(self) -> RuleRegistry:
        return self._rules

    @property
    def audit(self) -> AuditSink:
        return self._audit

    def next_sequence(self) -> int:
        """分配全局唯一、严格递增的审计序号（实时访问与合规入口共用）。"""
        with self._seq_lock:
            return next(self._seq)

    def write_audit_event(
        self,
        *,
        timestamp: datetime,
        subject_id: str,
        record_id: str,
        rule_version: int,
        allowed: bool,
        reason: DenyReason | None,
        presented: dict[str, str],
        action: str = "access",
        archive_id: str | None = None,
        subject_level: int | None = None,
    ) -> bool:
        """先落审计。返回是否写入成功；失败时调用方必须整次失败。

        所有入口（实时访问、历史查询、封存、复核、规则发布）都走这里，
        保证"审计失败即失败、不放数据、不留半条记录"的语义全局一致。
        """
        with self._seq_lock:
            seq = next(self._seq)
        event = AuditEvent(
            sequence=seq,
            timestamp=timestamp,
            subject_id=subject_id,
            record_id=record_id,
            rule_version=rule_version,
            allowed=allowed,
            reason=reason.value if reason else None,
            presented=dict(presented),
            action=action,
            archive_id=archive_id,
            subject_level=subject_level,
        )
        try:
            self._audit.write(event)
        except Exception:
            return False
        return True

    def access(self, subject_id: str, record_id: str, now: datetime) -> Decision:
        """判定并呈现一次访问。

        语义保证：
        - 进入时取一次规则快照，整次请求只使用该版本，绝不混用新旧规则；
        - 允许与拒绝都会先写审计；审计写失败时访问一并失败
          （返回 AUDIT_FAILURE，不放行任何数据，不留半成品结论）；
        - 同一 (主体授权, 记录, 规则版本) 的呈现结果确定。
        """
        rules = self._rules.snapshot()  # 版本快照：本请求恒定
        result = evaluate(rules, self._subjects, self._records,
                          subject_id, record_id, now)
        return self._conclude(subject_id, record_id, result, now)

    def _conclude(
        self,
        subject_id: str,
        record_id: str,
        result: Evaluation,
        now: datetime,
    ) -> Decision:
        """先落审计，再给结论；审计失败则结论改为 AUDIT_FAILURE 且不放行数据。"""
        ok = self.write_audit_event(
            timestamp=now,
            subject_id=subject_id,
            record_id=record_id,
            rule_version=result.rule_version,
            allowed=result.allowed,
            reason=result.reason,
            presented=result.presented,
            action="access",
            subject_level=result.subject_level,
        )
        if not ok:
            return Decision(False, DenyReason.AUDIT_FAILURE, subject_id,
                            record_id, result.rule_version, {})
        return Decision(result.allowed, result.reason, subject_id, record_id,
                        result.rule_version, dict(result.presented))
