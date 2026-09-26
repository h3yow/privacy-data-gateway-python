"""网关服务：编排授权判定、脱敏呈现与审计落痕。"""
from __future__ import annotations

import itertools
import threading
from datetime import datetime

from .audit import AuditSink
from .authz import SubjectStore
from .models import AuditEvent, Decision, DenyReason, MaskMode, SensitiveRecord
from .rules import RuleRegistry


def mask_value(value: str) -> str:
    """确定性脱敏：同一输入恒得同一输出，与请求顺序、缓存无关。"""
    if len(value) <= 2:
        return "*" * len(value)
    return value[0] + "*" * (len(value) - 2) + value[-1]


class RecordStore:
    """记录仓库（内存实现）。"""

    def __init__(self, records: dict[str, SensitiveRecord] | None = None) -> None:
        self._records: dict[str, SensitiveRecord] = dict(records or {})

    def get(self, record_id: str) -> SensitiveRecord | None:
        return self._records.get(record_id)


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

    def access(self, subject_id: str, record_id: str, now: datetime) -> Decision:
        """判定并呈现一次访问。

        语义保证：
        - 进入时取一次规则快照，整次请求只使用该版本，绝不混用新旧规则；
        - 允许与拒绝都会先写审计；审计写失败时访问一并失败
          （返回 AUDIT_FAILURE，不放行任何数据，不留半成品结论）；
        - 同一 (主体授权, 记录, 规则版本) 的呈现结果确定。
        """
        rules = self._rules.snapshot()  # 版本快照：本请求恒定

        record = self._records.get(record_id)
        if record is None:
            return self._conclude(subject_id, record_id, rules.version, now,
                                  False, DenyReason.RESOURCE_NOT_FOUND, {})

        level, deny = self._subjects.effective_level(subject_id, now)
        if deny is not None:
            return self._conclude(subject_id, record_id, rules.version, now,
                                  False, DenyReason(deny), {})
        assert level is not None
        if level <= 0:
            return self._conclude(subject_id, record_id, rules.version, now,
                                  False, DenyReason.INSUFFICIENT_LEVEL, {})

        presented: dict[str, str] = {}
        for name in sorted(record.fields):  # 排序遍历保证确定性
            mode = rules.mode_for(name, level)
            if mode is MaskMode.PLAIN:
                presented[name] = record.fields[name]
            elif mode is MaskMode.MASKED:
                presented[name] = mask_value(record.fields[name])
            # HIDDEN：不出现在呈现结果中

        return self._conclude(subject_id, record_id, rules.version, now,
                              True, None, presented)

    def _conclude(
        self,
        subject_id: str,
        record_id: str,
        rule_version: int,
        now: datetime,
        allowed: bool,
        reason: DenyReason | None,
        presented: dict[str, str],
    ) -> Decision:
        """先落审计，再给结论；审计失败则结论改为 AUDIT_FAILURE 且不放行数据。"""
        with self._seq_lock:
            seq = next(self._seq)
        event = AuditEvent(
            sequence=seq,
            timestamp=now,
            subject_id=subject_id,
            record_id=record_id,
            rule_version=rule_version,
            allowed=allowed,
            reason=reason.value if reason else None,
            presented=dict(presented),
        )
        try:
            self._audit.write(event)
        except Exception:
            return Decision(False, DenyReason.AUDIT_FAILURE, subject_id,
                            record_id, rule_version, {})
        return Decision(allowed, reason, subject_id, record_id, rule_version,
                        dict(presented))
