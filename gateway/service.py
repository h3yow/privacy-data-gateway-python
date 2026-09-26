"""网关服务：编排授权判定、脱敏呈现与审计落痕。"""
from __future__ import annotations

from datetime import datetime

from .audit import AuditSink
from .authz import SubjectStore
from .models import Decision, SensitiveRecord
from .rules import RuleRegistry


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

    def access(self, subject_id: str, record_id: str, now: datetime) -> Decision:
        """判定并呈现一次访问；审计失败时访问一并失败。骨架：暂不实现。"""
        raise NotImplementedError
