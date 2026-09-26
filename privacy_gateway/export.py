"""导出服务：导出结果不可变且可复现（按判定时的规则版本固化）。

导出物来源于审计条目中的呈现快照，因此：
- 规则后续演进不影响已生成的导出；
- 同一 decision 重复导出返回同一份固化结果。
"""

from __future__ import annotations

import threading
from datetime import datetime, timezone

from .audit import AuditLog


class ExportService:
    def __init__(self, audit: AuditLog) -> None:
        self._lock = threading.RLock()
        self._audit = audit
        self._exports: dict[str, dict] = {}

    def export(self, decision_id: str, now: datetime | None = None) -> dict:
        """基于已存在的审计条目生成导出物；同一 decision 重复导出结果一致。"""
        with self._lock:
            if decision_id in self._exports:
                return self._exports[decision_id]
            entry = self._audit.get(decision_id)
            if entry is None:
                raise KeyError(f"unknown decision_id {decision_id}")
            now = now or datetime.now(timezone.utc)
            artifact = {
                "export_id": f"exp-{decision_id}",
                "decision_id": decision_id,
                "subject_id": entry.subject_id,
                "record_id": entry.record_id,
                "result": entry.result.value,
                "deny_reason": entry.deny_reason,
                "rule_version": entry.rule_version,
                "decided_at": entry.decided_at.isoformat(),
                "exported_at": now.isoformat(),
                "fields": dict(entry.presented),
            }
            self._exports[decision_id] = artifact
            return artifact
