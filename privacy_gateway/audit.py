"""审计日志：同步写入、失败显式抛出，保证访问与审计成败语义一致。"""

from __future__ import annotations

import threading

from .models import AuditEntry


class AuditLogError(Exception):
    """审计存储层面的错误。"""


class AuditLog:
    """审计条目存储（内存实现）。

    write 同步且原子：写入失败时抛出 AuditLogError，
    上层据此拒绝整个访问（既不放行也不留不完整记录）。
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._entries: list[AuditEntry] = []

    def write(self, entry: AuditEntry) -> None:
        if entry is None:
            raise AuditLogError("audit entry must not be None")
        if not entry.decision_id:
            raise AuditLogError("audit entry missing decision_id")
        with self._lock:
            if any(e.decision_id == entry.decision_id for e in self._entries):
                raise AuditLogError(f"duplicate decision_id {entry.decision_id}")
            self._entries.append(entry)

    def list_all(self) -> list[AuditEntry]:
        with self._lock:
            return list(self._entries)

    def get(self, decision_id: str) -> AuditEntry | None:
        with self._lock:
            for e in self._entries:
                if e.decision_id == decision_id:
                    return e
            return None
