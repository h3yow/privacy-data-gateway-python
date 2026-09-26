"""数据存储与授权存储（内存实现，线程安全）。"""

from __future__ import annotations

import threading

from .models import Grant, Record


class RecordStore:
    """记录存储。"""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._records: dict[str, Record] = {}

    def put(self, record: Record) -> None:
        with self._lock:
            self._records[record.record_id] = record

    def get(self, record_id: str) -> Record | None:
        with self._lock:
            return self._records.get(record_id)


class GrantStore:
    """授权存储：(主体, 记录) -> Grant。"""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._grants: dict[tuple[str, str], Grant] = {}

    def put(self, grant: Grant) -> None:
        with self._lock:
            self._grants[(grant.subject_id, grant.record_id)] = grant

    def get(self, subject_id: str, record_id: str) -> Grant | None:
        with self._lock:
            return self._grants.get((subject_id, record_id))
