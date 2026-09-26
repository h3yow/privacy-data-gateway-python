"""审计汇：所有敏感访问与拒绝都必须落痕，写失败即失败。"""
from __future__ import annotations

import threading
from typing import Protocol

from .models import AuditEvent


class AuditError(Exception):
    """审计写入失败。"""


class AuditSink(Protocol):
    def write(self, event: AuditEvent) -> None:
        """写入一条审计事件；失败必须抛 AuditError。"""
        ...


class InMemoryAuditSink:
    """线程安全的内存审计汇，事件按序追加、不可变。"""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._events: list[AuditEvent] = []

    def write(self, event: AuditEvent) -> None:
        """追加一条事件；sequence 由调用方给定，落盘后不可变。"""
        if event is None:
            raise AuditError("event must not be None")
        with self._lock:
            self._events.append(event)

    def events(self) -> list[AuditEvent]:
        """返回已有事件的快照副本，调用方修改不影响内部状态。"""
        with self._lock:
            return list(self._events)
