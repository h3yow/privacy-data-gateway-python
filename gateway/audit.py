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
        """骨架：暂不实现。"""
        raise NotImplementedError

    def events(self) -> list[AuditEvent]:
        """返回已有事件的快照副本。"""
        raise NotImplementedError
