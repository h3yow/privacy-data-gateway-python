"""脱敏与留存规则：版本化、运行中可原子切换。"""
from __future__ import annotations

import threading
from dataclasses import dataclass, field

from .models import MaskMode


@dataclass(frozen=True)
class RuleSet:
    """一个不可变的规则版本。

    field_modes: {字段名: {所需最低授权级别: 呈现方式}}，
    判定取主体级别可达的最高档位的呈现方式。
    retention_days: 留存天数（元数据，随版本固定）。
    """

    version: int
    field_modes: dict[str, dict[int, MaskMode]] = field(default_factory=dict)
    retention_days: int = 30

    def mode_for(self, field_name: str, subject_level: int) -> MaskMode:
        """返回该字段对给定授权级别的呈现方式（骨架：恒 HIDDEN）。"""
        raise NotImplementedError


class RuleRegistry:
    """规则注册表：读侧无锁快照，写侧原子整体替换，绝不混用新旧规则。"""

    def __init__(self, initial: RuleSet) -> None:
        self._lock = threading.Lock()
        self._current = initial

    def snapshot(self) -> RuleSet:
        """获取当前规则版本的不可变快照（骨架）。"""
        raise NotImplementedError

    def publish(self, rules: RuleSet) -> None:
        """原子发布新版本（骨架）。"""
        raise NotImplementedError
