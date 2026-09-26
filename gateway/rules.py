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
        """返回该字段对给定授权级别的呈现方式。

        取主体级别可达的最高档位；无匹配档位或字段未配置时 HIDDEN。
        结果仅取决于 (字段, 级别, 规则版本)，与请求顺序无关。
        """
        tiers = self.field_modes.get(field_name)
        if not tiers:
            return MaskMode.HIDDEN
        reachable = [lvl for lvl in tiers if subject_level >= lvl]
        if not reachable:
            return MaskMode.HIDDEN
        return tiers[max(reachable)]


class RuleRegistry:
    """规则注册表：读侧无锁快照，写侧原子整体替换，绝不混用新旧规则。"""

    def __init__(self, initial: RuleSet) -> None:
        self._lock = threading.Lock()
        self._current = initial

    def snapshot(self) -> RuleSet:
        """获取当前规则版本的不可变快照。

        RuleSet 为 frozen 对象，引用读取在 GIL 下原子；
        调用方拿到的快照在整次请求中恒定，不受后续 publish 影响。
        """
        return self._current

    def publish(self, rules: RuleSet) -> None:
        """原子发布新版本：单次引用替换，旧版本不被修改。

        切换期间并发请求各自持有切换前或切换后的完整快照，
        不会混用新旧两套规则。
        """
        if not isinstance(rules, RuleSet):
            raise TypeError("rules must be an immutable RuleSet")
        with self._lock:
            self._current = rules
