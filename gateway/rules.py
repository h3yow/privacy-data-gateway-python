"""脱敏与留存规则：版本化、运行中可原子切换。"""
from __future__ import annotations

import threading
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Mapping

from .models import MaskMode


def _freeze_modes(
    modes: Mapping[str, Mapping[int, MaskMode]],
) -> Mapping[str, Mapping[int, MaskMode]]:
    """构造期防御性拷贝并冻结为只读映射：调用方事后改入参不影响规则版本。"""
    return MappingProxyType({
        field_name: MappingProxyType(dict(tiers))
        for field_name, tiers in modes.items()
    })


@dataclass(frozen=True)
class RuleSet:
    """一个不可变的规则版本。

    field_modes: {字段名: {所需最低授权级别: 呈现方式}}，
    判定取主体级别可达的最高档位的呈现方式。
    retention_days: 留存天数（元数据，随版本固定）。
    """

    version: int
    field_modes: Mapping[str, Mapping[int, MaskMode]] = field(default_factory=dict)
    retention_days: int = 30

    def __post_init__(self) -> None:
        # frozen dataclass 中通过 object.__setattr__ 写入冻结副本
        object.__setattr__(self, "field_modes", _freeze_modes(self.field_modes))

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


class RuleVersionConflictError(Exception):
    """规则版本发布被拒：版本号重复或不大于已发布的最新版本。"""

    def __init__(self, attempted: int, latest: int) -> None:
        super().__init__(
            f"rule version {attempted} rejected: must be greater than latest {latest}"
        )
        self.attempted = attempted
        self.latest = latest


class RuleRegistry:
    """规则注册表：读侧无锁快照，写侧原子整体替换，绝不混用新旧规则。

    版本历史：
    - 已发布版本只增不改不删，全部保留，发布顺序即历史顺序；
    - 新版本号必须严格大于所有已发布版本，重复或回退当场拒绝
      （RuleVersionConflictError，调用方可明确识别为被拒发布）；
    - snapshot/history_version 均为 O(1) 字典查找，不随历史增长退化；
      history 为定长分页切片，在线访问不触碰历史结构。
    """

    def __init__(self, initial: RuleSet) -> None:
        self._lock = threading.Lock()
        self._current = initial
        self._history: dict[int, RuleSet] = {initial.version: initial}
        self._order: list[int] = [initial.version]

    def snapshot(self) -> RuleSet:
        """获取当前规则版本的不可变快照。

        RuleSet 为 frozen 对象，引用读取在 GIL 下原子；
        调用方拿到的快照在整次请求中恒定，不受后续 publish 影响。
        """
        return self._current

    def publish(self, rules: RuleSet) -> None:
        """原子发布新版本。

        - 版本号必须严格大于最新已发布版本，否则抛 RuleVersionConflictError，
          当前版本与历史均不发生任何变化（拒绝可被调用方明确识别）；
        - 单次引用替换完成切换，旧版本快照原样留在历史中，不被覆盖或删除；
        - 切换期间并发请求各自持有切换前或切换后的完整快照，不混用新旧规则。
        """
        if not isinstance(rules, RuleSet):
            raise TypeError("rules must be an immutable RuleSet")
        with self._lock:
            latest = self._order[-1]
            if rules.version <= latest:
                raise RuleVersionConflictError(rules.version, latest)
            self._history[rules.version] = rules
            self._order.append(rules.version)
            self._current = rules

    def history_version(self, version: int) -> RuleSet | None:
        """按版本号查历史配置，O(1)；不存在返回 None。"""
        return self._history.get(version)

    def history(self, limit: int | None = None, offset: int = 0) -> list[RuleSet]:
        """按发布先后返回版本列表（旧→新），定长分页，不随历史增长退化。"""
        with self._lock:
            ordered = [self._history[v] for v in self._order]
        if offset:
            ordered = ordered[offset:]
        if limit is not None:
            ordered = ordered[:limit]
        return ordered

    def latest_version(self) -> int:
        """当前最新已发布版本号。"""
        return self._current.version
