"""脱敏与留存规则：版本化、运行中可原子切换、全部历史版本永久留存。"""
from __future__ import annotations

import threading
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from types import MappingProxyType

from .errors import VersionConflictError, VersionNotFoundError
from .models import MaskMode


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class RuleSet:
    """一个不可变的规则版本。

    field_modes: {字段名: {所需最低授权级别: 呈现方式}}，
    判定取主体级别可达的最高档位的呈现方式。
    retention_days: 留存天数（元数据，随版本固定）。

    业务上 RuleSet 一经发布即不可变；发布路径会用 MappingProxyType
    再冻结嵌套字典，防止发布后通过原引用改写历史版本。
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


@dataclass(frozen=True)
class VersionInfo:
    """历史版本的目录项：版本号 + 发布时刻。"""

    version: int
    published_at: datetime


def freeze_rules(rules: RuleSet) -> RuleSet:
    """深拷贝并冻结规则：发布后外部无法再通过原引用改写其内容。"""
    copied = {
        name: dict(tiers)
        for name, tiers in rules.field_modes.items()
    }
    frozen_modes = MappingProxyType({
        name: MappingProxyType(tiers) for name, tiers in copied.items()
    })
    return replace(rules, field_modes=frozen_modes)


class RuleRegistry:
    """规则注册表：只追加的版本历史 + 当前版本的无锁快照。

    不变量：
    - 已发布版本永久保留，绝不被覆盖、改写或删除；
    - 新版本号必须严格大于所有已发版本，否则当场抛 VersionConflictError；
    - snapshot() 为 O(1) 引用读取，历史增长不拖垮在线访问；
      get_version() 为 O(1) 哈希查找，list_versions() 为 O(版本数)。
    """

    def __init__(self, initial: RuleSet, now: datetime | None = None) -> None:
        self._lock = threading.Lock()
        current = freeze_rules(initial)
        self._current = current
        self._by_version: dict[int, RuleSet] = {current.version: current}
        self._published_at: dict[int, datetime] = {
            current.version: now or _utcnow(),
        }
        self._order: list[int] = [current.version]

    def snapshot(self) -> RuleSet:
        """获取当前规则版本的不可变快照。

        RuleSet 为 frozen 对象，引用读取在 GIL 下原子；
        调用方拿到的快照在整次请求中恒定，不受后续 publish 影响，
        且不触碰版本历史，性能与历史长度无关。
        """
        return self._current

    def publish(self, rules: RuleSet, now: datetime | None = None) -> RuleSet:
        """原子发布新版本。

        - 版本号必须严格大于最新已发版本；重复使用老版本号或回退发布，
          当场抛 VersionConflictError，注册表状态保持不变；
        - 发布内容先深拷贝冻结再入库，旧版本永不被修改；
        - 单次引用替换切换当前版本，并发请求不会混用新旧两套规则。
        """
        if not isinstance(rules, RuleSet):
            raise TypeError("rules must be an immutable RuleSet")
        frozen = freeze_rules(rules)
        with self._lock:
            latest = self._order[-1]
            if frozen.version in self._by_version or frozen.version <= latest:
                raise VersionConflictError(
                    f"rule version {frozen.version} is not newer than "
                    f"latest published version {latest}"
                )
            self._by_version[frozen.version] = frozen
            self._published_at[frozen.version] = now or _utcnow()
            self._order.append(frozen.version)
            self._current = frozen
        return frozen

    def get_version(self, version: int) -> RuleSet:
        """按号取历史版本（O(1)）；不存在抛 VersionNotFoundError。"""
        found = self._by_version.get(version)
        if found is None:
            raise VersionNotFoundError(f"rule version {version} not found")
        return found

    def list_versions(self) -> list[VersionInfo]:
        """按发布先后返回全部历史版本目录（O(版本数)）。"""
        with self._lock:
            return [
                VersionInfo(v, self._published_at[v])
                for v in self._order
            ]

    def has_version(self, version: int) -> bool:
        return version in self._by_version
