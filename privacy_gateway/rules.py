"""规则版本注册表：不可变版本 + 原子切换 + 历史版本留存。

并发语义：
- current_snapshot() 原子抓取当前版本引用；调用方整次请求只持有该快照。
- publish() 在锁内一次性替换“当前版本”，不存在半新半旧的中间态。
- 历史版本永久保留，供历史审计结论的复现使用。
"""

from __future__ import annotations

import threading

from .models import RuleSnapshot, RuleVersion


class RuleRegistry:
    """持有当前生效规则版本，并保留全部历史版本（供复现）。"""

    def __init__(self, initial: RuleVersion) -> None:
        self._lock = threading.RLock()
        self._versions: dict[int, RuleVersion] = {initial.version: initial}
        self._current: RuleVersion = initial

    def current_snapshot(self) -> RuleSnapshot:
        """原子抓取当前规则快照。"""
        with self._lock:
            return RuleSnapshot(rule=self._current)

    def publish(self, rule: RuleVersion) -> RuleSnapshot:
        """发布新版本（版本号必须严格递增），原子替换当前版本。"""
        with self._lock:
            if rule.version in self._versions:
                raise ValueError(f"rule version {rule.version} already exists")
            if rule.version <= self._current.version:
                raise ValueError(
                    f"rule version {rule.version} must be greater than "
                    f"current {self._current.version}"
                )
            self._versions[rule.version] = rule
            self._current = rule
            return RuleSnapshot(rule=rule)

    def snapshot_of(self, version: int) -> RuleSnapshot:
        """按版本号取历史规则快照（复现历史结论用）。"""
        with self._lock:
            try:
                return RuleSnapshot(rule=self._versions[version])
            except KeyError:
                raise KeyError(f"unknown rule version {version}") from None
