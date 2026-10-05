"""历史规则版本查询：只读序列化，供合规编排层调用。

查询路径只走注册表的 O(1) 哈希查找 / O(版本数) 目录遍历，
不扫描、不加载全部历史，历史增长不拖垮在线访问。
"""
from __future__ import annotations

from .rules import RuleRegistry, RuleSet


def rules_to_dict(rules: RuleSet) -> dict:
    """把一个不可变规则版本序列化成可返回的普通字典（深拷贝解代理）。"""
    return {
        "version": rules.version,
        "retention_days": rules.retention_days,
        "field_modes": {
            field: {int(lvl): mode.value for lvl, mode in tiers.items()}
            for field, tiers in rules.field_modes.items()
        },
    }


class HistoryService:
    """规则历史只读查询。"""

    def __init__(self, rules: RuleRegistry) -> None:
        self._rules = rules

    def list_versions(self) -> list[dict]:
        """按发布先后返回全部历史版本目录。"""
        return [
            {"version": info.version, "published_at": info.published_at}
            for info in self._rules.list_versions()
        ]

    def get_version(self, version: int) -> dict:
        """取指定历史版本的完整配置；不存在抛 VersionNotFoundError。"""
        return rules_to_dict(self._rules.get_version(version))
