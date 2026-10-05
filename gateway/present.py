"""字段呈现：实时访问与档案复核重算共用同一套确定性算法。"""
from __future__ import annotations

from .models import MaskMode
from .rules import RuleSet


def mask_value(value: str) -> str:
    """确定性脱敏：同一输入恒得同一输出，与请求顺序、缓存无关。"""
    if len(value) <= 2:
        return "*" * len(value)
    return value[0] + "*" * (len(value) - 2) + value[-1]


def present_fields(rules: RuleSet, level: int, fields: dict[str, str]) -> dict[str, str]:
    """按规则版本与主体级别计算逐字段呈现结果。

    字段按名排序遍历保证确定性；HIDDEN 字段不出现在结果中。
    """
    presented: dict[str, str] = {}
    for name in sorted(fields):
        mode = rules.mode_for(name, level)
        if mode is MaskMode.PLAIN:
            presented[name] = fields[name]
        elif mode is MaskMode.MASKED:
            presented[name] = mask_value(fields[name])
    return presented
