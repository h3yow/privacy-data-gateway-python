"""纯判定逻辑：给定规则版本快照 + 当前主体/记录，产出一次访问判定。

与注册表、审计汇解耦，实时访问与事后复核共用同一份判定语义，
保证"重放"与"当时"走的是同一套规则解释，判定顺序也完全一致：
先看记录是否存在，再解析主体授权（未知/过期/级别），最后逐字段呈现。
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING

from .authz import SubjectStore
from .models import DenyReason, MaskMode
from .rules import RuleSet

if TYPE_CHECKING:  # 避免与 service.py 的运行时循环导入
    from .service import RecordStore


def mask_value(value: str) -> str:
    """确定性脱敏：同一输入恒得同一输出，与请求顺序、缓存无关。"""
    if len(value) <= 2:
        return "*" * len(value)
    return value[0] + "*" * (len(value) - 2) + value[-1]


@dataclass(frozen=True)
class Evaluation:
    """一次纯判定的结论（尚未落审计）。"""

    allowed: bool
    reason: DenyReason | None
    rule_version: int
    presented: dict[str, str]
    subject_level: int | None = None  # 判定当时的主体级别（拒绝时可能为 None）


def evaluate(
    rules: RuleSet,
    subjects: SubjectStore,
    records: RecordStore,
    subject_id: str,
    record_id: str,
    now: datetime,
) -> Evaluation:
    """按给定规则版本快照重放一次判定。

    now 决定授权是否过期：实时访问用当前时刻；复核重放用被封存事件的
    发生时刻，从而复现"当时"的过期状态。
    """
    record = records.get(record_id)
    if record is None:
        return Evaluation(False, DenyReason.RESOURCE_NOT_FOUND,
                          rules.version, {})

    level, deny = subjects.effective_level(subject_id, now)
    if deny is not None:
        return Evaluation(False, DenyReason(deny), rules.version, {})
    assert level is not None
    if level <= 0:
        return Evaluation(False, DenyReason.INSUFFICIENT_LEVEL,
                          rules.version, {}, subject_level=level)

    presented: dict[str, str] = {}
    for name in sorted(record.fields):  # 排序遍历保证确定性
        mode = rules.mode_for(name, level)
        if mode is MaskMode.PLAIN:
            presented[name] = record.fields[name]
        elif mode is MaskMode.MASKED:
            presented[name] = mask_value(record.fields[name])
        # HIDDEN：不出现在呈现结果中

    return Evaluation(True, None, rules.version, presented, subject_level=level)
