"""领域模型：密级、授权、记录、规则版本、脱敏结果与审计痕迹。

设计要点：
- 规则（RuleVersion）一旦发布即不可变；运行中变更是通过“发布新版本”实现的。
- 每次请求开始时抓取当前规则快照（snapshot），整次判定都用同一个快照，
  因此规则切换期间的并发请求不会混用新旧两套规则。
- 审计条目（AuditEntry）保存判定时的完整依据（规则版本、授权状态、
  记录快照），使历史结论可离线复现，不受后续数据/规则变化影响。
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime, timezone


class ClearanceLevel(enum.IntEnum):
    """授权密级，数值越大可见范围越高。"""

    PUBLIC = 0
    INTERNAL = 1
    CONFIDENTIAL = 2
    RESTRICTED = 3


class MaskingStrategy(enum.Enum):
    """字段脱敏策略。"""

    VISIBLE = "visible"          # 明文呈现
    MASK = "mask"                # 固定掩码（如 ****）
    PARTIAL = "partial"          # 部分保留（如 138****1234）
    HASH = "hash"                # 哈希呈现（确定性哈希）
    REDACT = "redact"          # 整个字段移除


class DecisionResult(enum.Enum):
    """审计结果标记。"""

    ALLOW = "allow"
    DENY = "deny"


@dataclass(frozen=True)
class Grant:
    """主体对某条记录的授权。"""

    subject_id: str
    record_id: str
    level: ClearanceLevel
    expires_at: datetime | None = None  # None 表示不过期

    def is_expired(self, now: datetime) -> bool:
        if self.expires_at is None:
            return False
        expires = self.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        return now >= expires


@dataclass(frozen=True)
class Record:
    """一条受保护的数据记录。

    required_level 为记录级最低密级门槛；字段级策略在规则版本中定义。
    record_type 用于在规则版本中索引该记录的字段策略。
    """

    record_id: str
    record_type: str
    required_level: ClearanceLevel
    data: dict[str, str]


@dataclass(frozen=True)
class FieldPolicy:
    """某个字段在某条规则版本下的呈现策略。

    呈现规则（subject_level 为主体授权密级）：
    - subject_level >= full_level（若设置） -> 明文 VISIBLE
    - subject_level >= min_level            -> 按 strategy 脱敏呈现
    - 否则                                   -> 字段隐藏（REDACT）
    """

    field_name: str
    min_level: ClearanceLevel
    strategy: MaskingStrategy
    full_level: ClearanceLevel | None = None


@dataclass(frozen=True)
class RetentionPolicy:
    """留存规则（随规则版本演进；快照保存在审计条目中以便复现）。"""

    retain_days: int = 3650
    export_fields: tuple[str, ...] = ()


@dataclass(frozen=True)
class RuleVersion:
    """一个不可变的规则版本。

    version 单调递增；published_at 标记生效时刻。
    field_policies 为 record_type -> 字段名 -> 字段策略 的映射。
    """

    version: int
    published_at: datetime
    field_policies: dict[str, dict[str, FieldPolicy]] = field(default_factory=dict)
    retention: RetentionPolicy = field(default_factory=RetentionPolicy)

    def policy_for(self, record_type: str, field_name: str) -> FieldPolicy | None:
        return self.field_policies.get(record_type, {}).get(field_name)


@dataclass(frozen=True)
class RuleSnapshot:
    """请求级规则快照：整次判定（含审计写入）只使用这一个不可变对象。"""

    rule: RuleVersion


@dataclass(frozen=True)
class PresentedField:
    """单个字段的呈现结果及其判定依据。"""

    name: str
    value: str | None
    strategy: MaskingStrategy
    visible: bool


@dataclass(frozen=True)
class AccessDecision:
    """一次访问的完整判定结果。"""

    decision_id: str
    subject_id: str
    record_id: str
    result: DecisionResult
    rule_version: int
    decided_at: datetime
    presented: dict[str, PresentedField] = field(default_factory=dict)
    deny_reason: str | None = None
    basis: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class AuditEntry:
    """可追溯的审计条目：包含输入、判定依据、结果标记与复现所需快照。"""

    decision_id: str
    subject_id: str
    record_id: str
    result: DecisionResult
    deny_reason: str | None
    rule_version: int
    rule_published_at: datetime
    decided_at: datetime
    # 判定依据（可读、可解释）
    basis: dict[str, str]
    # 复现用快照：记录数据 + 字段策略 + 当时授权状态
    record_type: str
    record_snapshot: dict[str, str]
    record_required_level: int
    policies_snapshot: dict[str, dict[str, object]]
    grant_level: int | None
    grant_expires_at: datetime | None
    presented: dict[str, object]
