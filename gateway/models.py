"""核心数据模型：主体、记录、授权判定与审计事件。"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime


class DenyReason(enum.Enum):
    """拒绝原因，必须可区分。"""

    SUBJECT_UNKNOWN = "SUBJECT_UNKNOWN"        # 主体不存在（未授权）
    GRANT_EXPIRED = "GRANT_EXPIRED"            # 授权已过期
    RESOURCE_NOT_FOUND = "RESOURCE_NOT_FOUND"  # 资源不存在
    INSUFFICIENT_LEVEL = "INSUFFICIENT_LEVEL"  # 授权级别不足
    AUDIT_FAILURE = "AUDIT_FAILURE"            # 审计写入失败，访问一并失败


class MaskMode(enum.Enum):
    """字段呈现方式。"""

    HIDDEN = "HIDDEN"      # 完全不可见
    MASKED = "MASKED"      # 脱敏后可见
    PLAIN = "PLAIN"        # 明文可见


@dataclass(frozen=True)
class Subject:
    """访问主体及其授权。"""

    subject_id: str
    level: int                       # 授权级别，数值越大可见性越高
    expires_at: datetime | None      # None 表示永不过期


@dataclass(frozen=True)
class SensitiveRecord:
    """含敏感字段的记录。fields 的值即敏感原文。"""

    record_id: str
    fields: dict[str, str]


@dataclass(frozen=True)
class Decision:
    """一次访问判定的完整结论。"""

    allowed: bool
    reason: DenyReason | None        # 允许时为 None
    subject_id: str
    record_id: str
    rule_version: int                # 判定所依据的规则版本
    presented: dict[str, str] = field(default_factory=dict)  # 允许时的呈现结果


@dataclass(frozen=True)
class AuditEvent:
    """审计事件：判定依据 + 结果标记，可追溯、可复现。"""

    sequence: int
    timestamp: datetime
    subject_id: str
    record_id: str
    rule_version: int
    allowed: bool
    reason: str | None
    presented: dict[str, str]
