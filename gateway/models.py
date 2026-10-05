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
    VERSION_CONFLICT = "VERSION_CONFLICT"      # 发布版本号重复或回退
    VERSION_NOT_FOUND = "VERSION_NOT_FOUND"    # 历史规则版本不存在
    ARCHIVE_NOT_FOUND = "ARCHIVE_NOT_FOUND"    # 封存档案不存在
    ARCHIVE_EMPTY = "ARCHIVE_EMPTY"            # 封存时间窗内无任何事件


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
    action: str = "access"  # access|publish|rule_history|seal|review
    archive_id: str | None = None  # 封存/复核类事件关联的档案号
    subject_level: int | None = None  # 判定当时的主体授权级别（复核依据）


@dataclass(frozen=True)
class OpResult:
    """非实时访问入口（历史查询/封存/复核）的统一成败结论。

    拒绝语义与实时访问一致：allowed=False 时 reason 给出可区分的拒绝原因，
    data 为空；AUDIT_FAILURE 时同样不放任何数据。
    """

    allowed: bool
    reason: DenyReason | None
    action: str
    rule_version: int
    data: dict | None = None


@dataclass(frozen=True)
class ArchivedEntry:
    """档案中的一条封存条目：审计事件的不可变快照 + 完整性指纹。

    fingerprint 为封存时刻对条目判定依据（除 fingerprint 外全部字段）
    计算的规范化哈希；复核先验指纹，再对底层当前数据重放判定。
    """

    sequence: int
    timestamp: datetime
    subject_id: str
    record_id: str
    rule_version: int
    allowed: bool
    reason: str | None
    presented: dict[str, str]
    subject_level: int | None = None  # 封存当时的主体级别（复核依据）
    fingerprint: str = ""


@dataclass(frozen=True)
class Archive:
    """一份固定的封存档案：时间窗 + 不可变条目列表 + 逐条指纹。

    档案一经创建不可修改：后续规则发布、底层数据变更、审计汇新增事件
    都不影响档案内容；档案自身也带整体指纹，便于外部存证。
    """

    archive_id: str
    created_at: datetime
    start: datetime | None   # 封存时间窗起点（含），None 表示从头
    end: datetime | None     # 封存时间窗终点（不含），None 表示到封存时刻
    rule_versions: tuple[int, ...]  # 档案涉及的规则版本（去重、升序）
    entries: tuple[ArchivedEntry, ...]
    fingerprint: str


class EntryVerdict(enum.Enum):
    """复核条目的比对结论。"""

    MATCH = "MATCH"                      # 与封存时完全一致
    TAMPERED = "TAMPERED"                # 档案条目自身指纹不匹配（档案被改）
    SUBJECT_CHANGED = "SUBJECT_CHANGED"  # 主体授权状态/级别已变（含过期）
    RESOURCE_MISSING = "RESOURCE_MISSING"  # 底层记录已不存在
    PRESENTATION_DIFF = "PRESENTATION_DIFF"  # 判定结果（允许/拒绝/呈现）有差异
    VERSION_MISSING = "VERSION_MISSING"  # 复核所需历史规则版本已不在注册表


@dataclass(frozen=True)
class EntryReview:
    """单条复核结果：封存内容 vs 当前重放结论。"""

    sequence: int
    verdict: EntryVerdict
    sealed: dict          # 封存时的判定依据快照
    current: dict | None  # 当前重放结论；档案自身损坏或版本缺失时为 None
    diff: dict            # 字段级差异：{字段: {sealed: ..., current: ...}}


@dataclass(frozen=True)
class ReviewReport:
    """整份档案的复核报告。

    只读操作：不改动已封存档案，不影响实时访问。
    """

    archive_id: str
    reviewed_at: datetime
    total: int
    matched: int
    mismatched: int
    entries: tuple[EntryReview, ...]

    @property
    def consistent(self) -> bool:
        """全部对得上才算档案与当前状态一致。"""
        return self.mismatched == 0
