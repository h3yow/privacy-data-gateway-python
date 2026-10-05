"""封存档案与事后复核：整批封存、内容固定、复核不改档。"""
from __future__ import annotations

import threading
from dataclasses import dataclass, field
from datetime import datetime
from types import MappingProxyType
from typing import Mapping, Protocol

from .present import present_fields
from .rules import RuleRegistry, RuleSet


class RecordLookup(Protocol):
    def get(self, record_id: str) -> object | None: ...


@dataclass(frozen=True)
class SealedEntry:
    """档案中的单条封存记录：判定依据随档固定，复核时不依赖底层数据。"""

    sequence: int
    timestamp: datetime
    subject_id: str
    subject_level: int | None
    record_id: str
    rule_version: int
    allowed: bool
    reason: str | None
    presented: dict[str, str]
    record_snapshot: dict[str, str]   # 记录原文快照：允许判定复核的依据
    rules_snapshot: RuleSet | None    # 规则快照：按版本封存，缺档时为 None


@dataclass(frozen=True)
class Archive:
    """一份不可变封存档案：封存在某时间区间内发生过的访问与拒绝。"""

    archive_id: str
    created_at: datetime
    range_start: datetime | None
    range_end: datetime | None
    entries: tuple[SealedEntry, ...]
    rules_snapshots: Mapping[int, RuleSet]  # 档案涉及到的每个规则版本各一份快照


@dataclass(frozen=True)
class EntryDifference:
    """单条复核差异。"""

    sequence: int
    kind: str                 # PRESENTATION / OUTCOME / RULE_DRIFT
    field: str | None
    sealed: object
    current: object


@dataclass(frozen=True)
class EntryReview:
    """单条复核结论。"""

    sequence: int
    matches: bool
    differences: tuple[EntryDifference, ...]


@dataclass(frozen=True)
class ReviewReport:
    """整档复核报告：复核动作本身不改动档案。"""

    archive_id: str
    reviewed_at: datetime
    total: int
    matched: int
    mismatched: int
    entries: tuple[EntryReview, ...]


class ArchiveStore:
    """封存档案仓库（内存实现）：只增不改不删，按封存先后排列。"""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._archives: dict[str, Archive] = {}
        self._order: list[str] = []

    def save(self, archive: Archive) -> None:
        """保存一份档案；ID 重复则拒绝（档案不可覆盖）。"""
        with self._lock:
            if archive.archive_id in self._archives:
                raise ValueError(f"archive already exists: {archive.archive_id}")
            self._archives[archive.archive_id] = archive
            self._order.append(archive.archive_id)

    def get(self, archive_id: str) -> Archive | None:
        return self._archives.get(archive_id)

    def list_ids(self) -> list[str]:
        with self._lock:
            return list(self._order)


def build_archive(
    archive_id: str,
    created_at: datetime,
    range_start: datetime | None,
    range_end: datetime | None,
    events: list,  # list[AuditEvent]，仅 ACCESS 动作
    records: RecordLookup,
    registry: RuleRegistry,
) -> Archive:
    """把一批审计事件整批封存成固定档案。

    每条封存当时的规则版本快照与记录原文快照；之后规则继续发布、
    记录内容被改，都只作用于底层数据，档案内容不变。
    """
    rules_snapshots: dict[int, RuleSet] = {}
    sealed: list[SealedEntry] = []
    for e in events:
        rules = registry.history_version(e.rule_version)
        if rules is not None and e.rule_version not in rules_snapshots:
            rules_snapshots[e.rule_version] = rules
        record = records.get(e.record_id)
        snapshot = dict(record.fields) if record is not None else {}
        sealed.append(SealedEntry(
            sequence=e.sequence,
            timestamp=e.timestamp,
            subject_id=e.subject_id,
            subject_level=e.subject_level,
            record_id=e.record_id,
            rule_version=e.rule_version,
            allowed=e.allowed,
            reason=e.reason,
            presented=dict(e.presented),
            record_snapshot=snapshot,
            rules_snapshot=rules,
        ))
    return Archive(
        archive_id=archive_id,
        created_at=created_at,
        range_start=range_start,
        range_end=range_end,
        entries=tuple(sealed),
        rules_snapshots=MappingProxyType(dict(rules_snapshots)),
    )


def review_archive(
    archive: Archive,
    reviewed_at: datetime,
    records: RecordLookup,
    registry: RuleRegistry,
) -> ReviewReport:
    """事后复核：逐条比对封存依据与按同一版本在当前数据上的重算结果。

    - 不修改档案，也不触碰实时访问路径；
    - 允许条目：用封存的规则版本与主体级别，对当前记录原文重算呈现并逐字段比对；
    - 资源缺失拒绝：当前记录若已存在则为结果漂移；
    - 其余拒绝（主体未知/过期/级别不足）结论只取决于封存时主体授权，原样保持；
    - 规则版本在注册表中的现行留档若与封存快照不一致，记 RULE_DRIFT。
    """
    reviews: list[EntryReview] = []
    for entry in archive.entries:
        diffs: list[EntryDifference] = []

        sealed_rules = archive.rules_snapshots.get(entry.rule_version)
        if sealed_rules is None:
            sealed_rules = entry.rules_snapshot
        live_rules = registry.history_version(entry.rule_version)
        if sealed_rules is None:
            diffs.append(EntryDifference(entry.sequence, "RULE_DRIFT", None,
                                         "snapshot missing", entry.rule_version))
        elif live_rules is not None and live_rules.field_modes != sealed_rules.field_modes:
            diffs.append(EntryDifference(entry.sequence, "RULE_DRIFT", None,
                                         dict(sealed_rules.field_modes),
                                         dict(live_rules.field_modes)))

        current = records.get(entry.record_id)
        if entry.allowed:
            if current is None or sealed_rules is None or entry.subject_level is None:
                diffs.append(EntryDifference(
                    entry.sequence, "OUTCOME", None,
                    {"allowed": True},
                    {"allowed": False, "reason": "RESOURCE_NOT_FOUND" if current is None else "UNRECOMPUTABLE"},
                ))
            else:
                recomputed = present_fields(sealed_rules, entry.subject_level, current.fields)
                for name in sorted(set(recomputed) | set(entry.presented)):
                    if recomputed.get(name) != entry.presented.get(name):
                        diffs.append(EntryDifference(
                            entry.sequence, "PRESENTATION", name,
                            entry.presented.get(name), recomputed.get(name),
                        ))
        elif entry.reason == "RESOURCE_NOT_FOUND" and current is not None:
            diffs.append(EntryDifference(
                entry.sequence, "OUTCOME", None,
                {"allowed": False, "reason": "RESOURCE_NOT_FOUND"},
                {"allowed": True, "reason": None},
            ))

        reviews.append(EntryReview(entry.sequence, not diffs, tuple(diffs)))

    matched = sum(1 for r in reviews if r.matches)
    return ReviewReport(
        archive_id=archive.archive_id,
        reviewed_at=reviewed_at,
        total=len(reviews),
        matched=matched,
        mismatched=len(reviews) - matched,
        entries=tuple(reviews),
    )
