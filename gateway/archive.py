"""封存档案与事后复核：不可变档案、逐条指纹、只读比对。

封存：把一段时间窗内的审计事件整批深拷贝固化为一份 Archive，
每条带规范化 SHA-256 指纹，档案整体也有指纹。封存后：
- 档案内容不再依赖审计汇、注册表或底层数据，任何后续变更都改不到它；
- 复核是只读操作：用注册表里保存的历史规则版本对"当前"主体/记录重放，
  先校验条目自身指纹（档案有没有被改），再逐字段比对封存结论与重放结论。
"""
from __future__ import annotations

import copy
import hashlib
import json
import threading
from datetime import datetime

from .decision import evaluate
from .models import (
    Archive,
    ArchivedEntry,
    EntryReview,
    EntryVerdict,
    ReviewReport,
)


def _canonical_json(payload) -> str:
    """规范化 JSON：键排序、无空白、UTC 时间统一 ISO 文本，保证可复现。"""
    return json.dumps(
        payload,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
        default=lambda o: o.isoformat() if isinstance(o, datetime) else str(o),
    )


def canonical_fingerprint(payload: dict) -> str:
    """对可 JSON 化的判定依据计算规范化 SHA-256 指纹。"""
    return hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


def _entry_payload(entry: ArchivedEntry) -> dict:
    """条目指纹的覆盖范围：除指纹外的全部判定依据字段。"""
    return {
        "sequence": entry.sequence,
        "timestamp": entry.timestamp,
        "subject_id": entry.subject_id,
        "record_id": entry.record_id,
        "rule_version": entry.rule_version,
        "allowed": entry.allowed,
        "reason": entry.reason,
        "presented": entry.presented,
        "subject_level": entry.subject_level,
    }


def _make_entry(event) -> ArchivedEntry:
    """把一条审计事件深拷贝成封存条目并计算封存时刻指纹。"""
    partial = ArchivedEntry(
        sequence=event.sequence,
        timestamp=event.timestamp,
        subject_id=event.subject_id,
        record_id=event.record_id,
        rule_version=event.rule_version,
        allowed=event.allowed,
        reason=event.reason,
        presented=dict(event.presented),
        subject_level=getattr(event, "subject_level", None),
        fingerprint="",
    )
    return ArchivedEntry(
        sequence=partial.sequence,
        timestamp=partial.timestamp,
        subject_id=partial.subject_id,
        record_id=partial.record_id,
        rule_version=partial.rule_version,
        allowed=partial.allowed,
        reason=partial.reason,
        presented=dict(partial.presented),
        subject_level=partial.subject_level,
        fingerprint=canonical_fingerprint(_entry_payload(partial)),
    )


class ArchiveStore:
    """档案仓库：只追加、按号 O(1) 取档，档案取出即为不可变快照。"""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._archives: dict[str, Archive] = {}
        self._order: list[str] = []

    def put(self, archive: Archive) -> None:
        """追加一份档案；档案号重复视为程序错误直接拒绝。"""
        with self._lock:
            if archive.archive_id in self._archives:
                raise ValueError(f"archive {archive.archive_id} already exists")
            self._archives[archive.archive_id] = archive
            self._order.append(archive.archive_id)

    def get(self, archive_id: str) -> Archive | None:
        return self._archives.get(archive_id)

    def list_ids(self) -> list[str]:
        with self._lock:
            return list(self._order)


class Archiver:
    """封存器：把时间窗内审计事件整批固化为档案。"""

    def __init__(self, audit, archives: ArchiveStore, rules) -> None:
        self._audit = audit
        self._archives = archives
        self._rules = rules

    def build(
        self,
        archive_id: str,
        start: datetime | None,
        end: datetime | None,
        created_at: datetime,
    ) -> Archive:
        """构造一份档案（不写仓库）；窗内无事件抛 ArchiveEmptyError。

        在锁内一次性取事件快照，封存期间审计汇继续追加也不影响本档案；
        条目深拷贝固化，调用方确认审计落痕成功后再调用 ArchiveStore.put。
        """
        from .errors import ArchiveEmptyError

        events = self._audit.events()  # 已经是快照副本
        # 档案只封存敏感数据访问事件（含允许与拒绝）；
        # 历史查询/封存/复核等合规元操作仍在审计汇留痕，但不进入档案。
        selected = [
            e for e in events
            if getattr(e, "action", "access") == "access"
            and (start is None or e.timestamp >= start)
            and (end is None or e.timestamp < end)
        ]
        if not selected:
            raise ArchiveEmptyError(
                f"no audit events in window [{start}, {end})"
            )
        selected.sort(key=lambda e: e.sequence)
        entries = tuple(_make_entry(copy.deepcopy(e)) for e in selected)
        versions = tuple(sorted({e.rule_version for e in entries}))
        return Archive(
            archive_id=archive_id,
            created_at=created_at,
            start=start,
            end=end,
            rule_versions=versions,
            entries=entries,
            fingerprint=canonical_fingerprint({
                "archive_id": archive_id,
                "created_at": created_at,
                "start": start,
                "end": end,
                "rule_versions": list(versions),
                "entries": [_entry_payload(e) | {"fingerprint": e.fingerprint}
                            for e in entries],
            }),
        )

    def seal(
        self,
        archive_id: str,
        start: datetime | None,
        end: datetime | None,
        created_at: datetime,
    ) -> Archive:
        """构造并立即落库（仅供不需要外部审计协调的场景使用）。"""
        archive = self.build(archive_id, start, end, created_at)
        self._archives.put(archive)
        return archive


class Reviewer:
    """复核器：用历史规则版本对当前数据重放，逐条与封存结论比对。"""

    def __init__(self, archives: ArchiveStore, rules, subjects, records) -> None:
        self._archives = archives
        self._rules = rules
        self._subjects = subjects
        self._records = records

    def review(self, archive_id: str, reviewed_at: datetime) -> ReviewReport:
        """只读复核一份档案；档案不存在抛 ArchiveNotFoundError。"""
        from .errors import ArchiveNotFoundError, VersionNotFoundError

        archive = self._archives.get(archive_id)
        if archive is None:
            raise ArchiveNotFoundError(f"archive {archive_id} not found")

        reviews: list[EntryReview] = []
        for entry in archive.entries:
            reviews.append(self._review_entry(entry, reviewed_at))

        matched = sum(1 for r in reviews if r.verdict is EntryVerdict.MATCH)
        return ReviewReport(
            archive_id=archive_id,
            reviewed_at=reviewed_at,
            total=len(reviews),
            matched=matched,
            mismatched=len(reviews) - matched,
            entries=tuple(reviews),
        )

    def _review_entry(self, entry: ArchivedEntry, reviewed_at: datetime) -> EntryReview:
        sealed = {
            "subject_id": entry.subject_id,
            "record_id": entry.record_id,
            "rule_version": entry.rule_version,
            "allowed": entry.allowed,
            "reason": entry.reason,
            "presented": dict(entry.presented),
            "subject_level": entry.subject_level,
        }

        # 1) 档案条目自身指纹：检查封存内容有没有被改动
        expected_fp = canonical_fingerprint(_entry_payload(entry))
        if not _safe_equal(expected_fp, entry.fingerprint):
            return EntryReview(
                sequence=entry.sequence,
                verdict=EntryVerdict.TAMPERED,
                sealed=sealed,
                current=None,
                diff={"fingerprint": {
                    "sealed": entry.fingerprint,
                    "current": expected_fp,
                }},
            )

        # 2) 取出封存时所用的历史规则版本（已发布版本永久留存）
        try:
            rules = self._rules.get_version(entry.rule_version)
        except VersionNotFoundError:
            return EntryReview(
                sequence=entry.sequence,
                verdict=EntryVerdict.VERSION_MISSING,
                sealed=sealed,
                current=None,
                diff={"rule_version": {"missing": entry.rule_version}},
            )

        # 3) 按事件发生时刻对当前底层数据重放判定（now=事件时刻，复现过期状态）
        current_level, _ = self._subjects.effective_level(
            entry.subject_id, entry.timestamp
        )
        ev = evaluate(rules, self._subjects, self._records,
                      entry.subject_id, entry.record_id, entry.timestamp)
        current = {
            "subject_id": entry.subject_id,
            "record_id": entry.record_id,
            "rule_version": rules.version,
            "allowed": ev.allowed,
            "reason": ev.reason.value if ev.reason else None,
            "presented": dict(ev.presented),
            "subject_level": ev.subject_level,
        }

        # 4) 归类差异
        if current["reason"] == "RESOURCE_NOT_FOUND":
            verdict = EntryVerdict.RESOURCE_MISSING
        elif current["reason"] in ("SUBJECT_UNKNOWN", "GRANT_EXPIRED"):
            verdict = EntryVerdict.SUBJECT_CHANGED
        elif current_level != entry.subject_level:
            # 主体仍存在且按当时点未过期，但授权级别已与封存时不同
            verdict = EntryVerdict.SUBJECT_CHANGED
        elif (current["allowed"], current["reason"], current["presented"]) == (
            entry.allowed, entry.reason, dict(entry.presented)
        ):
            verdict = EntryVerdict.MATCH
        else:
            verdict = EntryVerdict.PRESENTATION_DIFF

        return EntryReview(
            sequence=entry.sequence,
            verdict=verdict,
            sealed=sealed,
            current=current,
            diff=_diff_decisions(sealed, current),
        )


def _safe_equal(a: str, b: str) -> bool:
    """常时间字符串比较，避免复核指纹校验的计时侧信道。"""
    import hmac
    return hmac.compare_digest(a, b)


def _diff_decisions(sealed: dict, current: dict) -> dict:
    """字段级差异：结果标记、拒绝原因、逐字段呈现分别对比。"""
    diff: dict = {}
    if sealed["allowed"] != current["allowed"]:
        diff["allowed"] = {"sealed": sealed["allowed"], "current": current["allowed"]}
    if sealed["reason"] != current["reason"]:
        diff["reason"] = {"sealed": sealed["reason"], "current": current["reason"]}
    if sealed.get("subject_level") != current.get("subject_level"):
        diff["subject_level"] = {
            "sealed": sealed.get("subject_level"),
            "current": current.get("subject_level"),
        }
    fields = sorted(set(sealed["presented"]) | set(current["presented"]))
    for name in fields:
        old = sealed["presented"].get(name, "<HIDDEN>")
        new = current["presented"].get(name, "<HIDDEN>")
        if old != new:
            diff[f"presented.{name}"] = {"sealed": old, "current": new}
    return diff
