"""合规入口编排：历史查询、封存、复核的授权校验与审计成败一致。

与实时访问共用同一审计汇与同一套可区分拒绝语义：
- 进入先做合规授权校验（主体存在、未过期、级别达标），拒绝同样落痕；
- 任何一次操作都先写审计再给结论；审计写失败一律 AUDIT_FAILURE，
  不返回任何数据、封存不落库、复核不出报告、不留半条记录；
- 所有读判定都基于进入时取得的确定版本/档案快照，不受并发切换影响。
"""
from __future__ import annotations

import itertools
import threading
from datetime import datetime, timezone

from .archive import ArchiveStore, Archiver, Reviewer
from .errors import (
    ArchiveEmptyError,
    ArchiveNotFoundError,
    VersionNotFoundError,
)
from .history import HistoryService
from .models import DenyReason, OpResult


class ComplianceService:
    """合规/运营入口。"""

    COMPLIANCE_LEVEL = 2  # 合规入口所需最低授权级别

    def __init__(self, service, *, compliance_level: int = COMPLIANCE_LEVEL) -> None:
        self._service = service
        self._compliance_level = compliance_level
        self._archives = ArchiveStore()
        self._history = HistoryService(service.rules)
        self._archiver = Archiver(service.audit, self._archives, service.rules)
        self._reviewer = Reviewer(
            self._archives, service.rules,
            service._subjects, service._records,
        )
        self._id_lock = threading.Lock()
        self._id_seq = itertools.count(1)

    @property
    def archives(self) -> ArchiveStore:
        return self._archives

    def _now(self) -> datetime:
        return datetime.now(timezone.utc)

    def _authorize(self, subject_id: str, now: datetime):
        """合规授权：返回 (级别, 拒绝原因)。级别达标才放行。"""
        level, deny = self._service._subjects.effective_level(subject_id, now)
        if deny is not None:
            return None, DenyReason(deny)
        if level < self._compliance_level:
            return None, DenyReason.INSUFFICIENT_LEVEL
        return level, None

    def _finish(
        self,
        *,
        subject_id: str,
        action: str,
        rule_version: int,
        now: datetime,
        allowed: bool,
        reason: DenyReason | None,
        data: dict | None,
        record_id: str = "-",
        archive_id: str | None = None,
    ) -> OpResult:
        """统一收口：先落审计；审计失败则整次结果改为 AUDIT_FAILURE 且无数据。"""
        ok = self._service.write_audit_event(
            timestamp=now,
            subject_id=subject_id,
            record_id=record_id,
            rule_version=rule_version,
            allowed=allowed,
            reason=reason,
            presented=data.get("presented", {}) if data else {},
            action=action,
            archive_id=archive_id,
        )
        if not ok:
            return OpResult(False, DenyReason.AUDIT_FAILURE, action,
                            rule_version, None)
        return OpResult(allowed, reason, action, rule_version,
                        data if allowed else None)

    def _reject(self, subject_id, action, rule_version, now, reason,
                record_id="-", archive_id=None) -> OpResult:
        return self._finish(
            subject_id=subject_id, action=action, rule_version=rule_version,
            now=now, allowed=False, reason=reason, data=None,
            record_id=record_id, archive_id=archive_id,
        )

    # ---- 历史版本查询 -----------------------------------------------------

    def list_rule_versions(self, subject_id: str, now: datetime | None = None) -> OpResult:
        """按发布先后列全部规则版本（合规级只读）。"""
        now = now or self._now()
        version = self._service.rules.snapshot().version
        _, deny = self._authorize(subject_id, now)
        if deny is not None:
            return self._reject(subject_id, "rule_history", version, now, deny)
        data = {"versions": self._history.list_versions()}
        return self._finish(subject_id=subject_id, action="rule_history",
                            rule_version=version, now=now, allowed=True,
                            reason=None, data=data)

    def get_rule_version(self, subject_id: str, version_no: int,
                         now: datetime | None = None) -> OpResult:
        """取指定历史版本完整配置；版本不存在返回 VERSION_NOT_FOUND。"""
        now = now or self._now()
        current = self._service.rules.snapshot().version
        _, deny = self._authorize(subject_id, now)
        if deny is not None:
            return self._reject(subject_id, "rule_history", current, now, deny)
        try:
            data = self._history.get_version(version_no)
        except VersionNotFoundError:
            return self._reject(subject_id, "rule_history", current, now,
                                DenyReason.VERSION_NOT_FOUND,
                                record_id=f"rule@{version_no}")
        return self._finish(subject_id=subject_id, action="rule_history",
                            rule_version=current, now=now, allowed=True,
                            reason=None, data=data)

    # ---- 封存 -------------------------------------------------------------

    def seal_archive(self, subject_id: str, start: datetime | None,
                     end: datetime | None, now: datetime | None = None,
                     archive_id: str | None = None) -> OpResult:
        """把 [start, end) 时间窗事件整批封存；空窗返回 ARCHIVE_EMPTY。

        顺序保证原子性：先在内存构造固化档案（不落库），审计写成功后才把
        档案放进仓库；审计失败则档案根本不存在，绝无半成品封存。
        """
        now = now or self._now()
        current = self._service.rules.snapshot().version
        _, deny = self._authorize(subject_id, now)
        if deny is not None:
            return self._reject(subject_id, "seal", current, now, deny)

        with self._id_lock:
            archive_id = archive_id or f"arc-{now.strftime('%Y%m%d%H%M%S')}-{next(self._id_seq)}"

        try:
            archive = self._archiver.build(archive_id, start, end, now)
        except ArchiveEmptyError:
            return self._reject(subject_id, "seal", current, now,
                                DenyReason.ARCHIVE_EMPTY,
                                record_id=f"window[{start},{end})")

        result = self._finish(
            subject_id=subject_id, action="seal", rule_version=current, now=now,
            allowed=True, reason=None,
            data={
                "archive_id": archive.archive_id,
                "created_at": archive.created_at,
                "start": archive.start,
                "end": archive.end,
                "entry_count": len(archive.entries),
                "rule_versions": list(archive.rule_versions),
                "fingerprint": archive.fingerprint,
            },
            record_id=f"archive:{archive.archive_id}",
            archive_id=archive.archive_id,
        )
        if result.allowed:
            self._archives.put(archive)  # 审计成功，封存才成立
        return result

    # ---- 复核 -------------------------------------------------------------

    def review_archive(self, subject_id: str, archive_id: str,
                       now: datetime | None = None) -> OpResult:
        """只读复核档案：给出逐条对得上/对不上及差异；不改档案、不影响实时访问。"""
        now = now or self._now()
        current = self._service.rules.snapshot().version
        _, deny = self._authorize(subject_id, now)
        if deny is not None:
            return self._reject(subject_id, "review", current, now, deny,
                                archive_id=archive_id)
        try:
            report = self._reviewer.review(archive_id, now)
        except ArchiveNotFoundError:
            return self._reject(subject_id, "review", current, now,
                                DenyReason.ARCHIVE_NOT_FOUND,
                                record_id=f"archive:{archive_id}",
                                archive_id=archive_id)

        data = {
            "archive_id": report.archive_id,
            "reviewed_at": report.reviewed_at,
            "total": report.total,
            "matched": report.matched,
            "mismatched": report.mismatched,
            "consistent": report.consistent,
            "entries": [
                {
                    "sequence": r.sequence,
                    "verdict": r.verdict.value,
                    "sealed": _jsonable(r.sealed),
                    "current": _jsonable(r.current),
                    "diff": _jsonable(r.diff),
                }
                for r in report.entries
            ],
        }
        return self._finish(subject_id=subject_id, action="review",
                            rule_version=current, now=now, allowed=True,
                            reason=None, data=data,
                            record_id=f"archive:{archive_id}",
                            archive_id=archive_id)


def _jsonable(value):
    """把报告里的 datetime 等转成可序列化形式（HTTP 层再统一 json 化）。"""
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    return value
