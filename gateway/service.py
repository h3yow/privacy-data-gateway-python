"""网关服务：编排授权判定、脱敏呈现、规则历史、封存复核与审计落痕。"""
from __future__ import annotations

import itertools
import threading
from dataclasses import dataclass, field
from datetime import datetime
from typing import Generic, TypeVar

from .archives import (
    Archive,
    ArchiveStore,
    ReviewReport,
    build_archive,
    review_archive,
)
from .audit import AuditSink
from .authz import SubjectStore
from .models import AuditEvent, Decision, DenyReason
from .present import present_fields
from .rules import RuleRegistry, RuleSet

T = TypeVar("T")


@dataclass(frozen=True)
class OperationResult(Generic[T]):
    """非访问类操作的统一结论：成败可辨、拒绝原因可区分。"""

    ok: bool
    reason: DenyReason | None
    payload: T | None = None


class RecordStore:
    """记录仓库（内存实现）。底层记录可被后续改写，封存档案不受影响。"""

    def __init__(self, records: dict | None = None) -> None:
        self._lock = threading.Lock()
        self._records: dict = dict(records or {})

    def get(self, record_id: str):
        return self._records.get(record_id)

    def put(self, record) -> None:
        """新增或替换一条记录（模拟运营侧对底层数据的修改）。"""
        with self._lock:
            self._records[record.record_id] = record


class GatewayService:
    """网关入口。

    语义保证：
    - 每次访问进入时取一次规则快照，整次请求只使用该版本，绝不混用新旧规则；
    - 允许、拒绝以及历史查询/封存/复核都先写审计；审计写失败时操作一并失败，
      不放行数据、不保存档案、不留半成品结论；
    - 历史查询、封存、复核与实时访问共用同一套可区分拒绝原因。
    """

    def __init__(
        self,
        subjects: SubjectStore,
        records: RecordStore,
        rules: RuleRegistry,
        audit: AuditSink,
        archives: ArchiveStore | None = None,
    ) -> None:
        self._subjects = subjects
        self._records = records
        self._rules = rules
        self._audit = audit
        self._archives = archives if archives is not None else ArchiveStore()
        self._seq_lock = threading.Lock()
        self._seq = itertools.count(1)
        self._archive_seq = itertools.count(1)

    @property
    def rules(self) -> RuleRegistry:
        return self._rules

    @property
    def audit(self) -> AuditSink:
        return self._audit

    @property
    def archives(self) -> ArchiveStore:
        return self._archives

    # ---------- 实时访问 ----------

    def access(self, subject_id: str, record_id: str, now: datetime) -> Decision:
        """判定并呈现一次访问（语义同旧版，审计事件额外记录主体级别）。"""
        rules = self._rules.snapshot()  # 版本快照：本请求恒定

        record = self._records.get(record_id)
        if record is None:
            return self._conclude_access(
                subject_id, record_id, rules.version, now,
                False, DenyReason.RESOURCE_NOT_FOUND, {}, None)

        level, deny = self._subjects.effective_level(subject_id, now)
        if deny is not None:
            return self._conclude_access(
                subject_id, record_id, rules.version, now,
                False, DenyReason(deny), {}, None)
        assert level is not None
        if level <= 0:
            return self._conclude_access(
                subject_id, record_id, rules.version, now,
                False, DenyReason.INSUFFICIENT_LEVEL, {}, level)

        presented = present_fields(rules, level, record.fields)
        return self._conclude_access(
            subject_id, record_id, rules.version, now, True, None, presented, level)

    def _conclude_access(
        self, subject_id, record_id, rule_version, now,
        allowed, reason, presented, level,
    ) -> Decision:
        """先落审计，再给结论；审计失败则结论改为 AUDIT_FAILURE 且不放行数据。"""
        event = self._build_event(
            now, subject_id, record_id, rule_version, allowed,
            reason.value if reason else None, presented, "ACCESS", level)
        if not self._safe_write(event):
            return Decision(False, DenyReason.AUDIT_FAILURE, subject_id,
                            record_id, rule_version, {})
        return Decision(allowed, reason, subject_id, record_id, rule_version,
                        dict(presented))

    # ---------- 规则历史 ----------

    def list_rule_versions(
        self, subject_id: str, now: datetime,
        limit: int | None = None, offset: int = 0,
    ) -> OperationResult[list[RuleSet]]:
        """按发布先后列出规则版本（旧→新，定长分页），读侧 O(1) 定位。"""
        version = self._rules.latest_version()
        gate = self._gate(subject_id, now, action="HISTORY",
                          record_id="rules", rule_version=version)
        if gate is not None:
            return gate  # type: ignore[return-value]
        payload = self._rules.history(limit, offset)
        event = self._build_event(
            now, subject_id, "rules", version, True, None,
            {"count": str(len(payload))}, "HISTORY", None)
        if not self._safe_write(event):
            return OperationResult(False, DenyReason.AUDIT_FAILURE, None)
        return OperationResult(True, None, payload)

    def get_rule_version(
        self, subject_id: str, version: int, now: datetime,
    ) -> OperationResult[RuleSet]:
        """查某个历史版本当时的完整配置；不存在明确拒绝为 VERSION_NOT_FOUND。"""
        gate = self._gate(subject_id, now, action="HISTORY",
                          record_id=f"rule:{version}", rule_version=version)
        if gate is not None:
            return gate  # type: ignore[return-value]
        rules = self._rules.history_version(version)
        if rules is None:
            denied = self._deny_operation(
                subject_id, f"rule:{version}", version, now,
                DenyReason.VERSION_NOT_FOUND, "HISTORY")
            if denied is not None:
                return denied  # type: ignore[return-value]
            return OperationResult(False, DenyReason.VERSION_NOT_FOUND, None)
        event = self._build_event(
            now, subject_id, f"rule:{version}", version, True, None,
            {"retention_days": str(rules.retention_days)}, "HISTORY", None)
        if not self._safe_write(event):
            return OperationResult(False, DenyReason.AUDIT_FAILURE, None)
        return OperationResult(True, None, rules)

    # ---------- 封存档案 ----------

    def seal_archive(
        self,
        subject_id: str,
        now: datetime,
        range_start: datetime | None = None,
        range_end: datetime | None = None,
    ) -> OperationResult[Archive]:
        """把时间区间内的访问/拒绝整批封存为固定档案。

        每条封存当时所用规则版本与记录原文；先落封存审计、再保存档案，
        审计失败则档案不落库。
        """
        gate = self._gate(subject_id, now, min_level=2, action="SEAL",
                          record_id="archive:pending",
                          rule_version=self._rules.latest_version())
        if gate is not None:
            return gate  # type: ignore[return-value]

        events = [
            e for e in self._audit.events()
            if e.action == "ACCESS"
            and (range_start is None or e.timestamp >= range_start)
            and (range_end is None or e.timestamp <= range_end)
        ]
        with self._seq_lock:
            archive_id = f"archive-{next(self._archive_seq)}"
        archive = build_archive(archive_id, now, range_start, range_end,
                                events, self._records, self._rules)

        summary = {"archive_id": archive_id, "entries": str(len(events))}
        seal_event = self._build_event(
            now, subject_id, f"archive:{archive_id}",
            self._rules.latest_version(), True, None, summary, "SEAL", None)
        if not self._safe_write(seal_event):
            return OperationResult(False, DenyReason.AUDIT_FAILURE, None)

        self._archives.save(archive)
        return OperationResult(True, None, archive)

    def review_archive(
        self, subject_id: str, archive_id: str, now: datetime,
    ) -> OperationResult[ReviewReport]:
        """对已封存档案做事后复核，给出逐条对得上/对不上及差异；不改档。"""
        gate = self._gate(subject_id, now, min_level=2, action="REVIEW",
                          record_id=f"archive:{archive_id}",
                          rule_version=self._rules.latest_version())
        if gate is not None:
            return gate  # type: ignore[return-value]

        archive = self._archives.get(archive_id)
        if archive is None:
            denied = self._deny_operation(
                subject_id, f"archive:{archive_id}",
                self._rules.latest_version(), now,
                DenyReason.ARCHIVE_NOT_FOUND, "REVIEW")
            if denied is not None:
                return denied  # type: ignore[return-value]
            return OperationResult(False, DenyReason.ARCHIVE_NOT_FOUND, None)

        review_event = self._build_event(
            now, subject_id, f"archive:{archive_id}",
            self._rules.latest_version(), True, None,
            {"entries": str(len(archive.entries))}, "REVIEW", None)
        if not self._safe_write(review_event):
            return OperationResult(False, DenyReason.AUDIT_FAILURE, None)

        report = review_archive(archive, now, self._records, self._rules)
        return OperationResult(True, None, report)

    def list_archives(
        self, subject_id: str, now: datetime,
    ) -> OperationResult[list[str]]:
        """列出已封存档案 ID（按封存先后）。"""
        gate = self._gate(subject_id, now, min_level=2, action="REVIEW",
                          record_id="archives",
                          rule_version=self._rules.latest_version())
        if gate is not None:
            return gate  # type: ignore[return-value]
        ids = self._archives.list_ids()
        event = self._build_event(
            now, subject_id, "archives", self._rules.latest_version(),
            True, None, {"count": str(len(ids))}, "REVIEW", None)
        if not self._safe_write(event):
            return OperationResult(False, DenyReason.AUDIT_FAILURE, None)
        return OperationResult(True, None, ids)

    # ---------- 公共：门禁与审计 ----------

    def _gate(
        self, subject_id: str, now: datetime, min_level: int = 1,
        action: str = "HISTORY", record_id: str = "",
        rule_version: int = 0,
    ) -> OperationResult | None:
        """统一门禁：主体存在、未过期、级别达标；拒绝也落审计。

        门禁通过返回 None；被拒返回带可区分原因的 OperationResult。
        """
        level, deny = self._subjects.effective_level(subject_id, now)
        reason: DenyReason | None = None
        if deny is not None:
            reason = DenyReason(deny)
        elif level is not None and level < min_level:
            reason = DenyReason.INSUFFICIENT_LEVEL
        if reason is None:
            return None
        return self._deny_operation(subject_id, record_id, rule_version,
                                    now, reason, action, level)

    def _deny_operation(
        self, subject_id, record_id, rule_version, now,
        reason: DenyReason, action: str, level: int | None = None,
    ) -> OperationResult | None:
        """拒绝类操作先落审计；审计失败升级为 AUDIT_FAILURE。"""
        event = self._build_event(
            now, subject_id, record_id, rule_version, False,
            reason.value, {}, action, level)
        if not self._safe_write(event):
            return OperationResult(False, DenyReason.AUDIT_FAILURE, None)
        return OperationResult(False, reason, None)

    def _build_event(
        self, now, subject_id, record_id, rule_version, allowed,
        reason, presented, action, level,
    ) -> AuditEvent:
        with self._seq_lock:
            seq = next(self._seq)
        return AuditEvent(
            sequence=seq,
            timestamp=now,
            subject_id=subject_id,
            record_id=record_id,
            rule_version=rule_version,
            allowed=allowed,
            reason=reason,
            presented=dict(presented),
            action=action,
            subject_level=level,
        )

    def _safe_write(self, event: AuditEvent) -> bool:
        """写审计；任何失败都返回 False，由调用方令整次操作失败。"""
        try:
            self._audit.write(event)
            return True
        except Exception:
            return False
