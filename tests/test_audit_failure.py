"""审计写入失败测试。

验证：审计写失败时不静默放行、不返回数据；
且只有“审计成功写入”的访问才算成功（访问与审计成败语义一致）。
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from privacy_gateway.audit import AuditLog, AuditLogError
from privacy_gateway.errors import (
    AuditWriteError,
    GrantExpiredError,
)
from privacy_gateway.models import AuditEntry
from privacy_gateway.service import AccessService

NOW = datetime(2026, 9, 26, tzinfo=timezone.utc)


class FailingAuditLog(AuditLog):
    """始终写入失败的审计日志。"""

    def write(self, entry: AuditEntry) -> None:
        print(f"[AUDIT FAIL] would write decision={entry.decision_id} "
              f"result={entry.result.value}")
        raise AuditLogError("simulated storage outage")


def test_audit_failure_blocks_allow(components):
    failing = FailingAuditLog()
    svc = AccessService(
        components["records"], components["grants"], components["rules"], failing
    )
    print("[INPUT] subject=alice with broken audit log")
    with pytest.raises(AuditWriteError) as exc:
        svc.access(subject_id="alice", record_id="rec-1", now=NOW)
    assert exc.value.reason_code == "audit_write_failed"
    assert exc.value.http_status == 500
    # 没有数据被返回，失败的审计存储中也没有“半条”记录
    assert failing.list_all() == []


def test_audit_failure_blocks_even_for_deny(components):
    """拒绝场景下审计失败也必须整体失败，不能只返回拒绝而缺审计。"""
    failing = FailingAuditLog()
    svc = AccessService(
        components["records"], components["grants"], components["rules"], failing
    )
    print("[INPUT] subject=dave(expired) with broken audit log")
    # 审计失败优先级高于授权过期：抛 AuditWriteError 而非 GrantExpiredError，
    # 避免出现“请求被拒但没有审计记录”的不一致。
    with pytest.raises(AuditWriteError) as exc:
        svc.access(subject_id="dave", record_id="rec-1", now=NOW)
    assert not isinstance(exc.value, GrantExpiredError)


class FlakyAuditLog(AuditLog):
    """前 fail_times 次写入失败，之后恢复。"""

    def __init__(self, fail_times: int) -> None:
        super().__init__()
        self._remaining = fail_times

    def write(self, entry: AuditEntry) -> None:
        if self._remaining > 0:
            self._remaining -= 1
            raise AuditLogError("temporary outage")
        super().write(entry)


def test_access_succeeds_exactly_when_audit_written(components):
    flaky = FlakyAuditLog(fail_times=3)
    svc = AccessService(
        components["records"], components["grants"], components["rules"], flaky
    )
    successes = 0
    attempts = 6
    for i in range(attempts):
        try:
            svc.access(subject_id="alice", record_id="rec-1", now=NOW)
            successes += 1
        except AuditWriteError:
            pass
    print(f"[INPUT] {attempts} attempts, successes={successes}")
    # 成功的访问数 == 审计条目数（一一对应，无静默放行/无孤儿记录）
    assert successes == attempts - 3
    assert len(flaky.list_all()) == successes


def test_audit_failure_returns_500_via_http(client, monkeypatch):
    failing = FailingAuditLog()
    service = client.app.state.service
    monkeypatch.setattr(service, "_audit", failing)
    print("[INPUT] HTTP GET with broken audit log")
    r = client.get("/records/rec-1?subject_id=alice")
    assert r.status_code == 500
    assert r.json()["error"] == "audit_write_failed"
