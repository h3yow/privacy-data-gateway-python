"""审计：允许与拒绝均留痕；审计失败时访问一并失败、不放行数据。"""
from __future__ import annotations

import logging
import threading

from gateway.audit import AuditError
from gateway.models import DenyReason
from tests.conftest import NOW

logger = logging.getLogger("gateway-test")


class FlakySink:
    """可开关的故障审计汇：fail=True 时写入抛错。"""

    def __init__(self, inner):
        self._inner = inner
        self.fail = False

    def write(self, event):
        if self.fail:
            raise AuditError("simulated sink outage")
        self._inner.write(event)


def test_allow_and_deny_both_audited(service, audit):
    service.access("admin", "r1", NOW)     # 允许
    service.access("ghost", "r1", NOW)     # 拒绝：主体未知
    service.access("admin", "nope", NOW)   # 拒绝：资源不存在

    events = audit.events()
    assert len(events) == 3
    for e in events:
        logger.info("审计 seq=%d subject=%s record=%s v=%d allowed=%s reason=%s",
                    e.sequence, e.subject_id, e.record_id, e.rule_version,
                    e.allowed, e.reason)
    assert [e.allowed for e in events] == [True, False, False]
    assert events[1].reason == "SUBJECT_UNKNOWN"
    assert events[2].reason == "RESOURCE_NOT_FOUND"
    assert [e.sequence for e in events] == [1, 2, 3]  # 有序可追溯


def test_audit_event_carries_decision_basis(service, audit):
    d = service.access("clerk", "r1", NOW)
    e = audit.events()[0]
    assert e.rule_version == d.rule_version == 1
    assert e.presented == d.presented  # 审计中的呈现结果与响应一致
    assert e.timestamp == NOW


def test_audit_failure_fails_access_without_leaking(service, audit):
    flaky = FlakySink(audit)
    svc = type(service)(service._subjects, service._records, service._rules, flaky)

    flaky.fail = True
    d = svc.access("admin", "r1", NOW)
    logger.info("审计故障时判定 allowed=%s reason=%s presented=%s",
                d.allowed, d.reason, d.presented)
    assert not d.allowed
    assert d.reason is DenyReason.AUDIT_FAILURE
    assert d.presented == {}            # 不放行任何数据
    assert audit.events() == []         # 无不完整记录

    flaky.fail = False                  # 恢复后正常放行
    d2 = svc.access("admin", "r1", NOW)
    assert d2.allowed and d2.presented["phone"] == "13800001111"


def test_audit_failure_on_deny_also_fails_consistently(service, audit):
    flaky = FlakySink(audit)
    svc = type(service)(service._subjects, service._records, service._rules, flaky)
    flaky.fail = True
    d = svc.access("ghost", "r1", NOW)  # 本应拒绝，但审计也写不进去
    assert not d.allowed and d.reason is DenyReason.AUDIT_FAILURE


def test_concurrent_access_audit_sequences_unique(service, audit):
    results = []
    def worker(i):
        results.append(service.access("clerk", "r1", NOW))
    threads = [threading.Thread(target=worker, args=(i,)) for i in range(16)]
    for t in threads: t.start()
    for t in threads: t.join()
    seqs = [e.sequence for e in audit.events()]
    assert len(seqs) == 16 and len(set(seqs)) == 16  # 序号唯一、无丢失
    assert all(r.allowed for r in results)
