"""封存档案 + 事后复核：档案固定、复核可检出漂移、复核不改档、拒绝语义可区分。"""
from __future__ import annotations

import logging
import threading
from datetime import timedelta

from gateway.models import DenyReason, SensitiveRecord
from tests.conftest import NOW, make_rules_v2

logger = logging.getLogger("gateway-test")


def seal_all(service, now=NOW):
    result = service.seal_archive("admin", now)
    assert result.ok, result.reason
    return result.payload


def test_sealed_archive_freezes_entries(service, audit):
    d = service.access("clerk", "r1", NOW)          # v1 下允许
    service.access("ghost", "r1", NOW)              # 拒绝
    archive = seal_all(service)

    logger.info("档案 %s 含 %d 条; 首条 v=%d presented=%s",
                archive.archive_id, len(archive.entries),
                archive.entries[0].rule_version, archive.entries[0].presented)
    assert len(archive.entries) == 2
    e0 = archive.entries[0]
    assert e0.rule_version == 1
    assert e0.subject_level == 1
    assert e0.presented == d.presented
    assert e0.record_snapshot["phone"] == "13800001111"   # 原文快照
    assert 1 in archive.rules_snapshots


def test_review_matches_when_nothing_changed(service):
    service.access("clerk", "r1", NOW)
    archive = seal_all(service)
    report = service.review_archive("admin", archive.archive_id, NOW).payload
    logger.info("无漂移复核 total=%d matched=%d mismatched=%d",
                report.total, report.matched, report.mismatched)
    assert report.total == 1 and report.matched == 1 and report.mismatched == 0
    assert report.entries[0].matches and report.entries[0].differences == ()


def test_review_detects_record_mutation(service):
    service.access("clerk", "r1", NOW)
    archive = seal_all(service)

    # 封存后底层记录被改
    service._records.put(SensitiveRecord("r1", {
        "name": "alice",
        "phone": "13900002222",
        "id_card": "110101199001011234",
    }))
    report = service.review_archive("admin", archive.archive_id, NOW).payload
    entry = report.entries[0]
    kinds = [(d.kind, d.field, d.sealed, d.current) for d in entry.differences]
    logger.info("数据被改后复核差异=%s", kinds)
    assert report.mismatched == 1 and not entry.matches
    assert any(d.kind == "PRESENTATION" and d.field == "phone"
               and d.sealed == "1*********1" and d.current == "1*********2"
               for d in entry.differences)


def test_review_uses_sealed_rule_version_not_current(service, registry):
    service.access("clerk", "r1", NOW)              # v1 下封存
    archive = seal_all(service)
    registry.publish(make_rules_v2())               # 之后规则演进到 v2

    report = service.review_archive("admin", archive.archive_id, NOW).payload
    logger.info("规则演进后复核 matched=%d/%d", report.matched, report.total)
    # 档案内 v1 留档未被改写，按 v1 重算仍对得上；v2 不影响该条
    assert report.matched == 1 and report.mismatched == 0


def test_sealed_content_immutable_after_more_publishes_and_writes(service, registry, audit):
    service.access("clerk", "r1", NOW)
    archive = seal_all(service)
    before = archive.entries[0].presented

    registry.publish(make_rules_v2())
    service.access("clerk", "r1", NOW + timedelta(seconds=1))
    service._records.put(SensitiveRecord("r1", {"name": "bob", "phone": "13900002222"}))

    assert archive.entries[0].presented == before
    assert archive.entries[0].rules_snapshot.version == 1
    assert archive.rules_snapshots[1].mode_for("phone", 1).value == "MASKED"
    logger.info("档案首条结论固定=%s", before)


def test_review_detects_resource_then_appeared(service, records):
    service.access("admin", "missing", NOW)        # 当时 RESOURCE_NOT_FOUND
    archive = seal_all(service)
    service._records.put(SensitiveRecord("missing", {"name": "later"}))

    report = service.review_archive("admin", archive.archive_id, NOW).payload
    diffs = report.entries[0].differences
    logger.info("缺失记录事后出现差异=%s", [(d.kind, d.sealed, d.current) for d in diffs])
    assert not report.entries[0].matches
    assert any(d.kind == "OUTCOME" for d in diffs)


def test_review_does_not_modify_archive(service):
    service.access("clerk", "r1", NOW)
    archive = seal_all(service)
    sealed_presented = archive.entries[0].presented
    service._records.put(SensitiveRecord("r1", {"name": "carol", "phone": "13900002222"}))
    service.review_archive("admin", archive.archive_id, NOW)
    service.review_archive("admin", archive.archive_id, NOW)  # 复核两次
    assert archive.entries[0].presented == sealed_presented
    # 复核不产生新的访问判定，实时路径不受影响
    assert all(e.action != "ACCESS" or e.record_id != "r1" or e.subject_id == "clerk"
               for e in service.audit.events())
    logger.info("两次复核后档案内容未变=%s", sealed_presented)


def test_archive_not_found_review_denied(service):
    result = service.review_archive("admin", "archive-nope", NOW)
    assert not result.ok and result.reason is DenyReason.ARCHIVE_NOT_FOUND
    logger.info("复核不存在档案拒绝原因=%s", result.reason)


def test_archive_id_range_filter(service):
    service.access("clerk", "r1", NOW)
    service.access("clerk", "r1", NOW + timedelta(days=2))
    a1 = service.seal_archive("admin", NOW + timedelta(days=1),
                              range_end=NOW + timedelta(days=1)).payload
    logger.info("时间窗封存条目数=%d", len(a1.entries))
    assert len(a1.entries) == 1
    assert a1.entries[0].timestamp == NOW


def test_seal_requires_level_two(service):
    service.access("clerk", "r1", NOW)
    denied = service.seal_archive("clerk", NOW)
    assert not denied.ok and denied.reason is DenyReason.INSUFFICIENT_LEVEL
    ghost = service.seal_archive("ghost", NOW)
    assert not ghost.ok and ghost.reason is DenyReason.SUBJECT_UNKNOWN
    logger.info("封存越权拒绝: clerk=%s ghost=%s", denied.reason, ghost.reason)


def test_history_endpoint_requires_valid_subject(service):
    assert service.list_rule_versions("ghost", NOW).reason is DenyReason.SUBJECT_UNKNOWN
    ok = service.list_rule_versions("clerk", NOW)
    assert ok.ok and [r.version for r in ok.payload] == [1]


def test_audit_failure_aborts_seal(service, audit):
    from tests.test_audit import FlakySink
    flaky = __import__("tests.test_audit", fromlist=["FlakySink"]).FlakySink(audit)
    svc = type(service)(service._subjects, service._records, service._rules, flaky,
                        service._archives)
    service.access("admin", "r1", NOW)             # 先有一条可封存数据
    before = len(service._archives.list_ids())

    flaky.fail = True
    result = svc.seal_archive("admin", NOW)
    flaky.fail = False
    logger.info("审计故障时封存结果 ok=%s reason=%s", result.ok, result.reason)
    assert not result.ok and result.reason is DenyReason.AUDIT_FAILURE
    assert len(service._archives.list_ids()) == before   # 没有半份档案落库


def test_audit_failure_aborts_review(service):
    from tests.test_audit import FlakySink
    service.access("clerk", "r1", NOW)
    archive = seal_all(service)
    flaky = __import__("tests.test_audit", fromlist=["FlakySink"]).FlakySink(service.audit)
    svc = type(service)(service._subjects, service._records, service._rules, flaky,
                        service._archives)
    flaky.fail = True
    result = svc.review_archive("admin", archive.archive_id, NOW)
    assert not result.ok and result.reason is DenyReason.AUDIT_FAILURE
    flaky.fail = False
    logger.info("审计故障时复核结果 reason=%s", result.reason)


def test_concurrent_access_and_seal_use_single_version(service, registry):
    """封存与访问并发：同一请求只认一个版本，档案按各自条目版本固定。"""
    errors: list[str] = []
    stop = threading.Event()

    def reader():
        while not stop.is_set():
            d = service.access("clerk", "r1", NOW)
            if d.rule_version == 1 and d.presented.get("phone") != "1*********1":
                errors.append(f"v1 混用: {d.presented}")
            if d.rule_version == 2 and "phone" in d.presented:
                errors.append(f"v2 混用: {d.presented}")

    def switcher():
        v = 3
        while not stop.is_set():
            rs = make_rules_v2()
            object.__setattr__(rs, "version", v)
            try:
                registry.publish(rs)
            except Exception:
                pass
            v += 1

    def sealer():
        for _ in range(20):
            r = service.seal_archive("admin", NOW)
            if not r.ok:
                errors.append(f"封存失败: {r.reason}")

    threads = [threading.Thread(target=reader) for _ in range(4)]
    threads += [threading.Thread(target=switcher), threading.Thread(target=sealer)]
    for t in threads:
        t.start()
    threading.Event().wait(0.2)
    stop.set()
    for t in threads:
        t.join()
    logger.info("并发封存档案数=%d 错误=%s",
                len(service._archives.list_ids()), errors)
    assert errors == []
    # 每份档案的每条都自洽：封存的规则版本与呈现结论匹配
    for aid in service._archives.list_ids():
        a = service._archives.get(aid)
        for e in a.entries:
            assert e.rule_version in a.rules_snapshots


def test_audit_failure_aborts_history_query(service, audit):
    flaky = __import__("tests.test_audit", fromlist=["FlakySink"]).FlakySink(audit)
    svc = type(service)(service._subjects, service._records, service._rules, flaky,
                        service._archives)
    flaky.fail = True
    listing = svc.list_rule_versions("admin", NOW)
    detail = svc.get_rule_version("admin", 1, NOW)
    flaky.fail = False
    logger.info("审计故障时历史查询: list=%s detail=%s", listing.reason, detail.reason)
    assert not listing.ok and listing.reason is DenyReason.AUDIT_FAILURE
    assert not detail.ok and detail.reason is DenyReason.AUDIT_FAILURE
