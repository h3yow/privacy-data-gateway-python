"""封存档案 + 事后复核：不可变、指纹、逐条差异、审计成败一致、并发不串版。"""
from __future__ import annotations

import logging
import threading
from dataclasses import replace
from datetime import timedelta

import pytest

from gateway.audit import AuditError
from gateway.compliance import ComplianceService
from gateway.models import (
    DenyReason,
    EntryVerdict,
    MaskMode,
    SensitiveRecord,
    Subject,
)
from gateway.rules import RuleSet
from tests.conftest import NOW, make_rules_v1, make_rules_v2

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

    def events(self):
        return self._inner.events()


def make_compliance(service):
    return ComplianceService(service)


def _verdicts(report_data):
    return [(e["sequence"], e["verdict"]) for e in report_data["entries"]]


# ---- 封存基本语义 ---------------------------------------------------------

def test_seal_freezes_access_events_with_decision_basis(service):
    comp = make_compliance(service)
    d1 = service.access("clerk", "r1", NOW)
    service.access("ghost", "r1", NOW)                  # 拒绝也要进档案
    r = comp.seal_archive("admin", None, None, NOW + timedelta(minutes=1),
                          archive_id="arc-1")
    assert r.allowed and r.data["entry_count"] == 2
    assert r.data["rule_versions"] == [1]

    arc = comp.archives.get("arc-1")
    logger.info("封存输入: 1 允许 + 1 拒绝 | 条目=%s 指纹=%s",
                [(e.subject_id, e.allowed, e.reason, e.rule_version) for e in arc.entries],
                r.data["fingerprint"][:12])
    assert arc.entries[0].presented == d1.presented
    assert arc.entries[0].subject_level == 1
    assert arc.entries[1].allowed is False
    assert arc.entries[1].reason == "SUBJECT_UNKNOWN"
    assert all(e.fingerprint for e in arc.entries)


def test_seal_window_is_half_open_and_filters_non_access(service, audit):
    comp = make_compliance(service)
    service.access("clerk", "r1", NOW)
    service.access("clerk", "r1", NOW + timedelta(minutes=2))
    comp.list_rule_versions("admin", NOW + timedelta(minutes=3))  # 元操作不进档案

    # [NOW, NOW+1min) 只含第一条
    r = comp.seal_archive("admin", NOW, NOW + timedelta(minutes=1),
                          NOW + timedelta(minutes=4), archive_id="arc-w")
    assert r.allowed and r.data["entry_count"] == 1
    assert comp.archives.get("arc-w").entries[0].timestamp == NOW


def test_seal_empty_window_denied(service):
    comp = make_compliance(service)
    r = comp.seal_archive("admin", NOW + timedelta(days=9),
                          NOW + timedelta(days=10), NOW, archive_id="arc-e")
    logger.info("输入: 封存空时间窗 | 结果 allowed=%s reason=%s", r.allowed, r.reason)
    assert not r.allowed and r.reason is DenyReason.ARCHIVE_EMPTY
    assert comp.archives.get("arc-e") is None  # 没有半成品档案


def test_seal_requires_compliance_level(service, audit):
    comp = make_compliance(service)
    r = comp.seal_archive("clerk", None, None, NOW, archive_id="no")
    assert not r.allowed and r.reason is DenyReason.INSUFFICIENT_LEVEL
    assert comp.archives.get("no") is None


# ---- 档案不可变：规则演进、数据变更、审计追加都不影响档案 -------------------

def test_archive_immutable_after_rules_and_data_change(service, records):
    comp = make_compliance(service)
    service.access("clerk", "r1", NOW)
    comp.seal_archive("admin", None, None, NOW + timedelta(minutes=1),
                      archive_id="arc-imm")
    sealed_phone = comp.archives.get("arc-imm").entries[0].presented["phone"]

    # 之后规则继续发、记录内容被改、审计继续增加
    service.rules.publish(make_rules_v2())
    records.upsert(SensitiveRecord("r1", {"name": "bob", "phone": "13900009999"}))
    service.access("clerk", "r1", NOW + timedelta(minutes=2))

    arc = comp.archives.get("arc-imm")
    logger.info("规则发 v2+记录被改后，档案仍记录 rule_version=%d phone=%s",
                arc.entries[0].rule_version, arc.entries[0].presented["phone"])
    assert arc.entries[0].rule_version == 1
    assert arc.entries[0].presented["phone"] == sealed_phone == "1*********1"
    assert len(arc.entries) == 1  # 新审计事件没有渗进旧档案


def test_archive_spans_multiple_rule_versions(service, registry):
    comp = make_compliance(service)
    service.access("clerk", "r1", NOW)                    # v1
    registry.publish(make_rules_v2())
    service.access("clerk", "r1", NOW + timedelta(minutes=1))  # v2
    r = comp.seal_archive("admin", None, None, NOW + timedelta(minutes=2),
                          archive_id="arc-multi")
    assert r.data["rule_versions"] == [1, 2]
    seq_versions = [(e.rule_version) for e in comp.archives.get("arc-multi").entries]
    assert seq_versions == [1, 2]


# ---- 复核 -----------------------------------------------------------------

def test_review_clean_archive_all_match(service):
    comp = make_compliance(service)
    service.access("clerk", "r1", NOW)
    service.access("admin", "r1", NOW + timedelta(seconds=1))
    comp.seal_archive("admin", None, None, NOW + timedelta(seconds=2),
                      archive_id="arc-clean")
    r = comp.review_archive("admin", "arc-clean", NOW + timedelta(seconds=3))
    assert r.allowed
    assert r.data["matched"] == 2 and r.data["mismatched"] == 0
    assert r.data["consistent"] is True
    logger.info("干净档案复核: %d/%d MATCH", r.data["matched"], r.data["total"])


def test_review_detects_record_content_change(service, records):
    comp = make_compliance(service)
    service.access("clerk", "r1", NOW)
    comp.seal_archive("admin", None, None, NOW + timedelta(seconds=1),
                      archive_id="arc-data")
    records.upsert(SensitiveRecord("r1", {"name": "alice", "phone": "13900008888"}))

    r = comp.review_archive("admin", "arc-data", NOW + timedelta(seconds=2))
    entry = r.data["entries"][0]
    logger.info("输入: phone 已改 | 判定=%s 差异=%s", entry["verdict"], entry["diff"])
    assert entry["verdict"] == EntryVerdict.PRESENTATION_DIFF.value
    assert entry["diff"]["presented.phone"]["sealed"] == "1*********1"
    assert entry["diff"]["presented.phone"]["current"] == "1*********8"
    assert r.data["consistent"] is False


def test_review_detects_record_deletion(service, records):
    comp = make_compliance(service)
    service.access("clerk", "r1", NOW)
    comp.seal_archive("admin", None, None, NOW + timedelta(seconds=1),
                      archive_id="arc-del")
    records.delete("r1")
    r = comp.review_archive("admin", "arc-del", NOW + timedelta(seconds=2))
    assert r.data["entries"][0]["verdict"] == EntryVerdict.RESOURCE_MISSING.value


def test_review_detects_subject_level_change(service, subjects):
    comp = make_compliance(service)
    service.access("clerk", "r1", NOW)  # clerk 级别 1：phone MASKED，id_card HIDDEN
    comp.seal_archive("admin", None, None, NOW + timedelta(seconds=1),
                      archive_id="arc-lvl")
    # clerk 被提权到 3：id_card 变可见、phone 变明文
    subjects._subjects["clerk"] = Subject("clerk", 3, None)
    r = comp.review_archive("admin", "arc-lvl", NOW + timedelta(seconds=2))
    entry = r.data["entries"][0]
    logger.info("输入: clerk 1->3 提权 | 判定=%s 差异=%s", entry["verdict"], entry["diff"])
    assert entry["verdict"] == EntryVerdict.SUBJECT_CHANGED.value
    assert entry["diff"]["subject_level"] == {"sealed": 1, "current": 3}


def test_review_detects_tampered_archive_entry(service):
    comp = make_compliance(service)
    service.access("clerk", "r1", NOW)
    comp.seal_archive("admin", None, None, NOW + timedelta(seconds=1),
                      archive_id="arc-tamper")
    arc = comp.archives.get("arc-tamper")
    hacked = replace(arc.entries[0], presented={"name": "HACKED"})
    comp.archives._archives["arc-tamper"] = replace(arc, entries=(hacked,))

    r = comp.review_archive("admin", "arc-tamper", NOW + timedelta(seconds=2))
    entry = r.data["entries"][0]
    assert entry["verdict"] == EntryVerdict.TAMPERED.value
    assert "fingerprint" in entry["diff"]
    logger.info("档案被改 -> 复核判定 TAMPERED, current=%s", entry["current"])


def test_review_does_not_modify_archive_or_affect_live_access(service):
    comp = make_compliance(service)
    service.access("clerk", "r1", NOW)
    comp.seal_archive("admin", None, None, NOW + timedelta(seconds=1),
                      archive_id="arc-ro")
    before = comp.archives.get("arc-ro")
    comp.review_archive("admin", "arc-ro", NOW + timedelta(seconds=2))
    comp.review_archive("admin", "arc-ro", NOW + timedelta(seconds=3))
    after = comp.archives.get("arc-ro")
    assert before is after  # 复核只读：档案对象不被替换
    assert after.entries == before.entries
    # 实时访问仍正常，且不被复核动作改变
    live = service.access("clerk", "r1", NOW + timedelta(seconds=4))
    assert live.allowed and live.presented["name"] == "alice"


def test_review_unknown_archive_denied(service):
    comp = make_compliance(service)
    r = comp.review_archive("admin", "ghost-arc", NOW)
    logger.info("输入: 复核不存在档案 | 结果 allowed=%s reason=%s", r.allowed, r.reason)
    assert not r.allowed and r.reason is DenyReason.ARCHIVE_NOT_FOUND


def test_review_replays_with_pinned_historical_version(service, registry, records):
    """封存用 v1，之后发 v3 且数据也变；复核条目仍按各自封存版本重放。"""
    comp = make_compliance(service)
    service.access("clerk", "r1", NOW)
    registry.publish(make_rules_v2())
    service.access("clerk", "r1", NOW + timedelta(minutes=1))
    comp.seal_archive("admin", None, None, NOW + timedelta(minutes=2),
                      archive_id="arc-pin")
    # 数据漂移（name 是所有版本下 clerk 都可见的字段），两条都应识别为差异，
    # 且重放必须分别按封存时的 v1/v2，而不是按新发布的 v3 重新判定。
    records.upsert(SensitiveRecord("r1", {"name": "ALICE-X", "phone": "13911112222"}))
    registry.publish(RuleSet(version=3, field_modes={"phone": {1: MaskMode.PLAIN}},
                             retention_days=365))
    r = comp.review_archive("admin", "arc-pin", NOW + timedelta(minutes=3))
    verdicts = {e["sequence"]: e["verdict"] for e in r.data["entries"]}
    logger.info("版本固定复核: %s", verdicts)
    assert all(v == EntryVerdict.PRESENTATION_DIFF.value for v in verdicts.values())
    # 差异重放用的规则版本必须与封存时一致
    for e in r.data["entries"]:
        assert e["current"]["rule_version"] == e["sealed"]["rule_version"]


# ---- 审计成败一致 ----------------------------------------------------------

def test_audit_failure_aborts_seal_without_archive(service, audit):
    flaky = FlakySink(audit)
    svc = type(service)(service._subjects, service._records, service._rules, flaky)
    svc.access("clerk", "r1", NOW)  # 正常留痕
    comp = make_compliance(svc)
    flaky.fail = True
    r = comp.seal_archive("admin", None, None, NOW + timedelta(seconds=1),
                          archive_id="arc-fail")
    logger.info("审计故障封存: allowed=%s reason=%s data=%s",
                r.allowed, r.reason, r.data)
    assert not r.allowed and r.reason is DenyReason.AUDIT_FAILURE
    assert r.data is None
    assert comp.archives.get("arc-fail") is None  # 无半成品档案
    flaky.fail = False


def test_audit_failure_aborts_review(service, audit):
    flaky = FlakySink(audit)
    svc = type(service)(service._subjects, service._records, service._rules, flaky)
    good_comp = make_compliance(service)
    service.access("clerk", "r1", NOW)
    good_comp.seal_archive("admin", None, None, NOW + timedelta(seconds=1),
                           archive_id="arc-rf")
    bad_comp = make_compliance(svc)
    flaky.fail = True
    r = bad_comp.review_archive("admin", "arc-rf", NOW + timedelta(seconds=2))
    assert not r.allowed and r.reason is DenyReason.AUDIT_FAILURE and r.data is None


# ---- 并发：封存/切换/访问同时进行，请求不串版 ------------------------------

def test_concurrent_seal_and_publish_each_request_pins_one_version(service, registry):
    comp = make_compliance(service)
    errors: list[str] = []
    stop = threading.Event()

    def reader():
        for _ in range(400):
            if stop.is_set():
                break
            d = service.access("clerk", "r1", NOW)
            # 每次请求只认一个版本：v1 必有 MASKED phone，v2+ 不见 phone
            if d.rule_version == 1:
                if d.presented.get("phone") != "1*********1":
                    errors.append(f"v1 呈现异常 {d.presented}")
            elif d.presented.get("name") != "alice":
                errors.append(f"v{d.rule_version} 呈现异常 {d.presented}")

    def publisher():
        for v in range(2, 32):
            try:
                registry.publish(make_rules_v2() if v == 2 else RuleSet(
                    version=v,
                    field_modes={"name": {1: MaskMode.PLAIN},
                                 "phone": {2: MaskMode.MASKED, 3: MaskMode.PLAIN}},
                    retention_days=v,
                ))
            except Exception:
                pass

    def sealer():
        for k in range(10):
            comp.seal_archive("admin", None, None,
                              NOW + timedelta(minutes=10 + k),
                              archive_id=f"arc-c{k}")

    threads = [threading.Thread(target=reader) for _ in range(6)]
    threads += [threading.Thread(target=publisher), threading.Thread(target=sealer)]
    for t in threads:
        t.start()
    stop.set()
    for t in threads:
        t.join()

    # 每份档案内部：条目 rule_version 必须与呈现结论自洽，不出现新旧混用
    for arc_id in comp.archives.list_ids():
        arc = comp.archives.get(arc_id)
        for e in arc.entries:
            if e.rule_version == 1 and e.allowed:
                assert e.presented.get("phone") == "1*********1"
    logger.info("并发结束: 档案数=%d 事件数=%d 错误=%s",
                len(comp.archives.list_ids()), len(service.audit.events()), errors)
    assert errors == []
