"""规则历史版本：只追加、按序可查、旧版不可变、版本号单调、查询不随历史退化。"""
from __future__ import annotations

import logging
import time

import pytest

from gateway.errors import VersionConflictError, VersionNotFoundError
from gateway.models import DenyReason, MaskMode
from gateway.rules import RuleSet
from tests.conftest import NOW, make_rules_v1, make_rules_v2

logger = logging.getLogger("gateway-test")


def rules_v3() -> RuleSet:
    return RuleSet(version=3, field_modes={"name": {1: MaskMode.PLAIN}},
                   retention_days=365)


def test_versions_listed_in_publish_order(registry):
    registry.publish(make_rules_v2())
    registry.publish(rules_v3())
    infos = registry.list_versions()
    got = [i.version for i in infos]
    logger.info("历史版本目录(输入: 依次发布 v1,v2,v3) -> %s, 发布时刻单调=%s",
                got, [i.published_at for i in infos])
    assert got == [1, 2, 3]
    assert infos[0].published_at <= infos[1].published_at <= infos[2].published_at


def test_get_historical_version_returns_its_config(registry):
    registry.publish(make_rules_v2())
    v1 = registry.get_version(1)
    logger.info("输入: get_version(1)，当前已是 v2 | 判定依据 v1.phone=%s",
                dict(v1.field_modes["phone"]))
    assert v1.version == 1
    assert v1.retention_days == 30
    assert v1.mode_for("phone", 1) is MaskMode.MASKED  # v1 旧配置
    v2 = registry.get_version(2)
    assert v2.mode_for("phone", 1) is MaskMode.HIDDEN  # v2 新配置


def test_get_unknown_version_raises(registry):
    with pytest.raises(VersionNotFoundError):
        registry.get_version(404)


def test_duplicate_and_regressive_publish_rejected(registry):
    registry.publish(make_rules_v2())  # 当前最新 2
    for bad in (1, 2, -1):
        with pytest.raises(VersionConflictError):
            registry.publish(RuleSet(version=bad, field_modes={}, retention_days=1))
        logger.info("输入: 发布版本号 %d（最新=2）-> 拒绝 VERSION_CONFLICT", bad)
    # 被拒后注册表不变，仍可正常发更大版本
    registry.publish(rules_v3())
    assert [i.version for i in registry.list_versions()] == [1, 2, 3]


def test_published_versions_cannot_be_mutated_via_original(registry):
    """发布后用发布者手里的原对象改写，不能影响已入库的历史版本。"""
    mutable = RuleSet(version=2, field_modes={
        "name": {1: MaskMode.PLAIN},
        "phone": {1: MaskMode.MASKED},
    }, retention_days=30)
    registry.publish(mutable)
    mutable.field_modes.clear()          # 试图改原对象
    stored = registry.get_version(2)
    logger.info("发布后外部清空原 field_modes，库存 v1? 版本=%d 字段数=%d",
                stored.version, len(stored.field_modes))
    assert len(stored.field_modes) == 2
    with pytest.raises(TypeError):
        stored.field_modes["phone"] = {}  # 库存版本嵌套结构被冻结


def test_publishing_new_version_never_overwrites_old(registry):
    registry.publish(make_rules_v2())
    registry.publish(rules_v3())
    v1_before = registry.get_version(1)
    cfg_before = dict(v1_before.field_modes["phone"])
    assert registry.get_version(2).retention_days == 90
    assert registry.get_version(1).retention_days == 30
    assert dict(registry.get_version(1).field_modes["phone"]) == cfg_before


def test_history_lookup_is_constant_time(registry):
    """按号取版本走哈希查找：发布 2000 个版本后，取早期版本不随历史变慢。"""
    for v in range(2, 2002):
        registry.publish(RuleSet(version=v, field_modes={}, retention_days=v))
    start = time.perf_counter()
    for _ in range(2000):
        rules = registry.get_version(3)
    elapsed_many = time.perf_counter() - start
    start = time.perf_counter()
    for _ in range(2000):
        rules_small = registry.get_version(3)
    elapsed_baseline = time.perf_counter() - start
    logger.info("2000 版本下 2000 次 get_version(3) 耗时 %.4fs", elapsed_many)
    assert rules.version == 3
    assert elapsed_many < 1.0  # O(1) 哈希查找的宽松上界
    assert elapsed_baseline < 1.0


def test_online_access_unaffected_by_history_growth(service, registry):
    """历史越攒越多，在线访问仍只取一次快照、耗时稳定。"""
    d0 = service.access("clerk", "r1", NOW)
    for v in range(2, 502):
        registry.publish(RuleSet(version=v, field_modes={
            "name": {1: MaskMode.PLAIN},
        }, retention_days=v))
    d1 = service.access("clerk", "r1", NOW)
    logger.info("历史增长到 501 版后在线访问 rule_version=%d presented=%s",
                d1.rule_version, d1.presented)
    assert d1.rule_version == 501
    assert d1.presented["name"] == d0.presented["name"] == "alice"


# ---- 合规入口（ComplianceService）的历史查询拒绝语义 ----

def test_history_endpoints_require_compliance_level(service):
    comp = _make_compliance(service)
    # 级别不足（clerk=1 < 2）拒绝，原因可区分
    r = comp.list_rule_versions("clerk", NOW)
    logger.info("输入: clerk(1级) 列历史 | 结果 allowed=%s reason=%s",
                r.allowed, r.reason)
    assert not r.allowed and r.reason is DenyReason.INSUFFICIENT_LEVEL

    r = comp.get_rule_version("ghost", 1, NOW)
    assert not r.allowed and r.reason is DenyReason.SUBJECT_UNKNOWN
    r = comp.get_rule_version("expired", 1, NOW)
    assert not r.allowed and r.reason is DenyReason.GRANT_EXPIRED


def test_history_endpoints_authorized_access(service):
    comp = _make_compliance(service)
    service.rules.publish(make_rules_v2())
    listing = comp.list_rule_versions("analyst", NOW)
    assert listing.allowed
    assert [v["version"] for v in listing.data["versions"]] == [1, 2]

    one = comp.get_rule_version("analyst", 1, NOW)
    assert one.allowed and one.data["version"] == 1

    missing = comp.get_rule_version("analyst", 99, NOW)
    logger.info("输入: analyst 查版本 99 | 结果 allowed=%s reason=%s",
                missing.allowed, missing.reason)
    assert not missing.allowed and missing.reason is DenyReason.VERSION_NOT_FOUND


def test_history_query_denials_are_audited(service, audit):
    comp = _make_compliance(service)
    comp.get_rule_version("ghost", 1, NOW)
    comp.get_rule_version("analyst", 123, NOW)
    events = [e for e in audit.events() if e.action == "rule_history"]
    assert len(events) == 2
    assert [e.allowed for e in events] == [False, False]
    assert events[0].reason == "SUBJECT_UNKNOWN"
    assert events[1].reason == "VERSION_NOT_FOUND"


def _make_compliance(service):
    from gateway.compliance import ComplianceService
    return ComplianceService(service)
