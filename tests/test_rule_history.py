"""规则历史版本：单调发布、旧版永留、冲突当场拒绝、查询不随历史退化。"""
from __future__ import annotations

import logging
import threading
import time

import pytest

from gateway.models import DenyReason
from gateway.rules import RuleVersionConflictError
from tests.conftest import NOW, make_rules_v1, make_rules_v2

logger = logging.getLogger("gateway-test")


def test_published_versions_kept_in_order(registry):
    registry.publish(make_rules_v2())
    versions = [r.version for r in registry.history()]
    logger.info("发布顺序历史=%s", versions)
    assert versions == [1, 2]
    assert registry.latest_version() == 2


def test_duplicate_version_rejected(registry):
    dup = make_rules_v1()
    with pytest.raises(RuleVersionConflictError) as exc:
        registry.publish(dup)
    logger.info("重复发布 v1 被拒: attempted=%s latest=%s",
                exc.value.attempted, exc.value.latest)
    assert exc.value.attempted == 1 and exc.value.latest == 1
    assert registry.latest_version() == 1          # 现行版本不变
    assert [r.version for r in registry.history()] == [1]


def test_lower_version_rejected_after_newer_published(registry):
    registry.publish(make_rules_v2())
    back = make_rules_v1()
    with pytest.raises(RuleVersionConflictError):
        registry.publish(back)
    logger.info("回退发布 v1 被拒，最新仍为 %s", registry.latest_version())
    assert registry.latest_version() == 2


def test_rejected_publish_preserves_all_history(registry):
    registry.publish(make_rules_v2())
    with pytest.raises(RuleVersionConflictError):
        registry.publish(make_rules_v2())   # 再发同号
    assert [r.version for r in registry.history()] == [1, 2]


def test_history_version_returns_exact_config(registry):
    registry.publish(make_rules_v2())
    v1 = registry.history_version(1)
    assert v1 is not None and v1.retention_days == 30
    # v1 当时 clerk(1级) 可见脱敏 phone；v2 不可见
    assert v1.mode_for("phone", 1).value == "MASKED"
    assert registry.history_version(2).mode_for("phone", 1).value == "HIDDEN"
    assert registry.history_version(99) is None
    logger.info("v1 phone@1=%s v2 phone@1=%s",
                v1.mode_for("phone", 1), registry.history_version(2).mode_for("phone", 1))


def test_history_pagination_is_fixed_size(registry):
    for v in range(2, 12):
        rs = make_rules_v2()
        object.__setattr__(rs, "version", v)
        registry.publish(rs)
    page1 = [r.version for r in registry.history(limit=3)]
    page2 = [r.version for r in registry.history(limit=3, offset=3)]
    last = [r.version for r in registry.history(limit=3, offset=9)]
    logger.info("分页 page1=%s page2=%s last=%s", page1, page2, last)
    assert page1 == [1, 2, 3] and page2 == [4, 5, 6] and last == [10, 11]


def test_history_lookup_does_not_degrade(registry):
    for v in range(2, 3002):
        rs = make_rules_v1()
        object.__setattr__(rs, "version", v)
        registry.publish(rs)
    start = time.perf_counter()
    for v in (1, 1500, 3001):
        assert registry.history_version(v).version == v
    elapsed = time.perf_counter() - start
    logger.info("3001 个版本中按号查 3 次耗时 %.6fs", elapsed)
    assert elapsed < 0.01  # O(1)：三千历史与个位数历史同量级


def test_old_version_not_mutated_by_later_publish(registry):
    v1_before = registry.history_version(1)
    registry.publish(make_rules_v2())
    v1_after = registry.history_version(1)
    assert v1_before is v1_after                      # 同一不可变对象
    assert {l: m.value for l, m in v1_after.field_modes["phone"].items()} == {
        1: "MASKED", 3: "PLAIN",
    }


def test_ruleset_immutable_to_caller_mutation():
    # 通过 main 发布路径同样安全；这里直接构造验证冻结
    from gateway.models import MaskMode
    from gateway.rules import RuleSet
    raw = {"phone": {1: MaskMode.MASKED}}
    rs = RuleSet(version=1, field_modes=raw)
    raw["phone"][1] = MaskMode.PLAIN                 # 调用方事后改入参
    raw["injected"] = {1: MaskMode.PLAIN}
    assert rs.mode_for("phone", 1) is MaskMode.MASKED
    assert rs.mode_for("injected", 1).value == "HIDDEN"
    logger.info("入参被改后已发布规则 phone@1=%s", rs.mode_for("phone", 1))


def test_concurrent_publish_each_version_once(registry):
    accepted: list[int] = []
    rejected: list[int] = []
    barrier = threading.Barrier(8)

    def worker(base: int):
        barrier.wait()
        for v in range(base, base + 3):  # 各线程版本区间重叠制造竞争
            rs = make_rules_v1()
            object.__setattr__(rs, "version", v)
            try:
                registry.publish(rs)
                accepted.append(v)
            except RuleVersionConflictError:
                rejected.append(v)

    threads = [threading.Thread(target=worker, args=(2 + i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    versions = [r.version for r in registry.history()]
    logger.info("并发发布 accepted=%s rejected=%s 历史=%s",
                sorted(accepted), sorted(rejected), versions)
    assert len(versions) == len(set(versions))       # 无重复版本
    assert versions == sorted(versions)              # 严格递增
    assert versions[0] == 1


def test_get_history_version_deny_semantics(service):
    ghost = service.get_rule_version("ghost", 1, NOW)
    assert not ghost.ok and ghost.reason is DenyReason.SUBJECT_UNKNOWN
    missing = service.get_rule_version("admin", 999, NOW)
    assert not missing.ok and missing.reason is DenyReason.VERSION_NOT_FOUND
    ok = service.get_rule_version("admin", 1, NOW)
    assert ok.ok and ok.payload.version == 1
    logger.info("历史查询拒绝原因: ghost=%s missing=%s",
                ghost.reason, missing.reason)
