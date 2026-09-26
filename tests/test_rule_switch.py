"""规则版本切换测试。

验证：
- 切换前已产生的审计结论与导出保持原样、可复现；
- 切换后的新请求按新规则判定；
- 历史规则版本可查询，重放结论与审计条目逐字段一致。
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from privacy_gateway.models import (
    ClearanceLevel,
    FieldPolicy,
    MaskingStrategy,
    RetentionPolicy,
    RuleVersion,
)


NOW = datetime(2026, 9, 26, tzinfo=timezone.utc)


def _publish_v2(rules):
    v2 = RuleVersion(
        version=2,
        published_at=NOW,
        field_policies={
            "customer": {
                # 新规则：INTERNAL 看到的是哈希而非部分明文；id_card 整体隐藏
                "phone": FieldPolicy(
                    "phone", ClearanceLevel.INTERNAL, MaskingStrategy.HASH,
                    full_level=ClearanceLevel.RESTRICTED,
                ),
                "email": FieldPolicy(
                    "email", ClearanceLevel.INTERNAL, MaskingStrategy.MASK,
                    full_level=ClearanceLevel.CONFIDENTIAL,
                ),
                "id_card": FieldPolicy(
                    "id_card", ClearanceLevel.RESTRICTED, MaskingStrategy.REDACT,
                    full_level=ClearanceLevel.RESTRICTED,
                ),
                "address": FieldPolicy(
                    "address", ClearanceLevel.CONFIDENTIAL,
                    MaskingStrategy.VISIBLE,
                ),
            }
        },
        retention=RetentionPolicy(retain_days=90),
    )
    rules.publish(v2)


def test_old_decision_remains_reproducible_after_switch(components):
    svc = components["service"]
    replayer = components["replayer"]
    exporter = components["exporter"]

    old = svc.access(subject_id="alice", record_id="rec-1", now=NOW)
    old_phone = old.presented["phone"].value
    assert old_phone == "138****1234"
    assert old.rule_version == 1

    export_v1 = exporter.export(old.decision_id, now=NOW)
    assert export_v1["fields"]["phone"]["value"] == "138****1234"

    _publish_v2(components["rules"])
    assert components["rules"].current_snapshot().rule.version == 2

    # 新请求按新规则
    new = svc.access(subject_id="alice", record_id="rec-1", now=NOW)
    print(f"[INPUT] after switch subject=alice rule=v2")
    assert new.rule_version == 2
    assert new.presented["phone"].value.startswith("sha256:")
    assert new.presented["id_card"].visible is False  # v2 下 INTERNAL 被隐藏

    # 旧审计结论保持原样
    old_entry = components["audit"].get(old.decision_id)
    assert old_entry.rule_version == 1
    assert old_entry.presented["phone"]["value"] == "138****1234"

    # 旧判定可按历史规则版本重放且一致
    assert replayer.verify(old.decision_id) is True
    replayed = replayer.replay(old.decision_id)
    assert replayed.presented["phone"].value == "138****1234"

    # 旧导出保持原样（重复导出返回同一固化结果）
    export_again = exporter.export(old.decision_id, now=NOW)
    assert export_again == export_v1
    assert export_again["rule_version"] == 1


def test_new_rule_replay_consistent(components):
    svc = components["service"]
    replayer = components["replayer"]
    _publish_v2(components["rules"])
    new = svc.access(subject_id="bob", record_id="rec-1", now=NOW)
    assert replayer.verify(new.decision_id) is True


def test_historical_rule_versions_retained(components):
    rules = components["rules"]
    _publish_v2(rules)
    assert rules.snapshot_of(1).rule.version == 1
    assert rules.snapshot_of(2).rule.version == 2
    with pytest.raises(KeyError):
        rules.snapshot_of(99)


def test_retention_policy_is_versioned(components):
    rules = components["rules"]
    assert rules.current_snapshot().rule.retention.retain_days == 3650
    _publish_v2(rules)
    assert rules.current_snapshot().rule.retention.retain_days == 90
    # 历史版本留存规则不变
    assert rules.snapshot_of(1).rule.retention.retain_days == 3650


def test_version_must_monotonically_increase(components):
    rules = components["rules"]
    duplicate = RuleVersion(version=1, published_at=NOW)
    with pytest.raises(ValueError):
        rules.publish(duplicate)


def test_concurrent_requests_during_switch_never_mix_rules(components):
    """规则切换期间的并发请求：要么全用旧版，要么全用新版，不混用。

    通过事件栅栏把 N 个请求精确停在“已抓到 v1 快照、尚未判定”的窗口内，
    主线程在此窗口发布 v2，再放行所有请求——它们必须全部按 v1 判定。
    """
    import threading
    from privacy_gateway.audit import AuditLog
    from privacy_gateway.service import AccessService

    rules = components["rules"]
    captured = threading.Event()
    released = threading.Event()
    count = {"n": 0}
    count_lock = threading.Lock()
    n_workers = 8

    class PausedRegistry(type(rules)):
        def current_snapshot(self):
            snap = super().current_snapshot()
            with count_lock:
                count["n"] += 1
                if count["n"] == n_workers:
                    captured.set()
            released.wait()
            return snap

    # 用被拦截的注册表替换组件中的注册表（共享历史版本）
    paused = PausedRegistry(rules.snapshot_of(1).rule)
    audit = AuditLog()
    svc = AccessService(components["records"], components["grants"], paused, audit)

    results: list[object] = []
    results_lock = threading.Lock()

    def worker():
        d = svc.access(subject_id="alice", record_id="rec-1", now=NOW)
        with results_lock:
            results.append(d)

    threads = [threading.Thread(target=worker) for _ in range(n_workers)]
    for t in threads:
        t.start()
    assert captured.wait(timeout=5), "workers did not capture snapshot"

    # 切换发生在所有请求的快照窗口内
    _publish_v2(paused)
    released.set()
    for t in threads:
        t.join(timeout=5)

    assert len(results) == n_workers
    versions = {d.rule_version for d in results}
    print(f"[INPUT] concurrent rule switch, versions seen={versions}")
    assert versions == {1}, "并发请求混用了新旧规则"
    # 依据 v1：phone 必须全部为部分脱敏，id_card 全部隐藏
    assert {d.presented["phone"].value for d in results} == {"138****1234"}
    assert {d.presented["id_card"].visible for d in results} == {False}
    # 切换后新请求按 v2
    after = svc.access(subject_id="alice", record_id="rec-1", now=NOW)
    assert after.rule_version == 2
    assert after.presented["phone"].value.startswith("sha256:")


def test_requests_started_after_switch_all_use_new_rule(components):
    import threading
    svc = components["service"]
    _publish_v2(components["rules"])

    results = []
    threads = [
        threading.Thread(target=lambda: results.append(
            svc.access(subject_id="alice", record_id="rec-1", now=NOW)))
        for _ in range(6)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5)
    assert {d.rule_version for d in results} == {2}
