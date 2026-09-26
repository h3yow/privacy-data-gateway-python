"""规则运行中切换：新请求按新版本，旧审计结论保持原样且可复现。"""
from __future__ import annotations

import logging
import threading

from gateway.models import MaskMode
from gateway.rules import RuleRegistry, RuleSet
from gateway.service import GatewayService
from tests.conftest import NOW, make_rules_v1, make_rules_v2

logger = logging.getLogger("gateway-test")


def test_new_requests_use_new_rules(service, registry):
    before = service.access("clerk", "r1", NOW)
    assert before.rule_version == 1 and before.presented["phone"] == "1*********1"

    registry.publish(make_rules_v2())

    after = service.access("clerk", "r1", NOW)
    logger.info("切换前 presented=%s | 切换后 presented=%s", before.presented, after.presented)
    assert after.rule_version == 2
    assert "phone" not in after.presented  # v2 中 clerk(1级) 不可见 phone


def test_old_audit_entries_remain_reproducible(service, registry, audit):
    d1 = service.access("clerk", "r1", NOW)
    registry.publish(make_rules_v2())
    service.access("clerk", "r1", NOW)

    events = audit.events()
    assert events[0].rule_version == 1
    assert events[0].presented == d1.presented  # 旧结论未被改写
    assert events[1].rule_version == 2
    # 复现：用 v1 规则重新判定，结果与历史审计一致
    replay_svc = GatewayService(service._subjects, service._records,
                                RuleRegistry(make_rules_v1()), audit)
    assert replay_svc.access("clerk", "r1", NOW).presented == events[0].presented


def _variant_rules(version: int) -> RuleSet:
    """奇偶交替的两种规则，用于并发切换压测。"""
    if version % 2 == 0:
        return RuleSet(version=version, field_modes={
            "name": {1: MaskMode.PLAIN},
            "phone": {2: MaskMode.MASKED},
        })
    return RuleSet(version=version, field_modes={})


def test_concurrent_requests_never_mix_rule_versions(service, registry):
    """切换期间并发请求：每个请求的判定与版本标记必须自洽。"""
    v1_phone = "1*********1"  # v1: clerk 可见 MASKED phone
    errors: list[str] = []
    stop = threading.Event()

    def reader():
        while not stop.is_set():
            d = service.access("clerk", "r1", NOW)
            if d.rule_version == 1 and d.presented.get("phone") != v1_phone:
                errors.append(f"v1 判定异常: {d.presented}")
            elif d.rule_version == 2 and "phone" in d.presented:
                errors.append(f"v2 判定异常: {d.presented}")
            elif d.rule_version >= 3:
                # 压测变体：偶数版 clerk 不见 phone，奇数版全 HIDDEN
                if "phone" in d.presented:
                    errors.append(f"v{d.rule_version} 判定异常: {d.presented}")

    threads = [threading.Thread(target=reader) for _ in range(8)]
    for t in threads:
        t.start()
    for v in range(2, 12):  # 反复切换版本制造竞争
        registry.publish(make_rules_v2() if v == 2 else _variant_rules(v))
    stop.set()
    for t in threads:
        t.join()
    logger.info("并发期间完成请求数=%d 错误=%s", len(service.audit.events()), errors)
    assert errors == []
