"""测试公共夹具：构造带演示数据的网关服务。"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

import pytest

from gateway.audit import InMemoryAuditSink
from gateway.authz import SubjectStore
from gateway.models import MaskMode, SensitiveRecord, Subject
from gateway.rules import RuleRegistry, RuleSet
from gateway.service import GatewayService, RecordStore

logger = logging.getLogger("gateway-test")

NOW = datetime(2026, 9, 26, tzinfo=timezone.utc)


def make_rules_v1() -> RuleSet:
    return RuleSet(version=1, field_modes={
        "name": {1: MaskMode.PLAIN},
        "phone": {1: MaskMode.MASKED, 3: MaskMode.PLAIN},
        "id_card": {2: MaskMode.MASKED, 3: MaskMode.PLAIN},
    }, retention_days=30)


def make_rules_v2() -> RuleSet:
    """演进后的规则：phone 对级别 1 也不再可见，id_card 级别 3 仅脱敏。"""
    return RuleSet(version=2, field_modes={
        "name": {1: MaskMode.PLAIN},
        "phone": {2: MaskMode.MASKED, 3: MaskMode.PLAIN},
        "id_card": {3: MaskMode.MASKED},
    }, retention_days=90)


@pytest.fixture()
def subjects() -> SubjectStore:
    return SubjectStore({
        "admin": Subject("admin", level=3, expires_at=None),
        "analyst": Subject("analyst", level=2, expires_at=None),
        "clerk": Subject("clerk", level=1, expires_at=None),
        "zero": Subject("zero", level=0, expires_at=None),
        "expired": Subject("expired", level=3, expires_at=NOW - timedelta(days=1)),
    })


@pytest.fixture()
def records() -> RecordStore:
    return RecordStore({
        "r1": SensitiveRecord("r1", {
            "name": "alice",
            "phone": "13800001111",
            "id_card": "110101199001011234",
        }),
    })


@pytest.fixture()
def audit() -> InMemoryAuditSink:
    return InMemoryAuditSink()


@pytest.fixture()
def registry() -> RuleRegistry:
    return RuleRegistry(make_rules_v1())


@pytest.fixture()
def service(subjects, records, registry, audit) -> GatewayService:
    return GatewayService(subjects, records, registry, audit)
