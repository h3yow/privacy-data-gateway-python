"""授权级别分级呈现与可区分拒绝原因。"""
from __future__ import annotations

import logging

from gateway.models import DenyReason
from tests.conftest import NOW

logger = logging.getLogger("gateway-test")


def check(service, subject_id, record_id="r1"):
    d = service.access(subject_id, record_id, NOW)
    logger.info(
        "输入 subject=%s record=%s | 判定依据 rule_version=%d | 结果 allowed=%s reason=%s presented=%s",
        subject_id, record_id, d.rule_version, d.allowed,
        d.reason.value if d.reason else None, d.presented,
    )
    return d


def test_admin_sees_everything_plain(service):
    d = check(service, "admin")
    assert d.allowed
    assert d.presented == {
        "name": "alice",
        "phone": "13800001111",
        "id_card": "110101199001011234",
    }
    assert d.rule_version == 1


def test_analyst_sees_masked_id_card(service):
    d = check(service, "analyst")
    assert d.allowed
    assert d.presented["phone"] == "1*********1"          # MASKED
    assert d.presented["id_card"] == "1****************4"  # MASKED
    assert d.presented["name"] == "alice"                  # PLAIN


def test_clerk_cannot_see_id_card(service):
    d = check(service, "clerk")
    assert d.allowed
    assert "id_card" not in d.presented  # HIDDEN 字段不出现
    assert d.presented["phone"] == "1*********1"


def test_zero_level_denied_insufficient(service):
    d = check(service, "zero")
    assert not d.allowed and d.reason is DenyReason.INSUFFICIENT_LEVEL


def test_unknown_subject_denied(service):
    d = check(service, "ghost")
    assert not d.allowed and d.reason is DenyReason.SUBJECT_UNKNOWN


def test_expired_grant_denied(service):
    d = check(service, "expired")
    assert not d.allowed and d.reason is DenyReason.GRANT_EXPIRED


def test_missing_record_denied(service):
    d = check(service, "admin", record_id="nope")
    assert not d.allowed and d.reason is DenyReason.RESOURCE_NOT_FOUND


def test_deny_reasons_are_distinct(service):
    reasons = {
        check(service, "ghost").reason,
        check(service, "expired").reason,
        check(service, "admin", "nope").reason,
        check(service, "zero").reason,
    }
    assert len(reasons) == 4  # 四种拒绝原因互不相同


def test_presentation_is_deterministic(service):
    first = check(service, "clerk").presented
    for _ in range(20):
        assert check(service, "clerk").presented == first
