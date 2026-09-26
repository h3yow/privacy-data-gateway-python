"""授权级别与分级呈现测试。

覆盖：INTERNAL / CONFIDENTIAL / RESTRICTED 三级可见性差异，
以及未授权 / 授权过期 / 资源不存在 / 密级不足四类可区分拒绝原因。
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from privacy_gateway.errors import (
    ClearanceInsufficientError,
    GrantExpiredError,
    ResourceNotFoundError,
    UnauthorizedError,
)
from privacy_gateway.models import ClearanceLevel, Grant, Record
from privacy_gateway.models import DecisionResult


NOW = datetime(2026, 9, 26, tzinfo=timezone.utc)


def test_internal_level_partial_presentation(components):
    svc = components["service"]
    decision = svc.access(subject_id="alice", record_id="rec-1", now=NOW)
    fields = decision.presented
    print(f"[INPUT] subject=alice level=INTERNAL rule=v1")
    assert decision.result is DecisionResult.ALLOW
    assert fields["name"].value == "Zhang San"
    assert fields["phone"].value == "138****1234"          # 部分脱敏
    assert fields["email"].value == "****"                 # 掩码
    assert fields["id_card"].visible is False              # 密级不足 -> 隐藏
    assert fields["id_card"].value is None
    assert fields["address"].visible is False


def test_confidential_level_more_visible(components):
    svc = components["service"]
    decision = svc.access(subject_id="bob", record_id="rec-1", now=NOW)
    fields = decision.presented
    print(f"[INPUT] subject=bob level=CONFIDENTIAL rule=v1")
    assert fields["phone"].value == "13800001234"          # full_level 明文
    assert fields["email"].value == "zhangsan@example.com"
    assert fields["id_card"].value.startswith("sha256:")   # 哈希呈现
    assert fields["address"].value == "Beijing Haidian"


def test_restricted_level_full_plaintext(components):
    svc = components["service"]
    decision = svc.access(subject_id="carol", record_id="rec-1", now=NOW)
    fields = decision.presented
    print(f"[INPUT] subject=carol level=RESTRICTED rule=v1")
    assert fields["id_card"].value == "110101199001011234"  # 明文
    assert fields["phone"].value == "13800001234"


def test_deny_unauthorized_is_distinguishable(components):
    svc = components["service"]
    print("[INPUT] subject=eve grant=<none>")
    with pytest.raises(UnauthorizedError) as exc:
        svc.access(subject_id="eve", record_id="rec-1", now=NOW)
    assert exc.value.reason_code == "unauthorized"
    entry = components["audit"].list_all()[-1]
    assert entry.deny_reason == "unauthorized"


def test_deny_expired_is_distinguishable(components):
    svc = components["service"]
    print("[INPUT] subject=dave grant=expired@2020-01-01")
    with pytest.raises(GrantExpiredError) as exc:
        svc.access(subject_id="dave", record_id="rec-1", now=NOW)
    assert exc.value.reason_code == "grant_expired"


def test_deny_resource_not_found_is_distinguishable(components):
    svc = components["service"]
    print("[INPUT] record=missing")
    with pytest.raises(ResourceNotFoundError) as exc:
        svc.access(subject_id="alice", record_id="missing", now=NOW)
    assert exc.value.reason_code == "resource_not_found"
    assert exc.value.http_status == 404


def test_deny_clearance_insufficient(components):
    records = components["records"]
    grants = components["grants"]
    records.put(Record(
        record_id="rec-restricted",
        record_type="customer",
        required_level=ClearanceLevel.RESTRICTED,
        data={"name": "Secret"},
    ))
    grants.put(Grant("alice", "rec-restricted", ClearanceLevel.INTERNAL))
    svc = components["service"]
    print("[INPUT] subject=alice level=INTERNAL required=RESTRICTED")
    with pytest.raises(ClearanceInsufficientError) as exc:
        svc.access(subject_id="alice", record_id="rec-restricted", now=NOW)
    assert exc.value.reason_code == "clearance_insufficient"


def test_presentation_is_deterministic_regardless_of_order(components):
    """同一主体、同一记录、同一规则版本：重复访问呈现结果完全一致。"""
    svc = components["service"]
    d1 = svc.access(subject_id="alice", record_id="rec-1", now=NOW)
    d2 = svc.access(subject_id="bob", record_id="rec-1", now=NOW)
    d3 = svc.access(subject_id="alice", record_id="rec-1", now=NOW)
    d4 = svc.access(subject_id="alice", record_id="rec-1", now=NOW)

    def snapshot(decision):
        return {k: (v.value, v.strategy.value, v.visible)
                for k, v in decision.presented.items()}

    assert snapshot(d1) == snapshot(d3) == snapshot(d4)
    assert snapshot(d1) != snapshot(d2)  # 不同授权级别仍有差异


def test_deny_reasons_distinct_via_http(client):
    cases = [
        ("eve", "rec-1", 403, "unauthorized"),
        ("dave", "rec-1", 403, "grant_expired"),
        ("alice", "missing", 404, "resource_not_found"),
    ]
    for subject, record, status, code in cases:
        r = client.get(f"/records/{record}?subject_id={subject}")
        print(f"[INPUT] GET subject={subject} record={record}")
        assert r.status_code == status
        assert r.json()["error"] == code


def test_audit_entry_contains_basis(components):
    svc = components["service"]
    svc.access(subject_id="alice", record_id="rec-1", now=NOW)
    entry = components["audit"].list_all()[-1]
    assert entry.basis["rule_version"] == "1"
    assert "field.phone" in entry.basis
    assert entry.result is DecisionResult.ALLOW
