"""HTTP 接口级测试。"""

from __future__ import annotations


def test_get_record_returns_basis_and_version(client):
    r = client.get("/records/rec-1?subject_id=alice")
    assert r.status_code == 200
    body = r.json()
    assert body["rule_version"] == 1
    assert body["fields"]["phone"]["value"] == "138****1234"
    assert "field.phone" in body["basis"]
    assert "decision_id" in body


def test_publish_rule_changes_subsequent_decisions(client):
    r = client.post("/admin/rules", json={
        "version": 2,
        "field_policies": {
            "customer": {
                "phone": {"min_level": "INTERNAL", "strategy": "hash",
                          "full_level": "RESTRICTED"},
            }
        },
        "retention_days": 30,
    })
    assert r.status_code == 200
    assert r.json() == {"published": 2}

    r = client.get("/records/rec-1?subject_id=alice")
    body = r.json()
    assert body["rule_version"] == 2
    assert body["fields"]["phone"]["value"].startswith("sha256:")

    r = client.get("/admin/rules/current")
    assert r.json()["version"] == 2
    r = client.get("/admin/rules/1")
    assert r.status_code == 200
    assert r.json()["retention_days"] == 3650
    r = client.get("/admin/rules/99")
    assert r.status_code == 404


def test_export_and_audit_verify_endpoints(client):
    r = client.get("/records/rec-1?subject_id=bob")
    decision_id = r.json()["decision_id"]

    r = client.post(f"/exports/{decision_id}")
    assert r.status_code == 200
    export1 = r.json()
    assert export1["rule_version"] == 1
    assert export1["fields"]["id_card"]["value"].startswith("sha256:")
    # 重复导出一致
    r = client.post(f"/exports/{decision_id}")
    assert r.json() == export1

    r = client.get(f"/audit/{decision_id}/verify")
    assert r.status_code == 200
    assert r.json() == {"decision_id": decision_id, "consistent": True}

    r = client.get("/audit")
    assert any(e["decision_id"] == decision_id for e in r.json())
    # 拒绝也留痕
    client.get("/records/rec-1?subject_id=eve")
    entries = client.get("/audit").json()
    deny = [e for e in entries if e["deny_reason"] == "unauthorized"]
    assert deny and deny[0]["result"] == "deny"


def test_export_unknown_decision_404(client):
    r = client.post("/exports/nope")
    assert r.status_code == 404


def test_publish_invalid_enum_and_duplicate_version_400(client):
    r = client.post("/admin/rules", json={
        "version": 2,
        "field_policies": {
            "customer": {"phone": {"min_level": "INTERNAL", "strategy": "WAT"}},
        },
    })
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_request"

    r = client.post("/admin/rules", json={"version": 1})
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_request"
    # 失败后当前版本仍是 v1
    assert client.get("/admin/rules/current").json()["version"] == 1
