"""HTTP 层端到端：访问、规则热切换、审计导出。"""
from __future__ import annotations

import logging

from fastapi.testclient import TestClient

from main import app, service

logger = logging.getLogger("gateway-test")


def client() -> TestClient:
    return TestClient(app)


def test_access_levels_over_http():
    c = client()
    r = c.get("/records/r1", headers={"X-Subject-Id": "admin"})
    assert r.status_code == 200
    body = r.json()
    logger.info("admin 响应: %s", body)
    assert body["allowed"] and body["presented"]["phone"] == "13800001111"

    r = c.get("/records/r1", headers={"X-Subject-Id": "clerk"})
    body = r.json()
    logger.info("clerk 响应: %s", body)
    assert body["allowed"] and body["presented"]["phone"] == "1*********1"
    assert "id_card" not in body["presented"]


def test_deny_reasons_distinct_over_http():
    c = client()
    cases = [
        ({"X-Subject-Id": "ghost"}, "/records/r1", "SUBJECT_UNKNOWN"),
        ({"X-Subject-Id": "expired"}, "/records/r1", "GRANT_EXPIRED"),
        ({"X-Subject-Id": "admin"}, "/records/nope", "RESOURCE_NOT_FOUND"),
    ]
    reasons = set()
    for headers, path, expected in cases:
        body = c.get(path, headers=headers).json()
        logger.info("请求 %s %s -> %s", headers, path, body)
        assert body["allowed"] is False and body["reason"] == expected
        reasons.add(body["reason"])
    assert len(reasons) == 3


def test_rule_publish_and_audit_export_over_http():
    c = client()
    before = c.get("/records/r1", headers={"X-Subject-Id": "clerk"}).json()
    assert before["rule_version"] == 1

    r = c.post("/rules", json={
        "version": 2,
        "field_modes": {
            "name": {"1": "PLAIN"},
            "phone": {"2": "MASKED", "3": "PLAIN"},
            "id_card": {"3": "MASKED"},
        },
        "retention_days": 90,
    })
    assert r.status_code == 201

    after = c.get("/records/r1", headers={"X-Subject-Id": "clerk"}).json()
    logger.info("切换前=%s 切换后=%s", before, after)
    assert after["rule_version"] == 2 and "phone" not in after["presented"]

    audit = c.get("/audit").json()
    assert len(audit) >= 2
    # 找到本次 clerk 在 v1 下的请求对应的审计条目，确认其结论原样保留
    clerk_v1 = [e for e in audit
                if e["rule_version"] == 1 and e["subject_id"] == "clerk"]
    assert clerk_v1 and clerk_v1[-1]["presented"] == before["presented"]
