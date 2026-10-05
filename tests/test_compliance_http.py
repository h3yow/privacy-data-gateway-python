"""HTTP 端到端：规则版本冲突、历史查询、封存、复核与可区分拒绝语义。"""
from __future__ import annotations

import logging

from fastapi.testclient import TestClient

from main import app

logger = logging.getLogger("gateway-test")


def client() -> TestClient:
    return TestClient(app)


def test_publish_duplicate_version_returns_409():
    c = client()
    # 默认服务初始为 v1；再发 v1 必须被拒，且注册表不变
    r = c.post("/rules", json={
        "version": 1,
        "field_modes": {"name": {"1": "PLAIN"}},
        "retention_days": 7,
    })
    logger.info("输入: POST /rules version=1（已存在）-> 状态码=%d body=%s",
                r.status_code, r.json())
    assert r.status_code == 409
    assert r.json()["detail"]["reason"] == "VERSION_CONFLICT"
    # 当前仍是 v1：clerk 仍能看到脱敏 phone
    body = c.get("/records/r1", headers={"X-Subject-Id": "clerk"}).json()
    assert body["rule_version"] == 1
    assert body["presented"]["phone"] == "1*********1"


def test_rule_history_list_and_get_over_http():
    c = client()
    r = c.get("/rules", headers={"X-Subject-Id": "analyst"})
    assert r.status_code == 200
    body = r.json()
    logger.info("GET /rules(analyst) -> %s", body)
    assert body["allowed"] is True
    versions = [v["version"] for v in body["data"]["versions"]]
    assert 1 in versions  # 历史目录至少含初版

    r = c.get(f"/rules/{versions[0]}", headers={"X-Subject-Id": "admin"})
    body = r.json()
    assert body["allowed"] is True and body["data"]["version"] == versions[0]
    logger.info("GET /rules/%d -> retention_days=%s",
                versions[0], body["data"]["retention_days"])


def test_rule_history_distinct_denials_over_http():
    c = client()
    # 越权（clerk 级别不足）
    r = c.get("/rules", headers={"X-Subject-Id": "clerk"})
    body = r.json()
    logger.info("clerk GET /rules -> %s", body)
    assert body["allowed"] is False and body["reason"] == "INSUFFICIENT_LEVEL"
    # 主体未知 / 过期
    assert c.get("/rules", headers={"X-Subject-Id": "ghost"}).json()["reason"] \
        == "SUBJECT_UNKNOWN"
    assert c.get("/rules", headers={"X-Subject-Id": "expired"}).json()["reason"] \
        == "GRANT_EXPIRED"
    # 版本不存在（合规主体）
    body = c.get("/rules/99999", headers={"X-Subject-Id": "admin"}).json()
    assert body["allowed"] is False and body["reason"] == "VERSION_NOT_FOUND"


def test_seal_and_review_immutable_archive_over_http():
    c = client()
    # 产生两条访问（v1）
    c.get("/records/r1", headers={"X-Subject-Id": "clerk"})
    c.get("/records/r1", headers={"X-Subject-Id": "admin"})

    r = c.post("/archives", headers={"X-Subject-Id": "admin"},
               json={"start": None, "end": None, "archive_id": "http-arc-1"})
    assert r.status_code == 201
    sealed = r.json()
    logger.info("POST /archives -> %s", sealed)
    assert sealed["allowed"] is True
    assert sealed["data"]["entry_count"] >= 2
    assert sealed["data"]["rule_versions"] == [1]
    arc_id = sealed["data"]["archive_id"]

    # 复核：数据未变 -> consistent
    r = c.get(f"/archives/{arc_id}", headers={"X-Subject-Id": "admin"})
    report = r.json()
    logger.info("复核(未变更) matched=%s/%s consistent=%s",
                report["data"]["matched"], report["data"]["total"],
                report["data"]["consistent"])
    assert report["allowed"] is True
    assert report["data"]["matched"] == report["data"]["total"]
    assert report["data"]["consistent"] is True
    # 每条都带封存判定依据：规则版本、结果、呈现
    for e in report["data"]["entries"]:
        assert e["sealed"]["rule_version"] == 1
        assert "presented" in e["sealed"]


def test_review_missing_archive_denied_over_http():
    c = client()
    body = c.get("/archives/no-such-arc", headers={"X-Subject-Id": "admin"}).json()
    logger.info("复核不存在档案 -> %s", body)
    assert body["allowed"] is False and body["reason"] == "ARCHIVE_NOT_FOUND"


def test_seal_empty_window_denied_over_http():
    c = client()
    body = c.post("/archives", headers={"X-Subject-Id": "admin"}, json={
        "start": "2000-01-01T00:00:00Z",
        "end": "2000-01-02T00:00:00Z",
        "archive_id": "http-arc-empty",
    }).json()
    logger.info("封存空窗 -> %s", body)
    assert body["allowed"] is False and body["reason"] == "ARCHIVE_EMPTY"


def test_archive_review_records_rule_version_basis_over_http():
    """档案条目必须看得出各自用的规则版本（跨版本封存）。"""
    c = client()
    c.get("/records/r1", headers={"X-Subject-Id": "clerk"})  # v1
    # 发 v2
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
    c.get("/records/r1", headers={"X-Subject-Id": "clerk"})  # v2：phone 不可见

    r = c.post("/archives", headers={"X-Subject-Id": "admin"},
               json={"archive_id": "http-arc-multi"})
    assert r.status_code == 201
    arc_id = r.json()["data"]["archive_id"]
    report = c.get(f"/archives/{arc_id}", headers={"X-Subject-Id": "admin"}).json()
    entries = report["data"]["entries"]
    versions = sorted({e["sealed"]["rule_version"] for e in entries})
    logger.info("跨版本档案条目版本=%s 条目数=%d", versions, len(entries))
    assert versions == [1, 2]
    v1_entries = [e for e in entries if e["sealed"]["rule_version"] == 1]
    v2_entries = [e for e in entries if e["sealed"]["rule_version"] == 2]
    assert any("phone" in e["sealed"]["presented"] for e in v1_entries)
    assert all("phone" not in e["sealed"]["presented"] for e in v2_entries)


def test_audit_failure_makes_history_endpoint_500(monkeypatch):
    """合规入口审计写失败：HTTP 500，不返回任何数据。"""
    import main
    from gateway.audit import AuditError

    calls = {"n": 0}
    real_write = main.service.audit.write

    def failing_write(event):
        calls["n"] += 1
        raise AuditError("simulated outage")

    monkeypatch.setattr(main.service.audit, "write", failing_write)
    c = client()
    r = c.get("/rules", headers={"X-Subject-Id": "admin"})
    logger.info("审计故障时 GET /rules -> 状态码=%d", r.status_code)
    assert r.status_code == 500
    assert calls["n"] == 1

    r = c.post("/archives", headers={"X-Subject-Id": "admin"}, json={})
    assert r.status_code == 500
    assert main.compliance.archives.list_ids() == []  # 审计失败，无档案落库
