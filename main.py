"""HTTP 入口：隐私数据访问网关。"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import uvicorn
from fastapi import FastAPI, Header, HTTPException, Query
from pydantic import BaseModel

from gateway.archives import Archive, ReviewReport
from gateway.audit import InMemoryAuditSink
from gateway.authz import SubjectStore
from gateway.models import DenyReason, MaskMode, SensitiveRecord, Subject
from gateway.rules import RuleRegistry, RuleSet, RuleVersionConflictError
from gateway.service import GatewayService, RecordStore

app = FastAPI(title="privacy-data-gateway")


def build_default_service() -> GatewayService:
    """组装默认内存实现的网关服务（含演示数据）。"""
    now = datetime.now(timezone.utc)
    subjects = SubjectStore({
        "admin": Subject("admin", level=3, expires_at=None),
        "clerk": Subject("clerk", level=1, expires_at=None),
        "expired": Subject("expired", level=3, expires_at=now - timedelta(days=1)),
    })
    records = RecordStore({
        "r1": SensitiveRecord("r1", {"name": "alice", "phone": "13800001111", "id_card": "110101199001011234"}),
    })
    rules = RuleRegistry(RuleSet(version=1, field_modes={
        "name": {1: MaskMode.PLAIN},
        "phone": {1: MaskMode.MASKED, 3: MaskMode.PLAIN},
        "id_card": {2: MaskMode.MASKED, 3: MaskMode.PLAIN},
    }, retention_days=30))
    return GatewayService(subjects, records, rules, InMemoryAuditSink())


service = build_default_service()


class AccessResponse(BaseModel):
    allowed: bool
    reason: str | None
    rule_version: int
    presented: dict[str, str]


class RulePublishRequest(BaseModel):
    version: int
    field_modes: dict[str, dict[int, str]]  # {字段: {最低级别: HIDDEN|MASKED|PLAIN}}
    retention_days: int = 30


class ArchiveSealRequest(BaseModel):
    range_start: datetime | None = None
    range_end: datetime | None = None


def ruleset_to_dict(rules: RuleSet) -> dict:
    return {
        "version": rules.version,
        "retention_days": rules.retention_days,
        "field_modes": {
            field: {str(lvl): mode.value for lvl, mode in tiers.items()}
            for field, tiers in rules.field_modes.items()
        },
    }


def archive_to_dict(a: Archive) -> dict:
    return {
        "archive_id": a.archive_id,
        "created_at": a.created_at.isoformat(),
        "range_start": a.range_start.isoformat() if a.range_start else None,
        "range_end": a.range_end.isoformat() if a.range_end else None,
        "entry_count": len(a.entries),
        "rule_versions": sorted(a.rules_snapshots),
        "entries": [
            {
                "sequence": e.sequence,
                "timestamp": e.timestamp.isoformat(),
                "subject_id": e.subject_id,
                "subject_level": e.subject_level,
                "record_id": e.record_id,
                "rule_version": e.rule_version,
                "allowed": e.allowed,
                "reason": e.reason,
                "presented": e.presented,
            }
            for e in a.entries
        ],
    }


def report_to_dict(r: ReviewReport) -> dict:
    return {
        "archive_id": r.archive_id,
        "reviewed_at": r.reviewed_at.isoformat(),
        "total": r.total,
        "matched": r.matched,
        "mismatched": r.mismatched,
        "entries": [
            {
                "sequence": er.sequence,
                "matches": er.matches,
                "differences": [
                    {
                        "kind": d.kind,
                        "field": d.field,
                        "sealed": d.sealed,
                        "current": d.current,
                    }
                    for d in er.differences
                ],
            }
            for er in r.entries
        ],
    }


_DENY_STATUS = {
    DenyReason.SUBJECT_UNKNOWN: 401,
    DenyReason.GRANT_EXPIRED: 403,
    DenyReason.INSUFFICIENT_LEVEL: 403,
    DenyReason.VERSION_NOT_FOUND: 404,
    DenyReason.ARCHIVE_NOT_FOUND: 404,
    DenyReason.AUDIT_FAILURE: 500,
}


def reject(reason: DenyReason) -> HTTPException:
    """把可区分拒绝原因映射成带统一 body 的 HTTP 失败。"""
    return HTTPException(status_code=_DENY_STATUS[reason],
                         detail={"ok": False, "reason": reason.value})


@app.get("/")
def read_root() -> dict[str, str]:
    return {"Hello": "World"}


@app.get("/records/{record_id}", response_model=AccessResponse)
def access_record(record_id: str, x_subject_id: str = Header(default="")) -> AccessResponse:
    """按主体授权级别呈现记录；拒绝原因可区分，审计失败返回 500。"""
    decision = service.access(x_subject_id, record_id, datetime.now(timezone.utc))
    if decision.reason is DenyReason.AUDIT_FAILURE:
        raise HTTPException(status_code=500, detail="audit failure")
    return AccessResponse(
        allowed=decision.allowed,
        reason=decision.reason.value if decision.reason else None,
        rule_version=decision.rule_version,
        presented=decision.presented,
    )


@app.post("/rules", status_code=201)
def publish_rules(req: RulePublishRequest) -> dict:
    """运行中原子发布新规则版本。

    版本号必须严格大于最新已发布版本；重复或回退当场拒绝（409，
    body.reason=VERSION_CONFLICT），现行版本与历史不变。
    """
    modes = {
        field: {int(lvl): MaskMode(mode) for lvl, mode in tiers.items()}
        for field, tiers in req.field_modes.items()
    }
    try:
        service.rules.publish(RuleSet(version=req.version, field_modes=modes,
                                      retention_days=req.retention_days))
    except RuleVersionConflictError as exc:
        raise HTTPException(status_code=409, detail={
            "ok": False,
            "reason": "VERSION_CONFLICT",
            "attempted": exc.attempted,
            "latest": exc.latest,
        })
    return {"ok": True, "published": req.version}


@app.get("/rules")
def list_rule_versions(
    x_subject_id: str = Header(default=""),
    limit: int | None = Query(default=None, ge=1),
    offset: int = Query(default=0, ge=0),
) -> dict:
    """按发布先后列出全部规则版本（旧→新，定长分页），不随历史增长退化。"""
    result = service.list_rule_versions(x_subject_id, datetime.now(timezone.utc),
                                        limit=limit, offset=offset)
    if not result.ok:
        assert result.reason is not None
        raise reject(result.reason)
    return {"ok": True, "versions": [ruleset_to_dict(r) for r in result.payload]}


@app.get("/rules/{version}")
def get_rule_version(version: int, x_subject_id: str = Header(default="")) -> dict:
    """查某个历史版本当时的完整配置；不存在返回 404 VERSION_NOT_FOUND。"""
    result = service.get_rule_version(x_subject_id, version, datetime.now(timezone.utc))
    if not result.ok:
        assert result.reason is not None
        raise reject(result.reason)
    return {"ok": True, "rules": ruleset_to_dict(result.payload)}


@app.post("/archives", status_code=201)
def seal_archive(
    req: ArchiveSealRequest,
    x_subject_id: str = Header(default=""),
) -> dict:
    """封存一段时间内的访问/拒绝为固定档案（需级别 ≥ 2）。"""
    result = service.seal_archive(x_subject_id, datetime.now(timezone.utc),
                                  req.range_start, req.range_end)
    if not result.ok:
        assert result.reason is not None
        raise reject(result.reason)
    return {"ok": True, "archive": archive_to_dict(result.payload)}


@app.get("/archives")
def list_archives(x_subject_id: str = Header(default="")) -> dict:
    """列出已封存档案（需级别 ≥ 2）。"""
    result = service.list_archives(x_subject_id, datetime.now(timezone.utc))
    if not result.ok:
        assert result.reason is not None
        raise reject(result.reason)
    return {"ok": True, "archives": result.payload}


@app.get("/archives/{archive_id}/review")
def review_archive_endpoint(
    archive_id: str,
    x_subject_id: str = Header(default=""),
) -> dict:
    """事后复核档案：逐条给出对得上/对不上及差异（需级别 ≥ 2），复核不改档。"""
    result = service.review_archive(x_subject_id, archive_id, datetime.now(timezone.utc))
    if not result.ok:
        assert result.reason is not None
        raise reject(result.reason)
    return {"ok": True, "report": report_to_dict(result.payload)}


@app.get("/audit")
def list_audit() -> list[dict]:
    """导出审计痕迹（含判定依据与结果标记），内容随规则版本固定、可复现。"""
    return [
        {
            "sequence": e.sequence,
            "timestamp": e.timestamp.isoformat(),
            "subject_id": e.subject_id,
            "record_id": e.record_id,
            "rule_version": e.rule_version,
            "allowed": e.allowed,
            "reason": e.reason,
            "presented": e.presented,
            "action": e.action,
            "subject_level": e.subject_level,
        }
        for e in service.audit.events()
    ]


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=0)
