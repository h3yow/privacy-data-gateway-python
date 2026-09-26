"""HTTP 入口：隐私数据访问网关。"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import uvicorn
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

from gateway.audit import InMemoryAuditSink
from gateway.authz import SubjectStore
from gateway.models import DenyReason, MaskMode, SensitiveRecord, Subject
from gateway.rules import RuleRegistry, RuleSet
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
def publish_rules(req: RulePublishRequest) -> dict[str, int]:
    """运行中原子发布新规则版本；发布后新请求按新版本判定。"""
    modes = {
        field: {int(lvl): MaskMode(mode) for lvl, mode in tiers.items()}
        for field, tiers in req.field_modes.items()
    }
    service.rules.publish(RuleSet(version=req.version, field_modes=modes,
                                   retention_days=req.retention_days))
    return {"published": req.version}


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
        }
        for e in service.audit.events()
    ]


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=0)
