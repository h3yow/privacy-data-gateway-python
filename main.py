"""HTTP 入口：隐私数据访问网关。"""
from __future__ import annotations

from datetime import datetime, timezone

import uvicorn
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

from gateway.audit import InMemoryAuditSink
from gateway.authz import SubjectStore
from gateway.models import DenyReason, MaskMode, Subject
from gateway.rules import RuleRegistry, RuleSet
from gateway.service import GatewayService, RecordStore
from gateway.models import SensitiveRecord

app = FastAPI(title="privacy-data-gateway")


def build_default_service() -> GatewayService:
    """组装默认内存实现的网关服务（骨架，后续填充演示数据）。"""
    rules = RuleRegistry(RuleSet(version=1, field_modes={}, retention_days=30))
    return GatewayService(SubjectStore(), RecordStore(), rules, InMemoryAuditSink())


service = build_default_service()


class AccessResponse(BaseModel):
    allowed: bool
    reason: str | None
    rule_version: int
    presented: dict[str, str]


@app.get("/")
def read_root() -> dict[str, str]:
    return {"Hello": "World"}


@app.get("/records/{record_id}", response_model=AccessResponse)
def access_record(record_id: str, x_subject_id: str = Header(default="")) -> AccessResponse:
    """按主体授权级别呈现记录（骨架：调用服务层）。"""
    decision = service.access(x_subject_id, record_id, datetime.now(timezone.utc))
    if decision.reason is DenyReason.AUDIT_FAILURE:
        raise HTTPException(status_code=500, detail="audit failure")
    return AccessResponse(
        allowed=decision.allowed,
        reason=decision.reason.value if decision.reason else None,
        rule_version=decision.rule_version,
        presented=decision.presented,
    )


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=0)
