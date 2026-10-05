"""HTTP 入口：隐私数据访问网关。"""
from __future__ import annotations

from datetime import datetime, timezone

import uvicorn
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

from gateway.audit import InMemoryAuditSink
from gateway.authz import SubjectStore
from gateway.compliance import ComplianceService
from gateway.errors import VersionConflictError
from gateway.models import DenyReason, MaskMode, SensitiveRecord, Subject
from gateway.rules import RuleRegistry, RuleSet
from gateway.service import GatewayService, RecordStore

app = FastAPI(title="privacy-data-gateway")


def build_default_service() -> GatewayService:
    """组装默认内存实现的网关服务（含演示数据）。"""
    now = datetime.now(timezone.utc)
    subjects = SubjectStore({
        "admin": Subject("admin", level=3, expires_at=None),
        "analyst": Subject("analyst", level=2, expires_at=None),
        "clerk": Subject("clerk", level=1, expires_at=None),
        "expired": Subject("expired", level=3, expires_at=now),
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
compliance = ComplianceService(service)


def reset_services() -> tuple[GatewayService, ComplianceService]:
    """重建全局服务（测试隔离用）：清空规则历史、审计与封存档案。"""
    global service, compliance
    service = build_default_service()
    compliance = ComplianceService(service)
    return service, compliance


class AccessResponse(BaseModel):
    allowed: bool
    reason: str | None
    rule_version: int
    presented: dict[str, str]


class RulePublishRequest(BaseModel):
    version: int
    field_modes: dict[str, dict[int, str]]  # {字段: {最低级别: HIDDEN|MASKED|PLAIN}}
    retention_days: int = 30


class SealRequest(BaseModel):
    # ISO-8601 时间窗；null 表示开放边界（从头 / 到现在）
    start: str | None = None
    end: str | None = None
    archive_id: str | None = None


def _parse_dt(value: str | None) -> datetime | None:
    if value is None:
        return None
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _op_envelope(result) -> dict:
    """把合规操作结论统一成 {allowed, reason, rule_version, data} 信封。"""
    return {
        "allowed": result.allowed,
        "reason": result.reason.value if result.reason else None,
        "rule_version": result.rule_version,
        "data": result.data,
    }


def _raise_if_audit_failure(result) -> None:
    """任何入口审计失败都返回 500，绝不放数据。"""
    if not result.allowed and result.reason is DenyReason.AUDIT_FAILURE:
        raise HTTPException(status_code=500, detail="audit failure")


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
    """原子发布新规则版本。

    版本号必须严格大于最新已发版本；重复或回退发布返回 409 VERSION_CONFLICT，
    注册表保持不变，调用方可从状态码与 reason 分辨这是一次被拒绝的发布。
    """
    modes = {
        field: {int(lvl): MaskMode(mode) for lvl, mode in tiers.items()}
        for field, tiers in req.field_modes.items()
    }
    try:
        service.rules.publish(RuleSet(version=req.version, field_modes=modes,
                                      retention_days=req.retention_days))
    except VersionConflictError as exc:
        raise HTTPException(status_code=409, detail={
            "reason": DenyReason.VERSION_CONFLICT.value,
            "message": str(exc),
        })
    return {"published": req.version}


@app.get("/rules")
def list_rule_versions(x_subject_id: str = Header(default="")) -> dict:
    """按发布先后列出全部历史规则版本目录（合规级，默认 level>=2）。"""
    result = compliance.list_rule_versions(x_subject_id, datetime.now(timezone.utc))
    _raise_if_audit_failure(result)
    return _op_envelope(result)


@app.get("/rules/{version}")
def get_rule_version(version: int, x_subject_id: str = Header(default="")) -> dict:
    """取某个历史版本的完整配置；版本不存在返回 allowed=false/VERSION_NOT_FOUND。"""
    result = compliance.get_rule_version(x_subject_id, version, datetime.now(timezone.utc))
    _raise_if_audit_failure(result)
    return _op_envelope(result)


@app.post("/archives", status_code=201)
def seal_archive(req: SealRequest, x_subject_id: str = Header(default="")) -> dict:
    """把时间窗内的访问/拒绝整批封存为固定档案。"""
    result = compliance.seal_archive(
        x_subject_id, _parse_dt(req.start), _parse_dt(req.end),
        datetime.now(timezone.utc), archive_id=req.archive_id,
    )
    _raise_if_audit_failure(result)
    return _op_envelope(result)


@app.get("/archives/{archive_id}")
def review_archive(archive_id: str, x_subject_id: str = Header(default="")) -> dict:
    """只读复核档案：逐条给出 MATCH/差异类型与字段级差异，不改动档案。"""
    result = compliance.review_archive(x_subject_id, archive_id,
                                       datetime.now(timezone.utc))
    _raise_if_audit_failure(result)
    return _op_envelope(result)


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
            "archive_id": e.archive_id,
            "subject_level": e.subject_level,
        }
        for e in service.audit.events()
    ]


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=0)
