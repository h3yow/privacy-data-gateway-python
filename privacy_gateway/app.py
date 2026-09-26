"""FastAPI 应用装配：路由 + 依赖注入 + 默认种子数据。"""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from .audit import AuditLog
from .errors import GatewayError
from .export import ExportService
from .models import (
    ClearanceLevel,
    FieldPolicy,
    Grant,
    MaskingStrategy,
    Record,
    RetentionPolicy,
    RuleVersion,
)
from .replay import ReplayService
from .rules import RuleRegistry
from .service import AccessService
from .store import GrantStore, RecordStore


# ---------- 请求模型 ----------

class FieldPolicyIn(BaseModel):
    min_level: str
    strategy: str
    full_level: str | None = None


class RulePublishIn(BaseModel):
    version: int
    field_policies: dict[str, dict[str, FieldPolicyIn]] = {}
    retention_days: int = 3650


# ---------- 默认种子 ----------

def build_default_rules() -> RuleRegistry:
    """构造初始规则版本 v1。"""
    v1 = RuleVersion(
        version=1,
        published_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        field_policies={
            "customer": {
                "phone": FieldPolicy(
                    field_name="phone",
                    min_level=ClearanceLevel.INTERNAL,
                    strategy=MaskingStrategy.PARTIAL,
                    full_level=ClearanceLevel.CONFIDENTIAL,
                ),
                "email": FieldPolicy(
                    field_name="email",
                    min_level=ClearanceLevel.INTERNAL,
                    strategy=MaskingStrategy.MASK,
                    full_level=ClearanceLevel.CONFIDENTIAL,
                ),
                "id_card": FieldPolicy(
                    field_name="id_card",
                    min_level=ClearanceLevel.CONFIDENTIAL,
                    strategy=MaskingStrategy.HASH,
                    full_level=ClearanceLevel.RESTRICTED,
                ),
                "address": FieldPolicy(
                    field_name="address",
                    min_level=ClearanceLevel.CONFIDENTIAL,
                    strategy=MaskingStrategy.VISIBLE,
                ),
            }
        },
        retention=RetentionPolicy(retain_days=3650),
    )
    return RuleRegistry(v1)


def build_seed_stores() -> tuple[RecordStore, GrantStore]:
    records = RecordStore()
    records.put(Record(
        record_id="rec-1",
        record_type="customer",
        required_level=ClearanceLevel.INTERNAL,
        data={
            "name": "Zhang San",
            "phone": "13800001234",
            "email": "zhangsan@example.com",
            "id_card": "110101199001011234",
            "address": "Beijing Haidian",
        },
    ))
    grants = GrantStore()
    grants.put(Grant("alice", "rec-1", ClearanceLevel.INTERNAL))
    grants.put(Grant("bob", "rec-1", ClearanceLevel.CONFIDENTIAL))
    grants.put(Grant("carol", "rec-1", ClearanceLevel.RESTRICTED))
    grants.put(Grant(
        "dave", "rec-1", ClearanceLevel.INTERNAL,
        expires_at=datetime(2020, 1, 1, tzinfo=timezone.utc),
    ))
    return records, grants


# ---------- 应用工厂 ----------

def create_app() -> FastAPI:
    """创建应用并注入各组件。"""
    app = FastAPI(title="Privacy Data Gateway")

    records, grants = build_seed_stores()
    rules = build_default_rules()
    audit = AuditLog()
    service = AccessService(records, grants, rules, audit)
    exporter = ExportService(audit)
    replayer = ReplayService(audit, rules)

    app.state.records = records
    app.state.grants = grants
    app.state.rules = rules
    app.state.audit = audit
    app.state.service = service
    app.state.exporter = exporter
    app.state.replayer = replayer

    @app.exception_handler(GatewayError)
    async def gateway_error_handler(_req: Request, exc: GatewayError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.http_status,
            content={"error": exc.reason_code, "message": exc.message},
        )

    @app.exception_handler(KeyError)
    async def key_error_handler(_req: Request, exc: KeyError) -> JSONResponse:
        return JSONResponse(
            status_code=404,
            content={"error": "not_found", "message": str(exc.args[0])},
        )

    @app.exception_handler(ValueError)
    async def value_error_handler(_req: Request, exc: ValueError) -> JSONResponse:
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_request", "message": str(exc)},
        )

    @app.get("/records/{record_id}")
    def get_record(record_id: str, subject_id: str) -> dict:
        decision = service.access(subject_id=subject_id, record_id=record_id)
        return {
            "decision_id": decision.decision_id,
            "subject_id": decision.subject_id,
            "record_id": decision.record_id,
            "rule_version": decision.rule_version,
            "decided_at": decision.decided_at.isoformat(),
            "fields": {
                name: {
                    "value": pf.value,
                    "strategy": pf.strategy.value,
                    "visible": pf.visible,
                }
                for name, pf in decision.presented.items()
            },
            "basis": decision.basis,
        }

    @app.post("/admin/rules")
    def publish_rule(body: RulePublishIn) -> dict:
        policies = {
            rtype: {
                fname: FieldPolicy(
                    field_name=fname,
                    min_level=ClearanceLevel[p.min_level],
                    strategy=MaskingStrategy(p.strategy),
                    full_level=ClearanceLevel[p.full_level]
                    if p.full_level else None,
                )
                for fname, p in fields.items()
            }
            for rtype, fields in body.field_policies.items()
        }
        rule = RuleVersion(
            version=body.version,
            published_at=datetime.now(timezone.utc),
            field_policies=policies,
            retention=RetentionPolicy(retain_days=body.retention_days),
        )
        snap = rules.publish(rule)
        return {"published": snap.rule.version}

    @app.get("/admin/rules/current")
    def current_rule() -> dict:
        snap = rules.current_snapshot()
        return {
            "version": snap.rule.version,
            "published_at": snap.rule.published_at.isoformat(),
        }

    @app.get("/admin/rules/{version}")
    def get_rule(version: int) -> dict:
        snap = rules.snapshot_of(version)
        return {
            "version": snap.rule.version,
            "published_at": snap.rule.published_at.isoformat(),
            "field_policies": {
                rtype: {
                    fname: {
                        "min_level": p.min_level.name,
                        "strategy": p.strategy.value,
                        "full_level": p.full_level.name if p.full_level else None,
                    }
                    for fname, p in fields.items()
                }
                for rtype, fields in snap.rule.field_policies.items()
            },
            "retention_days": snap.rule.retention.retain_days,
        }

    @app.post("/exports/{decision_id}")
    def export(decision_id: str) -> dict:
        return exporter.export(decision_id)

    @app.get("/audit")
    def list_audit() -> list[dict]:
        return [
            {
                "decision_id": e.decision_id,
                "subject_id": e.subject_id,
                "record_id": e.record_id,
                "result": e.result.value,
                "deny_reason": e.deny_reason,
                "rule_version": e.rule_version,
                "decided_at": e.decided_at.isoformat(),
                "basis": e.basis,
            }
            for e in audit.list_all()
        ]

    @app.get("/audit/{decision_id}/verify")
    def verify(decision_id: str) -> dict:
        return {"decision_id": decision_id, "consistent": replayer.verify(decision_id)}

    return app
