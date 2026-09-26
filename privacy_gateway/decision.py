"""判定引擎：把 主体授权 + 记录 + 规则快照 组合成确定性的访问判定。

判定为纯函数：相同输入（含规则版本与当前时间）必然得到相同输出，
与请求顺序、缓存无关。
"""

from __future__ import annotations

from datetime import datetime

from .masking import apply_mask
from .models import (
    AccessDecision,
    ClearanceLevel,
    DecisionResult,
    FieldPolicy,
    Grant,
    MaskingStrategy,
    PresentedField,
    Record,
    RuleSnapshot,
)


def decide(
    *,
    decision_id: str,
    subject_id: str,
    record: Record | None,
    grant: Grant | None,
    snapshot: RuleSnapshot,
    now: datetime,
) -> AccessDecision:
    """执行判定。

    拒绝原因优先级（且可区分）：
    1. 资源不存在 -> resource_not_found
    2. 无授权     -> unauthorized
    3. 授权过期   -> grant_expired
    4. 密级不足   -> clearance_insufficient
    """
    rule = snapshot.rule
    basis: dict[str, str] = {
        "rule_version": str(rule.version),
        "decided_at": now.isoformat(),
    }

    # 1. 资源存在性
    if record is None:
        basis["record"] = "not_found"
        return AccessDecision(
            decision_id=decision_id,
            subject_id=subject_id,
            record_id="",
            result=DecisionResult.DENY,
            rule_version=rule.version,
            decided_at=now,
            deny_reason="resource_not_found",
            basis=basis,
        )
    basis["record"] = "found"
    basis["record_required_level"] = record.required_level.name

    # 2. 授权存在性
    if grant is None:
        basis["grant"] = "none"
        return AccessDecision(
            decision_id=decision_id,
            subject_id=subject_id,
            record_id=record.record_id,
            result=DecisionResult.DENY,
            rule_version=rule.version,
            decided_at=now,
            deny_reason="unauthorized",
            basis=basis,
        )
    basis["grant"] = (
        f"level={grant.level.name},"
        f"expires_at={grant.expires_at.isoformat() if grant.expires_at else 'never'}"
    )

    # 3. 授权时效
    if grant.is_expired(now):
        basis["grant_status"] = "expired"
        return AccessDecision(
            decision_id=decision_id,
            subject_id=subject_id,
            record_id=record.record_id,
            result=DecisionResult.DENY,
            rule_version=rule.version,
            decided_at=now,
            deny_reason="grant_expired",
            basis=basis,
        )
    basis["grant_status"] = "active"

    # 4. 记录级密级门槛
    if grant.level < record.required_level:
        basis["clearance_check"] = (
            f"subject={grant.level.name} < required={record.required_level.name}"
        )
        return AccessDecision(
            decision_id=decision_id,
            subject_id=subject_id,
            record_id=record.record_id,
            result=DecisionResult.DENY,
            rule_version=rule.version,
            decided_at=now,
            deny_reason="clearance_insufficient",
            basis=basis,
        )
    basis["clearance_check"] = (
        f"subject={grant.level.name} >= required={record.required_level.name}"
    )

    # 5. 字段级分级呈现（按字段名排序，保证输出确定）
    presented: dict[str, PresentedField] = {}
    for field_name in sorted(record.data):
        raw = record.data[field_name]
        policy = rule.policy_for(record.record_type, field_name)
        presented[field_name] = _present_field(field_name, raw, policy, grant.level, basis)

    return AccessDecision(
        decision_id=decision_id,
        subject_id=subject_id,
        record_id=record.record_id,
        result=DecisionResult.ALLOW,
        rule_version=rule.version,
        decided_at=now,
        presented=presented,
        basis=basis,
    )


def _present_field(
    field_name: str,
    raw: str,
    policy: FieldPolicy | None,
    subject_level: ClearanceLevel,
    basis: dict[str, str],
) -> PresentedField:
    key = f"field.{field_name}"
    if policy is None:
        basis[key] = "no_policy -> VISIBLE"
        return PresentedField(
            name=field_name, value=raw, strategy=MaskingStrategy.VISIBLE, visible=True
        )

    if policy.full_level is not None and subject_level >= policy.full_level:
        basis[key] = (
            f"subject={subject_level.name} >= full_level={policy.full_level.name}"
            " -> VISIBLE"
        )
        return PresentedField(
            name=field_name, value=raw, strategy=MaskingStrategy.VISIBLE, visible=True
        )

    if subject_level >= policy.min_level:
        basis[key] = (
            f"subject={subject_level.name} >= min_level={policy.min_level.name}"
            f" -> {policy.strategy.name}"
        )
        return PresentedField(
            name=field_name,
            value=apply_mask(raw, policy.strategy),
            strategy=policy.strategy,
            visible=True,
        )

    basis[key] = (
        f"subject={subject_level.name} < min_level={policy.min_level.name}"
        " -> REDACT"
    )
    return PresentedField(
        name=field_name, value=None, strategy=MaskingStrategy.REDACT, visible=False
    )
