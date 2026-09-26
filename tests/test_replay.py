"""复现性测试：即使底层数据后续被修改，历史结论仍可按审计快照复现。"""

from __future__ import annotations

from datetime import datetime, timezone

from privacy_gateway.models import ClearanceLevel, Record

NOW = datetime(2026, 9, 26, tzinfo=timezone.utc)


def test_replay_immune_to_later_data_change(components):
    svc = components["service"]
    replayer = components["replayer"]
    decision = svc.access(subject_id="bob", record_id="rec-1", now=NOW)
    saved_phone = decision.presented["phone"].value  # CONFIDENTIAL -> 明文
    assert saved_phone == "13800001234"

    # 底层数据后来被修改
    components["records"].put(Record(
        record_id="rec-1",
        record_type="customer",
        required_level=ClearanceLevel.INTERNAL,
        data={
            "name": "Zhang San",
            "phone": "19999999999",
            "email": "changed@example.com",
            "id_card": "000000000000000000",
            "address": "Shanghai",
        },
    ))

    # 用审计快照重放，结论与当时一致
    replayed = replayer.replay(decision.decision_id)
    assert replayed.presented["phone"].value == saved_phone
    assert replayed.presented["email"].value == "zhangsan@example.com"
    assert replayer.verify(decision.decision_id) is True


def test_replay_deny_decision(components):
    from privacy_gateway.errors import UnauthorizedError
    import pytest
    svc = components["service"]
    with pytest.raises(UnauthorizedError):
        svc.access(subject_id="eve", record_id="rec-1", now=NOW)
    entry = components["audit"].list_all()[-1]
    assert components["replayer"].verify(entry.decision_id) is True
