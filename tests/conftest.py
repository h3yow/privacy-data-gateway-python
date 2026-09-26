"""测试公共夹具。

autouse 夹具为 service 日志（输入与判定依据）挂一个直接打印到 stdout 的
handler，使每个单测日志中都能看到输入与判定依据（pytest -s 查看）。
不使用 caplog，避免 pytest 在 setup/call 阶段切换捕获句柄导致丢失。
"""

from __future__ import annotations

import logging

import pytest
from fastapi.testclient import TestClient

from privacy_gateway.app import build_default_rules, build_seed_stores, create_app
from privacy_gateway.audit import AuditLog
from privacy_gateway.export import ExportService
from privacy_gateway.replay import ReplayService
from privacy_gateway.service import AccessService


class _StdoutHandler(logging.Handler):
    def emit(self, record: logging.LogRecord) -> None:
        print(f"[LOG] {record.levelname} {record.getMessage()}")


@pytest.fixture(autouse=True)
def _print_decision_logs():
    logger = logging.getLogger("privacy_gateway.service")
    handler = _StdoutHandler()
    old_level = logger.level
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    yield
    logger.removeHandler(handler)
    logger.setLevel(old_level)


@pytest.fixture()
def components():
    records, grants = build_seed_stores()
    rules = build_default_rules()
    audit = AuditLog()
    service = AccessService(records, grants, rules, audit)
    exporter = ExportService(audit)
    replayer = ReplayService(audit, rules)
    return {
        "records": records,
        "grants": grants,
        "rules": rules,
        "audit": audit,
        "service": service,
        "exporter": exporter,
        "replayer": replayer,
    }


@pytest.fixture()
def client():
    app = create_app()
    return TestClient(app, raise_server_exceptions=True)
