"""可区分的业务异常：调用方通过异常类型即可分辨拒绝种类。"""
from __future__ import annotations


class GatewayError(Exception):
    """网关业务异常基类。"""


class VersionConflictError(GatewayError):
    """发布被拒：版本号已存在或小于当前最新版本。"""


class VersionNotFoundError(GatewayError):
    """查询被拒：历史规则版本不存在。"""


class ArchiveNotFoundError(GatewayError):
    """查询/复核被拒：封存档案不存在。"""


class ArchiveEmptyError(GatewayError):
    """封存被拒：时间窗内没有任何可封存事件。"""
