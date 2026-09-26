"""网关领域错误类型。

每一种拒绝原因对应一个独立的异常类型（并带 reason_code），
使 未授权 / 授权过期 / 资源不存在 / 审计写入失败 在 API 层可区分。
"""

from __future__ import annotations


class GatewayError(Exception):
    """所有网关领域错误的基类。"""

    reason_code: str = "gateway_error"
    http_status: int = 400

    def __init__(self, message: str = "") -> None:
        super().__init__(message or self.reason_code)
        self.message = message or self.reason_code


class AccessDeniedError(GatewayError):
    """访问被拒绝的基类（可区分原因的子类见下）。"""

    reason_code = "access_denied"
    http_status = 403


class UnauthorizedError(AccessDeniedError):
    """主体没有任何针对该资源的有效授权（未授权）。"""

    reason_code = "unauthorized"
    http_status = 403


class GrantExpiredError(AccessDeniedError):
    """主体对该资源的授权存在但已过期。"""

    reason_code = "grant_expired"
    http_status = 403


class ClearanceInsufficientError(AccessDeniedError):
    """授权存在且未过期，但密级不足以访问该资源。"""

    reason_code = "clearance_insufficient"
    http_status = 403


class ResourceNotFoundError(AccessDeniedError):
    """请求的资源不存在。"""

    reason_code = "resource_not_found"
    http_status = 404


class AuditWriteError(GatewayError):
    """审计写入失败；为避免静默放行，访问必须整体失败。"""

    reason_code = "audit_write_failed"
    http_status = 500
