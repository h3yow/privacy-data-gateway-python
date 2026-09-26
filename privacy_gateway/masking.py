"""脱敏函数：纯函数、确定性（同一输入与策略永远同一输出）。"""

from __future__ import annotations

import hashlib

from .models import MaskingStrategy

MASK_TOKEN = "****"


def apply_mask(value: str, strategy: MaskingStrategy) -> str | None:
    """按策略对字段值脱敏。

    - VISIBLE: 原样返回
    - MASK:    固定掩码 ****
    - PARTIAL: 保留前 3 位与后 4 位，中间以 **** 替代（过短则整体掩码）
    - HASH:    确定性哈希前缀（同一值永远同一哈希）
    - REDACT:  返回 None（字段整体移除）
    """
    if strategy is MaskingStrategy.VISIBLE:
        return value
    if strategy is MaskingStrategy.MASK:
        return MASK_TOKEN
    if strategy is MaskingStrategy.PARTIAL:
        if len(value) <= 7:
            return MASK_TOKEN
        return f"{value[:3]}{MASK_TOKEN}{value[-4:]}"
    if strategy is MaskingStrategy.HASH:
        return _stable_hash(value)
    if strategy is MaskingStrategy.REDACT:
        return None
    raise ValueError(f"unknown masking strategy: {strategy}")


def _stable_hash(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]
