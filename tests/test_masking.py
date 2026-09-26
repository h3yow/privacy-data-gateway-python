"""脱敏函数确定性测试。"""

from __future__ import annotations

import pytest

from privacy_gateway.masking import apply_mask
from privacy_gateway.models import MaskingStrategy


@pytest.mark.parametrize("strategy,expected", [
    (MaskingStrategy.VISIBLE, "13800001234"),
    (MaskingStrategy.MASK, "****"),
    (MaskingStrategy.PARTIAL, "138****1234"),
    (MaskingStrategy.REDACT, None),
])
def test_mask_strategies(strategy, expected):
    assert apply_mask("13800001234", strategy) == expected


def test_hash_is_stable_and_distinct():
    v = "110101199001011234"
    h1 = apply_mask(v, MaskingStrategy.HASH)
    h2 = apply_mask(v, MaskingStrategy.HASH)
    assert h1 == h2 and h1.startswith("sha256:")
    assert apply_mask("other", MaskingStrategy.HASH) != h1


def test_partial_short_value_falls_back_to_mask():
    assert apply_mask("123", MaskingStrategy.PARTIAL) == "****"
