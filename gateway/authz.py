"""主体授权解析：存在性、过期与级别判定。"""
from __future__ import annotations

from datetime import datetime

from .models import Subject


class SubjectStore:
    """主体仓库接口（内存实现）。"""

    def __init__(self, subjects: dict[str, Subject] | None = None) -> None:
        self._subjects: dict[str, Subject] = dict(subjects or {})

    def get(self, subject_id: str) -> Subject | None:
        """按 ID 查找主体，不存在返回 None。"""
        return self._subjects.get(subject_id)

    def effective_level(self, subject_id: str, now: datetime) -> tuple[int | None, str | None]:
        """返回 (级别, 拒绝原因)。骨架：恒拒绝。"""
        raise NotImplementedError
