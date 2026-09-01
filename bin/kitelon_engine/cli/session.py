"""REPL session state."""


from dataclasses import dataclass, field
from typing import Any


@dataclass
class SessionContext:
    workspace: str | None = None
    last_job_id: int | None = None
    _cache: dict[str, Any] = field(default_factory=dict)

    def clear_cache(self) -> None:
        self._cache.clear()
