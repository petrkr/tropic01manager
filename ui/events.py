from __future__ import annotations

from typing import Callable, Dict, List


class EventBus:
    def __init__(self) -> None:
        self._handlers: Dict[str, List[Callable[..., None]]] = {}

    def on(self, event: str, handler: Callable[..., None]) -> None:
        self._handlers.setdefault(event, []).append(handler)

    def emit(self, event: str, **kwargs) -> None:
        for handler in self._handlers.get(event, []):
            handler(**kwargs)
