from __future__ import annotations

from typing import Any

from kivy.app import App
from kivy.storage.jsonstore import JsonStore


class SettingsStore:
    def __init__(self, app_name: str = "tropic01manager") -> None:
        app = App.get_running_app()
        if app is None:
            raise RuntimeError("Kivy app not running")
        self._store = JsonStore(f"{app.user_data_dir}/settings.json")

    def get(self, section: str, default: dict[str, Any]) -> dict[str, Any]:
        if self._store.exists(section):
            return dict(self._store.get(section))
        return dict(default)

    def put(self, section: str, values: dict[str, Any]) -> None:
        self._store.put(section, **values)
