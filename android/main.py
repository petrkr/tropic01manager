from __future__ import annotations

import sys
from pathlib import Path
from threading import Thread

from kivy.app import App
from kivy.clock import Clock
from kivy.properties import StringProperty
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.popup import Popup
from kivy.uix.label import Label
from kivy.uix.button import Button

# Allow local repository import during early POC phase.
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from app.services.settings_store import SettingsStore
from app.services.tropic_client import TropicClient, TropicClientError


class ConnectionPopup(Popup):
    def __init__(self, root_view, **kwargs):
        self.root_view = root_view
        super().__init__(**kwargs)

    def on_transport_changed(self, value: str) -> None:
        self.root_view._save_connection()

    def on_pairing_profile_changed(self, value: str) -> None:
        # Enable/disable custom fields
        is_custom = value == "custom"
        self.ids.pairing_index.disabled = not is_custom
        self.ids.pairing_priv.disabled = not is_custom
        self.ids.pairing_pub.disabled = not is_custom
        self.root_view._save_pairing()

    def on_field_changed(self) -> None:
        self.root_view._save_connection()
        self.root_view._save_pairing()

    def connect_and_read_chipid(self) -> None:
        self.root_view.connect_and_read_chipid()
        self.dismiss()

    def disconnect(self) -> None:
        self.root_view.disconnect()
        self.dismiss()

    def start_session(self) -> None:
        self.root_view.start_session()

    def abort_session(self) -> None:
        self.root_view.abort_session()

    def save_and_close(self) -> None:
        # Save settings are already auto-saved on field change
        self.dismiss()


class RootView(BoxLayout):
    status = StringProperty("Idle")
    connection_status = StringProperty("Disconnected")
    session_status = StringProperty("No Session")
    chip_id = StringProperty("Unknown")
    is_connected = False
    is_session_active = False

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.client = TropicClient()
        self.settings = SettingsStore()
        self.connection_popup = None
        self.progress_popup = None
        Clock.schedule_once(self._load_settings, 0)

    def _set_status(self, text: str) -> None:
        self.status = text

    def _set_connection_status(self, text: str) -> None:
        self.connection_status = text

    def _set_session_status(self, text: str) -> None:
        self.session_status = text

    def open_connection_popup(self) -> None:
        if self.connection_popup is None:
            self.connection_popup = ConnectionPopup(self)
        # Update fields from current settings
        self.connection_popup.ids.transport.text = self._get_connection("transport", "TCP")
        self.connection_popup.ids.host.text = self._get_connection("host", "127.0.0.1")
        self.connection_popup.ids.port.text = self._get_connection("port", "28992")
        self.connection_popup.ids.pairing_profile.text = self._get_pairing("profile", "prod0")
        self.connection_popup.ids.pairing_index.text = self._get_pairing("custom_index", "0")
        self.connection_popup.ids.pairing_priv.text = self._get_pairing("custom_priv", "")
        self.connection_popup.ids.pairing_pub.text = self._get_pairing("custom_pub", "")
        self.connection_popup.open()

    def toggle_connect(self) -> None:
        if self.is_connected:
            self.disconnect()
        else:
            self.connect_and_read_chipid()

    def toggle_session(self) -> None:
        if self.is_session_active:
            self.abort_session()
        else:
            self.start_session()

    def toggle_session(self) -> None:
        if self.is_session_active:
            self.abort_session()
        else:
            self.start_session()

    def _update_connect_button(self) -> None:
        self.ids.btn_connect.text = "Disconnect" if self.is_connected else "Connect"

    def _update_session_button(self) -> None:
        self.ids.btn_session.text = "Abort Session" if self.is_session_active else "Start Session"

    def _get_connection(self, key, default):
        conn = self.settings.get("connection", {})
        return conn.get(key, default)

    def _get_pairing(self, key, default):
        pairing = self.settings.get("pairing", {})
        return pairing.get(key, default)

    def _save_connection(self) -> None:
        if self.connection_popup:
            self.settings.put("connection", {
                "transport": self.connection_popup.ids.transport.text,
                "host": self.connection_popup.ids.host.text.strip(),
                "port": self.connection_popup.ids.port.text.strip(),
            })

    def _save_pairing(self) -> None:
        if self.connection_popup:
            self.settings.put("pairing", {
                "profile": self.connection_popup.ids.pairing_profile.text,
                "custom_index": self.connection_popup.ids.pairing_index.text.strip(),
                "custom_priv": self.connection_popup.ids.pairing_priv.text.strip(),
                "custom_pub": self.connection_popup.ids.pairing_pub.text.strip(),
            })

    def _show_progress(self, title: str, message: str) -> None:
        """Show a non-dismissible progress popup"""
        if self.progress_popup:
            self.progress_popup.dismiss()
        content = BoxLayout(orientation='vertical', padding=20, spacing=10)
        content.add_widget(Label(text=message, font_size='16sp'))
        self.progress_popup = Popup(
            title=title,
            content=content,
            size_hint=(0.8, 0.3),
            auto_dismiss=False
        )
        self.progress_popup.open()

    def _hide_progress(self) -> None:
        """Hide the progress popup"""
        if self.progress_popup:
            self.progress_popup.dismiss()
            self.progress_popup = None

    def _show_error(self, message: str) -> None:
        """Show an error dialog"""
        # Truncate very long error messages
        if len(message) > 300:
            message = message[:300] + "\n... (truncated)"

        from kivy.core.window import Window
        from kivy.metrics import dp

        # Create content box with minimal padding
        content = BoxLayout(orientation='vertical', spacing=dp(8), padding=dp(12))

        # Error label - use size_hint_y to fill available space
        error_label = Label(
            text=message,
            font_size='14sp',
            halign='left',
            valign='top',
            text_size=(Window.size[0] * 0.85, None)
        )
        content.add_widget(error_label)

        # OK button
        btn = Button(text='OK', size_hint_y=None, height=dp(48))
        content.add_widget(btn)

        # Fixed height popup
        popup = Popup(
            title='Error',
            content=content,
            size_hint=(0.9, 0.4),
            auto_dismiss=True
        )
        btn.bind(on_release=popup.dismiss)
        popup.open()

    def connect_and_read_chipid(self) -> None:
        transport = self._get_connection("transport", "TCP")
        host = self._get_connection("host", "127.0.0.1").strip()
        port_text = self._get_connection("port", "28992").strip()

        if not host or not port_text:
            self._show_error("Host/port required")
            return

        # Show connecting progress
        self._show_progress("Connecting", "Connecting to server...\nPlease wait.")

        def worker() -> None:
            try:
                port = int(port_text)

                # Update progress to connecting
                Clock.schedule_once(lambda dt: self._update_progress_message(f"Connecting to {transport}://{host}:{port}..."), 0)

                self.client.connect(transport, host, port)

                # Update progress to reading chip ID
                Clock.schedule_once(lambda dt: self._update_progress_message("Reading Chip ID..."), 0)
                chipid = self.client.read_chipid()

                def _ok(_dt):
                    self._hide_progress()
                    self.is_connected = True
                    # Convert chipid bytes to hex string
                    chipid_hex = " ".join(f"{b:02x}" for b in chipid) if isinstance(chipid, bytes) else str(chipid)
                    self.chip_id = chipid_hex
                    self._set_status(f"Connected, chipid={chipid_hex}")
                    self._set_connection_status(f"Connected ({transport} {host}:{port})")
                    self._set_session_status("No Session")
                    self._update_connect_button()
                    self._update_session_button()

                Clock.schedule_once(_ok, 0)
            except (ValueError, TropicClientError) as exc:
                error_msg = str(exc)
                # Truncate very long error messages
                if len(error_msg) > 200:
                    error_msg = error_msg[:200] + "..."
                Clock.schedule_once(lambda dt: self._connection_error(error_msg), 0)

        Thread(target=worker, daemon=True).start()

    def _update_progress_message(self, message: str) -> None:
        """Update the progress dialog message"""
        if self.progress_popup and self.progress_popup.content:
            # Remove old label and add new one
            self.progress_popup.content.clear_widgets()
            self.progress_popup.content.add_widget(Label(text=message, font_size='16sp'))

    def _connection_error(self, error_msg: str) -> None:
        """Handle connection error"""
        self._hide_progress()
        self._show_error(f"Connection failed:\n\n{error_msg}")

    def disconnect(self) -> None:
        try:
            self.client.disconnect()
            self.is_connected = False
            self.is_session_active = False
            self._set_status("Disconnected")
            self._set_connection_status("Disconnected")
            self._set_session_status("No Session")
            self._update_connect_button()
            self._update_session_button()
        except TropicClientError as exc:
            self._set_status(f"Error: {exc}")

    def start_session(self) -> None:
        profile = self._get_pairing("profile", "prod0")
        idx_text = self._get_pairing("custom_index", "0").strip()
        idx = int(idx_text) if idx_text else 0
        priv = self._get_pairing("custom_priv", "").strip()
        pub = self._get_pairing("custom_pub", "").strip()

        def worker() -> None:
            try:
                key_index, pubkey = self.client.start_session(profile, idx, priv, pub)
                key_prefix = " ".join(f"{b:02x}" for b in pubkey[:8])

                def _ok(_dt):
                    self.is_session_active = True
                    self._set_status("Session active")
                    self._set_session_status(f"Session Active (Slot: {key_index}, Key: {key_prefix})")
                    self._update_session_button()

                Clock.schedule_once(_ok, 0)
            except (ValueError, TropicClientError) as exc:
                Clock.schedule_once(lambda _dt, err=exc: self._set_status(f"Error: {err}"), 0)

        self._set_status("Starting session...")
        Thread(target=worker, daemon=True).start()

    def abort_session(self) -> None:
        def worker() -> None:
            try:
                self.client.abort_session()

                def _ok(_dt):
                    self.is_session_active = False
                    self._set_status("Session aborted")
                    self._set_session_status("No Session")
                    self._update_session_button()

                Clock.schedule_once(_ok, 0)
            except TropicClientError as exc:
                Clock.schedule_once(lambda _dt, err=exc: self._set_status(f"Error: {err}"), 0)

        self._set_status("Aborting session...")
        Thread(target=worker, daemon=True).start()

    def _load_settings(self, _dt) -> None:
        self._set_connection_status("Disconnected")
        self._set_session_status("No Session")


class TropicAndroidApp(App):
    kv_file = 'main.kv'

    def build(self):
        return RootView()


if __name__ == "__main__":
    TropicAndroidApp().run()
