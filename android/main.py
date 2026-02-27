from __future__ import annotations

import sys
from pathlib import Path
from threading import Thread

from functools import partial

from kivy.clock import Clock
from kivy.properties import StringProperty, ObjectProperty, BooleanProperty

from kivymd.app import MDApp
from kivymd.uix.boxlayout import MDBoxLayout
from kivymd.uix.button import MDRaisedButton, MDFlatButton
from kivymd.uix.dialog import MDDialog
from kivymd.uix.label import MDLabel
from kivymd.uix.textfield import MDTextField
from kivymd.uix.spinner import MDSpinner
from kivymd.uix.tab import MDTabsBase
from kivymd.uix.menu import MDDropdownMenu
from kivy.uix.scrollview import ScrollView

# Allow local repository import during early POC phase.
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from app.services.settings_store import SettingsStore
from app.services.tropic_client import TropicClient, TropicClientError


# Tab classes
class ChipTab(MDBoxLayout, MDTabsBase):
    pass

class PingTab(MDBoxLayout, MDTabsBase):
    pass

class InfoTab(MDBoxLayout, MDTabsBase):
    pass

class RandomTab(MDBoxLayout, MDTabsBase):
    pass

class ConfigTab(MDBoxLayout, MDTabsBase):
    pass


class RootView(MDBoxLayout):
    status = StringProperty("Idle")
    connection_status = StringProperty("Disconnected")
    session_status = StringProperty("No Session")
    chip_id = StringProperty("Unknown")
    is_connected = BooleanProperty(False)
    is_session_active = BooleanProperty(False)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.client = TropicClient()
        self.settings = SettingsStore()
        self.connection_dialog = None
        self.progress_dialog = None
        Clock.schedule_once(self._load_settings, 0)

    def _set_status(self, text: str) -> None:
        self.status = text

    def _set_connection_status(self, text: str) -> None:
        self.connection_status = text

    def _set_session_status(self, text: str) -> None:
        self.session_status = text

    def open_connection_popup(self) -> None:
        """Open connection settings dialog"""
        if self.connection_dialog:
            self.connection_dialog.dismiss()
            self.connection_dialog = None

        # Get current settings
        transport = self._get_connection("transport", "TCP")
        host = self._get_connection("host", "127.0.0.1")
        port = self._get_connection("port", "28992")
        profile = self._get_pairing("profile", "prod0")
        custom_index = self._get_pairing("custom_index", "0")
        custom_priv = self._get_pairing("custom_priv", "")
        custom_pub = self._get_pairing("custom_pub", "")

        # Scrollable content container
        class ScrollContent(MDBoxLayout):
            def __init__(self, **kwargs):
                super().__init__(**kwargs)
                self.orientation = "vertical"
                self.spacing = "8dp"
                self.padding = "12dp"
                self.size_hint_y = None

        scroll_content = ScrollContent()

        # Section: Connection
        scroll_content.add_widget(MDLabel(
            text="Connection",
            font_style="Subtitle1",
            theme_text_color="Primary",
            size_hint_y=None,
            height="28dp",
            bold=True
        ))

        # Transport - button that opens dropdown
        transport_btn = MDRaisedButton(
            text=f"Transport: {transport}",
            size_hint=(1, None),
            height="44dp"
        )
        scroll_content.add_widget(transport_btn)

        # Host
        host_field = MDTextField(
            hint_text="Host",
            text=host,
            size_hint=(1, None),
            height="52dp"
        )
        scroll_content.add_widget(host_field)

        # Port
        port_field = MDTextField(
            hint_text="Port",
            text=port,
            size_hint=(1, None),
            height="52dp"
        )
        scroll_content.add_widget(port_field)

        # Divider
        divider = MDBoxLayout(size_hint_y=None, height="8dp")
        scroll_content.add_widget(divider)

        # Section: Secure Session
        scroll_content.add_widget(MDLabel(
            text="Secure Session",
            font_style="Subtitle1",
            theme_text_color="Primary",
            size_hint_y=None,
            height="28dp",
            bold=True
        ))

        # Profile - button that opens dropdown
        profile_btn = MDRaisedButton(
            text=f"Pairing: {profile}",
            size_hint=(1, None),
            height="44dp"
        )
        scroll_content.add_widget(profile_btn)

        # Spacer for dropdown
        dropdown_spacer = MDBoxLayout(size_hint_y=None, height="20dp")
        scroll_content.add_widget(dropdown_spacer)

        # Custom fields (initially hidden)
        class CustomFieldsBox(MDBoxLayout):
            def __init__(self, **kwargs):
                super().__init__(**kwargs)
                self.orientation = "vertical"
                self.spacing = "8dp"
                self.size_hint_y = None

        custom_fields_box = CustomFieldsBox()

        index_field = MDTextField(
            hint_text="Slot Index",
            text=custom_index,
            size_hint=(1, None),
            height="52dp"
        )
        custom_fields_box.add_widget(index_field)

        priv_field = MDTextField(
            hint_text="Private Key (hex)",
            text=custom_priv,
            size_hint=(1, None),
            height="52dp",
            password=True
        )
        custom_fields_box.add_widget(priv_field)

        pub_field = MDTextField(
            hint_text="Public Key (hex)",
            text=custom_pub,
            size_hint=(1, None),
            height="52dp"
        )
        custom_fields_box.add_widget(pub_field)

        # Calculate height - add spacing and padding
        padding_height = 24  # 12dp top + 12dp bottom
        spacing_count = 7  # spacings between elements (including spacer)
        spacing_height = 8 * spacing_count
        spacer_height = 20  # dropdown spacer
        base_height = 28 + 44 + 52 + 52 + 8 + 28 + 44 + spacer_height + padding_height + spacing_height
        custom_fields_height = 52 + 8 + 52 + 8 + 52  # 3 fields + 2 spacings

        # Store selected values
        selected_transport = [transport]
        selected_profile = [profile]

        # Initial state - add custom fields only if custom profile
        if profile == "custom":
            custom_fields_box.height = f"{custom_fields_height}dp"
            scroll_content.add_widget(custom_fields_box)
            scroll_content.height = base_height + custom_fields_height
            index_field.disabled = False
            priv_field.disabled = False
            pub_field.disabled = False
        else:
            scroll_content.height = base_height
            index_field.disabled = True
            priv_field.disabled = True
            pub_field.disabled = True

        # Define callbacks first (before menu creation)
        def set_transport(value):
            selected_transport[0] = value
            transport_btn.text = f"Transport: {value}"
            transport_menu.dismiss()

        def set_profile(value):
            selected_profile[0] = value
            profile_btn.text = f"Pairing: {value}"
            profile_menu.dismiss()

            if value == "custom":
                # Add custom fields if not already added
                if custom_fields_box.parent is None:
                    scroll_content.add_widget(custom_fields_box)
                custom_fields_box.height = f"{custom_fields_height}dp"
                index_field.disabled = False
                priv_field.disabled = False
                pub_field.disabled = False
                scroll_content.height = base_height + custom_fields_height
            else:
                # Remove custom fields
                if custom_fields_box.parent is not None:
                    scroll_content.remove_widget(custom_fields_box)
                index_field.disabled = True
                priv_field.disabled = True
                pub_field.disabled = True
                scroll_content.height = base_height

        # Transport dropdown menu
        transport_menu = MDDropdownMenu(
            caller=transport_btn,
            items=[
                {"viewclass": "OneLineListItem", "text": "TCP", "on_release": partial(set_transport, "TCP")},
                {"viewclass": "OneLineListItem", "text": "Network", "on_release": partial(set_transport, "Network")},
            ],
            width_mult=4,
        )

        transport_btn.on_release = lambda: transport_menu.open()

        # Profile dropdown menu
        profile_menu = MDDropdownMenu(
            caller=profile_btn,
            items=[
                {"viewclass": "OneLineListItem", "text": "prod0", "on_release": partial(set_profile, "prod0")},
                {"viewclass": "OneLineListItem", "text": "eng", "on_release": partial(set_profile, "eng")},
                {"viewclass": "OneLineListItem", "text": "custom", "on_release": partial(set_profile, "custom")},
            ],
            width_mult=4,
        )

        profile_btn.on_release = lambda: profile_menu.open()

        # ScrollView wrapper
        scroll_content_height = scroll_content.height
        scroll_height = min(scroll_content_height, 350)  # Max 350dp for scroll area

        scroll = ScrollView(size_hint=(1, None), height=f"{scroll_height}dp", do_scroll_x=False)
        scroll.clip_children = False  # Allow dropdown to extend outside
        scroll.add_widget(scroll_content)

        # Main dialog container
        total_dialog_height = scroll_height + 48 + 16  # scroll + buttons + padding
        dialog_container = MDBoxLayout(orientation="vertical", size_hint_y=None, height=f"{total_dialog_height}dp")
        dialog_container.add_widget(scroll)

        # Button row
        btn_box = MDBoxLayout(
            size_hint_y=None,
            height="48dp",
            spacing="8dp",
            padding="8dp"
        )

        def save(*args):
            self.settings.put("connection", {
                "transport": selected_transport[0],
                "host": host_field.text.strip(),
                "port": port_field.text.strip(),
            })
            self.settings.put("pairing", {
                "profile": selected_profile[0],
                "custom_index": index_field.text.strip(),
                "custom_priv": priv_field.text.strip(),
                "custom_pub": pub_field.text.strip(),
            })
            self.connection_dialog.dismiss()

        def cancel(*args):
            self.connection_dialog.dismiss()

        btn_box.add_widget(MDFlatButton(text="Cancel", on_release=cancel))
        btn_box.add_widget(MDRaisedButton(text="Save", on_release=save))
        dialog_container.add_widget(btn_box)

        self.connection_dialog = MDDialog(
            title="Connection Settings",
            type="custom",
            content_cls=dialog_container,
            auto_dismiss=False,
        )
        self.connection_dialog.open()

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

    def _update_connect_button(self) -> None:
        btn = self.ids.btn_connect
        btn.text = "Disconnect" if self.is_connected else "Connect"

    def _update_session_button(self) -> None:
        btn = self.ids.btn_session
        btn.text = "Abort Session" if self.is_session_active else "Start Session"

    def _get_connection(self, key, default):
        conn = self.settings.get("connection", {})
        return conn.get(key, default)

    def _get_pairing(self, key, default):
        pairing = self.settings.get("pairing", {})
        return pairing.get(key, default)

    def _show_progress(self, title: str, message: str) -> None:
        """Show a progress dialog with spinner"""
        if self.progress_dialog:
            self.progress_dialog.dismiss()

        content = MDBoxLayout(
            orientation="vertical",
            spacing="16dp",
            padding="24dp",
            size_hint_y=None,
            height="120dp"
        )

        content.add_widget(MDSpinner(size_hint=(None, None), size=("48dp", "48dp"), pos_hint={"center_x": 0.5}))
        content.add_widget(MDLabel(
            text=message,
            halign="center",
            theme_text_color="Primary"
        ))

        self.progress_dialog = MDDialog(
            title=title,
            type="custom",
            content_cls=content,
            auto_dismiss=False
        )
        self.progress_dialog.open()

    def _hide_progress(self) -> None:
        """Hide the progress dialog"""
        if self.progress_dialog:
            self.progress_dialog.dismiss()
            self.progress_dialog = None

    def _show_error(self, message: str) -> None:
        """Show an error dialog"""
        # Truncate very long error messages
        if len(message) > 300:
            message = message[:300] + "\n... (truncated)"

        content = MDBoxLayout(
            orientation="vertical",
            spacing="12dp",
            padding="16dp",
            size_hint_y=None,
            height="150dp"
        )

        content.add_widget(MDLabel(
            text=message,
            halign="left",
            valign="top",
            theme_text_color="Primary",
            font_style="Body1"
        ))

        btn = MDRaisedButton(text="OK", size_hint_x=None, width="100dp")
        content.add_widget(btn)

        dialog = MDDialog(
            title="Error",
            type="custom",
            content_cls=content,
            auto_dismiss=True
        )
        btn.bind(on_release=dialog.dismiss)
        dialog.open()

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
        if self.progress_dialog and self.progress_dialog.content_cls:
            # Remove old widgets and add new label
            self.progress_dialog.content_cls.clear_widgets()
            self.progress_dialog.content_cls.add_widget(
                MDSpinner(size_hint=(None, None), size=("48dp", "48dp"), pos_hint={"center_x": 0.5})
            )
            self.progress_dialog.content_cls.add_widget(
                MDLabel(text=message, halign="center", theme_text_color="Primary")
            )

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

        # Show progress
        self._show_progress("Starting Session", "Starting secure session...\nPlease wait.")

        def worker() -> None:
            try:
                key_index, pubkey = self.client.start_session(profile, idx, priv, pub)
                key_prefix = " ".join(f"{b:02x}" for b in pubkey[:8])

                def _ok(_dt):
                    self._hide_progress()
                    self.is_session_active = True
                    self._set_status("Session active")
                    self._set_session_status(f"Session Active (Slot: {key_index}, Key: {key_prefix})")
                    self._update_session_button()

                Clock.schedule_once(_ok, 0)
            except (ValueError, TropicClientError) as e:
                error_msg = str(e)
                def _error(_dt):
                    self._hide_progress()
                    self._show_error(f"Session start failed:\n\n{error_msg}")
                Clock.schedule_once(_error, 0)

        Thread(target=worker, daemon=True).start()

    def abort_session(self) -> None:
        # Show progress
        self._show_progress("Aborting Session", "Aborting secure session...\nPlease wait.")

        def worker() -> None:
            try:
                self.client.abort_session()

                def _ok(_dt):
                    self._hide_progress()
                    self.is_session_active = False
                    self._set_status("Session aborted")
                    self._set_session_status("No Session")
                    self._update_session_button()

                Clock.schedule_once(_ok, 0)
            except TropicClientError as e:
                error_msg = str(e)
                def _error(_dt):
                    self._hide_progress()
                    self._show_error(f"Session abort failed:\n\n{error_msg}")
                Clock.schedule_once(_error, 0)

        Thread(target=worker, daemon=True).start()

    def _load_settings(self, _dt) -> None:
        self._set_connection_status("Disconnected")
        self._set_session_status("No Session")


class TropicAndroidApp(MDApp):
    kv_file = 'main.kv'

    def build(self):
        self.theme_cls.theme_style = "Dark"  # Start with dark mode
        self.theme_cls.primary_palette = "Blue"
        self.theme_cls.accent_palette = "Teal"
        return RootView()

    def on_tab_switch(self, instance_tabs, instance_tab, instance_tab_label, tab_text):
        """Called when switching tabs"""
        pass

    def send_ping(self):
        """Send ping command - placeholder"""
        if self.root and self.root.is_connected:
            # TODO: Implement actual ping
            pass


if __name__ == "__main__":
    TropicAndroidApp().run()
