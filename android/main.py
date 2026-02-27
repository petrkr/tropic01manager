from __future__ import annotations

import sys
from pathlib import Path
from threading import Thread

from functools import partial

from kivy.clock import Clock
from kivy.properties import StringProperty, ObjectProperty, BooleanProperty, AliasProperty, NumericProperty

from kivymd.app import MDApp
from tropicsquare.chip_id import ChipId
from kivymd.uix.boxlayout import MDBoxLayout
from kivymd.uix.button import MDRaisedButton, MDFlatButton
from kivymd.uix.dialog import MDDialog
from kivymd.uix.label import MDLabel
from kivymd.uix.textfield import MDTextField
from kivymd.uix.spinner import MDSpinner
from kivymd.uix.tab import MDTabsBase
from kivymd.uix.menu import MDDropdownMenu
from kivy.uix.scrollview import ScrollView
from kivymd.uix.scrollview import MDScrollView

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


# Simple event bus for state changes
class EventBus:
    def __init__(self):
        self._listeners = {}

    def bind(self, event_name, callback):
        if event_name not in self._listeners:
            self._listeners[event_name] = []
        self._listeners[event_name].append(callback)

    def unbind(self, event_name, callback):
        if event_name in self._listeners:
            try:
                self._listeners[event_name].remove(callback)
            except ValueError:
                pass

    def trigger(self, event_name, **kwargs):
        if event_name in self._listeners:
            for callback in self._listeners[event_name]:
                callback(**kwargs)

    def clear(self):
        self._listeners.clear()


class RootView(MDBoxLayout):
    status = StringProperty("Idle")
    connection_status = StringProperty("Disconnected")
    session_status = StringProperty("No Session")

    # ChipId object storage (not directly accessible from KV)
    _chipid_obj = ObjectProperty(None, allownone=True)

    # Properties for KV access
    chip_id_version = StringProperty("")
    silicon_rev = StringProperty("")
    package_type = StringProperty("")
    fab_name = StringProperty("")
    part_number = StringProperty("")
    hsm_version = StringProperty("")
    prog_version = StringProperty("")
    serial_number = StringProperty("")
    batch_id = StringProperty("")

    is_connected = BooleanProperty(False)
    is_session_active = BooleanProperty(False)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.client = TropicClient()
        self.settings = SettingsStore()
        self.connection_dialog = None
        self.progress_dialog = None
        self.event_bus = EventBus()
        Clock.schedule_once(self._load_settings, 0)

    def _set_status(self, text: str) -> None:
        self.status = text

    def _set_chipid(self, chipid: ChipId) -> None:
        """Set ChipId object and update all display properties"""
        self._chipid_obj = chipid
        if chipid:
            self.chip_id_version = '.'.join(map(str, chipid.chip_id_version))
            self.silicon_rev = chipid.silicon_rev
            self.package_type = f"{chipid.package_type_name} (0x{chipid.package_type_id:04X})"
            self.fab_name = f"{chipid.fab_name} (0x{chipid.fab_id:03X})"
            self.part_number = f"0x{chipid.part_number_id:03X}"
            self.hsm_version = '.'.join(map(str, chipid.hsm_version))
            self.prog_version = '.'.join(map(str, chipid.prog_version))
            self.serial_number = str(chipid.serial_number)
            self.batch_id = chipid.batch_id.hex()
            print(f"DEBUG _set_chipid: chip_id_version={self.chip_id_version}, package_type={self.package_type}")
            # Refresh the ChipTab by forcing a property update cycle
            Clock.schedule_once(self._refresh_chip_tab, 0.01)
        else:
            self.chip_id_version = ""
            self.silicon_rev = ""
            self.package_type = ""
            self.fab_name = ""
            self.part_number = ""
            self.hsm_version = ""
            self.prog_version = ""
            self.serial_number = ""
            self.batch_id = ""
            Clock.schedule_once(self._refresh_chip_tab, 0.01)

    def _refresh_chip_tab(self, dt):
        """Force refresh of ChipID tab"""
        # Toggle a dummy property to force KV refresh
        pass

    def _clear_chipid(self) -> None:
        """Clear all chip ID properties"""
        self._chipid_obj = None
        self.chip_id_version = ""
        self.silicon_rev = ""
        self.package_type = ""
        self.fab_name = ""
        self.part_number = ""
        self.hsm_version = ""
        self.prog_version = ""
        self.serial_number = ""
        self.batch_id = ""

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
                    # Parse chipid as ChipId object
                    try:
                        from tropicsquare.chip_id import ChipId
                        print(f"DEBUG: chipid type={type(chipid)}, len={len(chipid) if hasattr(chipid, '__len__') else 'N/A'}")
                        chipid_obj = ChipId(chipid) if isinstance(chipid, bytes) else chipid
                        print(f"DEBUG: chipid_obj.package_type_name={chipid_obj.package_type_name}")
                        self._set_chipid(chipid_obj)
                        # Trigger connected event with chip_id string for status bar
                        chipid_hex = " ".join(f"{b:02x}" for b in chipid_obj.raw[:8])
                        self._set_status(f"Connected")
                        self._set_connection_status(f"Connected ({transport} {host}:{port})")
                        self.event_bus.trigger("connected", chip_id=chipid_hex, chipid_obj=chipid_obj)
                    except Exception as e:
                        # Fallback to hex string if parsing fails
                        import traceback
                        print(f"DEBUG: ChipId parsing failed: {e}")
                        traceback.print_exc()
                        chipid_hex = " ".join(f"{b:02x}" for b in chipid) if isinstance(chipid, bytes) else str(chipid)
                        self._clear_chipid()
                        self._set_status(f"Connected (raw chipid)")
                        self._set_connection_status(f"Connected ({transport} {host}:{port})")
                        self.event_bus.trigger("connected", chip_id=chipid_hex)
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
            self._clear_chipid()
            # Trigger disconnected event
            self.event_bus.trigger("disconnected")
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
                    # Trigger session_started event
                    self.event_bus.trigger("session_started", key_index=key_index, pubkey_prefix=key_prefix)

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
                    # Trigger session_ended event
                    self.event_bus.trigger("session_ended")

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
        self.root = RootView()
        # Setup event listeners after root is created
        Clock.schedule_once(self._setup_event_listeners, 0)
        return self.root

    def _setup_event_listeners(self, dt):
        """Setup event bus listeners for tabs"""
        if not self.root or not self.root.event_bus:
            return

        # Register listeners for connection state changes
        self.root.event_bus.bind("connected", self._on_connected)
        self.root.event_bus.bind("disconnected", self._on_disconnected)
        self.root.event_bus.bind("session_started", self._on_session_started)
        self.root.event_bus.bind("session_ended", self._on_session_ended)
        Clock.schedule_once(lambda dt: self._init_chip_tab(), 0.2)

    def _on_connected(self, **kwargs):
        """Handle connected event - update UI elements"""
        chip_id_obj = kwargs.get("chipid_obj")
        if chip_id_obj:
            self._update_chip_tab(chip_id_obj)

    def _find_chip_tab(self):
        """Find ChipTab in widget tree"""
        tabs = self.root.ids.tabs if self.root and hasattr(self.root, 'ids') else None
        if not tabs:
            return None

        def find_chip_tab(widget):
            if isinstance(widget, ChipTab):
                return widget
            if hasattr(widget, 'children'):
                for child in widget.children:
                    result = find_chip_tab(child)
                    if result:
                        return result
            return None

        return find_chip_tab(tabs)

    def _init_chip_tab(self):
        """Initialize chip tab structure on startup"""
        chip_tab = self._find_chip_tab()
        if chip_tab:
            self._init_chip_tab_structure(chip_tab)

    def _clear_chip_tab(self):
        """Clear chip tab values (keep structure)"""
        chip_tab = self._find_chip_tab()
        if chip_tab:
            container = chip_tab.ids.get('chip_container')
            if container:
                # Clear value labels (first child of each row, which is at index 0)
                for row in container.children:
                    if len(row.children) >= 2:
                        row.children[0].text = ""  # Clear value label

    def _update_chip_tab(self, chipid_obj):
        """Update Chip ID tab with data"""
        chip_tab = self._find_chip_tab()
        if not chip_tab:
            print("DEBUG ChipTab not found, retrying...")
            Clock.schedule_once(lambda dt: self._update_chip_tab(chipid_obj), 0.1)
            return

        self._populate_chip_tab(chip_tab, chipid_obj)

    def _init_chip_tab_structure(self, tab):
        """Initialize empty chip tab structure with keys"""
        container = tab.ids.get('chip_container')
        if not container:
            return

        # Clear any existing content
        container.clear_widgets()

        # Key labels (static)
        keys = [
            "Chip ID Version",
            "Silicon Revision",
            "Package Type",
            "Fabrication",
            "Part Number ID",
            "HSM Version",
            "Program Version",
            "Serial Number",
            "Batch ID",
        ]

        # Store value labels for later updates
        self._chip_tab_value_labels = []

        for key in keys:
            row = MDBoxLayout(
                orientation="horizontal",
                size_hint_y=None,
                height="32dp",
                spacing="8dp"
            )

            key_label = MDLabel(
                text=f"{key}:",
                size_hint_x=0.5,
                theme_text_color="Secondary",
                font_style="Body2"
            )

            value_label = MDLabel(
                text="",
                size_hint_x=0.5,
                theme_text_color="Primary",
                halign="right"
            )

            row.add_widget(key_label)
            row.add_widget(value_label)
            container.add_widget(row)
            self._chip_tab_value_labels.append(value_label)

        # Update container height
        container.height = container.minimum_height

    def _populate_chip_tab(self, tab, chipid_obj):
        """Update chip tab values"""
        container = tab.ids.get('chip_container')
        if not container:
            return

        sn = chipid_obj.serial_number
        sn_str = f"SN:0x{sn.sn:02X} Fab:0x{sn.fab_id:03X} PN:0x{sn.part_number_id:03X} Lot:{sn.lot_id.hex()} Wafer:0x{sn.wafer_id:02X} ({sn.x_coord},{sn.y_coord})"

        # Data values (must match keys order in _init_chip_tab_structure)
        data = [
            '.'.join(map(str, chipid_obj.chip_id_version)),
            chipid_obj.silicon_rev,
            f"{chipid_obj.package_type_name} (0x{chipid_obj.package_type_id:04X})",
            f"{chipid_obj.fab_name} (0x{chipid_obj.fab_id:03X})",
            f"0x{chipid_obj.part_number_id:03X}",
            '.'.join(map(str, chipid_obj.hsm_version)),
            '.'.join(map(str, chipid_obj.prog_version)),
            sn_str,
            chipid_obj.batch_id.hex(),
        ]

        # Update value labels
        for i, value in enumerate(data):
            if i < len(self._chip_tab_value_labels):
                self._chip_tab_value_labels[i].text = value

    def _on_disconnected(self, **kwargs):
        """Handle disconnected event - clear all L3/L4 data"""
        if self.root:
            self.root._clear_chipid()
        self._clear_chip_tab()
        self._update_ping_button_state()

    def _update_ping_button_state(self):
        """Update ping button enabled state"""
        ping_tab = self._find_ping_tab()
        if ping_tab:
            btn = ping_tab.ids.get('btn_send_ping')
            if btn:
                btn.disabled = not self.root.is_session_active

    def _on_session_started(self, **kwargs):
        """Handle session started event"""
        self._update_ping_button_state()

    def _on_session_ended(self, **kwargs):
        """Handle session ended event - clear L3 data"""
        self._update_ping_button_state()

    def on_tab_switch(self, instance_tabs, instance_tab, instance_tab_label, tab_text):
        """Called when switching tabs"""
        pass

    def send_ping(self):
        """Send ping command"""
        if not self.root or not self.root.is_session_active:
            return

        ping_tab = self._find_ping_tab()
        if not ping_tab:
            return

        input_field = ping_tab.ids.get('ping_input')
        result_label = ping_tab.ids.get('ping_result')
        if not input_field or not result_label:
            return

        input_text = input_field.text.strip()
        if not input_text:
            result_label.text = "[color=ff6666]Error: Empty input[/color]"
            return

        ping_data = input_text.encode("utf-8")

        def worker(data=ping_data):
            try:
                result = self.root.client.ts.ping(data)
                result_str = result.decode("utf-8")

                def update_ui(_dt):
                    result_label.text = f"[b]Response:[/b]\n{result_str}"

                Clock.schedule_once(update_ui, 0)
            except Exception as e:
                error_msg = str(e)
                def update_error(_dt):
                    result_label.text = f"[color=ff6666]Error: {error_msg}[/color]"

                Clock.schedule_once(update_error, 0)

        Thread(target=worker, daemon=True).start()

    def _find_ping_tab(self):
        """Find PingTab in widget tree"""
        tabs = self.root.ids.tabs if self.root and hasattr(self.root, 'ids') else None
        if not tabs:
            return None

        def find_ping_tab(widget):
            if isinstance(widget, PingTab):
                return widget
            if hasattr(widget, 'children'):
                for child in widget.children:
                    result = find_ping_tab(child)
                    if result:
                        return result
            return None

        return find_ping_tab(tabs)


if __name__ == "__main__":
    TropicAndroidApp().run()
