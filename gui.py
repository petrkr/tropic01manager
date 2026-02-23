from ui.events import EventBus
from ui.maintenance import setup_maintenance
from ui.ecc import setup_ecc
from ui.mcounter import setup_mcounter
from ui.pairing_keys import setup_pairing_keys
from ui.config_tab import setup_config_tab
from ui.mem_data import setup_mem_data
from ui.info import setup_info
from ui.chip_id import setup_chip_id
from ui.ping import setup_ping
from ui.random_data import setup_random_data
from tropicsquare.constants.pairing_keys import (
    FACTORY_PAIRING_KEY_INDEX,
    FACTORY_PAIRING_PRIVATE_KEY_PROD0,
    FACTORY_PAIRING_PUBLIC_KEY_PROD0,
    FACTORY_PAIRING_PRIVATE_KEY_ENG_SAMPLE,
    FACTORY_PAIRING_PUBLIC_KEY_ENG_SAMPLE
)
from tropicsquare.ports.cpython import TropicSquareCPython
from tropicsquare.exceptions import *
from tropicsquare.transports.uart import UartTransport
from tropicsquare.transports.network import NetworkSpiTransport
from tropicsquare.transports.tcp import TcpTransport

import threading


# Default factory pairing keys (PH0 / PROD0)
DEFAULT_PAIRING_INDEX = FACTORY_PAIRING_KEY_INDEX
DEFAULT_PAIRING_PRIV = FACTORY_PAIRING_PRIVATE_KEY_PROD0
DEFAULT_PAIRING_PUB = FACTORY_PAIRING_PUBLIC_KEY_PROD0


import sys
from PyQt6.QtCore import QSettings
from PyQt6 import QtWidgets, uic, QtGui, QtCore


def main():
    # Application starts without device connection
    ts = None
    transport = None
    settings = QSettings("tropic01manager", "tropic01manager")
    settings_initialized = False
    current_pairing_pubkey = None
    current_pairing_index = None
    ecc_set_enabled = None
    mcounter_set_enabled = None
    pairing_set_enabled = None
    pairing_reset_state = None
    config_set_enabled = None
    mem_set_enabled = None
    info_set_enabled = None
    ping_set_enabled = None
    random_set_enabled = None
    chip_id_refresh = None
    bus = EventBus()

    def close_transport():
        nonlocal transport
        if not transport:
            return
        if hasattr(transport, "close"):
            try:
                transport.close()
            except Exception:
                pass
        elif hasattr(transport, "_close"):
            try:
                transport._close()
            except Exception:
                pass
        transport = None

    # Helper function to update UI based on connection state
    def update_connection_ui():
        """Update UI elements based on current connection state"""
        connected = ts is not None
        has_session = connected and hasattr(ts, "_secure_session") and ts._secure_session is not None

        # Update connection controls
        window.btnConnectToggle.setEnabled(True)
        window.btnConnectToggle.setText("Disconnect" if connected else "Connect")

        if connected:
            window.lblConnectionStatus.setText("Connected")
            window.lblConnectionStatus.setStyleSheet("color: green; font-weight: bold;")
        else:
            window.lblConnectionStatus.setText("Disconnected")
            window.lblConnectionStatus.setStyleSheet("color: red; font-weight: bold;")

        # Update secure session controls
        window.btnSessionToggle.setEnabled(connected)
        window.btnSessionToggle.setText("Abort Session" if has_session else "Start Session")

        if has_session:
            pubkey = current_pairing_pubkey or DEFAULT_PAIRING_PUB
            pubkey_prefix = " ".join(f"{b:02x}" for b in bytes(pubkey)[:8])
            key_index = current_pairing_index if current_pairing_index is not None else "?"
            window.lblSessionStatus.setTextFormat(QtCore.Qt.TextFormat.RichText)
            window.lblSessionStatus.setText(
                f"Session Active <span style=\"color:#1f5fbf\">(Slot: {key_index}, Key: {pubkey_prefix})</span>"
            )
            window.lblSessionStatus.setStyleSheet("color: green; font-weight: bold;")
        else:
            window.lblSessionStatus.setTextFormat(QtCore.Qt.TextFormat.PlainText)
            window.lblSessionStatus.setText("No Session")
            window.lblSessionStatus.setStyleSheet("color: gray; font-weight: bold;")

        if connected:
            driver_type = window.cmbDriverType.currentText()
            param1 = window.leParam1.text()
            param2 = window.leParam2.text()
            if driver_type == "UART":
                target = param1
                label = "UART"
            elif driver_type == "Network":
                target = f"{param1}:{param2}"
                label = "NET"
            elif driver_type == "TCP":
                target = f"{param1}:{param2}"
                label = "TCP"
            else:
                target = ""
                label = driver_type
            window.lblConnectionTarget.setText(f"({label} {target})".strip())
        else:
            window.lblConnectionTarget.setText("")

        # Enable/disable device operation buttons based on connection
        if info_set_enabled is not None:
            info_set_enabled(connected)
        if ping_set_enabled is not None:
            ping_set_enabled(connected)
        if random_set_enabled is not None:
            random_set_enabled(connected)
        window.btnMaintenanceStartupReboot.setEnabled(connected)
        window.btnMaintenanceStartupBootloader.setEnabled(connected)
        window.btnMaintenanceSleep.setEnabled(connected)
        window.btnMaintenanceDeepSleep.setEnabled(connected)
        window.btnMaintenanceGetLogs.setEnabled(connected)
        if ecc_set_enabled is not None:
            ecc_set_enabled(connected)
        if mcounter_set_enabled is not None:
            mcounter_set_enabled(connected)
        if pairing_set_enabled is not None:
            pairing_set_enabled(connected)
        if mem_set_enabled is not None:
            mem_set_enabled(connected)
        if config_set_enabled is not None:
            config_set_enabled(connected)

    def on_driver_type_changed():
        """Update parameter labels and defaults when driver type changes"""
        driver_type = window.cmbDriverType.currentText()

        if driver_type == "UART":
            window.lblParam1.setText("Port:")
            window.lblParam2.setText("Baudrate:")
            default_param1 = "/dev/ttyACM1"
            default_param2 = "115200"
        elif driver_type == "Network":
            window.lblParam1.setText("Host:")
            window.lblParam2.setText("Port:")
            default_param1 = "localhost"
            default_param2 = "12345"
        elif driver_type == "TCP":
            window.lblParam1.setText("Host:")
            window.lblParam2.setText("Port:")
            default_param1 = "127.0.0.1"
            default_param2 = "28992"
        else:
            default_param1 = ""
            default_param2 = ""

        param1 = settings.value(f"connection/{driver_type}/param1", default_param1)
        param2 = settings.value(f"connection/{driver_type}/param2", default_param2)
        window.leParam1.setText(str(param1))
        window.leParam2.setText(str(param2))
        if settings_initialized:
            settings.setValue("connection/driver_type", driver_type)

    def save_connection_params():
        if not settings_initialized:
            return
        driver_type = window.cmbDriverType.currentText()
        settings.setValue(f"connection/{driver_type}/param1", window.leParam1.text())
        settings.setValue(f"connection/{driver_type}/param2", window.leParam2.text())

    def set_pairing_fields_visible(visible: bool):
        window.labelPairingIndex.setVisible(visible)
        window.lePairingIndex.setVisible(visible)
        window.labelPairingPriv.setVisible(visible)
        window.lePairingPriv.setVisible(visible)
        window.labelPairingPub.setVisible(visible)
        window.lePairingPub.setVisible(visible)

    def on_pairing_profile_changed():
        profile = window.cmbPairingProfile.currentData()
        set_pairing_fields_visible(profile == "custom")
        if settings_initialized:
            settings.setValue("pairing/profile", profile)

    def save_custom_pairing_params():
        if not settings_initialized:
            return
        profile = window.cmbPairingProfile.currentData()
        if profile != "custom":
            return
        settings.setValue("pairing/custom/index", window.lePairingIndex.text())
        settings.setValue("pairing/custom/priv", window.lePairingPriv.text())
        settings.setValue("pairing/custom/pub", window.lePairingPub.text())

    def parse_hex_bytes(text: str, field_name: str) -> bytes:
        cleaned = text.strip().replace(" ", "").replace("\n", "")
        if not cleaned:
            raise ValueError(f"{field_name} is required")
        if len(cleaned) % 2 != 0:
            raise ValueError(f"{field_name} must have even length")
        try:
            return bytes.fromhex(cleaned)
        except ValueError:
            raise ValueError(f"Invalid hex in {field_name}")

    def get_selected_pairing_keys():
        profile = window.cmbPairingProfile.currentData()
        if profile == "prod0":
            return (FACTORY_PAIRING_KEY_INDEX, FACTORY_PAIRING_PRIVATE_KEY_PROD0, FACTORY_PAIRING_PUBLIC_KEY_PROD0)
        if profile == "eng":
            return (FACTORY_PAIRING_KEY_INDEX, FACTORY_PAIRING_PRIVATE_KEY_ENG_SAMPLE, FACTORY_PAIRING_PUBLIC_KEY_ENG_SAMPLE)
        if profile == "custom":
            idx_text = window.lePairingIndex.text().strip()
            if not idx_text:
                raise ValueError("Custom index is required")
            idx = int(idx_text)
            if idx < 0 or idx > 3:
                raise ValueError("Custom index must be 0-3")
            priv = parse_hex_bytes(window.lePairingPriv.text(), "Custom priv")
            pub = parse_hex_bytes(window.lePairingPub.text(), "Custom pub")
            if len(priv) != 32 or len(pub) != 32:
                raise ValueError("Custom priv/pub must be 32 bytes")
            return (idx, priv, pub)
        return (DEFAULT_PAIRING_INDEX, DEFAULT_PAIRING_PRIV, DEFAULT_PAIRING_PUB)

    settings_visible = False

    def set_connection_settings_visible(visible: bool):
        window.groupBoxConnection.setVisible(visible)

    def on_toggle_connection_settings():
        nonlocal settings_visible
        settings_visible = not settings_visible
        set_connection_settings_visible(settings_visible)
        window.btnToggleConnectionSettings.setText(
            "Hide Connection" if settings_visible else "Connection..."
        )

    def on_connect_click():
        """Connect to device using selected driver type and configuration"""
        nonlocal ts, transport
        driver_type = window.cmbDriverType.currentText()
        param1 = window.leParam1.text()
        param2 = window.leParam2.text()

        # Show connecting status
        window.lblConnectionStatus.setText("Connecting...")
        window.lblConnectionStatus.setStyleSheet("color: orange; font-weight: bold;")
        window.btnConnectToggle.setEnabled(False)
        QtWidgets.QApplication.processEvents()  # Update UI immediately

        try:
            if ts is not None:
                if hasattr(ts, "_secure_session") and ts._secure_session:
                    try:
                        ts.abort_secure_session()
                    except Exception:
                        pass
                ts = None
                close_transport()

            if driver_type == "UART":
                transport = UartTransport(param1, int(param2))
            elif driver_type == "Network":
                transport = NetworkSpiTransport(param1, int(param2))
            elif driver_type == "TCP":
                transport = TcpTransport(param1, int(param2))
            else:
                raise ValueError(f"Unknown driver type: {driver_type}")

            ts = TropicSquareCPython(transport)

            # Validate device with timeout and fetch Chip ID in one pass
            validation_result = {"success": False, "error": None, "chip_id": None}

            def validate_device():
                try:
                    validation_result["chip_id"] = ts.chipid
                    validation_result["success"] = True
                except Exception as e:
                    validation_result["error"] = str(e)

            window.lblConnectionStatus.setText("Getting chip ID...")
            window.lblConnectionStatus.setStyleSheet("color: orange; font-weight: bold;")
            window.lblConnectionStatus.repaint()
            window.repaint()
            QtWidgets.QApplication.processEvents()

            validation_thread = threading.Thread(target=validate_device, daemon=True)
            validation_thread.start()
            validation_thread.join(timeout=10.0)

            if validation_thread.is_alive():
                raise ConnectionError(
                    "Chip ID timeout - device not responding"
                )

            if not validation_result["success"]:
                error_msg = validation_result["error"] or "Unknown error"
                raise ConnectionError(
                    f"Chip ID read failed: {error_msg}"
                )

            if chip_id_refresh is not None:
                chip_id_refresh(validation_result["chip_id"])
            update_connection_ui()
            bus.emit("device_changed", connected=True)

        except ValueError as e:
            QtWidgets.QMessageBox.critical(window, "Configuration Error",
                                          f"Invalid configuration:\n{str(e)}")
            close_transport()
            ts = None
            update_connection_ui()
        except Exception as e:
            QtWidgets.QMessageBox.critical(window, "Connection Failed",
                                          f"Failed to connect to device:\n\n{str(e)}")
            close_transport()
            ts = None
            update_connection_ui()

    def on_disconnect_click():
        """Disconnect from device"""
        nonlocal ts, current_pairing_pubkey, current_pairing_index
        try:
            if ts and hasattr(ts, "_secure_session") and ts._secure_session:
                try:
                    ts.abort_secure_session()
                except Exception:
                    pass
            ts = None
            close_transport()
            current_pairing_pubkey = None
            current_pairing_index = None
            update_connection_ui()
            bus.emit("device_changed", connected=False)
        except Exception as e:
            window.lblConnectionStatus.setText(f"Disconnect error: {str(e)}")
            window.lblConnectionStatus.setStyleSheet("color: orange; font-weight: bold;")
            update_connection_ui()  # Ensure buttons are in correct state

    def on_btnStartSecureSession_click():
        nonlocal current_pairing_pubkey, current_pairing_index
        if not ts:
            QtWidgets.QMessageBox.warning(window, "Not Connected", "Please connect to device first")
            return

        def format_start_session_error_message(err: Exception) -> str:
            msg = str(err)
            msg_l = msg.lower()
            if (
                "status: 0x79" in msg_l
                or "handshake error" in msg_l
                or "authentication tag mismatch" in msg_l
            ):
                return (
                    "Failed to start secure session:\n"
                    f"{msg}\n\n"
                    "Likely cause: pairing authentication failed.\n"
                    "Check selected pairing slot and private/public key pair for this chip."
                )
            return f"Failed to start secure session:\n{msg}"

        try:
            window.lblSessionStatus.setText("Starting...")
            window.lblSessionStatus.setStyleSheet("color: orange; font-weight: bold;")
            window.btnSessionToggle.setEnabled(False)
            QtWidgets.QApplication.processEvents()

            key_index, priv, pub = get_selected_pairing_keys()
            if ts.start_secure_session(key_index, bytes(priv), bytes(pub)):
                current_pairing_pubkey = pub
                current_pairing_index = key_index
                if pairing_reset_state is not None:
                    pairing_reset_state()
                update_connection_ui()  # Update UI to show active session
                bus.emit("session_changed", has_session=True)
        except TropicSquareHandshakeError as e:
            QtWidgets.QMessageBox.critical(window, "Handshake Error", format_start_session_error_message(e))
            update_connection_ui()
        except TropicSquareError as e:
            QtWidgets.QMessageBox.critical(window, "Error", format_start_session_error_message(e))
            update_connection_ui()
        except ValueError as e:
            QtWidgets.QMessageBox.critical(window, "Invalid Pairing Key", str(e))
            update_connection_ui()
        except Exception as e:
            QtWidgets.QMessageBox.critical(window, "Unexpected Error", format_start_session_error_message(e))
            update_connection_ui()


    def on_btnAbortSecureSession_click():
        nonlocal current_pairing_pubkey, current_pairing_index
        if not ts:
            QtWidgets.QMessageBox.warning(window, "Not Connected", "Please connect to device first")
            return

        try:
            window.lblSessionStatus.setText("Aborting...")
            window.lblSessionStatus.setStyleSheet("color: orange; font-weight: bold;")
            window.btnSessionToggle.setEnabled(False)
            QtWidgets.QApplication.processEvents()

            if ts.abort_secure_session():
                current_pairing_pubkey = None
                current_pairing_index = None
                update_connection_ui()  # Update UI to show no session
                bus.emit("session_changed", has_session=False)
        except Exception as e:
            QtWidgets.QMessageBox.warning(window, "Error", f"Failed to abort session:\n{str(e)}")
            update_connection_ui()

    def on_btnConnectToggle_click():
        connected = ts is not None
        if connected:
            on_disconnect_click()
        else:
            on_connect_click()

    def on_btnSessionToggle_click():
        if not ts:
            QtWidgets.QMessageBox.warning(window, "Not Connected", "Please connect to device first")
            return
        has_session = hasattr(ts, "_secure_session") and ts._secure_session is not None
        if has_session:
            on_btnAbortSecureSession_click()
        else:
            on_btnStartSecureSession_click()


    def has_secure_session():
        return ts is not None and hasattr(ts, "_secure_session") and ts._secure_session is not None

    app = QtWidgets.QApplication(sys.argv)
    window = uic.loadUi("mainwindow.ui")

    # Connect connection management signals
    window.cmbDriverType.currentTextChanged.connect(on_driver_type_changed)
    window.btnConnectToggle.clicked.connect(on_btnConnectToggle_click)
    window.btnSessionToggle.clicked.connect(on_btnSessionToggle_click)
    window.btnToggleConnectionSettings.clicked.connect(on_toggle_connection_settings)
    window.leParam1.textChanged.connect(save_connection_params)
    window.leParam2.textChanged.connect(save_connection_params)
    window.cmbPairingProfile.currentTextChanged.connect(on_pairing_profile_changed)
    window.lePairingIndex.textChanged.connect(save_custom_pairing_params)
    window.lePairingPriv.textChanged.connect(save_custom_pairing_params)
    window.lePairingPub.textChanged.connect(save_custom_pairing_params)

    window.splitterChipIdTop.setStretchFactor(0, 1)
    window.splitterChipIdTop.setStretchFactor(1, 1)
    setup_maintenance(window, bus, lambda: ts, has_secure_session, on_btnAbortSecureSession_click)
    chip_id_refresh = setup_chip_id(window, lambda: ts)
    info_set_enabled = setup_info(window, lambda: ts)
    ping_set_enabled = setup_ping(window, lambda: ts)
    random_set_enabled = setup_random_data(window, lambda: ts)

    ecc_set_enabled = setup_ecc(window, bus, lambda: ts, parse_hex_bytes)
    mcounter_set_enabled = setup_mcounter(window, bus, lambda: ts, has_secure_session)
    pairing_set_enabled, pairing_reset_state = setup_pairing_keys(window, bus, lambda: ts, has_secure_session)
    config_set_enabled = setup_config_tab(window, lambda: ts)
    mem_set_enabled = setup_mem_data(window, lambda: ts)

    window.cmbPairingProfile.clear()
    window.cmbPairingProfile.addItem("Factory PROD0 (PH0)", "prod0")
    window.cmbPairingProfile.addItem("Factory ENG sample", "eng")
    window.cmbPairingProfile.addItem("Custom", "custom")

    saved_pairing = settings.value("pairing/profile", "prod0")
    if saved_pairing:
        index = window.cmbPairingProfile.findData(str(saved_pairing))
        if index >= 0:
            window.cmbPairingProfile.setCurrentIndex(index)

    window.lePairingIndex.setText(str(settings.value("pairing/custom/index", "0")))
    window.lePairingPriv.setText(str(settings.value("pairing/custom/priv", "")))
    window.lePairingPub.setText(str(settings.value("pairing/custom/pub", "")))
    window.lePairingIndex.setValidator(QtGui.QIntValidator(0, 3))
    on_pairing_profile_changed()

    saved_driver = settings.value("connection/driver_type", "UART")
    if saved_driver:
        window.cmbDriverType.setCurrentText(str(saved_driver))
    settings_initialized = True
    on_driver_type_changed()
    set_connection_settings_visible(False)
    window.btnToggleConnectionSettings.setText("Connection...")
    # Initialize UI state (starts disconnected)
    update_connection_ui()

    window.show()

    sys.exit(app.exec())


if __name__ == '__main__':
    main()
