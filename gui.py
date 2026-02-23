from tropicsquare.constants.ecc import (
    ECC_CURVE_ED25519,
    ECC_CURVE_P256,
    ECC_KEY_ORIGIN_GENERATED,
    ECC_KEY_ORIGIN_STORED,
    ECC_MAX_KEYS
)
from tropicsquare.constants.l2 import (
    STARTUP_REBOOT,
    STARTUP_MAINTENANCE_REBOOT,
    SLEEP_MODE_SLEEP,
    SLEEP_MODE_DEEP_SLEEP
)
from tropicsquare.constants import MCOUNTER_MAX, MEM_DATA_MAX_SIZE, PAIRING_KEY_MAX, PAIRING_KEY_SIZE
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

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from datetime import datetime
import threading
import copy
import os
import hashlib


def parse_certificate_info(cert_data):
    """Parse certificate information with fallback for problematic certificates.

    Some TROPIC01 rev 1 chips have certificates with RFC 5280 violations:
    - CRL Distribution Points extension has explicit critical=FALSE encoding
    - This violates DER encoding rules (default values should be omitted)
    - Cryptography 43+ enforces strict validation and rejects these certs
    - OpenSSL accepts them (more lenient parser)

    This function tries multiple parsing approaches:
    1. Standard cryptography library parsing (works for rev 0 and compliant certs)
    2. Manual ASN.1 parsing for dates (fallback for non-compliant certs)

    Args:
        cert_data: Certificate in DER format (bytes or bytearray)

    Returns:
        tuple: (not_before, not_after, subject_cn) where dates are datetime objects
               or (None, None, None) on complete failure
    """
    cert_bytes = bytes(cert_data)

    # Try standard parsing first (works for most certs)
    try:
        cert = x509.load_der_x509_certificate(cert_bytes, default_backend())
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
        # Extract CN from subject
        try:
            cn = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
        except:
            cn = "Unknown"
        return (not_before, not_after, cn)
    except Exception:
        pass  # Fall through to manual parsing

    # Fallback: Manual ASN.1 parsing for dates
    # This handles certificates with encoding violations that cryptography rejects
    try:
        dates = []
        idx = 0
        # Find UTCTime fields (tag 0x17, length 0x0d for 13-byte format YYMMDDHHMMSSZ)
        while idx < len(cert_bytes) - 15:
            if cert_bytes[idx] == 0x17 and cert_bytes[idx+1] == 0x0d:
                date_str = cert_bytes[idx+2:idx+15].decode('ascii')
                # Parse YYMMDDHHMMSSZ format
                year = int(date_str[0:2])
                # Y2K handling: years 00-49 are 2000-2049, 50-99 are 1950-1999
                year = 2000 + year if year < 50 else 1900 + year
                month = int(date_str[2:4])
                day = int(date_str[4:6])
                hour = int(date_str[6:8])
                minute = int(date_str[8:10])
                second = int(date_str[10:12])
                dt = datetime(year, month, day, hour, minute, second)
                dates.append(dt)
            idx += 1

        # Extract subject CN manually (UTF8STRING after OID 55 04 03)
        # OID 2.5.4.3 (commonName) = 55 04 03
        # Note: There may be multiple CNs (issuer, subject) - use the LAST one (subject)
        cn = "Unknown"
        cn_oid = bytes.fromhex('550403')
        cn_occurrences = []
        idx = 0
        while idx < len(cert_bytes):
            idx = cert_bytes.find(cn_oid, idx)
            if idx < 0:
                break
            try:
                cn_len = cert_bytes[idx + 4]
                cn_start = idx + 5
                cn_value = cert_bytes[cn_start:cn_start + cn_len].decode('utf-8')
                cn_occurrences.append(cn_value)
            except:
                pass
            idx += 1

        if cn_occurrences:
            cn = cn_occurrences[-1]  # Last occurrence is subject CN

        if len(dates) >= 2:
            return (dates[0], dates[1], cn)
        return (None, None, cn)
    except Exception:
        return (None, None, None)


# Default factory pairing keys (PH0 / PROD0)
DEFAULT_PAIRING_INDEX = FACTORY_PAIRING_KEY_INDEX
DEFAULT_PAIRING_PRIV = FACTORY_PAIRING_PRIVATE_KEY_PROD0
DEFAULT_PAIRING_PUB = FACTORY_PAIRING_PUBLIC_KEY_PROD0


import sys
from PyQt6.QtCore import QSettings
from PyQt6 import QtWidgets, uic, QtGui, QtCore
from tropicsquare.constants import config as cfg_constants
from tropicsquare.config.uap_base import (
    UapMultiSlotConfig,
    UapSingleFieldConfig,
    UapDualFieldConfig,
    UapPermissionField
)


def main():
    # Application starts without device connection
    ts = None
    transport = None
    settings = QSettings("tropic01manager", "tropic01manager")
    settings_initialized = False
    current_pairing_pubkey = None
    current_pairing_index = None
    pairing_slot_cards = {}
    pairing_slot_states = {}
    pairing_slot_pubkey_prefix = {}
    mcounter_cards = {}
    mcounter_states = {}
    mcounter_values = {}
    ecc_slot_cards = {}
    ecc_slot_states = {}
    ecc_slot_info = {}

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
        window.btnGetInfo.setEnabled(connected)
        window.btnSaveCert.setEnabled(connected)
        window.btnPing.setEnabled(connected)
        window.btnGetRandom.setEnabled(connected)
        window.btnMaintenanceStartupReboot.setEnabled(connected)
        window.btnMaintenanceStartupBootloader.setEnabled(connected)
        window.btnMaintenanceSleep.setEnabled(connected)
        window.btnMaintenanceDeepSleep.setEnabled(connected)
        window.btnMaintenanceGetLogs.setEnabled(connected)
        window.btnEccSignMessage.setEnabled(connected)
        window.btnMemRead.setEnabled(connected)
        window.btnMemWrite.setEnabled(connected)
        window.btnMemErase.setEnabled(connected)
        window.btnRConfigRead.setEnabled(connected)
        window.btnRConfigWrite.setEnabled(connected)
        window.btnRConfigErase.setEnabled(connected)
        window.btnIConfigRead.setEnabled(connected)
        window.btnIConfigWrite.setEnabled(connected)
        window.btnRConfigBulkReadAll.setEnabled(connected)
        window.btnRConfigBulkDiscard.setEnabled(connected)
        window.btnRConfigBulkApply.setEnabled(connected)
        window.tblRConfigBulk.setEnabled(connected)
        window.leMemSlot.setEnabled(connected)
        window.pteMemInput.setEnabled(connected)
        window.rbMemHex.setEnabled(connected)
        window.rbMemText.setEnabled(connected)
        try:
            refresh_pairing_keys_overview()
        except NameError:
            pass
        try:
            refresh_mcounter_overview()
        except NameError:
            pass

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

            refresh_chip_id(validation_result["chip_id"])
            update_connection_ui()

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
        except Exception as e:
            window.lblConnectionStatus.setText(f"Disconnect error: {str(e)}")
            window.lblConnectionStatus.setStyleSheet("color: orange; font-weight: bold;")
            update_connection_ui()  # Ensure buttons are in correct state

    def on_btn_get_info_click():
        if not ts:
            QtWidgets.QMessageBox.warning(window, "Not Connected", "Please connect to device first")
            return

        try:
            riscv_ver = ts.riscv_fw_version
            spect_ver = ts.spect_fw_version
            window.lblRISCFWVersion.setText(f"{riscv_ver[0]}.{riscv_ver[1]}.{riscv_ver[2]}.{riscv_ver[3]}")
            window.lblSPECTFWVersion.setText(f"{spect_ver[0]}.{spect_ver[1]}.{spect_ver[2]}.{spect_ver[3]}")

            window.lblCertPubkey.setText(ts.public_key.hex())

            # Parse certificate with fallback for non-compliant certs
            not_before, not_after, subject_cn = parse_certificate_info(ts.certificate)
            if not_before and not_after:
                window.lblCertDateIssue.setText(not_before.isoformat())
                window.lblCertDateExpire.setText(not_after.isoformat())
            else:
                window.lblCertDateIssue.setText("Parse error")
                window.lblCertDateExpire.setText("Parse error")
        except Exception as e:
            QtWidgets.QMessageBox.critical(window, "Error", f"Failed to get info:\n{str(e)}")


    def on_btn_save_cert_click():
        if not ts:
            QtWidgets.QMessageBox.warning(window, "Not Connected", "Please connect to device first")
            return

        filename, fileformat = QtWidgets.QFileDialog.getSaveFileName(window, "Save certificate", "", "PEM Certificate files (*.pem *.crt);;DER Certificate files (*.der);;All files (*)")
        if not filename:
            return

        with open(filename, "wb") as f:
            if fileformat == "PEM Certificate files (*.pem *.crt)":
                cert = x509.load_der_x509_certificate(bytes(ts.certificate), default_backend())
                f.write(cert.public_bytes(encoding=serialization.Encoding.PEM))
            else:
                f.write(bytes(ts.certificate))


    def refresh_chip_id(chip_id=None):
        """Get and display chip ID information"""
        if chip_id is None and not ts:
            return

        try:
            # Get parsed chip ID (chipid is a property, not a method)
            if chip_id is None:
                chip_id = ts.chipid

            # Display chip information
            window.lblChipIDVersion.setText('.'.join(map(str, chip_id.chip_id_version)))
            window.lblSiliconRev.setText(chip_id.silicon_rev)
            window.lblPackageType.setText(f"{chip_id.package_type_name} (0x{chip_id.package_type_id:04X})")
            window.lblFabrication.setText(f"{chip_id.fab_name} (0x{chip_id.fab_id:03X})")
            window.lblPartNumberID.setText(f"0x{chip_id.part_number_id:03X}")
            window.lblHSMVersion.setText('.'.join(map(str, chip_id.hsm_version)))
            window.lblProgVersion.setText('.'.join(map(str, chip_id.prog_version)))
            window.lblBatchID.setText(chip_id.batch_id.hex())

            # Try to decode part number as ASCII (16 bytes)
            try:
                part_num_ascii = chip_id.part_num_data.decode('ascii', 'ignore').rstrip('\x00')
                if part_num_ascii:
                    window.lblPartNumberASCII.setText(part_num_ascii)
                else:
                    window.lblPartNumberASCII.setText(f"(hex: {chip_id.part_num_data.hex()})")
            except:
                window.lblPartNumberASCII.setText(f"(hex: {chip_id.part_num_data.hex()})")

            # Display serial number information
            sn = chip_id.serial_number
            window.lblSerialNumber.setText(f"0x{sn.sn:02X}")
            window.lblSNFabID.setText(f"0x{sn.fab_id:03X}")
            window.lblSNPartNumber.setText(f"0x{sn.part_number_id:03X}")
            window.lblLotID.setText(sn.lot_id.hex())
            window.lblWaferID.setText(f"0x{sn.wafer_id:02X}")
            window.lblWaferCoords.setText(f"({sn.x_coord}, {sn.y_coord})")

        except Exception as e:
            QtWidgets.QMessageBox.critical(window, "Error", f"Failed to get chip ID:\n{str(e)}")


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
                reset_pairing_keys_state()
                reset_mcounter_state()
                update_connection_ui()  # Update UI to show active session
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


    def on_btnPing_click():
        if not ts:
            QtWidgets.QMessageBox.warning(window, "Not Connected", "Please connect to device first")
            return

        ping = window.ptePingInput.toPlainText().encode("utf-8")
        try:
            window.ptePingResult.setPlainText(ts.ping(ping).decode("utf-8"))
        except TropicSquareNoSession:
            QtWidgets.QMessageBox.warning(window, "No Session", "No secure session established")
        except TropicSquareError as e:
            QtWidgets.QMessageBox.critical(window, "Ping Failed", str(e))


    def on_btnbtnGetRandom_click():
        if not ts:
            QtWidgets.QMessageBox.warning(window, "Not Connected", "Please connect to device first")
            return

        try:
            number_text = window.leRandomBytesNum.text().strip()
            if not number_text:
                raise ValueError("Byte count is required")
            number = int(number_text)
            if number > 255:
                raise ValueError("Number must be less than 256")
            window.pteRandomBytes.setPlainText(ts.get_random(number).hex())
        except TropicSquareNoSession:
            QtWidgets.QMessageBox.warning(window, "No Session", "No secure session established")
        except ValueError as e:
            QtWidgets.QMessageBox.warning(window, "Invalid Input", str(e))
        except Exception as e:
            QtWidgets.QMessageBox.critical(window, "Random Failed", str(e))

    def require_l2():
        if not ts:
            QtWidgets.QMessageBox.warning(window, "Not Connected", "Please connect to device first")
            return None
        if not hasattr(ts, "_l2"):
            QtWidgets.QMessageBox.critical(window, "Not Available", "L2 interface not available")
            return None
        return ts._l2

    def on_btnMaintenanceStartupReboot_click():
        l2 = require_l2()
        if l2 is None:
            return
        confirm = QtWidgets.QMessageBox.question(
            window,
            "Reboot",
            "Reboot device?",
            QtWidgets.QMessageBox.StandardButton.Yes
            | QtWidgets.QMessageBox.StandardButton.No
        )
        if confirm != QtWidgets.QMessageBox.StandardButton.Yes:
            return
        try:
            if has_secure_session():
                on_btnAbortSecureSession_click()
            l2.startup_req(STARTUP_REBOOT)
            QtWidgets.QMessageBox.information(window, "Reboot", "Reboot request sent")
        except Exception as e:
            QtWidgets.QMessageBox.critical(window, "Reboot Failed", str(e))

    def on_btnMaintenanceStartupBootloader_click():
        l2 = require_l2()
        if l2 is None:
            return
        confirm = QtWidgets.QMessageBox.question(
            window,
            "Reboot Bootloader",
            "Reboot to bootloader?",
            QtWidgets.QMessageBox.StandardButton.Yes
            | QtWidgets.QMessageBox.StandardButton.No
        )
        if confirm != QtWidgets.QMessageBox.StandardButton.Yes:
            return
        try:
            if has_secure_session():
                on_btnAbortSecureSession_click()
            l2.startup_req(STARTUP_MAINTENANCE_REBOOT)
            QtWidgets.QMessageBox.information(window, "Reboot Bootloader", "Bootloader reboot request sent")
        except Exception as e:
            QtWidgets.QMessageBox.critical(window, "Reboot Bootloader Failed", str(e))

    def on_btnMaintenanceSleep_click():
        l2 = require_l2()
        if l2 is None:
            return
        confirm = QtWidgets.QMessageBox.question(
            window,
            "Sleep",
            "Put device to sleep?",
            QtWidgets.QMessageBox.StandardButton.Yes
            | QtWidgets.QMessageBox.StandardButton.No
        )
        if confirm != QtWidgets.QMessageBox.StandardButton.Yes:
            return
        try:
            l2.sleep_req(SLEEP_MODE_SLEEP)
            QtWidgets.QMessageBox.information(window, "Sleep", "Sleep request sent")
        except Exception as e:
            QtWidgets.QMessageBox.critical(window, "Sleep Failed", str(e))

    def on_btnMaintenanceDeepSleep_click():
        l2 = require_l2()
        if l2 is None:
            return
        confirm = QtWidgets.QMessageBox.question(
            window,
            "Deep Sleep",
            "Put device to deep sleep?",
            QtWidgets.QMessageBox.StandardButton.Yes
            | QtWidgets.QMessageBox.StandardButton.No
        )
        if confirm != QtWidgets.QMessageBox.StandardButton.Yes:
            return
        try:
            l2.sleep_req(SLEEP_MODE_DEEP_SLEEP)
            QtWidgets.QMessageBox.information(window, "Deep Sleep", "Deep sleep request sent")
        except Exception as e:
            QtWidgets.QMessageBox.critical(window, "Deep Sleep Failed", str(e))

    def on_btnMaintenanceGetLogs_click():
        if not ts:
            QtWidgets.QMessageBox.warning(window, "Not Connected", "Please connect to device first")
            return
        try:
            log_text = ts.get_log()
            window.pteMaintenanceLogs.setPlainText(log_text)
        except Exception as e:
            QtWidgets.QMessageBox.critical(window, "Get Logs Failed", str(e))


    def ecc_curve_name(curve: int) -> str:
        if curve == ECC_CURVE_P256:
            return "P256"
        if curve == ECC_CURVE_ED25519:
            return "Ed25519"
        return f"Unknown (0x{curve:02X})"

    def ecc_origin_name(origin: int) -> str:
        if origin == ECC_KEY_ORIGIN_GENERATED:
            return "Generated"
        if origin == ECC_KEY_ORIGIN_STORED:
            return "Stored"
        return f"Origin 0x{origin:02X}"

    def prompt_ecc_curve(title: str):
        dialog = QtWidgets.QDialog(window)
        dialog.setWindowTitle(title)
        dialog.setModal(True)
        layout = QtWidgets.QFormLayout(dialog)
        cmb = QtWidgets.QComboBox(dialog)
        cmb.addItem("P256", ECC_CURVE_P256)
        cmb.addItem("Ed25519", ECC_CURVE_ED25519)
        layout.addRow("Curve", cmb)
        buttons = QtWidgets.QDialogButtonBox(
            QtWidgets.QDialogButtonBox.StandardButton.Ok
            | QtWidgets.QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addRow(buttons)
        if dialog.exec() != QtWidgets.QDialog.DialogCode.Accepted:
            return None
        return cmb.currentData()

    def prompt_ecc_store():
        dialog = QtWidgets.QDialog(window)
        dialog.setWindowTitle("Store ECC key")
        dialog.setModal(True)
        layout = QtWidgets.QFormLayout(dialog)
        cmb = QtWidgets.QComboBox(dialog)
        cmb.addItem("P256", ECC_CURVE_P256)
        cmb.addItem("Ed25519", ECC_CURVE_ED25519)
        le_key = QtWidgets.QLineEdit(dialog)
        le_key.setPlaceholderText("Private key (hex)")
        layout.addRow("Curve", cmb)
        layout.addRow("Private key (hex)", le_key)
        buttons = QtWidgets.QDialogButtonBox(
            QtWidgets.QDialogButtonBox.StandardButton.Ok
            | QtWidgets.QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addRow(buttons)
        if dialog.exec() != QtWidgets.QDialog.DialogCode.Accepted:
            return None
        try:
            key_bytes = parse_hex_bytes(le_key.text(), "Private key")
            if len(key_bytes) != 32:
                raise ValueError("Private key must be 32 bytes")
        except ValueError as e:
            QtWidgets.QMessageBox.warning(window, "Invalid Private Key", str(e))
            return None
        return cmb.currentData(), key_bytes

    def prompt_ecc_sign():
        slots = []
        for slot, state in ecc_slot_states.items():
            if state == "present":
                slots.append(slot)
        if not slots:
            QtWidgets.QMessageBox.warning(window, "No Keys", "No ECC key available for signing")
            return None
        dialog = QtWidgets.QDialog(window)
        dialog.setWindowTitle("Sign Message")
        dialog.setModal(True)
        layout = QtWidgets.QFormLayout(dialog)
        cmb = QtWidgets.QComboBox(dialog)
        for slot in sorted(slots):
            info = ecc_slot_info.get(slot)
            label = f"Slot {slot}"
            if info is not None:
                label = f"Slot {slot} ({ecc_curve_name(info.curve)})"
            cmb.addItem(label, slot)
        mode_row = QtWidgets.QHBoxLayout()
        rb_text = QtWidgets.QRadioButton("Text")
        rb_hex = QtWidgets.QRadioButton("Hex")
        rb_text.setChecked(True)
        mode_row.addWidget(rb_text)
        mode_row.addWidget(rb_hex)
        mode_row.addStretch(1)
        pte = QtWidgets.QPlainTextEdit(dialog)
        pte.setPlaceholderText("Message to sign")
        layout.addRow("Slot", cmb)
        layout.addRow("Mode", mode_row)
        layout.addRow("Message", pte)
        buttons = QtWidgets.QDialogButtonBox(
            QtWidgets.QDialogButtonBox.StandardButton.Ok
            | QtWidgets.QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addRow(buttons)
        if dialog.exec() != QtWidgets.QDialog.DialogCode.Accepted:
            return None
        text = pte.toPlainText()
        if not text.strip():
            QtWidgets.QMessageBox.warning(window, "Invalid Message", "Message is required")
            return None
        if rb_hex.isChecked():
            try:
                message = parse_hex_bytes(text, "Message")
            except ValueError as e:
                QtWidgets.QMessageBox.warning(window, "Invalid Message", str(e))
                return None
        else:
            message = text.encode("utf-8")
        return cmb.currentData(), message

    def on_btnEccSignMessage_click():
        if not ts:
            QtWidgets.QMessageBox.warning(window, "Not Connected", "Please connect to device first")
            return
        result = prompt_ecc_sign()
        if result is None:
            return
        slot, message = result
        try:
            info = ecc_slot_info.get(slot)
            if info is None:
                info = ts.ecc_key_read(slot)
                ecc_slot_states[slot] = "present"
                ecc_slot_info[slot] = info
                refresh_ecc_slot_card(slot)
            if info.curve == ECC_CURVE_P256:
                message_hash = hashlib.sha256(message).digest()
                signature = ts.ecdsa_sign(slot, message_hash)
                details = (
                    "Curve: P256 (ECDSA)\n"
                    f"Hash (SHA-256): {message_hash.hex()}\n"
                    f"R: {signature.r.hex()}\n"
                    f"S: {signature.s.hex()}"
                )
            elif info.curve == ECC_CURVE_ED25519:
                signature = ts.eddsa_sign(slot, message)
                signature_hex = (signature.r + signature.s).hex()
                details = (
                    "Curve: Ed25519 (EdDSA)\n"
                    f"R: {signature.r.hex()}\n"
                    f"S: {signature.s.hex()}\n"
                    f"Signature: {signature_hex}"
                )
            else:
                QtWidgets.QMessageBox.warning(window, "Unsupported Curve", f"Unknown curve: 0x{info.curve:02X}")
                return
            QtWidgets.QMessageBox.information(window, "Signature", details)
        except Exception as e:
            QtWidgets.QMessageBox.critical(window, "Sign Failed", str(e))

    def on_btnEccRefreshOne_click(slot: int):
        if not ts:
            QtWidgets.QMessageBox.warning(window, "Not Connected", "Please connect to device first")
            return
        try:
            key_info = ts.ecc_key_read(slot)
            ecc_slot_states[slot] = "present"
            ecc_slot_info[slot] = key_info
        except TropicSquareECCInvalidKeyError:
            ecc_slot_states[slot] = "empty"
            ecc_slot_info.pop(slot, None)
        except TropicSquareNoSession:
            QtWidgets.QMessageBox.warning(window, "No Session", "No secure session established")
            return
        except Exception:
            ecc_slot_states[slot] = "unknown"
            ecc_slot_info.pop(slot, None)
        refresh_ecc_slot_card(slot)

    def on_btnEccGenerateFromOverview_click(slot: int):
        if not ts:
            QtWidgets.QMessageBox.warning(window, "Not Connected", "Please connect to device first")
            return
        curve = prompt_ecc_curve(f"Generate ECC key in slot {slot}")
        if curve is None:
            return
        try:
            ts.ecc_key_generate(slot, curve)
            on_btnEccRefreshOne_click(slot)
            QtWidgets.QMessageBox.information(window, "ECC Generate", "Key generated successfully")
        except TropicSquareNoSession:
            QtWidgets.QMessageBox.warning(window, "No Session", "No secure session established")
        except Exception as e:
            QtWidgets.QMessageBox.critical(window, "ECC Generate Failed", str(e))

    def on_btnEccStoreFromOverview_click(slot: int):
        if not ts:
            QtWidgets.QMessageBox.warning(window, "Not Connected", "Please connect to device first")
            return
        result = prompt_ecc_store()
        if result is None:
            return
        curve, key_bytes = result
        try:
            ts.ecc_key_store(slot, curve, key_bytes)
            on_btnEccRefreshOne_click(slot)
            QtWidgets.QMessageBox.information(window, "ECC Store", "Key stored successfully")
        except TropicSquareNoSession:
            QtWidgets.QMessageBox.warning(window, "No Session", "No secure session established")
        except Exception as e:
            QtWidgets.QMessageBox.critical(window, "ECC Store Failed", str(e))

    def on_btnEccShowFromOverview_click(slot: int):
        info = ecc_slot_info.get(slot)
        if info is None:
            on_btnEccRefreshOne_click(slot)
            info = ecc_slot_info.get(slot)
        if info is None:
            return
        QtWidgets.QMessageBox.information(
            window,
            f"ECC Slot {slot}",
            info.public_key.hex()
        )

    def on_btnEccEraseFromOverview_click(slot: int):
        if not ts:
            QtWidgets.QMessageBox.warning(window, "Not Connected", "Please connect to device first")
            return
        confirm = QtWidgets.QMessageBox.question(
            window,
            "ECC Erase",
            f"Erase ECC key in slot {slot}?",
            QtWidgets.QMessageBox.StandardButton.Yes
            | QtWidgets.QMessageBox.StandardButton.No
        )
        if confirm != QtWidgets.QMessageBox.StandardButton.Yes:
            return
        try:
            ts.ecc_key_erase(slot)
            ecc_slot_states[slot] = "empty"
            ecc_slot_info.pop(slot, None)
            refresh_ecc_slot_card(slot)
            QtWidgets.QMessageBox.information(window, "ECC Erase", "Key erased successfully")
        except TropicSquareNoSession:
            QtWidgets.QMessageBox.warning(window, "No Session", "No secure session established")
        except Exception as e:
            QtWidgets.QMessageBox.critical(window, "ECC Erase Failed", str(e))

    def refresh_ecc_slot_card(slot: int):
        card = ecc_slot_cards.get(slot)
        if not card:
            return
        state = ecc_slot_states.get(slot, "unknown")
        status = card["status"]
        frame = card["frame"]
        base_style = (
            "font-weight: bold; border: 1px solid rgba(210, 210, 210, 0.82); "
            "border-radius: 6px; padding: 6px 8px;"
        )
        frame_selector = f"QFrame#{frame.objectName()}"
        if state == "present":
            info = ecc_slot_info.get(slot)
            if info:
                status_text = f"● {ecc_curve_name(info.curve)} / {ecc_origin_name(info.origin)}"
            else:
                status_text = "● Present"
            status.setText(status_text)
            status.setStyleSheet(f"color: #1f5fbf; {base_style}")
            frame.setStyleSheet(
                f"{frame_selector} {{ border: 1px solid #2e7d32; border-radius: 8px; padding: 8px; "
                f"background-color: rgba(46, 125, 50, 0.13); }}"
            )
            card["btn_primary"].setText("Show")
            card["btn_primary"].setVisible(True)
            card["btn_primary"].setEnabled(True)
            card["btn_secondary"].setText("Erase")
            card["btn_secondary"].setVisible(True)
            card["btn_secondary"].setEnabled(True)
            card["btn_refresh"].setVisible(False)
            card["btn_refresh"].setEnabled(False)
            card["primary_action"] = lambda s=slot: on_btnEccShowFromOverview_click(s)
            card["secondary_action"] = lambda s=slot: on_btnEccEraseFromOverview_click(s)
        elif state == "empty":
            status.setText("● Empty")
            status.setStyleSheet(f"color: #666666; {base_style}")
            frame.setStyleSheet(
                f"{frame_selector} {{ border: 1px solid #7a7a7a; border-radius: 8px; padding: 8px; "
                f"background-color: rgba(122, 122, 122, 0.11); }}"
            )
            card["btn_primary"].setText("Generate")
            card["btn_primary"].setVisible(True)
            card["btn_primary"].setEnabled(True)
            card["btn_secondary"].setText("Store")
            card["btn_secondary"].setVisible(True)
            card["btn_secondary"].setEnabled(True)
            card["btn_refresh"].setVisible(False)
            card["btn_refresh"].setEnabled(False)
            card["primary_action"] = lambda s=slot: on_btnEccGenerateFromOverview_click(s)
            card["secondary_action"] = lambda s=slot: on_btnEccStoreFromOverview_click(s)
        else:
            status.setText("● Unknown")
            status.setStyleSheet(f"color: #666666; {base_style}")
            frame.setStyleSheet(
                f"{frame_selector} {{ border: 1px solid #7a7a7a; border-radius: 8px; padding: 8px; "
                f"background-color: rgba(122, 122, 122, 0.11); }}"
            )
            card["btn_primary"].setText("Show")
            card["btn_primary"].setVisible(False)
            card["btn_primary"].setEnabled(False)
            card["btn_secondary"].setText("Erase")
            card["btn_secondary"].setVisible(False)
            card["btn_secondary"].setEnabled(False)
            card["btn_refresh"].setVisible(True)
            card["btn_refresh"].setEnabled(True)
            card["primary_action"] = None
            card["secondary_action"] = None

    def create_ecc_overview():
        top_row = QtWidgets.QHBoxLayout()
        top_row.setContentsMargins(0, 0, 0, 0)
        top_row.setSpacing(8)
        btn_refresh_all = QtWidgets.QPushButton("Refresh All")
        btn_sign_message = QtWidgets.QPushButton("Sign Message")
        progress = QtWidgets.QProgressBar()
        progress.setMinimum(0)
        progress.setMaximum(ECC_MAX_KEYS + 1)
        progress.setValue(0)
        progress.setTextVisible(False)
        progress.setFixedWidth(180)
        lbl_status = QtWidgets.QLabel("Idle")
        top_row.addWidget(btn_refresh_all)
        top_row.addWidget(btn_sign_message)
        top_row.addWidget(progress)
        top_row.addWidget(lbl_status)
        top_row.addStretch(1)

        overview_group = QtWidgets.QGroupBox("Keys Overview")
        overview_group.setContentsMargins(6, 6, 6, 6)
        overview_group.setSizePolicy(
            QtWidgets.QSizePolicy.Policy.Expanding,
            QtWidgets.QSizePolicy.Policy.Expanding
        )
        overview_layout = QtWidgets.QGridLayout(overview_group)
        overview_layout.setContentsMargins(12, 28, 12, 12)
        overview_layout.setHorizontalSpacing(12)
        overview_layout.setVerticalSpacing(12)

        cols = 4
        for slot in range(ECC_MAX_KEYS + 1):
            frame = QtWidgets.QFrame()
            frame.setObjectName(f"eccSlotFrame{slot}")
            frame.setFrameShape(QtWidgets.QFrame.Shape.StyledPanel)
            frame.setStyleSheet("QFrame { border: 1px solid #bdbdbd; border-radius: 8px; padding: 8px; }")
            frame.setMinimumWidth(170)
            frame.setFixedHeight(120)
            frame.setSizePolicy(
                QtWidgets.QSizePolicy.Policy.Preferred,
                QtWidgets.QSizePolicy.Policy.Fixed
            )
            vbox = QtWidgets.QVBoxLayout(frame)
            vbox.setContentsMargins(6, 6, 6, 6)
            vbox.setSpacing(4)

            title = QtWidgets.QLabel(f"Slot {slot}")
            title.setStyleSheet(
                "font-weight: bold; border: 1px solid rgba(210, 210, 210, 0.82); "
                "border-radius: 6px; padding: 6px 8px;"
            )
            title.setMinimumHeight(20)
            status = QtWidgets.QLabel("● Unknown")
            status.setStyleSheet(
                "color: #666666; font-weight: bold; border: 1px solid rgba(210, 210, 210, 0.82); "
                "border-radius: 6px; padding: 6px 8px;"
            )
            status.setMinimumHeight(20)

            action_row = QtWidgets.QGridLayout()
            action_row.setHorizontalSpacing(4)
            action_row.setVerticalSpacing(4)
            btn_primary = QtWidgets.QPushButton("Show")
            btn_secondary = QtWidgets.QPushButton("Erase")
            btn_refresh = QtWidgets.QPushButton("Refresh")
            action_row.addWidget(btn_primary, 0, 0)
            action_row.addWidget(btn_secondary, 0, 1)
            action_row.addWidget(btn_refresh, 0, 0, 1, 2)

            vbox.addWidget(title)
            vbox.addWidget(status)
            vbox.addLayout(action_row)

            row = slot // cols
            col = slot % cols
            overview_layout.addWidget(frame, row, col)

            ecc_slot_cards[slot] = {
                "frame": frame,
                "status": status,
                "btn_primary": btn_primary,
                "btn_secondary": btn_secondary,
                "btn_refresh": btn_refresh,
                "primary_action": None,
                "secondary_action": None,
            }
            ecc_slot_states.setdefault(slot, "unknown")

            btn_primary.clicked.connect(lambda _=False, s=slot: ecc_slot_cards[s]["primary_action"] and ecc_slot_cards[s]["primary_action"]())
            btn_secondary.clicked.connect(lambda _=False, s=slot: ecc_slot_cards[s]["secondary_action"] and ecc_slot_cards[s]["secondary_action"]())
            btn_refresh.clicked.connect(lambda _=False, s=slot: on_btnEccRefreshOne_click(s))

            refresh_ecc_slot_card(slot)

        scroll = QtWidgets.QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QtWidgets.QFrame.Shape.NoFrame)
        scroll_content = QtWidgets.QWidget()
        scroll_content_layout = QtWidgets.QVBoxLayout(scroll_content)
        scroll_content_layout.setContentsMargins(0, 0, 0, 0)
        scroll_content_layout.setSpacing(0)
        scroll_content_layout.addWidget(overview_group)
        scroll.setWidget(scroll_content)

        window.layoutEcc.addLayout(top_row)
        window.layoutEcc.addWidget(scroll)

        def on_btnEccRefreshAll_click():
            if not ts:
                QtWidgets.QMessageBox.warning(window, "Not Connected", "Please connect to device first")
                return
            btn_refresh_all.setEnabled(False)
            progress.setValue(0)
            lbl_status.setText("Refreshing...")
            QtWidgets.QApplication.processEvents()
            for slot in range(ECC_MAX_KEYS + 1):
                lbl_status.setText(f"Reading slot {slot + 1}/{ECC_MAX_KEYS + 1}...")
                try:
                    key_info = ts.ecc_key_read(slot)
                    ecc_slot_states[slot] = "present"
                    ecc_slot_info[slot] = key_info
                except TropicSquareECCInvalidKeyError:
                    ecc_slot_states[slot] = "empty"
                    ecc_slot_info.pop(slot, None)
                except Exception:
                    ecc_slot_states[slot] = "unknown"
                    ecc_slot_info.pop(slot, None)
                refresh_ecc_slot_card(slot)
                progress.setValue(slot + 1)
            lbl_status.setText("Done")
            btn_refresh_all.setEnabled(True)

        btn_refresh_all.clicked.connect(on_btnEccRefreshAll_click)
        btn_sign_message.clicked.connect(on_btnEccSignMessage_click)
        window.btnEccSignMessage = btn_sign_message

    def get_mcounter_index():
        idx_text = window.leMCounterIndex.text().strip()
        if not idx_text:
            raise ValueError("Index is required")
        index = int(idx_text)
        if index < 0 or index > MCOUNTER_MAX:
            raise ValueError(f"Index must be 0-{MCOUNTER_MAX}")
        return index

    def on_btnMCounterGet_click():
        if not ts:
            QtWidgets.QMessageBox.warning(window, "Not Connected", "Please connect to device first")
            return
        try:
            index = get_mcounter_index()
            value = ts.mcounter_get(index)
            window.lblMCounterValue.setText(str(value))
        except TropicSquareNoSession:
            QtWidgets.QMessageBox.warning(window, "No Session", "No secure session established")
        except ValueError as e:
            QtWidgets.QMessageBox.warning(window, "Invalid Index", str(e))
        except Exception as e:
            QtWidgets.QMessageBox.critical(window, "MCounter Get Failed", str(e))

    def on_btnMCounterInit_click():
        if not ts:
            QtWidgets.QMessageBox.warning(window, "Not Connected", "Please connect to device first")
            return
        try:
            index = get_mcounter_index()
            value_text = window.leMCounterInitValue.text().strip()
            if not value_text:
                raise ValueError("Init value is required")
            value = int(value_text)
            if value < 0 or value > 0xFFFFFFFF:
                raise ValueError("Init value must be 0-4294967295")
            ts.mcounter_init(index, value)
            on_btnMCounterGet_click()
        except TropicSquareNoSession:
            QtWidgets.QMessageBox.warning(window, "No Session", "No secure session established")
        except ValueError as e:
            QtWidgets.QMessageBox.warning(window, "Invalid Input", str(e))
        except Exception as e:
            QtWidgets.QMessageBox.critical(window, "MCounter Init Failed", str(e))

    def on_btnMCounterUpdate_click():
        if not ts:
            QtWidgets.QMessageBox.warning(window, "Not Connected", "Please connect to device first")
            return
        try:
            index = get_mcounter_index()
            ts.mcounter_update(index)
            on_btnMCounterGet_click()
        except TropicSquareNoSession:
            QtWidgets.QMessageBox.warning(window, "No Session", "No secure session established")
        except ValueError as e:
            QtWidgets.QMessageBox.warning(window, "Invalid Index", str(e))
        except Exception as e:
            QtWidgets.QMessageBox.critical(window, "MCounter Update Failed", str(e))

    def clear_layout(layout):
        while layout.count():
            item = layout.takeAt(0)
            widget = item.widget()
            if widget:
                widget.deleteLater()
            else:
                child_layout = item.layout()
                if child_layout:
                    clear_layout(child_layout)

    def is_permission_field(field):
        return hasattr(field, "get_slot_permission") and hasattr(field, "set_slot_permission")

    def is_permission_dict(value):
        if not isinstance(value, dict):
            return False
        keys = ("pkey_slot_0", "pkey_slot_1", "pkey_slot_2", "pkey_slot_3")
        return all(key in value for key in keys)

    def get_permission_specs(config):
        specs = []
        if isinstance(config, dict):
            for key, value in config.items():
                if is_permission_dict(value):
                    specs.append(("dict", key))
            return specs

        try:
            data_keys = list(config.to_dict().keys())
        except Exception:
            data_keys = []

        for key in data_keys:
            if not hasattr(config, key):
                continue
            field = getattr(config, key)
            if is_permission_field(field):
                specs.append(("attr", key))
            elif isinstance(field, dict) and is_permission_dict(field):
                specs.append(("attr_dict", key))

        if specs:
            return specs

        for key in ("permissions", "cfg_permissions", "func_permissions"):
            if not hasattr(config, key):
                continue
            field = getattr(config, key)
            if is_permission_field(field):
                specs.append(("attr", key))
            elif isinstance(field, dict) and is_permission_dict(field):
                specs.append(("attr_dict", key))
        return specs

    def get_permission_value(config, spec_type, key, slot):
        slot_key = f"pkey_slot_{slot}"
        if spec_type == "dict":
            return bool(config.get(key, {}).get(slot_key, False))
        field = getattr(config, key)
        if is_permission_field(field):
            return field.get_slot_permission(slot)
        if isinstance(field, dict):
            return bool(field.get(slot_key, False))
        return False

    def add_permission_row(grid, row, label_text, config, spec_type, key, editable=False):
        label = QtWidgets.QLabel(label_text)
        grid.addWidget(label, row, 0)
        checkboxes = []
        for i in range(4):
            cb = QtWidgets.QCheckBox(f"P{i}")
            cb.setChecked(get_permission_value(config, spec_type, key, i))
            cb.setEnabled(editable)
            grid.addWidget(cb, row, i + 1)
            checkboxes.append(cb)
        return checkboxes

    def render_uap_permissions(parent_layout, config, editable=False):
        wrapper = QtWidgets.QVBoxLayout()
        wrapper.setContentsMargins(0, 0, 0, 0)
        wrapper.setSpacing(6)

        header_row = QtWidgets.QHBoxLayout()
        header_row.setContentsMargins(0, 0, 0, 0)
        header_row.setSpacing(12)
        header_title = QtWidgets.QLabel("Pairing key slots")
        header_title.setStyleSheet("font-weight: bold;")
        header_row.addWidget(header_title)
        header_row.addStretch(1)
        for i in range(4):
            h = QtWidgets.QLabel(f"P{i}")
            h.setAlignment(QtCore.Qt.AlignmentFlag.AlignHCenter | QtCore.Qt.AlignmentFlag.AlignVCenter)
            h.setMinimumWidth(36)
            header_row.addWidget(h)
        wrapper.addLayout(header_row)

        line = QtWidgets.QFrame()
        line.setFrameShape(QtWidgets.QFrame.Shape.HLine)
        line.setFrameShadow(QtWidgets.QFrame.Shadow.Sunken)
        wrapper.addWidget(line)

        grid = QtWidgets.QGridLayout()
        grid.setContentsMargins(0, 0, 0, 0)
        grid.setHorizontalSpacing(12)
        grid.setVerticalSpacing(6)
        grid.setColumnStretch(0, 1)

        row = 0
        fields = []
        for spec_type, key in get_permission_specs(config):
            label = key.replace("_", " ")
            checkboxes = add_permission_row(grid, row, label, config, spec_type, key, editable=editable)
            fields.append(((spec_type, key), checkboxes))
            row += 1
        wrapper.addLayout(grid)
        wrapper.addStretch(1)

        parent_layout.addLayout(wrapper)
        return fields

    def render_key_values(parent_layout, config, editable=False):
        if isinstance(config, dict):
            data = config
        else:
            try:
                data = config.to_dict()
            except Exception:
                data = {"value": str(config)}

        form = QtWidgets.QFormLayout()
        fields = []
        for key, value in data.items():
            key_label = QtWidgets.QLabel(str(key))
            if editable and isinstance(value, bool):
                cb = QtWidgets.QCheckBox()
                cb.setChecked(value)
                if isinstance(config, dict):
                    fields.append((("scalar_dict", key, "bool"), cb))
                elif hasattr(config, key):
                    fields.append((("scalar_attr", key, "bool"), cb))
                else:
                    cb.setEnabled(False)
                form.addRow(key_label, cb)
            elif editable and isinstance(value, int):
                if str(key) == "gpo_func":
                    combo = QtWidgets.QComboBox()
                    gpo_options = [
                        (0, "0x0"),
                        (1, "0x1"),
                        (2, "0x2"),
                        (3, "0x3"),
                        (4, "0x4"),
                        (5, "ALWAYS_LOW (0x5) - Always in logic low state"),
                        (6, "ALWAYS_HIGH (0x6) - Always in logic high state"),
                        (7, "INTERRUPT (0x7) - L2 result active high interrupt"),
                    ]
                    for option_value, option_label in gpo_options:
                        combo.addItem(option_label, option_value)
                    current_idx = combo.findData(int(value))
                    if current_idx >= 0:
                        combo.setCurrentIndex(current_idx)
                    if isinstance(config, dict):
                        fields.append((("scalar_dict", key, "int"), combo))
                    elif hasattr(config, key):
                        fields.append((("scalar_attr", key, "int"), combo))
                    else:
                        combo.setEnabled(False)
                    form.addRow(key_label, combo)
                else:
                    sb = QtWidgets.QSpinBox()
                    sb.setRange(0, 0x7FFFFFFF)
                    sb.setValue(max(sb.minimum(), min(int(value), sb.maximum())))
                    if isinstance(config, dict):
                        fields.append((("scalar_dict", key, "int"), sb))
                    elif hasattr(config, key):
                        fields.append((("scalar_attr", key, "int"), sb))
                    else:
                        sb.setEnabled(False)
                    form.addRow(key_label, sb)
            else:
                form.addRow(key_label, QtWidgets.QLabel(str(value)))
        parent_layout.addLayout(form)
        return fields

    def render_config_details(layout, config, editable=False):
        clear_layout(layout)
        if get_permission_specs(config):
            return render_uap_permissions(layout, config, editable=editable)
        return render_key_values(layout, config, editable=editable)

    def build_uap_config_from_ui(config, fields):
        if isinstance(config, dict):
            new_config = copy.deepcopy(config)
        else:
            new_config = config.__class__(config._value)
        for key, checkboxes in fields:
            spec_type = "attr"
            field_key = key
            if isinstance(key, tuple) and len(key) == 2:
                spec_type, field_key = key

            if spec_type == "dict":
                if field_key not in new_config or not isinstance(new_config[field_key], dict):
                    new_config[field_key] = {}
                for i, cb in enumerate(checkboxes):
                    new_config[field_key][f"pkey_slot_{i}"] = cb.isChecked()
                continue

            if isinstance(checkboxes, list):
                field = getattr(new_config, field_key)
                if is_permission_field(field):
                    for i, cb in enumerate(checkboxes):
                        field.set_slot_permission(i, cb.isChecked())
                    setattr(new_config, field_key, field)
                elif isinstance(field, dict):
                    updated = dict(field)
                    for i, cb in enumerate(checkboxes):
                        updated[f"pkey_slot_{i}"] = cb.isChecked()
                    setattr(new_config, field_key, updated)
                continue

            control = checkboxes
            if isinstance(key, tuple) and len(key) == 3 and key[0] in ("scalar_dict", "scalar_attr"):
                target_type, target_key, value_type = key
                if isinstance(control, QtWidgets.QCheckBox):
                    new_value = control.isChecked()
                elif isinstance(control, QtWidgets.QSpinBox):
                    new_value = int(control.value())
                elif isinstance(control, QtWidgets.QComboBox):
                    new_value = int(control.currentData())
                else:
                    continue

                if value_type == "bool":
                    new_value = bool(new_value)
                elif value_type == "int":
                    new_value = int(new_value)

                if target_type == "scalar_dict" and isinstance(new_config, dict):
                    new_config[target_key] = new_value
                elif target_type == "scalar_attr" and hasattr(new_config, target_key):
                    setattr(new_config, target_key, new_value)
        return new_config

    def get_config_value_from_ui(config, fields):
        if fields:
            return build_uap_config_from_ui(config, fields)
        return config

    def set_raw_config_label(label, config):
        try:
            raw_value = int.from_bytes(config.to_bytes(), "big")
            label.setText(f"0x{raw_value:08X}")
        except Exception:
            if hasattr(config, "_value"):
                label.setText(f"0x{config._value:08X}")

    def clone_config(config):
        if hasattr(config, "_value"):
            try:
                return config.__class__(config._value)
            except Exception:
                pass
        return config

    def config_raw_key(config):
        try:
            return ("bytes", bytes(config.to_bytes()))
        except Exception:
            if hasattr(config, "_value"):
                return ("value", int(config._value))
            return ("str", str(config))

    def config_raw_text(config):
        key_type, key_value = config_raw_key(config)
        if key_type == "bytes":
            return "0x" + key_value.hex().upper()
        if key_type == "value":
            return f"0x{key_value:08X}"
        return str(key_value)

    def bind_uap_fields_to_raw_label(fields, on_change):
        for _, controls in fields:
            if isinstance(controls, list):
                for cb in controls:
                    cb.toggled.connect(on_change)
                continue
            if isinstance(controls, QtWidgets.QCheckBox):
                controls.toggled.connect(on_change)
            elif isinstance(controls, QtWidgets.QSpinBox):
                controls.valueChanged.connect(lambda _=0: on_change())
            elif isinstance(controls, QtWidgets.QComboBox):
                controls.currentIndexChanged.connect(lambda _=0: on_change())

    def refresh_rconfig_raw_label():
        config = getattr(window, "_rconfig_current", None)
        fields = getattr(window, "_rconfig_fields", [])
        if config is None:
            return
        set_raw_config_label(window.lblRConfigRaw, get_config_value_from_ui(config, fields))

    def refresh_iconfig_raw_label():
        config = getattr(window, "_iconfig_current", None)
        fields = getattr(window, "_iconfig_fields", [])
        if config is None:
            return
        set_raw_config_label(window.lblIConfigRaw, get_config_value_from_ui(config, fields))

    def get_cfg_constants():
        items = []
        for name, value in cfg_constants.__dict__.items():
            if name.startswith("CFG_") and isinstance(value, int):
                items.append((name, value))
        return sorted(items, key=lambda x: x[1])

    def get_rconfig_bulk_dirty_addresses():
        snapshot = getattr(window, "_rconfig_bulk_snapshot", {})
        current = getattr(window, "_rconfig_bulk_current", {})
        dirty = []
        for _, address in getattr(window, "_cfg_items", []):
            if address not in snapshot or address not in current:
                continue
            if config_raw_key(snapshot[address]) != config_raw_key(current[address]):
                dirty.append(address)
        return dirty

    def refresh_rconfig_bulk_status():
        snapshot = getattr(window, "_rconfig_bulk_snapshot", {})
        if not snapshot:
            window.lblRConfigBulkStatus.setText("No snapshot loaded")
            return
        dirty_count = len(get_rconfig_bulk_dirty_addresses())
        window.lblRConfigBulkStatus.setText(
            f"Snapshot loaded ({len(snapshot)} regs), modified: {dirty_count}"
        )

    def refresh_rconfig_bulk_row(address):
        row_by_addr = getattr(window, "_rconfig_bulk_row_by_addr", {})
        row = row_by_addr.get(address)
        if row is None:
            return
        current = getattr(window, "_rconfig_bulk_current", {}).get(address)
        snapshot = getattr(window, "_rconfig_bulk_snapshot", {}).get(address)
        if current is None:
            window.tblRConfigBulk.item(row, 2).setText("-")
            window.tblRConfigBulk.item(row, 3).setText("-")
            window.tblRConfigBulk.item(row, 4).setText("no data")
            return

        window.tblRConfigBulk.item(row, 2).setText(config_raw_text(current))
        window.tblRConfigBulk.item(row, 3).setText(current.__class__.__name__)
        state_item = window.tblRConfigBulk.item(row, 4)
        if snapshot is None:
            state_item.setText("loaded")
            state_item.setForeground(QtGui.QBrush(QtGui.QColor("#666666")))
        elif config_raw_key(snapshot) != config_raw_key(current):
            state_item.setText("modified")
            state_item.setForeground(QtGui.QBrush(QtGui.QColor("#b36b00")))
        else:
            state_item.setText("clean")
            state_item.setForeground(QtGui.QBrush(QtGui.QColor("#1b7f1b")))

    def refresh_rconfig_bulk_table():
        for _, address in getattr(window, "_cfg_items", []):
            refresh_rconfig_bulk_row(address)
        refresh_rconfig_bulk_status()

    def persist_rconfig_bulk_editor():
        address = getattr(window, "_rconfig_bulk_selected_address", None)
        if address is None:
            return
        fields = getattr(window, "_rconfig_bulk_fields", [])
        if not fields:
            return
        current = getattr(window, "_rconfig_bulk_current", {})
        config = current.get(address)
        if config is None:
            return
        current[address] = build_uap_config_from_ui(config, fields)
        window._rconfig_bulk_current = current
        refresh_rconfig_bulk_row(address)
        window.lblRConfigBulkRaw.setText(f"Raw: {config_raw_text(current[address])}")
        refresh_rconfig_bulk_status()

    def on_rconfig_bulk_editor_changed():
        persist_rconfig_bulk_editor()

    def on_tblRConfigBulk_selection_changed():
        if not hasattr(window, "tblRConfigBulk"):
            return
        persist_rconfig_bulk_editor()
        selected_rows = window.tblRConfigBulk.selectionModel().selectedRows()
        if not selected_rows:
            window._rconfig_bulk_selected_address = None
            window._rconfig_bulk_fields = []
            window.lblRConfigBulkSelected.setText("Selected: -")
            window.lblRConfigBulkRaw.setText("Raw: -")
            clear_layout(window.layoutRConfigBulkDetails)
            return
        row = selected_rows[0].row()
        addr_item = window.tblRConfigBulk.item(row, 1)
        if addr_item is None:
            return
        address = addr_item.data(QtCore.Qt.ItemDataRole.UserRole)
        current = getattr(window, "_rconfig_bulk_current", {})
        config = current.get(address)
        name = getattr(window, "_rconfig_bulk_name_by_addr", {}).get(address, f"0x{address:02X}")
        window._rconfig_bulk_selected_address = address
        window.lblRConfigBulkSelected.setText(f"Selected: {name} (0x{address:02X})")
        if config is None:
            window._rconfig_bulk_fields = []
            window.lblRConfigBulkRaw.setText("Raw: -")
            clear_layout(window.layoutRConfigBulkDetails)
            return
        window._rconfig_bulk_fields = render_config_details(window.layoutRConfigBulkDetails, config, editable=True)
        bind_uap_fields_to_raw_label(window._rconfig_bulk_fields, on_rconfig_bulk_editor_changed)
        window.lblRConfigBulkRaw.setText(f"Raw: {config_raw_text(config)}")

    def select_rconfig_bulk_row(address):
        row_by_addr = getattr(window, "_rconfig_bulk_row_by_addr", {})
        row = row_by_addr.get(address)
        if row is None:
            return
        window.tblRConfigBulk.clearSelection()
        window.tblRConfigBulk.setCurrentCell(row, 0)
        window.tblRConfigBulk.selectRow(row)

    def on_btnRConfigBulkReadAll_click():
        if not ts:
            QtWidgets.QMessageBox.warning(window, "Not Connected", "Please connect to device first")
            return
        total = len(getattr(window, "_cfg_items", []))
        window.btnRConfigBulkReadAll.setEnabled(False)
        window.pbRConfigBulkProgress.setRange(0, total if total else 1)
        window.pbRConfigBulkProgress.setValue(0)
        window.lblRConfigBulkProgress.setText("Starting...")
        QtWidgets.QApplication.processEvents()
        try:
            snapshot = {}
            current = {}
            for idx, (_, address) in enumerate(getattr(window, "_cfg_items", []), start=1):
                window.lblRConfigBulkProgress.setText(f"Reading register {idx}/{total}...")
                window.pbRConfigBulkProgress.setValue(idx - 1)
                QtWidgets.QApplication.processEvents()
                cfg = ts.r_config_read(address)
                snapshot[address] = clone_config(cfg)
                current[address] = clone_config(cfg)
            window._rconfig_bulk_snapshot = snapshot
            window._rconfig_bulk_current = current
            window._rconfig_bulk_selected_address = None
            window._rconfig_bulk_fields = []
            refresh_rconfig_bulk_table()
            if window.tblRConfigBulk.rowCount() > 0:
                first_addr = getattr(window, "_cfg_items", [("", None)])[0][1]
                if first_addr is not None:
                    select_rconfig_bulk_row(first_addr)
            window.pbRConfigBulkProgress.setValue(total if total else 1)
            window.lblRConfigBulkProgress.setText("Done")
        except TropicSquareNoSession:
            QtWidgets.QMessageBox.warning(window, "No Session", "No secure session established")
            window.lblRConfigBulkProgress.setText("No session")
        except Exception as e:
            QtWidgets.QMessageBox.critical(window, "R-Config Read All Failed", str(e))
            window.lblRConfigBulkProgress.setText("Failed")
        finally:
            window.btnRConfigBulkReadAll.setEnabled(ts is not None)

    def on_btnRConfigBulkDiscard_click():
        snapshot = getattr(window, "_rconfig_bulk_snapshot", {})
        if not snapshot:
            QtWidgets.QMessageBox.warning(window, "R-Config Discard", "Read all registers first")
            return
        current_addr = getattr(window, "_rconfig_bulk_selected_address", None)
        window._rconfig_bulk_selected_address = None
        window._rconfig_bulk_fields = []
        window.lblRConfigBulkSelected.setText("Selected: -")
        window.lblRConfigBulkRaw.setText("Raw: -")
        clear_layout(window.layoutRConfigBulkDetails)
        window._rconfig_bulk_current = {addr: clone_config(cfg) for addr, cfg in snapshot.items()}
        refresh_rconfig_bulk_table()
        if current_addr is not None:
            select_rconfig_bulk_row(current_addr)

    def on_btnRConfigBulkApply_click():
        if not ts:
            QtWidgets.QMessageBox.warning(window, "Not Connected", "Please connect to device first")
            return
        snapshot = getattr(window, "_rconfig_bulk_snapshot", {})
        current = getattr(window, "_rconfig_bulk_current", {})
        if not snapshot or not current:
            QtWidgets.QMessageBox.warning(window, "R-Config Apply", "Read all registers first")
            return
        persist_rconfig_bulk_editor()
        dirty_addresses = get_rconfig_bulk_dirty_addresses()
        if not dirty_addresses:
            QtWidgets.QMessageBox.information(window, "R-Config Apply", "No modified registers")
            return
        confirm = QtWidgets.QMessageBox.warning(
            window,
            "R-Config Apply",
            f"Modified registers: {len(dirty_addresses)}\n"
            "Apply will erase whole R-CONFIG and write all registers from snapshot.\n"
            "Continue?",
            QtWidgets.QMessageBox.StandardButton.Yes | QtWidgets.QMessageBox.StandardButton.No
        )
        if confirm != QtWidgets.QMessageBox.StandardButton.Yes:
            return
        total = len(getattr(window, "_cfg_items", []))
        progress_total = total + 1 if total else 1
        window.btnRConfigBulkApply.setEnabled(False)
        window.pbRConfigBulkProgress.setRange(0, progress_total)
        window.pbRConfigBulkProgress.setValue(0)
        window.lblRConfigBulkProgress.setText("Erasing...")
        QtWidgets.QApplication.processEvents()
        try:
            ts.r_config_erase()
            window.pbRConfigBulkProgress.setValue(1)
            for idx, (_, address) in enumerate(getattr(window, "_cfg_items", []), start=1):
                window.lblRConfigBulkProgress.setText(f"Writing register {idx}/{total}...")
                window.pbRConfigBulkProgress.setValue(idx + 1)
                QtWidgets.QApplication.processEvents()
                ts.r_config_write(address, current[address])
            window._rconfig_bulk_snapshot = {addr: clone_config(cfg) for addr, cfg in current.items()}
            refresh_rconfig_bulk_table()
            window.pbRConfigBulkProgress.setValue(progress_total)
            window.lblRConfigBulkProgress.setText("Done")
            QtWidgets.QMessageBox.information(window, "R-Config Apply", "Configuration applied successfully")
        except TropicSquareNoSession:
            QtWidgets.QMessageBox.warning(window, "No Session", "No secure session established")
            window.lblRConfigBulkProgress.setText("No session")
        except Exception as e:
            QtWidgets.QMessageBox.critical(window, "R-Config Apply Failed", str(e))
            window.lblRConfigBulkProgress.setText("Failed")
        finally:
            window.btnRConfigBulkApply.setEnabled(ts is not None)

    def on_btnRConfigRead_click():
        if not ts:
            QtWidgets.QMessageBox.warning(window, "Not Connected", "Please connect to device first")
            return
        try:
            address = window.cmbRConfigReg.currentData()
            config = ts.r_config_read(address)
            window._rconfig_current = config
            window._rconfig_fields = render_config_details(window.layoutRConfigDetails, config, editable=True)
            bind_uap_fields_to_raw_label(window._rconfig_fields, refresh_rconfig_raw_label)
            refresh_rconfig_raw_label()
        except TropicSquareNoSession:
            QtWidgets.QMessageBox.warning(window, "No Session", "No secure session established")
        except Exception as e:
            QtWidgets.QMessageBox.critical(window, "R-Config Read Failed", str(e))

    def on_btnIConfigRead_click():
        if not ts:
            QtWidgets.QMessageBox.warning(window, "Not Connected", "Please connect to device first")
            return
        try:
            address = window.cmbIConfigReg.currentData()
            config = ts.i_config_read(address)
            window._iconfig_current = config
            window._iconfig_fields = render_config_details(window.layoutIConfigDetails, config, editable=True)
            bind_uap_fields_to_raw_label(window._iconfig_fields, refresh_iconfig_raw_label)
            refresh_iconfig_raw_label()
        except TropicSquareNoSession:
            QtWidgets.QMessageBox.warning(window, "No Session", "No secure session established")
        except Exception as e:
            QtWidgets.QMessageBox.critical(window, "I-Config Read Failed", str(e))

    def on_btnRConfigWrite_click():
        if not ts:
            QtWidgets.QMessageBox.warning(window, "Not Connected", "Please connect to device first")
            return
        config = getattr(window, "_rconfig_current", None)
        fields = getattr(window, "_rconfig_fields", [])
        if config is None:
            QtWidgets.QMessageBox.warning(window, "R-Config Write", "Read config first")
            return
        if not fields:
            QtWidgets.QMessageBox.warning(window, "R-Config Write", "Write not supported for this config")
            return
        try:
            address = window.cmbRConfigReg.currentData()
            new_config = build_uap_config_from_ui(config, fields)
            ts.r_config_write(address, new_config)
            QtWidgets.QMessageBox.information(window, "R-Config Write", "Config written successfully")
            on_btnRConfigRead_click()
        except TropicSquareNoSession:
            QtWidgets.QMessageBox.warning(window, "No Session", "No secure session established")
        except Exception as e:
            QtWidgets.QMessageBox.critical(window, "R-Config Write Failed", str(e))

    def on_btnRConfigErase_click():
        if not ts:
            QtWidgets.QMessageBox.warning(window, "Not Connected", "Please connect to device first")
            return
        confirm = QtWidgets.QMessageBox.warning(
            window,
            "R-Config Erase",
            "Erase whole R-CONFIG?\nThis sets all bits of all COs to 1.\nContinue?",
            QtWidgets.QMessageBox.StandardButton.Yes | QtWidgets.QMessageBox.StandardButton.No
        )
        if confirm != QtWidgets.QMessageBox.StandardButton.Yes:
            return
        try:
            ts.r_config_erase()
            QtWidgets.QMessageBox.information(window, "R-Config Erase", "R-CONFIG erased successfully")
            on_btnRConfigRead_click()
        except TropicSquareNoSession:
            QtWidgets.QMessageBox.warning(window, "No Session", "No secure session established")
        except Exception as e:
            QtWidgets.QMessageBox.critical(window, "R-Config Erase Failed", str(e))

    def on_btnIConfigWrite_click():
        if not ts:
            QtWidgets.QMessageBox.warning(window, "Not Connected", "Please connect to device first")
            return
        config = getattr(window, "_iconfig_current", None)
        fields = getattr(window, "_iconfig_fields", [])
        if config is None:
            QtWidgets.QMessageBox.warning(window, "I-Config Write", "Read config first")
            return
        if not fields:
            QtWidgets.QMessageBox.warning(window, "I-Config Write", "Write not supported for this config")
            return
        confirm = QtWidgets.QMessageBox.warning(
            window,
            "I-Config Write",
            "I-CONFIG is OTP. This is irreversible.\nContinue?",
            QtWidgets.QMessageBox.StandardButton.Yes | QtWidgets.QMessageBox.StandardButton.No
        )
        if confirm != QtWidgets.QMessageBox.StandardButton.Yes:
            return
        if not hasattr(ts, "i_config_write"):
            QtWidgets.QMessageBox.warning(window, "I-Config Write", "Current API does not provide i_config_write")
            return
        try:
            address = window.cmbIConfigReg.currentData()
            new_config = build_uap_config_from_ui(config, fields)
            ts.i_config_write(address, new_config)
            QtWidgets.QMessageBox.information(window, "I-Config Write", "Config written successfully")
            on_btnIConfigRead_click()
        except TropicSquareNoSession:
            QtWidgets.QMessageBox.warning(window, "No Session", "No secure session established")
        except Exception as e:
            QtWidgets.QMessageBox.critical(window, "I-Config Write Failed", str(e))

    def get_mem_slot():
        slot_text = window.leMemSlot.text().strip()
        if not slot_text:
            raise ValueError("Slot is required")
        slot = int(slot_text)
        if slot < 0 or slot > 511:
            raise ValueError("Slot must be 0-511")
        return slot

    def parse_mem_input() -> bytes:
        data_text = window.pteMemInput.toPlainText()
        if window.rbMemHex.isChecked():
            data_text = data_text.strip().replace(" ", "").replace("\n", "")
            if not data_text:
                return b""
            if len(data_text) % 2 != 0:
                raise ValueError("Hex input must have even length")
            try:
                return bytes.fromhex(data_text)
            except ValueError:
                raise ValueError("Invalid hex input")
        return data_text.encode("utf-8")

    def on_btnMemRead_click():
        if not ts:
            QtWidgets.QMessageBox.warning(window, "Not Connected", "Please connect to device first")
            return
        try:
            slot = get_mem_slot()
            data = ts.mem_data_read(slot)
            window.pteMemHex.setPlainText(data.hex())
            window.pteMemText.setPlainText(data.decode("utf-8", "replace"))
        except TropicSquareNoSession:
            QtWidgets.QMessageBox.warning(window, "No Session", "No secure session established")
        except ValueError as e:
            QtWidgets.QMessageBox.warning(window, "Invalid Input", str(e))
        except Exception as e:
            QtWidgets.QMessageBox.critical(window, "MEM Read Failed", str(e))

    def on_btnMemWrite_click():
        if not ts:
            QtWidgets.QMessageBox.warning(window, "Not Connected", "Please connect to device first")
            return
        try:
            slot = get_mem_slot()
            data = parse_mem_input()
            if len(data) > MEM_DATA_MAX_SIZE:
                raise ValueError(f"Max size is {MEM_DATA_MAX_SIZE} bytes")
            ts.mem_data_write(data, slot)
            on_btnMemRead_click()
            QtWidgets.QMessageBox.information(window, "MEM Write", "Data written successfully")
        except TropicSquareNoSession:
            QtWidgets.QMessageBox.warning(window, "No Session", "No secure session established")
        except ValueError as e:
            QtWidgets.QMessageBox.warning(window, "Invalid Input", str(e))
        except Exception as e:
            QtWidgets.QMessageBox.critical(window, "MEM Write Failed", str(e))

    def on_btnMemErase_click():
        if not ts:
            QtWidgets.QMessageBox.warning(window, "Not Connected", "Please connect to device first")
            return
        try:
            slot = get_mem_slot()
            confirm = QtWidgets.QMessageBox.question(
                window,
                "MEM Erase",
                f"Erase data in slot {slot}?",
                QtWidgets.QMessageBox.StandardButton.Yes | QtWidgets.QMessageBox.StandardButton.No
            )
            if confirm != QtWidgets.QMessageBox.StandardButton.Yes:
                return
            ts.mem_data_erase(slot)
            window.pteMemHex.setPlainText("")
            window.pteMemText.setPlainText("")
            QtWidgets.QMessageBox.information(window, "MEM Erase", "Data erased successfully")
        except TropicSquareNoSession:
            QtWidgets.QMessageBox.warning(window, "No Session", "No secure session established")
        except ValueError as e:
            QtWidgets.QMessageBox.warning(window, "Invalid Input", str(e))
        except Exception as e:
            QtWidgets.QMessageBox.critical(window, "MEM Erase Failed", str(e))

    def has_secure_session():
        return ts is not None and hasattr(ts, "_secure_session") and ts._secure_session is not None

    def reset_pairing_keys_state():
        for slot in range(PAIRING_KEY_MAX + 1):
            pairing_slot_states[slot] = "unknown"
        pairing_slot_pubkey_prefix.clear()
        refresh_pairing_keys_overview()

    def format_pubkey_prefix(key: bytes) -> str:
        return " ".join(f"{b:02x}" for b in key[:8])

    def refresh_pairing_slot_card(slot: int):
        card = pairing_slot_cards.get(slot)
        if not card:
            return
        frame = card["frame"]
        cached_state = pairing_slot_states.get(slot, "unknown")
        if ts is None:
            state = "disconnected"
        elif not has_secure_session():
            state = "no-session"
        else:
            state = cached_state
        status = card["status"]
        btn_write = card["btn_write"]
        btn_show = card["btn_show"]
        btn_invalidate = card["btn_invalidate"]
        btn_refresh_one = card["btn_refresh_one"]

        btn_write.setVisible(False)
        btn_show.setVisible(False)
        btn_invalidate.setVisible(False)
        btn_refresh_one.setVisible(False)

        if state == "full":
            frame_selector = f"QFrame#{frame.objectName()}"
            frame.setStyleSheet(
                f"{frame_selector} {{ border: 1px solid #2e7d32; border-radius: 8px; padding: 8px; background-color: rgba(46, 125, 50, 0.13); }}"
            )
            prefix = pairing_slot_pubkey_prefix.get(slot, "")
            if prefix:
                status.setText(f"● Full ({prefix})")
            else:
                status.setText("● Full")
            status.setStyleSheet(
                "color: #2e7d32; font-weight: bold; border: 1px solid rgba(210, 210, 210, 0.82); "
                "border-radius: 6px; padding: 6px 8px;"
            )
            btn_show.setVisible(True)
            btn_invalidate.setVisible(True)
            btn_show.setEnabled(True)
            btn_invalidate.setEnabled(True)
        elif state == "empty":
            frame_selector = f"QFrame#{frame.objectName()}"
            frame.setStyleSheet(
                f"{frame_selector} {{ border: 1px solid #c07a00; border-radius: 8px; padding: 8px; background-color: rgba(192, 122, 0, 0.11); }}"
            )
            status.setText("● Empty")
            status.setStyleSheet(
                "color: #c07a00; font-weight: bold; border: 1px solid rgba(210, 210, 210, 0.82); "
                "border-radius: 6px; padding: 6px 8px;"
            )
            btn_write.setVisible(True)
            btn_write.setEnabled(True)
        elif state == "invalidated":
            frame_selector = f"QFrame#{frame.objectName()}"
            frame.setStyleSheet(
                f"{frame_selector} {{ border: 1px solid #b00020; border-radius: 8px; padding: 8px; background-color: rgba(176, 0, 32, 0.11); }}"
            )
            status.setText("● Invalidated")
            status.setStyleSheet(
                "color: #b00020; font-weight: bold; border: 1px solid rgba(210, 210, 210, 0.82); "
                "border-radius: 6px; padding: 6px 8px;"
            )
        elif state == "no-session":
            frame_selector = f"QFrame#{frame.objectName()}"
            frame.setStyleSheet(
                f"{frame_selector} {{ border: 1px solid #666666; border-radius: 8px; padding: 8px; background-color: rgba(102, 102, 102, 0.09); }}"
            )
            status.setText("● No session")
            status.setStyleSheet(
                "color: #666666; font-weight: bold; border: 1px solid rgba(210, 210, 210, 0.82); "
                "border-radius: 6px; padding: 6px 8px;"
            )
        elif state == "disconnected":
            frame_selector = f"QFrame#{frame.objectName()}"
            frame.setStyleSheet(
                f"{frame_selector} {{ border: 1px solid #666666; border-radius: 8px; padding: 8px; background-color: rgba(102, 102, 102, 0.09); }}"
            )
            status.setText("● Disconnected")
            status.setStyleSheet(
                "color: #666666; font-weight: bold; border: 1px solid rgba(210, 210, 210, 0.82); "
                "border-radius: 6px; padding: 6px 8px;"
            )
        else:
            frame_selector = f"QFrame#{frame.objectName()}"
            frame.setStyleSheet(
                f"{frame_selector} {{ border: 1px solid #7a7a7a; border-radius: 8px; padding: 8px; background-color: rgba(122, 122, 122, 0.11); }}"
            )
            status.setText("● Unknown")
            status.setStyleSheet(
                "color: #666666; font-weight: bold; border: 1px solid rgba(210, 210, 210, 0.82); "
                "border-radius: 6px; padding: 6px 8px;"
            )
            btn_refresh_one.setVisible(True)
            btn_refresh_one.setEnabled(True)

    def refresh_pairing_keys_overview():
        for slot in range(PAIRING_KEY_MAX + 1):
            refresh_pairing_slot_card(slot)

    def create_pairing_status_tab():
        tab_layout = window.layoutPairingKeys
        while tab_layout.count():
            item = tab_layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.setParent(None)
        tab_layout.setContentsMargins(8, 8, 8, 8)
        tab_layout.setSpacing(8)
        tab_layout.setAlignment(QtCore.Qt.AlignmentFlag.AlignTop)

        top_row = QtWidgets.QHBoxLayout()
        top_row.setContentsMargins(0, 0, 0, 0)
        top_row.setSpacing(8)
        btn_refresh = QtWidgets.QPushButton("Refresh All")
        progress = QtWidgets.QProgressBar()
        progress.setMinimum(0)
        progress.setMaximum(PAIRING_KEY_MAX + 1)
        progress.setValue(0)
        progress.setTextVisible(False)
        progress.setFixedWidth(180)
        lbl_progress = QtWidgets.QLabel("Idle")
        top_row.addWidget(btn_refresh)
        top_row.addWidget(progress)
        top_row.addWidget(lbl_progress)
        top_row.addStretch(1)
        tab_layout.addLayout(top_row)

        overview_group = QtWidgets.QGroupBox("Slots Overview")
        overview_group.setContentsMargins(6, 6, 6, 6)
        overview_group.setSizePolicy(
            QtWidgets.QSizePolicy.Policy.Preferred,
            QtWidgets.QSizePolicy.Policy.Maximum
        )
        overview_layout = QtWidgets.QGridLayout(overview_group)
        overview_layout.setContentsMargins(12, 28, 12, 12)
        overview_layout.setHorizontalSpacing(12)
        overview_layout.setVerticalSpacing(12)

        for slot in range(PAIRING_KEY_MAX + 1):
            frame = QtWidgets.QFrame()
            frame.setObjectName(f"pairingSlotFrame{slot}")
            frame.setFrameShape(QtWidgets.QFrame.Shape.StyledPanel)
            frame.setStyleSheet("QFrame { border: 1px solid #bdbdbd; border-radius: 8px; padding: 8px; }")
            vbox = QtWidgets.QVBoxLayout(frame)

            title = QtWidgets.QLabel(f"Slot {slot}")
            title.setStyleSheet(
                "font-weight: bold; border: 1px solid rgba(210, 210, 210, 0.82); "
                "border-radius: 6px; padding: 6px 8px;"
            )
            status = QtWidgets.QLabel("● Unknown")
            status.setStyleSheet(
                "color: #666666; font-weight: bold; border: 1px solid rgba(210, 210, 210, 0.82); "
                "border-radius: 6px; padding: 6px 8px;"
            )

            action_row = QtWidgets.QHBoxLayout()
            btn_write = QtWidgets.QPushButton("Write")
            btn_show = QtWidgets.QPushButton("Show")
            btn_invalidate = QtWidgets.QPushButton("Invalidate")
            btn_refresh_one = QtWidgets.QPushButton("Refresh")
            action_row.addWidget(btn_write)
            action_row.addWidget(btn_show)
            action_row.addWidget(btn_invalidate)
            action_row.addWidget(btn_refresh_one)

            vbox.addWidget(title)
            vbox.addWidget(status)
            vbox.addLayout(action_row)

            row = slot // 2
            col = slot % 2
            overview_layout.addWidget(frame, row, col)

            pairing_slot_cards[slot] = {
                "frame": frame,
                "status": status,
                "btn_write": btn_write,
                "btn_show": btn_show,
                "btn_invalidate": btn_invalidate,
                "btn_refresh_one": btn_refresh_one,
            }
            pairing_slot_states.setdefault(slot, "unknown")

            btn_write.clicked.connect(lambda _=False, s=slot: on_btnPairingKeyWriteFromOverview_click(s))
            btn_show.clicked.connect(lambda _=False, s=slot: on_btnPairingKeyShowFromOverview_click(s))
            btn_invalidate.clicked.connect(lambda _=False, s=slot: on_btnPairingKeyInvalidate_click(s))
            btn_refresh_one.clicked.connect(lambda _=False, s=slot: on_btnPairingSlotRefresh_click(s))

        tab_layout.addWidget(overview_group)
        tab_layout.addStretch(1)

        window.btnPairingSlotsRefresh = btn_refresh
        window.pbPairingSlotsRefresh = progress
        window.lblPairingSlotsRefresh = lbl_progress

        btn_refresh.clicked.connect(on_btnPairingSlotsRefresh_click)
        refresh_pairing_keys_overview()

    def get_pairing_key_slot_for_overview(slot):
        slot = int(slot)
        if slot < 0 or slot > PAIRING_KEY_MAX:
            raise ValueError(f"Slot must be 0-{PAIRING_KEY_MAX}")
        return slot

    def on_btnPairingKeyShowFromOverview_click(slot):
        if not ts:
            QtWidgets.QMessageBox.warning(window, "Not Connected", "Please connect to device first")
            return
        try:
            slot = get_pairing_key_slot_for_overview(slot)
            key = ts.pairing_key_read(slot)
            pairing_slot_states[slot] = "full"
            pairing_slot_pubkey_prefix[slot] = format_pubkey_prefix(key)
            QtWidgets.QMessageBox.information(window, f"Pairing Key Slot {slot}", key.hex())
            refresh_pairing_slot_card(slot)
        except TropicSquarePairingKeyEmptyError:
            pairing_slot_states[slot] = "empty"
            pairing_slot_pubkey_prefix.pop(slot, None)
            QtWidgets.QMessageBox.information(window, "Pairing Key Read", f"Slot {slot} is empty.")
            refresh_pairing_slot_card(slot)
        except TropicSquarePairingKeyInvalidError:
            pairing_slot_states[slot] = "invalidated"
            pairing_slot_pubkey_prefix.pop(slot, None)
            QtWidgets.QMessageBox.information(window, "Pairing Key Read", f"Slot {slot} is invalidated.")
            refresh_pairing_slot_card(slot)
        except Exception as e:
            QtWidgets.QMessageBox.critical(window, "Pairing Key Read Failed", str(e))

    def on_btnPairingKeyWriteFromOverview_click(slot):
        initial = ""
        text, ok = QtWidgets.QInputDialog.getMultiLineText(
            window,
            f"Write Pairing Key Slot {slot}",
            "Public key (hex, 32 bytes):",
            initial,
        )
        if not ok:
            return
        slot = get_pairing_key_slot_for_overview(slot)
        try:
            key_hex = text.strip().replace(" ", "").replace("\n", "")
            if not key_hex:
                raise ValueError("Public key is empty")
            if len(key_hex) % 2 != 0:
                raise ValueError("Hex input must have even length")
            key = bytes.fromhex(key_hex)
            if len(key) != PAIRING_KEY_SIZE:
                raise ValueError(f"Public key must be {PAIRING_KEY_SIZE} bytes")
        except ValueError as e:
            QtWidgets.QMessageBox.warning(window, "Invalid Input", str(e))
            return
        confirm = QtWidgets.QMessageBox.warning(
            window,
            "Pairing Key Write",
            f"Are you sure?\n\nSlot {slot} is write-only and cannot be overwritten.\nContinue?",
            QtWidgets.QMessageBox.StandardButton.Yes | QtWidgets.QMessageBox.StandardButton.No
        )
        if confirm != QtWidgets.QMessageBox.StandardButton.Yes:
            return
        try:
            try:
                existing = ts.pairing_key_read(slot)
                pairing_slot_states[slot] = "full"
                pairing_slot_pubkey_prefix[slot] = format_pubkey_prefix(existing)
                refresh_pairing_slot_card(slot)
                QtWidgets.QMessageBox.critical(
                    window,
                    "Pairing Key Write Failed",
                    "Slot already contains a public key and cannot be overwritten."
                )
                return
            except TropicSquarePairingKeyEmptyError:
                pass
            ts.pairing_key_write(slot, key)
            pairing_slot_states[slot] = "full"
            pairing_slot_pubkey_prefix[slot] = format_pubkey_prefix(key)
            refresh_pairing_slot_card(slot)
            QtWidgets.QMessageBox.information(window, "Pairing Key Write", "Public key written successfully")
        except TropicSquareNoSession:
            QtWidgets.QMessageBox.warning(window, "No Session", "No secure session established")
        except TropicSquareCommandError as e:
            if "0x3c" in str(e).lower():
                QtWidgets.QMessageBox.critical(
                    window,
                    "Pairing Key Write Failed",
                    "Write failed (0x3C): slot is likely already programmed and not overwritable."
                )
            else:
                QtWidgets.QMessageBox.critical(window, "Pairing Key Write Failed", str(e))
        except Exception as e:
            QtWidgets.QMessageBox.critical(window, "Pairing Key Write Failed", str(e))

    def on_btnPairingSlotsRefresh_click():
        if not ts:
            QtWidgets.QMessageBox.warning(window, "Not Connected", "Please connect to device first")
            return
        if not has_secure_session():
            QtWidgets.QMessageBox.warning(window, "No Session", "No secure session established")
            return

        total = PAIRING_KEY_MAX + 1
        window.btnPairingSlotsRefresh.setEnabled(False)
        window.pbPairingSlotsRefresh.setRange(0, total)
        window.pbPairingSlotsRefresh.setValue(0)
        window.lblPairingSlotsRefresh.setText("Starting...")
        QtWidgets.QApplication.processEvents()

        try:
            for slot in range(total):
                window.lblPairingSlotsRefresh.setText(f"Reading slot {slot + 1}/{total}...")
                window.pbPairingSlotsRefresh.setValue(slot)
                QtWidgets.QApplication.processEvents()

                try:
                    key = ts.pairing_key_read(slot)
                    pairing_slot_states[slot] = "full"
                    pairing_slot_pubkey_prefix[slot] = format_pubkey_prefix(key)
                except TropicSquarePairingKeyEmptyError:
                    pairing_slot_states[slot] = "empty"
                    pairing_slot_pubkey_prefix.pop(slot, None)
                except TropicSquarePairingKeyInvalidError:
                    pairing_slot_states[slot] = "invalidated"
                    pairing_slot_pubkey_prefix.pop(slot, None)
                except Exception:
                    pairing_slot_states[slot] = "unknown"
                    pairing_slot_pubkey_prefix.pop(slot, None)
                refresh_pairing_slot_card(slot)

            window.pbPairingSlotsRefresh.setValue(total)
            window.lblPairingSlotsRefresh.setText("Done")
        finally:
            window.btnPairingSlotsRefresh.setEnabled(True)

    def on_btnPairingSlotRefresh_click(slot):
        if not ts:
            QtWidgets.QMessageBox.warning(window, "Not Connected", "Please connect to device first")
            return
        if not has_secure_session():
            QtWidgets.QMessageBox.warning(window, "No Session", "No secure session established")
            return

        slot = get_pairing_key_slot_for_overview(slot)
        window.lblPairingSlotsRefresh.setText(f"Reading slot {slot + 1}/{PAIRING_KEY_MAX + 1}...")
        QtWidgets.QApplication.processEvents()
        try:
            key = ts.pairing_key_read(slot)
            pairing_slot_states[slot] = "full"
            pairing_slot_pubkey_prefix[slot] = format_pubkey_prefix(key)
        except TropicSquarePairingKeyEmptyError:
            pairing_slot_states[slot] = "empty"
            pairing_slot_pubkey_prefix.pop(slot, None)
        except TropicSquarePairingKeyInvalidError:
            pairing_slot_states[slot] = "invalidated"
            pairing_slot_pubkey_prefix.pop(slot, None)
        except Exception:
            pairing_slot_states[slot] = "unknown"
            pairing_slot_pubkey_prefix.pop(slot, None)
        refresh_pairing_slot_card(slot)
        window.lblPairingSlotsRefresh.setText("Done")

    def on_btnPairingKeyInvalidate_click(slot):
        slot = get_pairing_key_slot_for_overview(slot)
        confirm = QtWidgets.QMessageBox.warning(
            window,
            "Pairing Key Invalidate",
            f"Invalidate slot {slot}?\n\nThis action is irreversible.",
            QtWidgets.QMessageBox.StandardButton.Yes | QtWidgets.QMessageBox.StandardButton.No
        )
        if confirm != QtWidgets.QMessageBox.StandardButton.Yes:
            return
        try:
            ts.pairing_key_invalidate(slot)
            pairing_slot_states[slot] = "invalidated"
            pairing_slot_pubkey_prefix.pop(slot, None)
            QtWidgets.QMessageBox.information(window, "Pairing Key Invalidate", f"Slot {slot} invalidated.")
            refresh_pairing_slot_card(slot)
        except TropicSquareNoSession:
            QtWidgets.QMessageBox.warning(window, "No Session", "No secure session established")
        except TropicSquarePairingKeyInvalidError:
            pairing_slot_states[slot] = "invalidated"
            pairing_slot_pubkey_prefix.pop(slot, None)
            QtWidgets.QMessageBox.information(window, "Pairing Key Invalidate", f"Slot {slot} is already invalidated.")
            refresh_pairing_slot_card(slot)
        except Exception as e:
            QtWidgets.QMessageBox.critical(window, "Pairing Key Invalidate Failed", str(e))

    def reset_mcounter_state():
        for idx in range(MCOUNTER_MAX + 1):
            mcounter_states[idx] = "unknown"
            mcounter_values.pop(idx, None)
        refresh_mcounter_overview()

    def refresh_mcounter_card(index: int):
        card = mcounter_cards.get(index)
        if not card:
            return
        frame = card["frame"]
        status = card["status"]
        btn_read = card["btn_read"]
        btn_init = card["btn_init"]
        btn_update = card["btn_update"]
        btn_refresh_one = card["btn_refresh_one"]

        if ts is None:
            state = "disconnected"
        elif not has_secure_session():
            state = "no-session"
        else:
            state = mcounter_states.get(index, "unknown")

        btn_read.setVisible(False)
        btn_init.setVisible(False)
        btn_update.setVisible(False)
        btn_refresh_one.setVisible(False)

        frame_selector = f"QFrame#{frame.objectName()}"
        if state == "value":
            frame.setStyleSheet(
                f"{frame_selector} {{ border: 1px solid #2e7d32; border-radius: 8px; padding: 8px; background-color: rgba(46, 125, 50, 0.13); }}"
            )
            value = mcounter_values.get(index, "?")
            status.setText(f"● Value: {value}")
            status.setStyleSheet(
                "color: #2e7d32; font-weight: bold; border: 1px solid rgba(210, 210, 210, 0.82); "
                "border-radius: 6px; padding: 6px 8px;"
            )
            btn_init.setVisible(True)
            btn_read.setVisible(True)
            btn_update.setVisible(True)
            btn_init.setEnabled(True)
            btn_read.setEnabled(True)
            btn_update.setEnabled(True)
        elif state == "zero":
            frame.setStyleSheet(
                f"{frame_selector} {{ border: 1px solid #b00020; border-radius: 8px; padding: 8px; background-color: rgba(176, 0, 32, 0.11); }}"
            )
            status.setText("● Depleted (0)")
            status.setStyleSheet(
                "color: #b00020; font-weight: bold; border: 1px solid rgba(210, 210, 210, 0.82); "
                "border-radius: 6px; padding: 6px 8px;"
            )
            btn_init.setVisible(True)
            btn_read.setVisible(True)
            btn_init.setEnabled(True)
            btn_read.setEnabled(True)
        elif state == "invalid":
            frame.setStyleSheet(
                f"{frame_selector} {{ border: 1px solid #c07a00; border-radius: 8px; padding: 8px; background-color: rgba(192, 122, 0, 0.11); }}"
            )
            status.setText("● Invalid")
            status.setStyleSheet(
                "color: #c07a00; font-weight: bold; border: 1px solid rgba(210, 210, 210, 0.82); "
                "border-radius: 6px; padding: 6px 8px;"
            )
            btn_init.setVisible(True)
            btn_init.setEnabled(True)
        elif state == "no-session":
            frame.setStyleSheet(
                f"{frame_selector} {{ border: 1px solid #666666; border-radius: 8px; padding: 8px; background-color: rgba(102, 102, 102, 0.09); }}"
            )
            status.setText("● No session")
            status.setStyleSheet(
                "color: #666666; font-weight: bold; border: 1px solid rgba(210, 210, 210, 0.82); "
                "border-radius: 6px; padding: 6px 8px;"
            )
        elif state == "disconnected":
            frame.setStyleSheet(
                f"{frame_selector} {{ border: 1px solid #666666; border-radius: 8px; padding: 8px; background-color: rgba(102, 102, 102, 0.09); }}"
            )
            status.setText("● Disconnected")
            status.setStyleSheet(
                "color: #666666; font-weight: bold; border: 1px solid rgba(210, 210, 210, 0.82); "
                "border-radius: 6px; padding: 6px 8px;"
            )
        else:
            frame.setStyleSheet(
                f"{frame_selector} {{ border: 1px solid #7a7a7a; border-radius: 8px; padding: 8px; background-color: rgba(122, 122, 122, 0.11); }}"
            )
            status.setText("● Unknown")
            status.setStyleSheet(
                "color: #666666; font-weight: bold; border: 1px solid rgba(210, 210, 210, 0.82); "
                "border-radius: 6px; padding: 6px 8px;"
            )
            btn_refresh_one.setVisible(True)
            btn_refresh_one.setEnabled(True)

    def refresh_mcounter_overview():
        for idx in range(MCOUNTER_MAX + 1):
            refresh_mcounter_card(idx)

    def read_mcounter_slot(index: int):
        value = ts.mcounter_get(index)
        mcounter_states[index] = "zero" if value == 0 else "value"
        mcounter_values[index] = value
        refresh_mcounter_card(index)
        return value

    def on_btnMCounterReadFromOverview_click(index):
        if not ts:
            QtWidgets.QMessageBox.warning(window, "Not Connected", "Please connect to device first")
            return
        if not has_secure_session():
            QtWidgets.QMessageBox.warning(window, "No Session", "No secure session established")
            return
        idx = int(index)
        try:
            value = read_mcounter_slot(idx)
            QtWidgets.QMessageBox.information(window, f"MCounter {idx}", f"Value: {value}")
        except TropicSquareCounterInvalidError:
            mcounter_states[idx] = "invalid"
            mcounter_values.pop(idx, None)
            refresh_mcounter_card(idx)
            QtWidgets.QMessageBox.information(window, "MCounter Read", f"Counter {idx} is invalid.")
        except Exception as e:
            QtWidgets.QMessageBox.critical(window, "MCounter Read Failed", str(e))

    def on_btnMCounterInitFromOverview_click(index):
        if not ts:
            QtWidgets.QMessageBox.warning(window, "Not Connected", "Please connect to device first")
            return
        if not has_secure_session():
            QtWidgets.QMessageBox.warning(window, "No Session", "No secure session established")
            return
        idx = int(index)
        text, ok = QtWidgets.QInputDialog.getText(
            window,
            f"Initialize MCounter {idx}",
            "Initial value (0..4294967295):",
            text="0"
        )
        if not ok:
            return
        value_text = text.strip()
        if not value_text:
            QtWidgets.QMessageBox.warning(window, "Invalid Input", "Initial value is required.")
            return
        try:
            value = int(value_text, 0)
        except ValueError:
            QtWidgets.QMessageBox.warning(window, "Invalid Input", "Invalid integer value.")
            return
        if value < 0 or value > 0xFFFFFFFF:
            QtWidgets.QMessageBox.warning(window, "Invalid Input", "Initial value must be 0..4294967295.")
            return
        try:
            ts.mcounter_init(idx, value)
            read_mcounter_slot(idx)
            QtWidgets.QMessageBox.information(window, "MCounter Init", f"Counter {idx} initialized to {value}.")
        except Exception as e:
            QtWidgets.QMessageBox.critical(window, "MCounter Init Failed", str(e))

    def on_btnMCounterUpdateFromOverview_click(index):
        if not ts:
            QtWidgets.QMessageBox.warning(window, "Not Connected", "Please connect to device first")
            return
        if not has_secure_session():
            QtWidgets.QMessageBox.warning(window, "No Session", "No secure session established")
            return
        idx = int(index)
        try:
            ts.mcounter_update(idx)
            value = read_mcounter_slot(idx)
            QtWidgets.QMessageBox.information(window, "MCounter Update", f"Counter {idx} updated to {value}.")
        except TropicSquareCounterInvalidError:
            mcounter_states[idx] = "invalid"
            mcounter_values.pop(idx, None)
            refresh_mcounter_card(idx)
            QtWidgets.QMessageBox.warning(window, "MCounter Update", f"Counter {idx} is invalid.")
        except Exception as e:
            QtWidgets.QMessageBox.critical(window, "MCounter Update Failed", str(e))

    def on_btnMCounterRefreshOne_click(index):
        if not ts:
            QtWidgets.QMessageBox.warning(window, "Not Connected", "Please connect to device first")
            return
        if not has_secure_session():
            QtWidgets.QMessageBox.warning(window, "No Session", "No secure session established")
            return
        idx = int(index)
        window.lblMCounterRefreshStatus.setText(f"Reading counter {idx + 1}/{MCOUNTER_MAX + 1}...")
        QtWidgets.QApplication.processEvents()
        try:
            read_mcounter_slot(idx)
        except TropicSquareCounterInvalidError:
            mcounter_states[idx] = "invalid"
            mcounter_values.pop(idx, None)
            refresh_mcounter_card(idx)
        except Exception:
            mcounter_states[idx] = "unknown"
            mcounter_values.pop(idx, None)
            refresh_mcounter_card(idx)
        window.lblMCounterRefreshStatus.setText("Done")

    def on_btnMCounterRefreshAll_click():
        if not ts:
            QtWidgets.QMessageBox.warning(window, "Not Connected", "Please connect to device first")
            return
        if not has_secure_session():
            QtWidgets.QMessageBox.warning(window, "No Session", "No secure session established")
            return

        total = MCOUNTER_MAX + 1
        window.btnMCounterRefreshAll.setEnabled(False)
        window.pbMCounterRefresh.setRange(0, total)
        window.pbMCounterRefresh.setValue(0)
        window.lblMCounterRefreshStatus.setText("Starting...")
        QtWidgets.QApplication.processEvents()

        try:
            for idx in range(total):
                window.lblMCounterRefreshStatus.setText(f"Reading counter {idx + 1}/{total}...")
                window.pbMCounterRefresh.setValue(idx)
                QtWidgets.QApplication.processEvents()
                try:
                    read_mcounter_slot(idx)
                except TropicSquareCounterInvalidError:
                    mcounter_states[idx] = "invalid"
                    mcounter_values.pop(idx, None)
                    refresh_mcounter_card(idx)
                except Exception:
                    mcounter_states[idx] = "unknown"
                    mcounter_values.pop(idx, None)
                    refresh_mcounter_card(idx)
            window.pbMCounterRefresh.setValue(total)
            window.lblMCounterRefreshStatus.setText("Done")
        finally:
            window.btnMCounterRefreshAll.setEnabled(True)

    def create_mcounter_status_tab():
        tab_layout = window.layoutMCounter
        while tab_layout.count():
            item = tab_layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.setParent(None)
        tab_layout.setContentsMargins(8, 8, 8, 8)
        tab_layout.setSpacing(8)
        tab_layout.setAlignment(QtCore.Qt.AlignmentFlag.AlignTop)

        top_row = QtWidgets.QHBoxLayout()
        top_row.setContentsMargins(0, 0, 0, 0)
        top_row.setSpacing(8)
        btn_refresh_all = QtWidgets.QPushButton("Refresh All")
        progress = QtWidgets.QProgressBar()
        progress.setMinimum(0)
        progress.setMaximum(MCOUNTER_MAX + 1)
        progress.setValue(0)
        progress.setTextVisible(False)
        progress.setFixedWidth(180)
        lbl_status = QtWidgets.QLabel("Idle")
        top_row.addWidget(btn_refresh_all)
        top_row.addWidget(progress)
        top_row.addWidget(lbl_status)
        top_row.addStretch(1)
        tab_layout.addLayout(top_row)

        overview_group = QtWidgets.QGroupBox("Counters Overview")
        overview_group.setContentsMargins(6, 6, 6, 6)
        overview_group.setSizePolicy(
            QtWidgets.QSizePolicy.Policy.Expanding,
            QtWidgets.QSizePolicy.Policy.Expanding
        )
        overview_layout = QtWidgets.QGridLayout(overview_group)
        overview_layout.setContentsMargins(12, 28, 12, 12)
        overview_layout.setHorizontalSpacing(12)
        overview_layout.setVerticalSpacing(12)

        cols = 3
        for idx in range(MCOUNTER_MAX + 1):
            frame = QtWidgets.QFrame()
            frame.setObjectName(f"mcounterFrame{idx}")
            frame.setFrameShape(QtWidgets.QFrame.Shape.StyledPanel)
            frame.setStyleSheet("QFrame { border: 1px solid #bdbdbd; border-radius: 8px; padding: 8px; }")
            frame.setMinimumWidth(180)
            frame.setFixedHeight(120)
            frame.setSizePolicy(
                QtWidgets.QSizePolicy.Policy.Preferred,
                QtWidgets.QSizePolicy.Policy.Fixed
            )
            vbox = QtWidgets.QVBoxLayout(frame)
            vbox.setContentsMargins(6, 6, 6, 6)
            vbox.setSpacing(4)

            title = QtWidgets.QLabel(f"Counter {idx}")
            title.setStyleSheet(
                "font-weight: bold; border: 1px solid rgba(210, 210, 210, 0.82); border-radius: 6px; padding: 6px 8px;"
            )
            title.setMinimumHeight(20)
            status = QtWidgets.QLabel("● Unknown")
            status.setStyleSheet(
                "color: #666666; font-weight: bold; border: 1px solid rgba(210, 210, 210, 0.82); border-radius: 6px; padding: 6px 8px;"
            )
            status.setMinimumHeight(20)

            action_row = QtWidgets.QGridLayout()
            action_row.setHorizontalSpacing(4)
            action_row.setVerticalSpacing(4)
            btn_read = QtWidgets.QPushButton("Read")
            btn_init = QtWidgets.QPushButton("Init")
            btn_update = QtWidgets.QPushButton("Decrement")
            btn_refresh_one = QtWidgets.QPushButton("Refresh")
            for btn in (btn_read, btn_init, btn_update, btn_refresh_one):
                btn.setSizePolicy(
                    QtWidgets.QSizePolicy.Policy.Expanding,
                    QtWidgets.QSizePolicy.Policy.Fixed
                )
                btn.setMinimumWidth(0)
            action_row.addWidget(btn_read, 0, 0)
            action_row.addWidget(btn_init, 0, 1)
            action_row.addWidget(btn_update, 0, 2)
            action_row.addWidget(btn_refresh_one, 1, 0, 1, 3)
            action_row.setColumnStretch(0, 1)
            action_row.setColumnStretch(1, 1)
            action_row.setColumnStretch(2, 1)

            vbox.addWidget(title)
            vbox.addWidget(status)
            vbox.addLayout(action_row)

            row = idx // cols
            col = idx % cols
            overview_layout.addWidget(frame, row, col)

            mcounter_cards[idx] = {
                "frame": frame,
                "status": status,
                "btn_read": btn_read,
                "btn_init": btn_init,
                "btn_update": btn_update,
                "btn_refresh_one": btn_refresh_one,
            }
            mcounter_states.setdefault(idx, "unknown")

            btn_read.clicked.connect(lambda _=False, i=idx: on_btnMCounterReadFromOverview_click(i))
            btn_init.clicked.connect(lambda _=False, i=idx: on_btnMCounterInitFromOverview_click(i))
            btn_update.clicked.connect(lambda _=False, i=idx: on_btnMCounterUpdateFromOverview_click(i))
            btn_refresh_one.clicked.connect(lambda _=False, i=idx: on_btnMCounterRefreshOne_click(i))

        scroll = QtWidgets.QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QtWidgets.QFrame.Shape.NoFrame)
        scroll_content = QtWidgets.QWidget()
        scroll_content_layout = QtWidgets.QVBoxLayout(scroll_content)
        scroll_content_layout.setContentsMargins(0, 0, 0, 0)
        scroll_content_layout.setSpacing(0)
        scroll_content_layout.addWidget(overview_group)
        scroll.setWidget(scroll_content)

        tab_layout.addWidget(scroll)

        window.btnMCounterRefreshAll = btn_refresh_all
        window.pbMCounterRefresh = progress
        window.lblMCounterRefreshStatus = lbl_status
        btn_refresh_all.clicked.connect(on_btnMCounterRefreshAll_click)
        refresh_mcounter_overview()


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

    # Connect device operation signals
    window.btnGetInfo.clicked.connect(on_btn_get_info_click)
    window.btnSaveCert.clicked.connect(on_btn_save_cert_click)
    window.btnPing.clicked.connect(on_btnPing_click)
    window.btnGetRandom.clicked.connect(on_btnbtnGetRandom_click)
    window.btnMaintenanceStartupReboot.clicked.connect(on_btnMaintenanceStartupReboot_click)
    window.btnMaintenanceStartupBootloader.clicked.connect(on_btnMaintenanceStartupBootloader_click)
    window.btnMaintenanceSleep.clicked.connect(on_btnMaintenanceSleep_click)
    window.btnMaintenanceDeepSleep.clicked.connect(on_btnMaintenanceDeepSleep_click)
    window.btnMaintenanceGetLogs.clicked.connect(on_btnMaintenanceGetLogs_click)
    window.leRandomBytesNum.setValidator(QtGui.QIntValidator(0, 255))
    window.splitterChipIdTop.setStretchFactor(0, 1)
    window.splitterChipIdTop.setStretchFactor(1, 1)

    for slot in range(ECC_MAX_KEYS + 1):
        ecc_slot_states[slot] = "unknown"
    create_ecc_overview()
    window.btnMemRead.clicked.connect(on_btnMemRead_click)
    window.btnMemWrite.clicked.connect(on_btnMemWrite_click)
    window.btnMemErase.clicked.connect(on_btnMemErase_click)
    window.rbMemHex.setChecked(True)
    window.leMemSlot.setValidator(QtGui.QIntValidator(0, 511))
    for idx in range(MCOUNTER_MAX + 1):
        mcounter_states[idx] = "unknown"
    create_mcounter_status_tab()
    for slot in range(PAIRING_KEY_MAX + 1):
        pairing_slot_states[slot] = "unknown"
    create_pairing_status_tab()

    cfg_items = get_cfg_constants()
    window._cfg_items = cfg_items
    for name, value in cfg_items:
        window.cmbRConfigReg.addItem(f"{name} (0x{value:02X})", value)
        window.cmbIConfigReg.addItem(f"{name} (0x{value:02X})", value)
    window._rconfig_bulk_name_by_addr = {value: name for name, value in cfg_items}
    window._rconfig_bulk_row_by_addr = {}
    window._rconfig_bulk_snapshot = {}
    window._rconfig_bulk_current = {}
    window._rconfig_bulk_selected_address = None
    window._rconfig_bulk_fields = []
    window.layoutRConfigBulk.setContentsMargins(0, 0, 0, 0)
    window.layoutRConfigBulk.setSpacing(6)
    window.layoutRConfigBulkTop.setContentsMargins(0, 0, 0, 0)
    window.layoutRConfigBulkTop.setSpacing(8)
    window.layoutRConfigBulkLeft.setContentsMargins(0, 0, 0, 0)
    window.layoutRConfigBulkLeft.setSpacing(8)
    window.layoutRConfigBulkRight.setContentsMargins(0, 0, 0, 0)
    window.layoutRConfigBulkRight.setSpacing(8)
    window.layoutRConfigBulkDetails.setContentsMargins(0, 0, 0, 0)
    window.layoutRConfigBulkDetails.setSpacing(0)
    window.layoutRConfigBulkDetails.setAlignment(QtCore.Qt.AlignmentFlag.AlignTop)
    window.layoutRConfigBulk.setStretch(0, 0)
    window.layoutRConfigBulk.setStretch(1, 1)
    window.pbRConfigBulkProgress.setMinimum(0)
    window.pbRConfigBulkProgress.setMaximum(len(cfg_items) if cfg_items else 1)
    window.pbRConfigBulkProgress.setValue(0)
    window.pbRConfigBulkProgress.setTextVisible(False)
    window.pbRConfigBulkProgress.setFixedWidth(180)
    window.lblRConfigBulkProgress.setText("Idle")
    window.tblRConfigBulk.setRowCount(len(cfg_items))
    window.tblRConfigBulk.setColumnCount(5)
    window.tblRConfigBulk.setHorizontalHeaderLabels(["Reg", "Addr", "Raw", "Type", "State"])
    for row, (name, value) in enumerate(cfg_items):
        name_item = QtWidgets.QTableWidgetItem(name)
        addr_item = QtWidgets.QTableWidgetItem(f"0x{value:02X}")
        raw_item = QtWidgets.QTableWidgetItem("-")
        type_item = QtWidgets.QTableWidgetItem("-")
        state_item = QtWidgets.QTableWidgetItem("no data")
        addr_item.setData(QtCore.Qt.ItemDataRole.UserRole, value)
        for item in (name_item, addr_item, raw_item, type_item, state_item):
            item.setFlags(item.flags() & ~QtCore.Qt.ItemFlag.ItemIsEditable)
        window.tblRConfigBulk.setItem(row, 0, name_item)
        window.tblRConfigBulk.setItem(row, 1, addr_item)
        window.tblRConfigBulk.setItem(row, 2, raw_item)
        window.tblRConfigBulk.setItem(row, 3, type_item)
        window.tblRConfigBulk.setItem(row, 4, state_item)
        window._rconfig_bulk_row_by_addr[value] = row
    window.tblRConfigBulk.horizontalHeader().setSectionResizeMode(0, QtWidgets.QHeaderView.ResizeMode.Stretch)
    window.tblRConfigBulk.horizontalHeader().setSectionResizeMode(1, QtWidgets.QHeaderView.ResizeMode.ResizeToContents)
    window.tblRConfigBulk.horizontalHeader().setSectionResizeMode(2, QtWidgets.QHeaderView.ResizeMode.ResizeToContents)
    window.tblRConfigBulk.horizontalHeader().setSectionResizeMode(3, QtWidgets.QHeaderView.ResizeMode.ResizeToContents)
    window.tblRConfigBulk.horizontalHeader().setSectionResizeMode(4, QtWidgets.QHeaderView.ResizeMode.ResizeToContents)
    window.tblRConfigBulk.verticalHeader().setVisible(False)
    window.btnRConfigRead.clicked.connect(on_btnRConfigRead_click)
    window.btnIConfigRead.clicked.connect(on_btnIConfigRead_click)
    window.btnRConfigWrite.clicked.connect(on_btnRConfigWrite_click)
    window.btnRConfigErase.clicked.connect(on_btnRConfigErase_click)
    window.btnIConfigWrite.clicked.connect(on_btnIConfigWrite_click)
    window.btnRConfigBulkReadAll.clicked.connect(on_btnRConfigBulkReadAll_click)
    window.btnRConfigBulkDiscard.clicked.connect(on_btnRConfigBulkDiscard_click)
    window.btnRConfigBulkApply.clicked.connect(on_btnRConfigBulkApply_click)
    window.tblRConfigBulk.itemSelectionChanged.connect(on_tblRConfigBulk_selection_changed)

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
