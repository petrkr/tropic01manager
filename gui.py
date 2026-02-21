from tropicsquare.constants.ecc import ECC_CURVE_ED25519, ECC_CURVE_P256
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
        window.btnECCRead.setEnabled(connected)
        window.btnECCGenerate.setEnabled(connected)
        window.btnECCStore.setEnabled(connected)
        window.btnECCErase.setEnabled(connected)
        window.leECCPrivateKey.setEnabled(connected)
        window.btnMCounterGet.setEnabled(connected)
        window.btnMCounterInit.setEnabled(connected)
        window.btnMCounterUpdate.setEnabled(connected)
        window.leMCounterIndex.setEnabled(connected)
        window.leMCounterInitValue.setEnabled(connected)
        window.btnMemRead.setEnabled(connected)
        window.btnMemWrite.setEnabled(connected)
        window.btnMemErase.setEnabled(connected)
        window.leMemSlot.setEnabled(connected)
        window.pteMemInput.setEnabled(connected)
        window.rbMemHex.setEnabled(connected)
        window.rbMemText.setEnabled(connected)
        try:
            refresh_pairing_keys_overview()
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


    def get_ecc_slot():
        slot_text = window.leECCSlot.text().strip()
        if not slot_text:
            raise ValueError("Slot number is required")
        slot = int(slot_text)
        if slot < 0 or slot > 31:
            raise ValueError("Slot must be 0-31")
        return slot

    def on_btnECCRead_click():
        if not ts:
            QtWidgets.QMessageBox.warning(window, "Not Connected", "Please connect to device first")
            return

        try:
            slot = get_ecc_slot()


            window.rbECCP256.setChecked(False)
            window.rbECCEd25519.setChecked(False)

            key_info = ts.ecc_key_read(slot)

            if key_info.origin == 0x01:
                window.lblECCKeySource.setText("Generated")
            elif key_info.origin == 0x02:
                window.lblECCKeySource.setText("User stored")
            else:
                window.lblECCKeySource.setText("Unknown")

            if key_info.curve == ECC_CURVE_P256:
                window.rbECCP256.setChecked(True)
                window.rbECCEd25519.setChecked(False)
                window.lblECCCurveInfo.setText("P256")
            elif key_info.curve == ECC_CURVE_ED25519:
                window.rbECCP256.setChecked(False)
                window.rbECCEd25519.setChecked(True)
                window.lblECCCurveInfo.setText("Ed25519")
            else:
                window.lblECCCurveInfo.setText(f"Unknown (0x{key_info.curve:02X})")

            window.pteECCPubkey.setPlainText(key_info.public_key.hex())

        except TropicSquareNoSession:
            QtWidgets.QMessageBox.warning(window, "No Session", "No secure session established")
        except ValueError as e:
            QtWidgets.QMessageBox.warning(window, "Invalid Slot", str(e))
        except Exception as e:
            QtWidgets.QMessageBox.critical(window, "ECC Read Failed", str(e))

    def get_ecc_curve():
        if window.rbECCP256.isChecked():
            return ECC_CURVE_P256
        if window.rbECCEd25519.isChecked():
            return ECC_CURVE_ED25519
        return None

    def on_btnECCGenerate_click():
        if not ts:
            QtWidgets.QMessageBox.warning(window, "Not Connected", "Please connect to device first")
            return

        try:
            slot = get_ecc_slot()
            curve = get_ecc_curve()
            if curve is None:
                raise ValueError("Select curve")
            try:
                ts.ecc_key_read(slot)
                QtWidgets.QMessageBox.critical(window, "ECC Generate Failed", "Slot already contains a key")
                return
            except TropicSquareError:
                pass
            ts.ecc_key_generate(slot, curve)
            on_btnECCRead_click()
            QtWidgets.QMessageBox.information(window, "ECC Generate", "Key generated successfully")
        except TropicSquareNoSession:
            QtWidgets.QMessageBox.warning(window, "No Session", "No secure session established")
        except ValueError as e:
            QtWidgets.QMessageBox.warning(window, "Invalid Slot", str(e))
        except Exception as e:
            QtWidgets.QMessageBox.critical(window, "ECC Generate Failed", str(e))

    def on_btnECCStore_click():
        if not ts:
            QtWidgets.QMessageBox.warning(window, "Not Connected", "Please connect to device first")
            return

        try:
            slot = get_ecc_slot()
            curve = get_ecc_curve()
            if curve is None:
                raise ValueError("Select curve")

            key_hex = window.leECCPrivateKey.text().strip()
            key_hex = key_hex.replace(" ", "").replace("\n", "")
            if not key_hex:
                raise ValueError("Private key is empty")

            key_bytes = bytes.fromhex(key_hex)
            if len(key_bytes) != 32:
                raise ValueError("Private key must be 32 bytes")

            try:
                ts.ecc_key_read(slot)
                QtWidgets.QMessageBox.critical(window, "ECC Store Failed", "Slot already contains a key")
                return
            except TropicSquareError:
                pass

            ts.ecc_key_store(slot, curve, key_bytes)
            on_btnECCRead_click()
            QtWidgets.QMessageBox.information(window, "ECC Store", "Key stored successfully")
        except TropicSquareNoSession:
            QtWidgets.QMessageBox.warning(window, "No Session", "No secure session established")
        except ValueError as e:
            QtWidgets.QMessageBox.warning(window, "Invalid Slot", str(e))
        except Exception as e:
            QtWidgets.QMessageBox.critical(window, "ECC Store Failed", str(e))

    def on_btnECCErase_click():
        if not ts:
            QtWidgets.QMessageBox.warning(window, "Not Connected", "Please connect to device first")
            return

        try:
            slot = get_ecc_slot()
            try:
                ts.ecc_key_read(slot)
            except TropicSquareError as e:
                QtWidgets.QMessageBox.critical(window, "ECC Erase Failed", f"Key not found: {e}")
                return

            ts.ecc_key_erase(slot)
            window.lblECCKeySource.setText("")
            window.lblECCCurveInfo.setText("")
            window.pteECCPubkey.setPlainText("")
            QtWidgets.QMessageBox.information(window, "ECC Erase", "Key erased successfully")
        except TropicSquareNoSession:
            QtWidgets.QMessageBox.warning(window, "No Session", "No secure session established")
        except ValueError as e:
            QtWidgets.QMessageBox.warning(window, "Invalid Slot", str(e))
        except Exception as e:
            QtWidgets.QMessageBox.critical(window, "ECC Erase Failed", str(e))

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

    def add_permission_row(grid, row, label_text, field, editable=False):
        label = QtWidgets.QLabel(label_text)
        grid.addWidget(label, row, 0)
        checkboxes = []
        for i in range(4):
            cb = QtWidgets.QCheckBox(f"P{i}")
            cb.setChecked(field.get_slot_permission(i))
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
        if isinstance(config, UapMultiSlotConfig):
            for key in config.to_dict().keys():
                label = key.replace("_", " ")
                field = getattr(config, key)
                checkboxes = add_permission_row(grid, row, label, field, editable=editable)
                fields.append((key, checkboxes))
                row += 1
        elif isinstance(config, UapDualFieldConfig):
            cfg_field = config.cfg_permissions
            func_field = config.func_permissions
            fields.append(("cfg_permissions", add_permission_row(grid, row, "cfg", cfg_field, editable=editable)))
            row += 1
            fields.append(("func_permissions", add_permission_row(grid, row, "func", func_field, editable=editable)))
        elif isinstance(config, UapSingleFieldConfig):
            fields.append(("permissions", add_permission_row(grid, row, "permissions", config.permissions, editable=editable)))
        wrapper.addLayout(grid)
        wrapper.addStretch(1)

        parent_layout.addLayout(wrapper)
        return fields

    def render_key_values(parent_layout, data):
        form = QtWidgets.QFormLayout()
        for key, value in data.items():
            form.addRow(QtWidgets.QLabel(str(key)), QtWidgets.QLabel(str(value)))
        parent_layout.addLayout(form)

    def render_config_details(layout, config, editable=False):
        clear_layout(layout)
        if isinstance(config, (UapMultiSlotConfig, UapDualFieldConfig, UapSingleFieldConfig)):
            return render_uap_permissions(layout, config, editable=editable)
        try:
            data = config.to_dict()
        except Exception:
            data = {"value": str(config)}
        render_key_values(layout, data)
        return []

    def build_uap_config_from_ui(config, fields):
        new_config = config.__class__(config._value)
        for key, checkboxes in fields:
            field = getattr(new_config, key)
            for i, cb in enumerate(checkboxes):
                field.set_slot_permission(i, cb.isChecked())
            setattr(new_config, key, field)
        return new_config

    def get_cfg_constants():
        items = []
        for name, value in cfg_constants.__dict__.items():
            if name.startswith("CFG_") and isinstance(value, int):
                items.append((name, value))
        return sorted(items, key=lambda x: x[1])

    def on_btnRConfigRead_click():
        if not ts:
            QtWidgets.QMessageBox.warning(window, "Not Connected", "Please connect to device first")
            return
        try:
            address = window.cmbRConfigReg.currentData()
            config = ts.r_config_read(address)
            window.lblRConfigRaw.setText(f"0x{config._value:08X}")
            window._rconfig_current = config
            window._rconfig_fields = render_config_details(window.layoutRConfigDetails, config, editable=True)
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
            window.lblIConfigRaw.setText(f"0x{config._value:08X}")
            window._iconfig_current = config
            window._iconfig_fields = render_config_details(window.layoutIConfigDetails, config, editable=True)
        except TropicSquareNoSession:
            QtWidgets.QMessageBox.warning(window, "No Session", "No secure session established")
        except Exception as e:
            QtWidgets.QMessageBox.critical(window, "I-Config Read Failed", str(e))

    def on_btnRConfigWrite_click():
        config = getattr(window, "_rconfig_current", None)
        fields = getattr(window, "_rconfig_fields", [])
        if config is None:
            QtWidgets.QMessageBox.warning(window, "R-Config Write", "Read config first")
            return
        if not fields:
            QtWidgets.QMessageBox.warning(window, "R-Config Write", "Write not supported for this config")
            return
        new_config = build_uap_config_from_ui(config, fields)
        QtWidgets.QMessageBox.information(
            window,
            "R-Config Write (Mock)",
            f"Planned value: 0x{new_config._value:08X}\n(Not written)"
        )

    def on_btnIConfigWrite_click():
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
        new_config = build_uap_config_from_ui(config, fields)
        QtWidgets.QMessageBox.information(
            window,
            "I-Config Write (Mock)",
            f"Planned value: 0x{new_config._value:08X}\n(Not written)"
        )

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
        tab = QtWidgets.QWidget()
        tab_layout = QtWidgets.QVBoxLayout(tab)
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

        window.tabWidget.addTab(tab, "Pairing Keys")

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
    window.leRandomBytesNum.setValidator(QtGui.QIntValidator(0, 255))

    window.btnECCRead.clicked.connect(on_btnECCRead_click)
    window.btnECCGenerate.clicked.connect(on_btnECCGenerate_click)
    window.btnECCStore.clicked.connect(on_btnECCStore_click)
    window.btnECCErase.clicked.connect(on_btnECCErase_click)
    window.leECCSlot.setValidator(QtGui.QIntValidator(0, 31))
    window.leMCounterIndex.setValidator(QtGui.QIntValidator(0, MCOUNTER_MAX))

    window.btnMCounterGet.clicked.connect(on_btnMCounterGet_click)
    window.btnMCounterInit.clicked.connect(on_btnMCounterInit_click)
    window.btnMCounterUpdate.clicked.connect(on_btnMCounterUpdate_click)
    window.btnMemRead.clicked.connect(on_btnMemRead_click)
    window.btnMemWrite.clicked.connect(on_btnMemWrite_click)
    window.btnMemErase.clicked.connect(on_btnMemErase_click)
    window.rbMemHex.setChecked(True)
    window.leMemSlot.setValidator(QtGui.QIntValidator(0, 511))
    for slot in range(PAIRING_KEY_MAX + 1):
        pairing_slot_states[slot] = "unknown"
    create_pairing_status_tab()

    cfg_items = get_cfg_constants()
    for name, value in cfg_items:
        window.cmbRConfigReg.addItem(f"{name} (0x{value:02X})", value)
        window.cmbIConfigReg.addItem(f"{name} (0x{value:02X})", value)
    window.btnRConfigRead.clicked.connect(on_btnRConfigRead_click)
    window.btnIConfigRead.clicked.connect(on_btnIConfigRead_click)
    window.btnRConfigWrite.clicked.connect(on_btnRConfigWrite_click)
    window.btnIConfigWrite.clicked.connect(on_btnIConfigWrite_click)

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
