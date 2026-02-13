from tropicsquare.constants.ecc import ECC_CURVE_ED25519, ECC_CURVE_P256
from tropicsquare.constants import MCOUNTER_MAX, MEM_DATA_MAX_SIZE
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


# Default factory pairing keys
pkey_index_0 = 0x00 # Slot 0
# Sample keys batch 1 (rev 0)
#sh0priv = [0xd0,0x99,0x92,0xb1,0xf1,0x7a,0xbc,0x4d,0xb9,0x37,0x17,0x68,0xa2,0x7d,0xa0,0x5b,0x18,0xfa,0xb8,0x56,0x13,0xa7,0x84,0x2c,0xa6,0x4c,0x79,0x10,0xf2,0x2e,0x71,0x6b]
#sh0pub  = [0xe7,0xf7,0x35,0xba,0x19,0xa3,0x3f,0xd6,0x73,0x23,0xab,0x37,0x26,0x2d,0xe5,0x36,0x08,0xca,0x57,0x85,0x76,0x53,0x43,0x52,0xe1,0x8f,0x64,0xe6,0x13,0xd3,0x8d,0x54]

# Sample keys batch 2 (rev 1)
sh0priv = [0x28,0x3F,0x5A,0x0F,0xFC,0x41,0xCF,0x50,0x98,0xA8,0xE1,0x7D,0xB6,0x37,0x2C,0x3C,0xAA,0xD1,0xEE,0xEE,0xDF,0x0F,0x75,0xBC,0x3F,0xBF,0xCD,0x9C,0xAB,0x3D,0xE9,0x72]
sh0pub =  [0xF9,0x75,0xEB,0x3C,0x2F,0xD7,0x90,0xC9,0x6F,0x29,0x4F,0x15,0x57,0xA5,0x03,0x17,0x80,0xC9,0xAA,0xFA,0x14,0x0D,0xA2,0x8F,0x55,0xE7,0x51,0x57,0x37,0xB2,0x50,0x2C]


import sys
from PyQt6.QtCore import QSettings
from PyQt6 import QtWidgets, uic, QtGui


def main():
    # Application starts without device connection
    ts = None
    transport = None
    settings = QSettings("tropic01manager", "tropic01manager")
    settings_initialized = False

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
            window.lblSessionStatus.setText("Session Active")
            window.lblSessionStatus.setStyleSheet("color: green; font-weight: bold;")
        else:
            window.lblSessionStatus.setText("No Session")
            window.lblSessionStatus.setStyleSheet("color: gray; font-weight: bold;")

        # Enable/disable device operation buttons based on connection
        window.btnGetInfo.setEnabled(connected)
        window.btnSaveCert.setEnabled(connected)
        window.btnGetChipID.setEnabled(connected)
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

            # Validate device with timeout
            validation_result = {"success": False, "error": None}

            def validate_device():
                try:
                    _ = ts.riscv_fw_version
                    validation_result["success"] = True
                except Exception as e:
                    validation_result["error"] = str(e)

            validation_thread = threading.Thread(target=validate_device, daemon=True)
            validation_thread.start()
            validation_thread.join(timeout=3.0)

            if validation_thread.is_alive():
                raise ConnectionError(
                    "Device validation timeout - device not responding or wrong device type"
                )

            if not validation_result["success"]:
                error_msg = validation_result["error"] or "Unknown error"
                raise ConnectionError(
                    f"Device validation failed - not a TROPIC01: {error_msg}"
                )

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
        nonlocal ts
        try:
            if ts and hasattr(ts, "_secure_session") and ts._secure_session:
                try:
                    ts.abort_secure_session()
                except Exception:
                    pass
            ts = None
            close_transport()
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


    def on_btnGetChipID_click():
        """Get and display chip ID information"""
        if not ts:
            QtWidgets.QMessageBox.warning(window, "Not Connected", "Please connect to device first")
            return

        try:
            # Get parsed chip ID (chipid is a property, not a method)
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
        if not ts:
            QtWidgets.QMessageBox.warning(window, "Not Connected", "Please connect to device first")
            return

        try:
            window.lblSessionStatus.setText("Starting...")
            window.lblSessionStatus.setStyleSheet("color: orange; font-weight: bold;")
            window.btnSessionToggle.setEnabled(False)
            QtWidgets.QApplication.processEvents()

            if ts.start_secure_session(0, bytes(sh0priv), bytes(sh0pub)):
                update_connection_ui()  # Update UI to show active session
        except TropicSquareHandshakeError as e:
            QtWidgets.QMessageBox.critical(window, "Handshake Error", f"Failed to start secure session:\n{str(e)}")
            update_connection_ui()
        except TropicSquareError as e:
            QtWidgets.QMessageBox.critical(window, "Error", f"Failed to start secure session:\n{str(e)}")
            update_connection_ui()
        except Exception as e:
            QtWidgets.QMessageBox.critical(window, "Unexpected Error", f"Failed to start secure session:\n{str(e)}")
            update_connection_ui()


    def on_btnAbortSecureSession_click():
        if not ts:
            QtWidgets.QMessageBox.warning(window, "Not Connected", "Please connect to device first")
            return

        try:
            window.lblSessionStatus.setText("Aborting...")
            window.lblSessionStatus.setStyleSheet("color: orange; font-weight: bold;")
            window.btnSessionToggle.setEnabled(False)
            QtWidgets.QApplication.processEvents()

            if ts.abort_secure_session():
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


    app = QtWidgets.QApplication(sys.argv)
    window = uic.loadUi("mainwindow.ui")

    # Connect connection management signals
    window.cmbDriverType.currentTextChanged.connect(on_driver_type_changed)
    window.btnConnectToggle.clicked.connect(on_btnConnectToggle_click)
    window.btnSessionToggle.clicked.connect(on_btnSessionToggle_click)
    window.btnToggleConnectionSettings.clicked.connect(on_toggle_connection_settings)
    window.leParam1.textChanged.connect(save_connection_params)
    window.leParam2.textChanged.connect(save_connection_params)

    # Connect device operation signals
    window.btnGetInfo.clicked.connect(on_btn_get_info_click)
    window.btnSaveCert.clicked.connect(on_btn_save_cert_click)
    window.btnGetChipID.clicked.connect(on_btnGetChipID_click)
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
