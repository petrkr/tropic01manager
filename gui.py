from tropicsquare.constants import ECC_CURVE_ED25519, ECC_CURVE_P256
from tropicsquare.ports.cpython import TropicSquareCPython
from tropicsquare.exceptions import *

from networkspi import NetworkSPI, DummyNetworkSpiCSPin

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from datetime import datetime


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
from PyQt6 import QtWidgets, uic, QtGui


def main():
    host = sys.argv[1]
    port = int(sys.argv[2])

    # L1 layer
    spi = NetworkSPI(host, port)
    cs = DummyNetworkSpiCSPin(spi)

    ts = TropicSquareCPython(spi, cs)

    # Injecting the certificate
    # NOTE: Disabled - this breaks handshake by overwriting the chip's real certificate
    #with open("tropic.crt", "rb") as f:
    #    ts._certificate = f.read()


    def on_btn_get_info_click():
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
        filename, fileformat = QtWidgets.QFileDialog.getSaveFileName(window, "Save certificate", "", "PEM Certificate files (*.pem *.crt);;DER Certificate files (*.der);;All files (*)")
        if not filename:
            return

        with open(filename, "wb") as f:
            if fileformat == "PEM Certificate files (*.pem *.crt)":
                cert = x509.load_der_x509_certificate(bytes(ts.certificate), default_backend())
                f.write(cert.public_bytes(encoding=serialization.Encoding.PEM))
            else:
                f.write(bytes(ts.certificate))


    def on_btnStartSecureSession_click():
        try:
            if ts.start_secure_session(0, bytes(sh0priv), bytes(sh0pub)):
                window.btnAbortSecureSession.setEnabled(True)
                window.btnStartSecureSession.setEnabled(False)
        except TropicSquareHandshakeError as e:
            QtWidgets.QMessageBox.critical(window, "Handshake Error", f"Failed to start secure session:\n{str(e)}")
        except TropicSquareError as e:
            QtWidgets.QMessageBox.critical(window, "Error", f"Failed to start secure session:\n{str(e)}")
        except Exception as e:
            QtWidgets.QMessageBox.critical(window, "Unexpected Error", f"Failed to start secure session:\n{str(e)}")


    def on_btnAbortSecureSession_click():
        if ts.abort_secure_session():
            window.btnAbortSecureSession.setEnabled(False)
            window.btnStartSecureSession.setEnabled(True)
    

    def on_btnPing_click():
        ping = window.ptePingInput.toPlainText().encode("utf-8")
        try:
            window.ptePingResult.setPlainText(ts.ping(ping).decode("utf-8"))
        except TropicSquareNoSession as e:
            window.ptePingResult.setPlainText("No secure session established")
        except TropicSquareError as e:
            window.ptePingResult.setPlainText("Error: " + str(e))


    def on_btnbtnGetRandom_click():
        try:
            number = int(window.leRandomBytesNum.text())
            if number > 255:
                raise ValueError("Number must be less than 256")
            window.pteRandomBytes.setPlainText(ts.get_random(number).hex())
        except TropicSquareNoSession as e:
            window.pteRandomBytes.setPlainText("No secure session established")
        except TropicSquareError as e:
            window.pteRandomBytes.setPlainText("Error: " + str(e))
        except ValueError as e:
            window.pteRandomBytes.setPlainText("Error: " + str(e))
        except Exception as e:
            window.pteRandomBytes.setPlainText("Error: " + str(e))


    def on_btnECCRead_click():
        try:
            slot = int(window.leECCSlot.text())
            if slot > 31:
                raise ValueError("Number must be less than 256")


            window.rbECCP256.setChecked(False)
            window.rbECCEd25519.setChecked(False)

            curve, origin, pubkey = ts.ecc_key_read(slot)

            if origin == 0x01:
                window.lblECCKeySource.setText("Generated")
            elif origin == 0x02:
                window.lblECCKeySource.setText("User stored")
            else:
                window.lblECCKeySource.setText("Unknown")

            if curve == ECC_CURVE_P256:
                window.rbECCP256.setChecked(True)
                window.rbECCEd25519.setChecked(False)
            elif curve == ECC_CURVE_ED25519:
                window.rbECCP256.setChecked(False)
                window.rbECCEd25519.setChecked(True)

            window.pteECCPubkey.setPlainText(pubkey.hex())

        except TropicSquareNoSession as e:
            window.pteECCPubkey.setPlainText("No secure session established")
        except TropicSquareError as e:
            window.pteECCPubkey.setPlainText("Error: " + str(e))
        except ValueError as e:
            window.pteECCPubkey.setPlainText("Error: " + str(e))
        except Exception as e:
            window.pteECCPubkey.setPlainText("Error: " + str(e))


    app = QtWidgets.QApplication(sys.argv)
    window = uic.loadUi("mainwindow.ui")
    window.btnGetInfo.clicked.connect(on_btn_get_info_click)
    window.btnSaveCert.clicked.connect(on_btn_save_cert_click)
    window.btnStartSecureSession.clicked.connect(on_btnStartSecureSession_click)
    window.btnAbortSecureSession.clicked.connect(on_btnAbortSecureSession_click)
    window.btnPing.clicked.connect(on_btnPing_click)
    window.btnGetRandom.clicked.connect(on_btnbtnGetRandom_click)
    window.leRandomBytesNum.setValidator(QtGui.QIntValidator(0, 255))

    window.btnECCRead.clicked.connect(on_btnECCRead_click)
    window.leECCSlot.setValidator(QtGui.QIntValidator(0, 31))


    window.show()

    sys.exit(app.exec())


if __name__ == '__main__':
    main()
