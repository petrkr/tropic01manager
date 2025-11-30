from tropicsquare.constants import ECC_CURVE_ED25519, ECC_CURVE_P256
from tropicsquare.ports.cpython import TropicSquareCPython
from tropicsquare.exceptions import *

from networkspi import NetworkSPI, DummyNetworkSpiCSPin

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization


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
    #with open("tropic.crt", "rb") as f:
    #    ts._certificate = f.read()


    def on_btn_get_info_click():
        riscv_ver = ts.riscv_fw_version
        spect_ver = ts.spect_fw_version
        window.lblRISCFWVersion.setText(f"{riscv_ver[0]}.{riscv_ver[1]}.{riscv_ver[2]}.{riscv_ver[3]}")
        window.lblSPECTFWVersion.setText(f"{spect_ver[0]}.{spect_ver[1]}.{spect_ver[2]}.{spect_ver[3]}")
        cert = x509.load_der_x509_certificate(ts.certificate, default_backend())
        #window.lteCertificate.setPlainText(cert.public_bytes(encoding=serialization.Encoding.PEM).decode())
        window.lblCertPubkey.setText(ts.public_key.hex())
        window.lblCertDateIssue.setText(cert.not_valid_before_utc.isoformat())
        window.lblCertDateExpire.setText(cert.not_valid_after_utc.isoformat())


    def on_btn_save_cert_click():
        filename, fileformat = QtWidgets.QFileDialog.getSaveFileName(window, "Save certificate", "", "PEM Certificate files (*.pem *.crt);;DER Certificate files (*.der);;All files (*)")
        if not filename:
            return

        with open(filename, "wb") as f:
            if fileformat == "PEM Certificate files (*.pem *.crt)":
                cert = x509.load_der_x509_certificate(ts.certificate, default_backend())
                f.write(cert.public_bytes(encoding=serialization.Encoding.PEM))
            else:
                f.write(ts.certificate)


    def on_btnStartSecureSession_click():
        if ts.start_secure_session(0, bytes(sh0priv), bytes(sh0pub)):
            window.btnAbortSecureSession.setEnabled(True)
            window.btnStartSecureSession.setEnabled(False)


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
