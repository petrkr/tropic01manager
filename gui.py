from tropicsquare.ports.cpython import TropicSquareCPython
from tropicsquare.exceptions import *

from networkspi import NetworkSPI, DummyNetworkSpiCSPin

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization


# Default factory pairing keys
pkey_index_0 = 0x00 # Slot 0
sh0priv = [0xd0,0x99,0x92,0xb1,0xf1,0x7a,0xbc,0x4d,0xb9,0x37,0x17,0x68,0xa2,0x7d,0xa0,0x5b,0x18,0xfa,0xb8,0x56,0x13,0xa7,0x84,0x2c,0xa6,0x4c,0x79,0x10,0xf2,0x2e,0x71,0x6b]
sh0pub  = [0xe7,0xf7,0x35,0xba,0x19,0xa3,0x3f,0xd6,0x73,0x23,0xab,0x37,0x26,0x2d,0xe5,0x36,0x08,0xca,0x57,0x85,0x76,0x53,0x43,0x52,0xe1,0x8f,0x64,0xe6,0x13,0xd3,0x8d,0x54]


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
        window.lblRISCFWVersion.setText(ts.riscv_fw_version.hex())
        window.lblSPECTFWVersion.setText(ts.spect_fw_version.hex())
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


    app = QtWidgets.QApplication(sys.argv)
    window = uic.loadUi("mainwindow.ui")
    window.btnGetInfo.clicked.connect(on_btn_get_info_click)
    window.btnSaveCert.clicked.connect(on_btn_save_cert_click)
    window.btnStartSecureSession.clicked.connect(on_btnStartSecureSession_click)
    window.btnAbortSecureSession.clicked.connect(on_btnAbortSecureSession_click)
    window.btnPing.clicked.connect(on_btnPing_click)
    window.btnGetRandom.clicked.connect(on_btnbtnGetRandom_click)
    window.leRandomBytesNum.setValidator(QtGui.QIntValidator(0, 255))

    window.show()

    sys.exit(app.exec())


if __name__ == '__main__':
    main()
