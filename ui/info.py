from __future__ import annotations

from datetime import datetime

from PyQt6 import QtWidgets
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization


def parse_certificate_info(cert_data):
    cert_bytes = bytes(cert_data)

    try:
        cert = x509.load_der_x509_certificate(cert_bytes, default_backend())
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
        try:
            cn = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
        except Exception:
            cn = "Unknown"
        return (not_before, not_after, cn)
    except Exception:
        pass

    try:
        dates = []
        idx = 0
        while idx < len(cert_bytes) - 15:
            if cert_bytes[idx] == 0x17 and cert_bytes[idx + 1] == 0x0D:
                date_str = cert_bytes[idx + 2:idx + 15].decode("ascii")
                year = int(date_str[0:2])
                year = 2000 + year if year < 50 else 1900 + year
                month = int(date_str[2:4])
                day = int(date_str[4:6])
                hour = int(date_str[6:8])
                minute = int(date_str[8:10])
                second = int(date_str[10:12])
                dates.append(datetime(year, month, day, hour, minute, second))
            idx += 1

        cn = "Unknown"
        cn_oid = bytes.fromhex("550403")
        cn_occurrences = []
        idx = 0
        while idx < len(cert_bytes):
            idx = cert_bytes.find(cn_oid, idx)
            if idx < 0:
                break
            try:
                cn_len = cert_bytes[idx + 4]
                cn_start = idx + 5
                cn_value = cert_bytes[cn_start:cn_start + cn_len].decode("utf-8")
                cn_occurrences.append(cn_value)
            except Exception:
                pass
            idx += 1

        if cn_occurrences:
            cn = cn_occurrences[-1]

        if len(dates) >= 2:
            return (dates[0], dates[1], cn)
        return (None, None, cn)
    except Exception:
        return (None, None, None)


def setup_info(window, bus, get_ts):
    def clear_info():
        window.lblRISCFWVersion.setText("")
        window.lblSPECTFWVersion.setText("")
        window.lblCertPubkey.setText("")
        window.lblCertDateIssue.setText("")
        window.lblCertDateExpire.setText("")

    def on_btn_get_info_click():
        ts = get_ts()
        if not ts:
            QtWidgets.QMessageBox.warning(window, "Not Connected", "Please connect to device first")
            return

        try:
            riscv_ver = ts.riscv_fw_version
            spect_ver = ts.spect_fw_version
            window.lblRISCFWVersion.setText(f"{riscv_ver[0]}.{riscv_ver[1]}.{riscv_ver[2]}.{riscv_ver[3]}")
            window.lblSPECTFWVersion.setText(f"{spect_ver[0]}.{spect_ver[1]}.{spect_ver[2]}.{spect_ver[3]}")

            window.lblCertPubkey.setText(ts.public_key.hex())

            not_before, not_after, _subject_cn = parse_certificate_info(ts.certificate)
            if not_before and not_after:
                window.lblCertDateIssue.setText(not_before.isoformat())
                window.lblCertDateExpire.setText(not_after.isoformat())
            else:
                window.lblCertDateIssue.setText("Parse error")
                window.lblCertDateExpire.setText("Parse error")
        except Exception as e:
            QtWidgets.QMessageBox.critical(window, "Error", f"Failed to get info:\n{str(e)}")

    def on_btn_save_cert_click():
        ts = get_ts()
        if not ts:
            QtWidgets.QMessageBox.warning(window, "Not Connected", "Please connect to device first")
            return

        filename, fileformat = QtWidgets.QFileDialog.getSaveFileName(
            window,
            "Save certificate",
            "",
            "PEM Certificate files (*.pem *.crt);;DER Certificate files (*.der);;All files (*)",
        )
        if not filename:
            return

        with open(filename, "wb") as f:
            if fileformat == "PEM Certificate files (*.pem *.crt)":
                cert = x509.load_der_x509_certificate(bytes(ts.certificate), default_backend())
                f.write(cert.public_bytes(encoding=serialization.Encoding.PEM))
            else:
                f.write(bytes(ts.certificate))

    window.btnGetInfo.clicked.connect(on_btn_get_info_click)
    window.btnSaveCert.clicked.connect(on_btn_save_cert_click)

    def on_device_changed(connected=False, **_):
        enabled = connected
        window.btnGetInfo.setEnabled(enabled)
        window.btnSaveCert.setEnabled(enabled)
        if not connected:
            clear_info()

    bus.on("device_changed", on_device_changed)
    on_device_changed(connected=False)
