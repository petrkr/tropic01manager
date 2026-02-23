from __future__ import annotations

from PyQt6 import QtWidgets
from tropicsquare.exceptions import TropicSquareError


def setup_ping(window, bus, get_ts):
    def on_btnPing_click():
        ts = get_ts()
        ping = window.ptePingInput.toPlainText().encode("utf-8")
        try:
            window.ptePingResult.setPlainText(ts.ping(ping).decode("utf-8"))
        except TropicSquareError as e:
            QtWidgets.QMessageBox.critical(window, "Ping Failed", str(e))
        except Exception as e:
            QtWidgets.QMessageBox.critical(window, "Ping Failed", str(e))

    window.btnPing.clicked.connect(on_btnPing_click)

    def on_device_changed(connected=False, **_):
        window.btnPing.setEnabled(False)

    def on_session_changed(has_session=False, **_):
        window.btnPing.setEnabled(has_session)

    bus.on("device_changed", on_device_changed)
    bus.on("session_changed", on_session_changed)
    on_device_changed(connected=False)
