from __future__ import annotations

from PyQt6 import QtWidgets
from tropicsquare.exceptions import TropicSquareNoSession, TropicSquareError


def setup_ping(window, get_ts):
    def on_btnPing_click():
        ts = get_ts()
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

    window.btnPing.clicked.connect(on_btnPing_click)

    def set_enabled(enabled: bool):
        window.btnPing.setEnabled(enabled)

    return set_enabled
