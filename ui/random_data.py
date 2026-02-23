from __future__ import annotations

from PyQt6 import QtWidgets, QtGui
from tropicsquare.exceptions import TropicSquareNoSession


def setup_random_data(window, get_ts):
    def on_btnGetRandom_click():
        ts = get_ts()
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

    window.leRandomBytesNum.setValidator(QtGui.QIntValidator(0, 255))
    window.btnGetRandom.clicked.connect(on_btnGetRandom_click)

    def set_enabled(enabled: bool):
        window.btnGetRandom.setEnabled(enabled)

    return set_enabled
