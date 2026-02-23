from __future__ import annotations

from PyQt6 import QtWidgets, QtGui
def setup_random_data(window, bus, get_ts):
    def on_btnGetRandom_click():
        ts = get_ts()

        try:
            number_text = window.leRandomBytesNum.text().strip()
            if not number_text:
                raise ValueError("Byte count is required")
            number = int(number_text)
            if number > 255:
                raise ValueError("Number must be less than 256")
            window.pteRandomBytes.setPlainText(ts.get_random(number).hex())
        except ValueError as e:
            QtWidgets.QMessageBox.warning(window, "Invalid Input", str(e))
        except Exception as e:
            QtWidgets.QMessageBox.critical(window, "Random Failed", str(e))

    window.leRandomBytesNum.setValidator(QtGui.QIntValidator(0, 255))
    window.btnGetRandom.clicked.connect(on_btnGetRandom_click)

    def on_device_changed(connected=False, **_):
        window.btnGetRandom.setEnabled(False)

    def on_session_changed(has_session=False, **_):
        window.btnGetRandom.setEnabled(has_session)

    bus.on("device_changed", on_device_changed)
    bus.on("session_changed", on_session_changed)
    on_device_changed(connected=False)
