from __future__ import annotations

from PyQt6 import QtWidgets, QtGui, QtCore
from tropicsquare.exceptions import TropicSquareError


def setup_mac_and_destroy(window, bus, get_ts):
    layout = window.layoutMacAndDestroyGeneric
    layout.setHorizontalSpacing(0)
    layout.setVerticalSpacing(0)
    layout.setAlignment(QtCore.Qt.AlignmentFlag.AlignTop)
    layout.setRowStretch(0, 0)
    layout.setRowStretch(1, 0)
    layout.setRowStretch(2, 0)
    layout.setRowStretch(3, 1)

    lbl_slot = QtWidgets.QLabel("Slot (0-127)")
    le_slot = QtWidgets.QLineEdit()
    le_slot.setValidator(QtGui.QIntValidator(0, 127))

    lbl_input = QtWidgets.QLabel("Input (32 bytes HEX)")
    le_input = QtWidgets.QLineEdit()
    le_input.setPlaceholderText("64 hex chars")

    btn_exec = QtWidgets.QPushButton("Execute")

    lbl_output = QtWidgets.QLabel("Output (32 bytes HEX)")
    le_output = QtWidgets.QLineEdit()
    le_output.setReadOnly(True)

    layout.addWidget(lbl_slot, 0, 0, alignment=QtCore.Qt.AlignmentFlag.AlignTop)
    layout.addWidget(le_slot, 0, 1, alignment=QtCore.Qt.AlignmentFlag.AlignTop)
    layout.addWidget(btn_exec, 0, 2, alignment=QtCore.Qt.AlignmentFlag.AlignTop)
    layout.addWidget(lbl_input, 1, 0, alignment=QtCore.Qt.AlignmentFlag.AlignTop)
    layout.addWidget(le_input, 1, 1, 1, 2, alignment=QtCore.Qt.AlignmentFlag.AlignTop)
    layout.addWidget(lbl_output, 2, 0, alignment=QtCore.Qt.AlignmentFlag.AlignTop)
    layout.addWidget(le_output, 2, 1, 1, 2, alignment=QtCore.Qt.AlignmentFlag.AlignTop)

    def parse_hex_input(value: str) -> bytes:
        cleaned = value.strip().replace(" ", "").replace("\n", "")
        if len(cleaned) != 64:
            raise ValueError("Input must be exactly 32 bytes (64 hex chars)")
        try:
            return bytes.fromhex(cleaned)
        except ValueError:
            raise ValueError("Input must be valid HEX")

    def on_btn_exec_click():
        ts = get_ts()
        try:
            slot_text = le_slot.text().strip()
            if not slot_text:
                raise ValueError("Slot is required")
            slot = int(slot_text)
            if slot < 0 or slot > 127:
                raise ValueError("Slot must be in range 0-127")

            data = parse_hex_input(le_input.text())
            result = ts.mac_and_destroy(slot, data)
            le_output.setText(result.hex())
        except ValueError as e:
            QtWidgets.QMessageBox.warning(window, "Invalid Input", str(e))
        except TropicSquareError as e:
            QtWidgets.QMessageBox.critical(window, "MAC and Destroy Failed", str(e))
        except Exception as e:
            QtWidgets.QMessageBox.critical(window, "MAC and Destroy Failed", str(e))

    btn_exec.clicked.connect(on_btn_exec_click)

    def on_device_changed(connected=False, **_):
        btn_exec.setEnabled(False)

    def on_session_changed(has_session=False, **_):
        btn_exec.setEnabled(has_session)

    bus.on("device_changed", on_device_changed)
    bus.on("session_changed", on_session_changed)
    on_device_changed(connected=False)
