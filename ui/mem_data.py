from __future__ import annotations

from PyQt6 import QtWidgets, QtGui
from tropicsquare.constants import MEM_DATA_MAX_SIZE
def setup_mem_data(window, bus, get_ts):
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
        ts = get_ts()
        try:
            slot = get_mem_slot()
            data = ts.mem_data_read(slot)
            window.pteMemHex.setPlainText(data.hex())
            window.pteMemText.setPlainText(data.decode("utf-8", "replace"))
        except ValueError as e:
            QtWidgets.QMessageBox.warning(window, "Invalid Input", str(e))
        except Exception as e:
            QtWidgets.QMessageBox.critical(window, "MEM Read Failed", str(e))

    def on_btnMemWrite_click():
        ts = get_ts()
        try:
            slot = get_mem_slot()
            data = parse_mem_input()
            if len(data) > MEM_DATA_MAX_SIZE:
                raise ValueError(f"Max size is {MEM_DATA_MAX_SIZE} bytes")
            ts.mem_data_write(data, slot)
            on_btnMemRead_click()
            QtWidgets.QMessageBox.information(window, "MEM Write", "Data written successfully")
        except ValueError as e:
            QtWidgets.QMessageBox.warning(window, "Invalid Input", str(e))
        except Exception as e:
            QtWidgets.QMessageBox.critical(window, "MEM Write Failed", str(e))

    def on_btnMemErase_click():
        ts = get_ts()
        try:
            slot = get_mem_slot()
            confirm = QtWidgets.QMessageBox.question(
                window,
                "MEM Erase",
                f"Erase data in slot {slot}?",
                QtWidgets.QMessageBox.StandardButton.Yes | QtWidgets.QMessageBox.StandardButton.No,
            )
            if confirm != QtWidgets.QMessageBox.StandardButton.Yes:
                return
            ts.mem_data_erase(slot)
            window.pteMemHex.setPlainText("")
            window.pteMemText.setPlainText("")
            QtWidgets.QMessageBox.information(window, "MEM Erase", "Data erased successfully")
        except ValueError as e:
            QtWidgets.QMessageBox.warning(window, "Invalid Input", str(e))
        except Exception as e:
            QtWidgets.QMessageBox.critical(window, "MEM Erase Failed", str(e))

    window.btnMemRead.clicked.connect(on_btnMemRead_click)
    window.btnMemWrite.clicked.connect(on_btnMemWrite_click)
    window.btnMemErase.clicked.connect(on_btnMemErase_click)
    window.rbMemHex.setChecked(True)
    window.leMemSlot.setValidator(QtGui.QIntValidator(0, 511))

    def on_device_changed(connected=False, **_):
        enabled = False
        window.btnMemRead.setEnabled(enabled)
        window.btnMemWrite.setEnabled(enabled)
        window.btnMemErase.setEnabled(enabled)
        window.leMemSlot.setEnabled(enabled)
        window.pteMemInput.setEnabled(enabled)
        window.rbMemHex.setEnabled(enabled)
        window.rbMemText.setEnabled(enabled)

    def on_session_changed(has_session=False, **_):
        enabled = has_session
        window.btnMemRead.setEnabled(enabled)
        window.btnMemWrite.setEnabled(enabled)
        window.btnMemErase.setEnabled(enabled)
        window.leMemSlot.setEnabled(enabled)
        window.pteMemInput.setEnabled(enabled)
        window.rbMemHex.setEnabled(enabled)
        window.rbMemText.setEnabled(enabled)

    bus.on("device_changed", on_device_changed)
    bus.on("session_changed", on_session_changed)
    on_device_changed(connected=False)
