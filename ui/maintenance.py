from __future__ import annotations

from PyQt6 import QtWidgets
from tropicsquare.constants.l2 import (
    STARTUP_REBOOT,
    STARTUP_MAINTENANCE_REBOOT,
    SLEEP_MODE_SLEEP,
    SLEEP_MODE_DEEP_SLEEP,
)


def setup_maintenance(window, bus, get_ts, has_secure_session, abort_session):
    def on_btnMaintenanceStartupReboot_click():
        ts = get_ts()
        confirm = QtWidgets.QMessageBox.question(
            window,
            "Reboot",
            "Reboot device?",
            QtWidgets.QMessageBox.StandardButton.Yes
            | QtWidgets.QMessageBox.StandardButton.No,
        )
        if confirm != QtWidgets.QMessageBox.StandardButton.Yes:
            return
        try:
            if has_secure_session():
                abort_session()
            ts.reboot(STARTUP_REBOOT)
            QtWidgets.QMessageBox.information(window, "Reboot", "Reboot request sent")
        except Exception as e:
            QtWidgets.QMessageBox.critical(window, "Reboot Failed", str(e))

    def on_btnMaintenanceStartupBootloader_click():
        ts = get_ts()
        confirm = QtWidgets.QMessageBox.question(
            window,
            "Reboot Bootloader",
            "Reboot to bootloader?",
            QtWidgets.QMessageBox.StandardButton.Yes
            | QtWidgets.QMessageBox.StandardButton.No,
        )
        if confirm != QtWidgets.QMessageBox.StandardButton.Yes:
            return
        try:
            if has_secure_session():
                abort_session()
            ts.reboot(STARTUP_MAINTENANCE_REBOOT)
            QtWidgets.QMessageBox.information(window, "Reboot Bootloader", "Bootloader reboot request sent")
        except Exception as e:
            QtWidgets.QMessageBox.critical(window, "Reboot Bootloader Failed", str(e))

    def on_btnMaintenanceSleep_click():
        ts = get_ts()
        if ts is None:
            QtWidgets.QMessageBox.warning(window, "Not Connected", "Please connect to device first")
            return
        confirm = QtWidgets.QMessageBox.question(
            window,
            "Sleep",
            "Put device to sleep?",
            QtWidgets.QMessageBox.StandardButton.Yes
            | QtWidgets.QMessageBox.StandardButton.No,
        )
        if confirm != QtWidgets.QMessageBox.StandardButton.Yes:
            return
        try:
            ts.sleep(SLEEP_MODE_SLEEP)
            QtWidgets.QMessageBox.information(window, "Sleep", "Sleep request sent")
        except Exception as e:
            QtWidgets.QMessageBox.critical(window, "Sleep Failed", str(e))

    def on_btnMaintenanceDeepSleep_click():
        ts = get_ts()
        if ts is None:
            QtWidgets.QMessageBox.warning(window, "Not Connected", "Please connect to device first")
            return
        confirm = QtWidgets.QMessageBox.question(
            window,
            "Deep Sleep",
            "Put device to deep sleep?",
            QtWidgets.QMessageBox.StandardButton.Yes
            | QtWidgets.QMessageBox.StandardButton.No,
        )
        if confirm != QtWidgets.QMessageBox.StandardButton.Yes:
            return
        try:
            ts.sleep(SLEEP_MODE_DEEP_SLEEP)
            QtWidgets.QMessageBox.information(window, "Deep Sleep", "Deep sleep request sent")
        except Exception as e:
            QtWidgets.QMessageBox.critical(window, "Deep Sleep Failed", str(e))

    def on_btnMaintenanceGetLogs_click():
        ts = get_ts()
        if not ts:
            QtWidgets.QMessageBox.warning(window, "Not Connected", "Please connect to device first")
            return
        try:
            log_text = ts.get_log()
            window.pteMaintenanceLogs.setPlainText(log_text)
        except Exception as e:
            QtWidgets.QMessageBox.critical(window, "Get Logs Failed", str(e))

    def on_session_changed(**_):
        window.pteMaintenanceLogs.clear()

    def on_device_changed(connected=False, **_):
        window.pteMaintenanceLogs.clear()
        window.btnMaintenanceStartupReboot.setEnabled(bool(connected))
        window.btnMaintenanceStartupBootloader.setEnabled(bool(connected))
        window.btnMaintenanceSleep.setEnabled(bool(connected))
        window.btnMaintenanceDeepSleep.setEnabled(bool(connected))
        window.btnMaintenanceGetLogs.setEnabled(bool(connected))

    window.btnMaintenanceStartupReboot.clicked.connect(on_btnMaintenanceStartupReboot_click)
    window.btnMaintenanceStartupBootloader.clicked.connect(on_btnMaintenanceStartupBootloader_click)
    window.btnMaintenanceSleep.clicked.connect(on_btnMaintenanceSleep_click)
    window.btnMaintenanceDeepSleep.clicked.connect(on_btnMaintenanceDeepSleep_click)
    window.btnMaintenanceGetLogs.clicked.connect(on_btnMaintenanceGetLogs_click)

    bus.on("session_changed", on_session_changed)
    bus.on("device_changed", on_device_changed)
    on_device_changed(connected=False)
