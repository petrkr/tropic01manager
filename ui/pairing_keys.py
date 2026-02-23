from __future__ import annotations

from PyQt6 import QtWidgets, QtCore
from tropicsquare.constants import PAIRING_KEY_MAX, PAIRING_KEY_SIZE
from tropicsquare.exceptions import (
    TropicSquarePairingKeyEmptyError,
    TropicSquarePairingKeyInvalidError,
    TropicSquareCommandError,
)


def setup_pairing_keys(window, bus, get_ts):
    pairing_slot_cards = {}
    pairing_slot_states = {}
    pairing_slot_pubkey_prefix = {}
    refresh_in_progress = False

    def format_pubkey_prefix(key: bytes) -> str:
        return " ".join(f"{b:02x}" for b in key[:8])

    def refresh_pairing_slot_card(slot: int):
        card = pairing_slot_cards.get(slot)
        if not card:
            return
        frame = card["frame"]
        state = pairing_slot_states.get(slot, "unknown")
        status = card["status"]
        btn_write = card["btn_write"]
        btn_show = card["btn_show"]
        btn_invalidate = card["btn_invalidate"]
        btn_refresh_one = card["btn_refresh_one"]

        btn_write.setVisible(False)
        btn_show.setVisible(False)
        btn_invalidate.setVisible(False)
        btn_refresh_one.setVisible(False)

        frame_selector = f"QFrame#{frame.objectName()}"
        if state == "full":
            frame.setStyleSheet(
                f"{frame_selector} {{ border: 1px solid #2e7d32; border-radius: 8px; padding: 8px; background-color: rgba(46, 125, 50, 0.13); }}"
            )
            prefix = pairing_slot_pubkey_prefix.get(slot, "")
            if prefix:
                status.setText(f"● Full ({prefix})")
            else:
                status.setText("● Full")
            status.setStyleSheet(
                "color: #2e7d32; font-weight: bold; border: 1px solid rgba(210, 210, 210, 0.82); "
                "border-radius: 6px; padding: 6px 8px;"
            )
            btn_show.setVisible(True)
            btn_invalidate.setVisible(True)
            btn_show.setEnabled(True)
            btn_invalidate.setEnabled(True)
        elif state == "empty":
            frame.setStyleSheet(
                f"{frame_selector} {{ border: 1px solid #c07a00; border-radius: 8px; padding: 8px; background-color: rgba(192, 122, 0, 0.11); }}"
            )
            status.setText("● Empty")
            status.setStyleSheet(
                "color: #c07a00; font-weight: bold; border: 1px solid rgba(210, 210, 210, 0.82); "
                "border-radius: 6px; padding: 6px 8px;"
            )
            btn_write.setVisible(True)
            btn_write.setEnabled(True)
        elif state == "invalidated":
            frame.setStyleSheet(
                f"{frame_selector} {{ border: 1px solid #b00020; border-radius: 8px; padding: 8px; background-color: rgba(176, 0, 32, 0.11); }}"
            )
            status.setText("● Invalidated")
            status.setStyleSheet(
                "color: #b00020; font-weight: bold; border: 1px solid rgba(210, 210, 210, 0.82); "
                "border-radius: 6px; padding: 6px 8px;"
            )
        elif state == "no-session":
            frame.setStyleSheet(
                f"{frame_selector} {{ border: 1px solid #666666; border-radius: 8px; padding: 8px; background-color: rgba(102, 102, 102, 0.09); }}"
            )
            status.setText("● No session")
            status.setStyleSheet(
                "color: #666666; font-weight: bold; border: 1px solid rgba(210, 210, 210, 0.82); "
                "border-radius: 6px; padding: 6px 8px;"
            )
        else:
            frame.setStyleSheet(
                f"{frame_selector} {{ border: 1px solid #7a7a7a; border-radius: 8px; padding: 8px; background-color: rgba(122, 122, 122, 0.11); }}"
            )
            status.setText("● Unknown")
            status.setStyleSheet(
                "color: #666666; font-weight: bold; border: 1px solid rgba(210, 210, 210, 0.82); "
                "border-radius: 6px; padding: 6px 8px;"
            )
            btn_refresh_one.setVisible(True)
            btn_refresh_one.setEnabled(True)

    def refresh_pairing_keys_overview():
        for slot in range(PAIRING_KEY_MAX + 1):
            refresh_pairing_slot_card(slot)

    def reset_pairing_keys_state():
        for slot in range(PAIRING_KEY_MAX + 1):
            pairing_slot_states[slot] = "unknown"
        pairing_slot_pubkey_prefix.clear()
        refresh_pairing_keys_overview()

    def get_pairing_key_slot_for_overview(slot):
        slot = int(slot)
        if slot < 0 or slot > PAIRING_KEY_MAX:
            raise ValueError(f"Slot must be 0-{PAIRING_KEY_MAX}")
        return slot

    def on_btnPairingKeyShowFromOverview_click(slot):
        ts = get_ts()
        try:
            slot = get_pairing_key_slot_for_overview(slot)
            key = ts.pairing_key_read(slot)
            pairing_slot_states[slot] = "full"
            pairing_slot_pubkey_prefix[slot] = format_pubkey_prefix(key)
            QtWidgets.QMessageBox.information(window, f"Pairing Key Slot {slot}", key.hex())
            refresh_pairing_slot_card(slot)
        except TropicSquarePairingKeyEmptyError:
            pairing_slot_states[slot] = "empty"
            pairing_slot_pubkey_prefix.pop(slot, None)
            QtWidgets.QMessageBox.information(window, "Pairing Key Read", f"Slot {slot} is empty.")
            refresh_pairing_slot_card(slot)
        except TropicSquarePairingKeyInvalidError:
            pairing_slot_states[slot] = "invalidated"
            pairing_slot_pubkey_prefix.pop(slot, None)
            QtWidgets.QMessageBox.information(window, "Pairing Key Read", f"Slot {slot} is invalidated.")
            refresh_pairing_slot_card(slot)
        except Exception as e:
            QtWidgets.QMessageBox.critical(window, "Pairing Key Read Failed", str(e))

    def on_btnPairingKeyWriteFromOverview_click(slot):
        ts = get_ts()
        initial = ""
        text, ok = QtWidgets.QInputDialog.getMultiLineText(
            window,
            f"Write Pairing Key Slot {slot}",
            "Public key (hex, 32 bytes):",
            initial,
        )
        if not ok:
            return
        slot = get_pairing_key_slot_for_overview(slot)
        try:
            key_hex = text.strip().replace(" ", "").replace("\n", "")
            if not key_hex:
                raise ValueError("Public key is empty")
            if len(key_hex) % 2 != 0:
                raise ValueError("Hex input must have even length")
            key = bytes.fromhex(key_hex)
            if len(key) != PAIRING_KEY_SIZE:
                raise ValueError(f"Public key must be {PAIRING_KEY_SIZE} bytes")
        except ValueError as e:
            QtWidgets.QMessageBox.warning(window, "Invalid Input", str(e))
            return
        confirm = QtWidgets.QMessageBox.warning(
            window,
            "Pairing Key Write",
            f"Are you sure?\n\nSlot {slot} is write-only and cannot be overwritten.\nContinue?",
            QtWidgets.QMessageBox.StandardButton.Yes | QtWidgets.QMessageBox.StandardButton.No,
        )
        if confirm != QtWidgets.QMessageBox.StandardButton.Yes:
            return
        try:
            try:
                existing = ts.pairing_key_read(slot)
                pairing_slot_states[slot] = "full"
                pairing_slot_pubkey_prefix[slot] = format_pubkey_prefix(existing)
                refresh_pairing_slot_card(slot)
                QtWidgets.QMessageBox.critical(
                    window,
                    "Pairing Key Write Failed",
                    "Slot already contains a public key and cannot be overwritten.",
                )
                return
            except TropicSquarePairingKeyEmptyError:
                pass
            ts.pairing_key_write(slot, key)
            pairing_slot_states[slot] = "full"
            pairing_slot_pubkey_prefix[slot] = format_pubkey_prefix(key)
            refresh_pairing_slot_card(slot)
            QtWidgets.QMessageBox.information(window, "Pairing Key Write", "Public key written successfully")
        except TropicSquareCommandError as e:
            if "0x3c" in str(e).lower():
                QtWidgets.QMessageBox.critical(
                    window,
                    "Pairing Key Write Failed",
                    "Write failed (0x3C): slot is likely already programmed and not overwritable.",
                )
            else:
                QtWidgets.QMessageBox.critical(window, "Pairing Key Write Failed", str(e))
        except Exception as e:
            QtWidgets.QMessageBox.critical(window, "Pairing Key Write Failed", str(e))

    def on_btnPairingSlotsRefresh_click():
        nonlocal refresh_in_progress
        if refresh_in_progress:
            return
        ts = get_ts()

        total = PAIRING_KEY_MAX + 1
        refresh_in_progress = True
        window.pbPairingSlotsRefresh.setRange(0, total)
        window.pbPairingSlotsRefresh.setValue(0)
        window.lblPairingSlotsRefresh.setText("Starting...")
        QtWidgets.QApplication.processEvents()

        try:
            for slot in range(total):
                window.lblPairingSlotsRefresh.setText(f"Reading slot {slot + 1}/{total}...")
                window.pbPairingSlotsRefresh.setValue(slot)
                QtWidgets.QApplication.processEvents()

                try:
                    key = ts.pairing_key_read(slot)
                    pairing_slot_states[slot] = "full"
                    pairing_slot_pubkey_prefix[slot] = format_pubkey_prefix(key)
                except TropicSquarePairingKeyEmptyError:
                    pairing_slot_states[slot] = "empty"
                    pairing_slot_pubkey_prefix.pop(slot, None)
                except TropicSquarePairingKeyInvalidError:
                    pairing_slot_states[slot] = "invalidated"
                    pairing_slot_pubkey_prefix.pop(slot, None)
                except Exception:
                    pairing_slot_states[slot] = "unknown"
                    pairing_slot_pubkey_prefix.pop(slot, None)
                refresh_pairing_slot_card(slot)

            window.pbPairingSlotsRefresh.setValue(total)
            window.lblPairingSlotsRefresh.setText("Done")
        finally:
            refresh_in_progress = False

    def on_btnPairingSlotRefresh_click(slot):
        ts = get_ts()

        slot = get_pairing_key_slot_for_overview(slot)
        window.lblPairingSlotsRefresh.setText(f"Reading slot {slot + 1}/{PAIRING_KEY_MAX + 1}...")
        QtWidgets.QApplication.processEvents()
        try:
            key = ts.pairing_key_read(slot)
            pairing_slot_states[slot] = "full"
            pairing_slot_pubkey_prefix[slot] = format_pubkey_prefix(key)
        except TropicSquarePairingKeyEmptyError:
            pairing_slot_states[slot] = "empty"
            pairing_slot_pubkey_prefix.pop(slot, None)
        except TropicSquarePairingKeyInvalidError:
            pairing_slot_states[slot] = "invalidated"
            pairing_slot_pubkey_prefix.pop(slot, None)
        except Exception:
            pairing_slot_states[slot] = "unknown"
            pairing_slot_pubkey_prefix.pop(slot, None)
        refresh_pairing_slot_card(slot)
        window.lblPairingSlotsRefresh.setText("Done")

    def on_btnPairingKeyInvalidate_click(slot):
        ts = get_ts()
        slot = get_pairing_key_slot_for_overview(slot)
        confirm = QtWidgets.QMessageBox.warning(
            window,
            "Pairing Key Invalidate",
            f"Invalidate slot {slot}?\n\nThis action is irreversible.",
            QtWidgets.QMessageBox.StandardButton.Yes | QtWidgets.QMessageBox.StandardButton.No,
        )
        if confirm != QtWidgets.QMessageBox.StandardButton.Yes:
            return
        try:
            ts.pairing_key_invalidate(slot)
            pairing_slot_states[slot] = "invalidated"
            pairing_slot_pubkey_prefix.pop(slot, None)
            QtWidgets.QMessageBox.information(window, "Pairing Key Invalidate", f"Slot {slot} invalidated.")
            refresh_pairing_slot_card(slot)
        except TropicSquarePairingKeyInvalidError:
            pairing_slot_states[slot] = "invalidated"
            pairing_slot_pubkey_prefix.pop(slot, None)
            QtWidgets.QMessageBox.information(window, "Pairing Key Invalidate", f"Slot {slot} is already invalidated.")
            refresh_pairing_slot_card(slot)
        except Exception as e:
            QtWidgets.QMessageBox.critical(window, "Pairing Key Invalidate Failed", str(e))

    def create_pairing_status_tab():
        tab_layout = window.layoutPairingKeys
        while tab_layout.count():
            item = tab_layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.setParent(None)
        tab_layout.setContentsMargins(8, 8, 8, 8)
        tab_layout.setSpacing(8)
        tab_layout.setAlignment(QtCore.Qt.AlignmentFlag.AlignTop)

        top_row = QtWidgets.QHBoxLayout()
        top_row.setContentsMargins(0, 0, 0, 0)
        top_row.setSpacing(8)
        btn_refresh = QtWidgets.QPushButton("Refresh All")
        progress = QtWidgets.QProgressBar()
        progress.setMinimum(0)
        progress.setMaximum(PAIRING_KEY_MAX + 1)
        progress.setValue(0)
        progress.setTextVisible(False)
        progress.setFixedWidth(180)
        lbl_progress = QtWidgets.QLabel("Idle")
        top_row.addWidget(btn_refresh)
        top_row.addWidget(progress)
        top_row.addWidget(lbl_progress)
        top_row.addStretch(1)
        tab_layout.addLayout(top_row)

        overview_group = QtWidgets.QGroupBox("")
        overview_group.setContentsMargins(6, 6, 6, 6)
        overview_group.setSizePolicy(
            QtWidgets.QSizePolicy.Policy.Preferred,
            QtWidgets.QSizePolicy.Policy.Maximum,
        )
        overview_layout = QtWidgets.QGridLayout(overview_group)
        overview_layout.setContentsMargins(12, 12, 12, 12)
        overview_layout.setHorizontalSpacing(12)
        overview_layout.setVerticalSpacing(12)

        for slot in range(PAIRING_KEY_MAX + 1):
            frame = QtWidgets.QFrame()
            frame.setObjectName(f"pairingSlotFrame{slot}")
            frame.setFrameShape(QtWidgets.QFrame.Shape.StyledPanel)
            frame.setStyleSheet("QFrame { border: 1px solid #bdbdbd; border-radius: 8px; padding: 8px; }")
            vbox = QtWidgets.QVBoxLayout(frame)

            title = QtWidgets.QLabel(f"Slot {slot}")
            title.setStyleSheet(
                "font-weight: bold; border: 1px solid rgba(210, 210, 210, 0.82); "
                "border-radius: 6px; padding: 6px 8px;"
            )
            status = QtWidgets.QLabel("● Unknown")
            status.setStyleSheet(
                "color: #666666; font-weight: bold; border: 1px solid rgba(210, 210, 210, 0.82); "
                "border-radius: 6px; padding: 6px 8px;"
            )

            action_row = QtWidgets.QHBoxLayout()
            btn_write = QtWidgets.QPushButton("Write")
            btn_show = QtWidgets.QPushButton("Show")
            btn_invalidate = QtWidgets.QPushButton("Invalidate")
            btn_refresh_one = QtWidgets.QPushButton("Refresh")
            action_row.addWidget(btn_write)
            action_row.addWidget(btn_show)
            action_row.addWidget(btn_invalidate)
            action_row.addWidget(btn_refresh_one)

            vbox.addWidget(title)
            vbox.addWidget(status)
            vbox.addLayout(action_row)

            row = slot // 2
            col = slot % 2
            overview_layout.addWidget(frame, row, col)

            pairing_slot_cards[slot] = {
                "frame": frame,
                "status": status,
                "btn_write": btn_write,
                "btn_show": btn_show,
                "btn_invalidate": btn_invalidate,
                "btn_refresh_one": btn_refresh_one,
            }
            pairing_slot_states.setdefault(slot, "unknown")

            btn_write.clicked.connect(lambda _=False, s=slot: on_btnPairingKeyWriteFromOverview_click(s))
            btn_show.clicked.connect(lambda _=False, s=slot: on_btnPairingKeyShowFromOverview_click(s))
            btn_invalidate.clicked.connect(lambda _=False, s=slot: on_btnPairingKeyInvalidate_click(s))
            btn_refresh_one.clicked.connect(lambda _=False, s=slot: on_btnPairingSlotRefresh_click(s))

        tab_layout.addWidget(overview_group)
        tab_layout.addStretch(1)

        window.btnPairingSlotsRefresh = btn_refresh
        window.pbPairingSlotsRefresh = progress
        window.lblPairingSlotsRefresh = lbl_progress

        btn_refresh.clicked.connect(on_btnPairingSlotsRefresh_click)
        refresh_pairing_keys_overview()

    def on_session_changed(has_session=False, **_):
        if has_session:
            reset_pairing_keys_state()
        else:
            for slot in range(PAIRING_KEY_MAX + 1):
                pairing_slot_states[slot] = "no-session"
            pairing_slot_pubkey_prefix.clear()
            refresh_pairing_keys_overview()
        window.btnPairingSlotsRefresh.setEnabled(has_session and not refresh_in_progress)

    def on_device_changed(connected=False, **_):
        window.btnPairingSlotsRefresh.setEnabled(False)
        for slot in range(PAIRING_KEY_MAX + 1):
            pairing_slot_states[slot] = "no-session"
        pairing_slot_pubkey_prefix.clear()
        refresh_pairing_keys_overview()

    for slot in range(PAIRING_KEY_MAX + 1):
        pairing_slot_states[slot] = "unknown"
    create_pairing_status_tab()

    bus.on("session_changed", on_session_changed)
    bus.on("device_changed", on_device_changed)
    on_device_changed(connected=False)
