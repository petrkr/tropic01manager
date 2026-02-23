from __future__ import annotations

import hashlib
from PyQt6 import QtWidgets
from tropicsquare.constants.ecc import (
    ECC_CURVE_P256,
    ECC_CURVE_ED25519,
    ECC_KEY_ORIGIN_GENERATED,
    ECC_KEY_ORIGIN_STORED,
    ECC_MAX_KEYS,
)
from tropicsquare.exceptions import TropicSquareECCInvalidKeyError


def setup_ecc(window, bus, get_ts, parse_hex_bytes):
    ecc_slot_cards = {}
    ecc_slot_states = {}
    ecc_slot_info = {}
    ecc_refresh_all_btn = None

    def ecc_curve_name(curve: int) -> str:
        if curve == ECC_CURVE_P256:
            return "P256"
        if curve == ECC_CURVE_ED25519:
            return "Ed25519"
        return f"Unknown (0x{curve:02X})"

    def ecc_origin_name(origin: int) -> str:
        if origin == ECC_KEY_ORIGIN_GENERATED:
            return "Generated"
        if origin == ECC_KEY_ORIGIN_STORED:
            return "Stored"
        return f"Origin 0x{origin:02X}"

    def prompt_ecc_curve(title: str):
        dialog = QtWidgets.QDialog(window)
        dialog.setWindowTitle(title)
        dialog.setModal(True)
        layout = QtWidgets.QFormLayout(dialog)
        cmb = QtWidgets.QComboBox(dialog)
        cmb.addItem("P256", ECC_CURVE_P256)
        cmb.addItem("Ed25519", ECC_CURVE_ED25519)
        layout.addRow("Curve", cmb)
        buttons = QtWidgets.QDialogButtonBox(
            QtWidgets.QDialogButtonBox.StandardButton.Ok
            | QtWidgets.QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addRow(buttons)
        if dialog.exec() != QtWidgets.QDialog.DialogCode.Accepted:
            return None
        return cmb.currentData()

    def prompt_ecc_store():
        dialog = QtWidgets.QDialog(window)
        dialog.setWindowTitle("Store ECC key")
        dialog.setModal(True)
        layout = QtWidgets.QFormLayout(dialog)
        cmb = QtWidgets.QComboBox(dialog)
        cmb.addItem("P256", ECC_CURVE_P256)
        cmb.addItem("Ed25519", ECC_CURVE_ED25519)
        le_key = QtWidgets.QLineEdit(dialog)
        le_key.setPlaceholderText("Private key (hex)")
        layout.addRow("Curve", cmb)
        layout.addRow("Private key (hex)", le_key)
        buttons = QtWidgets.QDialogButtonBox(
            QtWidgets.QDialogButtonBox.StandardButton.Ok
            | QtWidgets.QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addRow(buttons)
        if dialog.exec() != QtWidgets.QDialog.DialogCode.Accepted:
            return None
        try:
            key_bytes = parse_hex_bytes(le_key.text(), "Private key")
            if len(key_bytes) != 32:
                raise ValueError("Private key must be 32 bytes")
        except ValueError as e:
            QtWidgets.QMessageBox.warning(window, "Invalid Private Key", str(e))
            return None
        return cmb.currentData(), key_bytes

    def prompt_ecc_sign():
        slots = [slot for slot, state in ecc_slot_states.items() if state == "present"]
        if not slots:
            QtWidgets.QMessageBox.warning(window, "No Keys", "No ECC key available for signing")
            return None
        dialog = QtWidgets.QDialog(window)
        dialog.setWindowTitle("Sign Message")
        dialog.setModal(True)
        layout = QtWidgets.QFormLayout(dialog)
        cmb = QtWidgets.QComboBox(dialog)
        for slot in sorted(slots):
            info = ecc_slot_info.get(slot)
            label = f"Slot {slot}"
            if info is not None:
                label = f"Slot {slot} ({ecc_curve_name(info.curve)})"
            cmb.addItem(label, slot)
        mode_row = QtWidgets.QHBoxLayout()
        rb_text = QtWidgets.QRadioButton("Text")
        rb_hex = QtWidgets.QRadioButton("Hex")
        rb_text.setChecked(True)
        mode_row.addWidget(rb_text)
        mode_row.addWidget(rb_hex)
        mode_row.addStretch(1)
        pte = QtWidgets.QPlainTextEdit(dialog)
        pte.setPlaceholderText("Message to sign")
        layout.addRow("Slot", cmb)
        layout.addRow("Mode", mode_row)
        layout.addRow("Message", pte)
        buttons = QtWidgets.QDialogButtonBox(
            QtWidgets.QDialogButtonBox.StandardButton.Ok
            | QtWidgets.QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addRow(buttons)
        if dialog.exec() != QtWidgets.QDialog.DialogCode.Accepted:
            return None
        text = pte.toPlainText()
        if not text.strip():
            QtWidgets.QMessageBox.warning(window, "Invalid Message", "Message is required")
            return None
        if rb_hex.isChecked():
            try:
                message = parse_hex_bytes(text, "Message")
            except ValueError as e:
                QtWidgets.QMessageBox.warning(window, "Invalid Message", str(e))
                return None
        else:
            message = text.encode("utf-8")
        return cmb.currentData(), message

    def on_btnEccSignMessage_click():
        ts = get_ts()
        result = prompt_ecc_sign()
        if result is None:
            return
        slot, message = result
        try:
            info = ecc_slot_info.get(slot)
            if info is None:
                info = ts.ecc_key_read(slot)
                ecc_slot_states[slot] = "present"
                ecc_slot_info[slot] = info
                refresh_ecc_slot_card(slot)
            if info.curve == ECC_CURVE_P256:
                message_hash = hashlib.sha256(message).digest()
                signature = ts.ecdsa_sign(slot, message_hash)
                details = (
                    "Curve: P256 (ECDSA)\n"
                    f"Hash (SHA-256): {message_hash.hex()}\n"
                    f"R: {signature.r.hex()}\n"
                    f"S: {signature.s.hex()}"
                )
            elif info.curve == ECC_CURVE_ED25519:
                signature = ts.eddsa_sign(slot, message)
                signature_hex = (signature.r + signature.s).hex()
                details = (
                    "Curve: Ed25519 (EdDSA)\n"
                    f"R: {signature.r.hex()}\n"
                    f"S: {signature.s.hex()}\n"
                    f"Signature: {signature_hex}"
                )
            else:
                QtWidgets.QMessageBox.warning(window, "Unsupported Curve", f"Unknown curve: 0x{info.curve:02X}")
                return
            QtWidgets.QMessageBox.information(window, "Signature", details)
        except Exception as e:
            QtWidgets.QMessageBox.critical(window, "Sign Failed", str(e))

    def on_btnEccRefreshOne_click(slot: int):
        ts = get_ts()
        try:
            key_info = ts.ecc_key_read(slot)
            ecc_slot_states[slot] = "present"
            ecc_slot_info[slot] = key_info
        except TropicSquareECCInvalidKeyError:
            ecc_slot_states[slot] = "empty"
            ecc_slot_info.pop(slot, None)
        except Exception:
            ecc_slot_states[slot] = "unknown"
            ecc_slot_info.pop(slot, None)
        refresh_ecc_slot_card(slot)

    def on_btnEccGenerateFromOverview_click(slot: int):
        ts = get_ts()
        curve = prompt_ecc_curve(f"Generate ECC key in slot {slot}")
        if curve is None:
            return
        try:
            ts.ecc_key_generate(slot, curve)
            on_btnEccRefreshOne_click(slot)
            QtWidgets.QMessageBox.information(window, "ECC Generate", "Key generated successfully")
        except Exception as e:
            QtWidgets.QMessageBox.critical(window, "ECC Generate Failed", str(e))

    def on_btnEccStoreFromOverview_click(slot: int):
        ts = get_ts()
        result = prompt_ecc_store()
        if result is None:
            return
        curve, key_bytes = result
        try:
            ts.ecc_key_store(slot, curve, key_bytes)
            on_btnEccRefreshOne_click(slot)
            QtWidgets.QMessageBox.information(window, "ECC Store", "Key stored successfully")
        except Exception as e:
            QtWidgets.QMessageBox.critical(window, "ECC Store Failed", str(e))

    def on_btnEccShowFromOverview_click(slot: int):
        info = ecc_slot_info.get(slot)
        if info is None:
            on_btnEccRefreshOne_click(slot)
            info = ecc_slot_info.get(slot)
        if info is None:
            return
        QtWidgets.QMessageBox.information(
            window,
            f"ECC Slot {slot}",
            info.public_key.hex(),
        )

    def on_btnEccEraseFromOverview_click(slot: int):
        ts = get_ts()
        confirm = QtWidgets.QMessageBox.question(
            window,
            "ECC Erase",
            f"Erase ECC key in slot {slot}?",
            QtWidgets.QMessageBox.StandardButton.Yes
            | QtWidgets.QMessageBox.StandardButton.No,
        )
        if confirm != QtWidgets.QMessageBox.StandardButton.Yes:
            return
        try:
            ts.ecc_key_erase(slot)
            ecc_slot_states[slot] = "empty"
            ecc_slot_info.pop(slot, None)
            refresh_ecc_slot_card(slot)
            QtWidgets.QMessageBox.information(window, "ECC Erase", "Key erased successfully")
        except Exception as e:
            QtWidgets.QMessageBox.critical(window, "ECC Erase Failed", str(e))

    def refresh_ecc_slot_card(slot: int):
        card = ecc_slot_cards.get(slot)
        if not card:
            return
        state = ecc_slot_states.get(slot, "unknown")
        status = card["status"]
        frame = card["frame"]
        base_style = (
            "font-weight: bold; border: 1px solid rgba(210, 210, 210, 0.82); "
            "border-radius: 6px; padding: 6px 8px;"
        )
        frame_selector = f"QFrame#{frame.objectName()}"
        if state == "present":
            info = ecc_slot_info.get(slot)
            if info:
                status_text = f"● {ecc_curve_name(info.curve)} / {ecc_origin_name(info.origin)}"
            else:
                status_text = "● Present"
            status.setText(status_text)
            status.setStyleSheet(f"color: #1f5fbf; {base_style}")
            frame.setStyleSheet(
                f"{frame_selector} {{ border: 1px solid #2e7d32; border-radius: 8px; padding: 8px; "
                f"background-color: rgba(46, 125, 50, 0.13); }}"
            )
            card["btn_primary"].setText("Show")
            card["btn_primary"].setVisible(True)
            card["btn_primary"].setEnabled(True)
            card["btn_secondary"].setText("Erase")
            card["btn_secondary"].setVisible(True)
            card["btn_secondary"].setEnabled(True)
            card["btn_refresh"].setVisible(False)
            card["btn_refresh"].setEnabled(False)
            card["primary_action"] = lambda s=slot: on_btnEccShowFromOverview_click(s)
            card["secondary_action"] = lambda s=slot: on_btnEccEraseFromOverview_click(s)
        elif state == "empty":
            status.setText("● Empty")
            status.setStyleSheet(f"color: #666666; {base_style}")
            frame.setStyleSheet(
                f"{frame_selector} {{ border: 1px solid #7a7a7a; border-radius: 8px; padding: 8px; "
                f"background-color: rgba(122, 122, 122, 0.11); }}"
            )
            card["btn_primary"].setText("Generate")
            card["btn_primary"].setVisible(True)
            card["btn_primary"].setEnabled(True)
            card["btn_secondary"].setText("Store")
            card["btn_secondary"].setVisible(True)
            card["btn_secondary"].setEnabled(True)
            card["btn_refresh"].setVisible(False)
            card["btn_refresh"].setEnabled(False)
            card["primary_action"] = lambda s=slot: on_btnEccGenerateFromOverview_click(s)
            card["secondary_action"] = lambda s=slot: on_btnEccStoreFromOverview_click(s)
        elif state == "no-session":
            status.setText("● No session")
            status.setStyleSheet(f"color: #666666; {base_style}")
            frame.setStyleSheet(
                f"{frame_selector} {{ border: 1px solid #666666; border-radius: 8px; padding: 8px; "
                f"background-color: rgba(102, 102, 102, 0.09); }}"
            )
            card["btn_primary"].setText("Show")
            card["btn_primary"].setVisible(False)
            card["btn_primary"].setEnabled(False)
            card["btn_secondary"].setText("Erase")
            card["btn_secondary"].setVisible(False)
            card["btn_secondary"].setEnabled(False)
            card["btn_refresh"].setVisible(False)
            card["btn_refresh"].setEnabled(False)
            card["primary_action"] = None
            card["secondary_action"] = None
        else:
            status.setText("● Unknown")
            status.setStyleSheet(f"color: #666666; {base_style}")
            frame.setStyleSheet(
                f"{frame_selector} {{ border: 1px solid #7a7a7a; border-radius: 8px; padding: 8px; "
                f"background-color: rgba(122, 122, 122, 0.11); }}"
            )
            card["btn_primary"].setText("Show")
            card["btn_primary"].setVisible(False)
            card["btn_primary"].setEnabled(False)
            card["btn_secondary"].setText("Erase")
            card["btn_secondary"].setVisible(False)
            card["btn_secondary"].setEnabled(False)
            card["btn_refresh"].setVisible(True)
            card["btn_refresh"].setEnabled(True)
            card["primary_action"] = None
            card["secondary_action"] = None

    def create_ecc_overview():
        nonlocal ecc_refresh_all_btn
        top_row = QtWidgets.QHBoxLayout()
        top_row.setContentsMargins(0, 0, 0, 0)
        top_row.setSpacing(8)
        btn_refresh_all = QtWidgets.QPushButton("Refresh All")
        ecc_refresh_all_btn = btn_refresh_all
        btn_sign_message = QtWidgets.QPushButton("Sign Message")
        progress = QtWidgets.QProgressBar()
        progress.setMinimum(0)
        progress.setMaximum(ECC_MAX_KEYS + 1)
        progress.setValue(0)
        progress.setTextVisible(False)
        progress.setFixedWidth(180)
        lbl_status = QtWidgets.QLabel("Idle")
        top_row.addWidget(btn_refresh_all)
        top_row.addWidget(btn_sign_message)
        top_row.addWidget(progress)
        top_row.addWidget(lbl_status)
        top_row.addStretch(1)

        overview_group = QtWidgets.QGroupBox("")
        overview_group.setContentsMargins(6, 6, 6, 6)
        overview_group.setSizePolicy(
            QtWidgets.QSizePolicy.Policy.Expanding,
            QtWidgets.QSizePolicy.Policy.Expanding,
        )
        overview_layout = QtWidgets.QGridLayout(overview_group)
        overview_layout.setContentsMargins(12, 12, 12, 12)
        overview_layout.setHorizontalSpacing(12)
        overview_layout.setVerticalSpacing(12)

        cols = 4
        for slot in range(ECC_MAX_KEYS + 1):
            frame = QtWidgets.QFrame()
            frame.setObjectName(f"eccSlotFrame{slot}")
            frame.setFrameShape(QtWidgets.QFrame.Shape.StyledPanel)
            frame.setStyleSheet("QFrame { border: 1px solid #bdbdbd; border-radius: 8px; padding: 8px; }")
            frame.setMinimumWidth(170)
            frame.setFixedHeight(120)
            frame.setSizePolicy(
                QtWidgets.QSizePolicy.Policy.Preferred,
                QtWidgets.QSizePolicy.Policy.Fixed,
            )
            vbox = QtWidgets.QVBoxLayout(frame)
            vbox.setContentsMargins(6, 6, 6, 6)
            vbox.setSpacing(4)

            title = QtWidgets.QLabel(f"Slot {slot}")
            title.setStyleSheet(
                "font-weight: bold; border: 1px solid rgba(210, 210, 210, 0.82); "
                "border-radius: 6px; padding: 6px 8px;"
            )
            title.setMinimumHeight(20)
            status = QtWidgets.QLabel("● Unknown")
            status.setStyleSheet(
                "color: #666666; font-weight: bold; border: 1px solid rgba(210, 210, 210, 0.82); "
                "border-radius: 6px; padding: 6px 8px;"
            )
            status.setMinimumHeight(20)

            action_row = QtWidgets.QGridLayout()
            action_row.setHorizontalSpacing(4)
            action_row.setVerticalSpacing(4)
            btn_primary = QtWidgets.QPushButton("Show")
            btn_secondary = QtWidgets.QPushButton("Erase")
            btn_refresh = QtWidgets.QPushButton("Refresh")
            action_row.addWidget(btn_primary, 0, 0)
            action_row.addWidget(btn_secondary, 0, 1)
            action_row.addWidget(btn_refresh, 0, 0, 1, 2)

            vbox.addWidget(title)
            vbox.addWidget(status)
            vbox.addLayout(action_row)

            row = slot // cols
            col = slot % cols
            overview_layout.addWidget(frame, row, col)

            ecc_slot_cards[slot] = {
                "frame": frame,
                "status": status,
                "btn_primary": btn_primary,
                "btn_secondary": btn_secondary,
                "btn_refresh": btn_refresh,
                "primary_action": None,
                "secondary_action": None,
            }
            ecc_slot_states.setdefault(slot, "unknown")

            btn_primary.clicked.connect(
                lambda _=False, s=slot: ecc_slot_cards[s]["primary_action"]
                and ecc_slot_cards[s]["primary_action"]()
            )
            btn_secondary.clicked.connect(
                lambda _=False, s=slot: ecc_slot_cards[s]["secondary_action"]
                and ecc_slot_cards[s]["secondary_action"]()
            )
            btn_refresh.clicked.connect(lambda _=False, s=slot: on_btnEccRefreshOne_click(s))

            refresh_ecc_slot_card(slot)

        scroll = QtWidgets.QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QtWidgets.QFrame.Shape.NoFrame)
        scroll_content = QtWidgets.QWidget()
        scroll_content_layout = QtWidgets.QVBoxLayout(scroll_content)
        scroll_content_layout.setContentsMargins(0, 0, 0, 0)
        scroll_content_layout.setSpacing(0)
        scroll_content_layout.addWidget(overview_group)
        scroll.setWidget(scroll_content)

        window.layoutEcc.addLayout(top_row)
        window.layoutEcc.addWidget(scroll)

        def on_btnEccRefreshAll_click():
            ts = get_ts()
            progress.setValue(0)
            lbl_status.setText("Refreshing...")
            QtWidgets.QApplication.processEvents()
            for slot in range(ECC_MAX_KEYS + 1):
                lbl_status.setText(f"Reading slot {slot + 1}/{ECC_MAX_KEYS + 1}...")
                try:
                    key_info = ts.ecc_key_read(slot)
                    ecc_slot_states[slot] = "present"
                    ecc_slot_info[slot] = key_info
                except TropicSquareECCInvalidKeyError:
                    ecc_slot_states[slot] = "empty"
                    ecc_slot_info.pop(slot, None)
                except Exception:
                    ecc_slot_states[slot] = "unknown"
                    ecc_slot_info.pop(slot, None)
                refresh_ecc_slot_card(slot)
                progress.setValue(slot + 1)
            lbl_status.setText("Done")

        btn_refresh_all.clicked.connect(on_btnEccRefreshAll_click)
        btn_sign_message.clicked.connect(on_btnEccSignMessage_click)
        window.btnEccSignMessage = btn_sign_message

    def on_session_changed(has_session=False, **_):
        if ecc_refresh_all_btn is not None:
            ecc_refresh_all_btn.setEnabled(has_session)
        for slot in range(ECC_MAX_KEYS + 1):
            ecc_slot_states[slot] = "unknown" if has_session else "no-session"
            ecc_slot_info.pop(slot, None)
            refresh_ecc_slot_card(slot)

    def on_device_changed(connected=False, **_):
        if ecc_refresh_all_btn is not None:
            ecc_refresh_all_btn.setEnabled(False)
        for slot in range(ECC_MAX_KEYS + 1):
            ecc_slot_states[slot] = "no-session"
            ecc_slot_info.pop(slot, None)
            refresh_ecc_slot_card(slot)
        window.btnEccSignMessage.setEnabled(bool(connected))

    for slot in range(ECC_MAX_KEYS + 1):
        ecc_slot_states[slot] = "unknown"
    create_ecc_overview()

    bus.on("session_changed", on_session_changed)
    bus.on("device_changed", on_device_changed)
    on_device_changed(connected=False)
