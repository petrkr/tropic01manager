from __future__ import annotations

import re

from PyQt6 import QtWidgets, QtCore
from tropicsquare.constants import MEM_DATA_MAX_SIZE
from tropicsquare.exceptions import TropicSquareCommandError, TropicSquareUnauthorizedError


def setup_mem_data(window, bus, get_ts):
    slot_states = {slot: "no-session" for slot in range(512)}
    slot_data = {}
    session_active = False
    selected_slot = None
    page_cards = {}
    cards_columns = 4

    def clear_layout(layout):
        while layout.count():
            item = layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.setParent(None)
            else:
                child_layout = item.layout()
                if child_layout is not None:
                    clear_layout(child_layout)

    def current_page_base() -> int:
        bank_base = int(cmb_bank.currentData())
        page_idx = int(cmb_page.currentData())
        return bank_base + (page_idx * 32)

    def slot_for_index(index: int) -> int:
        return current_page_base() + index

    def state_label(slot: int) -> str:
        state = slot_states.get(slot, "unknown")
        if state == "data":
            return f"● Data ({len(slot_data.get(slot, b''))}B)"
        if state == "empty":
            return "● Empty"
        if state == "unauthorized":
            return "● Unauthorized"
        if state == "no-session":
            return "● No session"
        if isinstance(state, str) and state.startswith("error:"):
            return f"● Error {state.split(':', 1)[1]}"
        if state == "error":
            return "● Error code"
        return "● Unknown"

    def card_style(slot: int, selected: bool) -> str:
        state = slot_states.get(slot, "unknown")
        border_color = "#7a7a7a"
        bg = "rgba(122, 122, 122, 0.11)"
        status_color = "#666666"
        if state == "data":
            border_color = "#2e7d32"
            bg = "rgba(46, 125, 50, 0.13)"
            status_color = "#2e7d32"
        elif state == "empty":
            border_color = "#c07a00"
            bg = "rgba(192, 122, 0, 0.11)"
            status_color = "#c07a00"
        elif state == "error":
            border_color = "#b00020"
            bg = "rgba(176, 0, 32, 0.11)"
            status_color = "#b00020"
        elif state == "unauthorized":
            border_color = "#7b3fb0"
            bg = "rgba(123, 63, 176, 0.14)"
            status_color = "#7b3fb0"
        elif isinstance(state, str) and state.startswith("error:"):
            border_color = "#b00020"
            bg = "rgba(176, 0, 32, 0.11)"
            status_color = "#b00020"
        elif state == "no-session":
            border_color = "#666666"
            bg = "rgba(102, 102, 102, 0.09)"
            status_color = "#666666"
        if selected:
            border_color = "#1f5fbf"
            bg = "rgba(31, 95, 191, 0.13)"
        return border_color, bg, status_color

    def refresh_cards():
        title_style = (
            "font-weight: bold; border: 1px solid rgba(210, 210, 210, 0.82); "
            "border-radius: 6px; padding: 6px 8px;"
        )
        status_base_style = (
            "font-weight: bold; border: 1px solid rgba(210, 210, 210, 0.82); "
            "border-radius: 6px; padding: 6px 8px;"
        )
        for i in range(32):
            slot = slot_for_index(i)
            card = page_cards[i]
            card["lbl_id"].setText(f"Slot {slot}")
            card["lbl_state"].setText(state_label(slot))
            border_color, bg, status_color = card_style(slot, selected_slot == slot)
            frame_selector = f"QFrame#{card['frame'].objectName()}"
            card["frame"].setStyleSheet(
                f"{frame_selector} {{ border: 1px solid {border_color}; border-radius: 8px; "
                f"padding: 8px; background-color: {bg}; }}"
            )
            card["lbl_id"].setStyleSheet(title_style)
            card["lbl_state"].setStyleSheet(f"color: {status_color}; {status_base_style}")

    def update_detail():
        if selected_slot is None:
            lbl_selected.setText("Selected slot: -")
            pte_hex.setPlainText("")
            pte_text.setPlainText("")
            return
        lbl_selected.setText(f"Selected slot: {selected_slot} ({state_label(selected_slot)})")
        data = slot_data.get(selected_slot)
        if data is None:
            pte_hex.setPlainText("")
            pte_text.setPlainText("")
            return
        pte_hex.setPlainText(data.hex())
        pte_text.setPlainText(data.decode("utf-8", "replace"))

    def update_action_enabled():
        enabled = session_active and selected_slot is not None
        btn_read_slot.setEnabled(enabled)
        btn_write_slot.setEnabled(enabled)
        btn_erase_slot.setEnabled(enabled)
        rb_hex.setEnabled(session_active)
        rb_text.setEnabled(session_active)
        pte_input.setEnabled(session_active)
        cmb_bank.setEnabled(session_active)
        cmb_page.setEnabled(session_active)
        cards_widget.setEnabled(session_active)
        btn_refresh_page.setEnabled(session_active)
        btn_refresh_bank.setEnabled(session_active)
        btn_refresh_all.setEnabled(session_active)

    def read_slot(slot: int):
        ts = get_ts()
        data = ts.mem_data_read(slot)
        slot_data[slot] = data
        slot_states[slot] = "empty" if len(data) == 0 else "data"

    def extract_error_code(exc: Exception) -> str | None:
        text = str(exc)
        match = re.search(r"\((?:result|status):\s*(0x[0-9a-fA-F]+)\)", text)
        if match:
            return match.group(1).lower()
        match = re.search(r"\b0x[0-9a-fA-F]+\b", text)
        if match:
            return match.group(0).lower()
        return None

    def run_refresh(slots, label: str):
        btn_refresh_page.setEnabled(False)
        btn_refresh_bank.setEnabled(False)
        btn_refresh_all.setEnabled(False)
        pb_refresh.setRange(0, len(slots))
        pb_refresh.setValue(0)
        lbl_refresh.setText(label)
        QtWidgets.QApplication.processEvents()

        errors = 0
        try:
            for i, slot in enumerate(slots, start=1):
                lbl_refresh.setText(f"{label} {i}/{len(slots)} (slot {slot})")
                try:
                    read_slot(slot)
                except TropicSquareUnauthorizedError:
                    slot_states[slot] = "unauthorized"
                    slot_data.pop(slot, None)
                    errors += 1
                except TropicSquareCommandError as e:
                    code = extract_error_code(e)
                    slot_states[slot] = f"error:{code}" if code else "error"
                    slot_data.pop(slot, None)
                    errors += 1
                except Exception as e:
                    code = extract_error_code(e)
                    slot_states[slot] = f"error:{code}" if code else "error"
                    slot_data.pop(slot, None)
                    errors += 1
                pb_refresh.setValue(i)
                QtWidgets.QApplication.processEvents()
        finally:
            lbl_refresh.setText("Done" if errors == 0 else f"Done with {errors} error(s)")
            refresh_cards()
            update_detail()
            update_action_enabled()

    def parse_input() -> bytes:
        data_text = pte_input.toPlainText()
        if rb_hex.isChecked():
            cleaned = data_text.strip().replace(" ", "").replace("\n", "")
            if not cleaned:
                return b""
            if len(cleaned) % 2 != 0:
                raise ValueError("Hex input must have even length")
            return bytes.fromhex(cleaned)
        return data_text.encode("utf-8")

    def on_bank_changed(_index: int):
        refresh_cards()

    def on_page_changed(_index: int):
        refresh_cards()

    def on_card_clicked(index: int):
        nonlocal selected_slot
        selected_slot = slot_for_index(index)
        refresh_cards()
        update_detail()
        update_action_enabled()

    def on_btn_refresh_page_click():
        start = current_page_base()
        run_refresh(range(start, start + 32), "Refreshing page")

    def on_btn_refresh_bank_click():
        bank_base = int(cmb_bank.currentData())
        run_refresh(range(bank_base, bank_base + 128), "Refreshing bank")

    def on_btn_refresh_all_click():
        run_refresh(range(512), "Refreshing all")

    def on_btn_read_slot_click():
        if selected_slot is None:
            return
        run_refresh([selected_slot], "Reading slot")

    def on_btn_write_slot_click():
        if selected_slot is None:
            return
        try:
            data = parse_input()
            if len(data) > MEM_DATA_MAX_SIZE:
                raise ValueError(f"Max size is {MEM_DATA_MAX_SIZE} bytes")
            ts = get_ts()
            ts.mem_data_write(data, selected_slot)
            run_refresh([selected_slot], "Writing slot")
        except ValueError as e:
            QtWidgets.QMessageBox.warning(window, "Invalid Input", str(e))
        except Exception as e:
            QtWidgets.QMessageBox.critical(window, "MEM Write Failed", str(e))

    def on_btn_erase_slot_click():
        if selected_slot is None:
            return
        confirm = QtWidgets.QMessageBox.question(
            window,
            "MEM Erase",
            f"Erase slot {selected_slot}?",
            QtWidgets.QMessageBox.StandardButton.Yes | QtWidgets.QMessageBox.StandardButton.No,
        )
        if confirm != QtWidgets.QMessageBox.StandardButton.Yes:
            return
        try:
            ts = get_ts()
            ts.mem_data_erase(selected_slot)
            run_refresh([selected_slot], "Erasing slot")
        except Exception as e:
            QtWidgets.QMessageBox.critical(window, "MEM Erase Failed", str(e))

    def on_session_changed(has_session=False, **_):
        nonlocal session_active
        session_active = has_session
        if session_active:
            for slot in range(512):
                if slot_states[slot] == "no-session":
                    slot_states[slot] = "unknown"
        else:
            for slot in range(512):
                slot_states[slot] = "no-session"
            slot_data.clear()
        refresh_cards()
        update_detail()
        update_action_enabled()

    def on_device_changed(connected=False, **_):
        nonlocal session_active, selected_slot
        session_active = False
        selected_slot = None
        for slot in range(512):
            slot_states[slot] = "no-session"
        slot_data.clear()
        lbl_refresh.setText("Idle")
        pb_refresh.setValue(0)
        refresh_cards()
        update_detail()
        update_action_enabled()

    clear_layout(window.layoutMemData)
    window.layoutMemData.setContentsMargins(8, 8, 8, 8)
    window.layoutMemData.setSpacing(8)

    top_row = QtWidgets.QHBoxLayout()
    top_row.setContentsMargins(0, 0, 0, 0)
    top_row.setSpacing(8)
    lbl_bank = QtWidgets.QLabel("Bank")
    cmb_bank = QtWidgets.QComboBox()
    cmb_bank.addItem("0-127", 0)
    cmb_bank.addItem("128-255", 128)
    cmb_bank.addItem("256-383", 256)
    cmb_bank.addItem("384-511", 384)
    lbl_page = QtWidgets.QLabel("Page")
    cmb_page = QtWidgets.QComboBox()
    cmb_page.addItem("0-31", 0)
    cmb_page.addItem("32-63", 1)
    cmb_page.addItem("64-95", 2)
    cmb_page.addItem("96-127", 3)
    btn_refresh_page = QtWidgets.QPushButton("Refresh Page")
    btn_refresh_bank = QtWidgets.QPushButton("Refresh Bank")
    btn_refresh_all = QtWidgets.QPushButton("Refresh All")
    pb_refresh = QtWidgets.QProgressBar()
    pb_refresh.setRange(0, 1)
    pb_refresh.setValue(0)
    pb_refresh.setTextVisible(False)
    pb_refresh.setFixedWidth(180)
    lbl_refresh = QtWidgets.QLabel("Idle")
    top_row.addWidget(lbl_bank)
    top_row.addWidget(cmb_bank)
    top_row.addWidget(lbl_page)
    top_row.addWidget(cmb_page)
    top_row.addWidget(btn_refresh_page)
    top_row.addWidget(btn_refresh_bank)
    top_row.addWidget(btn_refresh_all)
    top_row.addWidget(pb_refresh)
    top_row.addWidget(lbl_refresh)
    top_row.addStretch(1)
    window.layoutMemData.addLayout(top_row)

    splitter = QtWidgets.QSplitter()
    splitter.setOrientation(QtCore.Qt.Orientation.Horizontal)

    left = QtWidgets.QWidget()
    left.setMinimumWidth(680)
    left_layout = QtWidgets.QVBoxLayout(left)
    left_layout.setContentsMargins(0, 0, 0, 0)
    left_layout.setSpacing(6)

    cards_scroll = QtWidgets.QScrollArea()
    cards_scroll.setWidgetResizable(True)
    cards_scroll.setFrameShape(QtWidgets.QFrame.Shape.NoFrame)
    cards_scroll.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
    cards_widget = QtWidgets.QWidget()
    cards_layout = QtWidgets.QGridLayout(cards_widget)
    cards_layout.setContentsMargins(0, 0, 0, 0)
    cards_layout.setHorizontalSpacing(8)
    cards_layout.setVerticalSpacing(8)
    for c in range(cards_columns):
        cards_layout.setColumnStretch(c, 1)

    for i in range(32):
        frame = QtWidgets.QFrame()
        frame.setObjectName(f"memDataSlotFrame{i}")
        frame.setFrameShape(QtWidgets.QFrame.Shape.StyledPanel)
        frame.setMinimumWidth(0)
        frame.setFixedHeight(98)
        frame.setSizePolicy(
            QtWidgets.QSizePolicy.Policy.Expanding,
            QtWidgets.QSizePolicy.Policy.Fixed,
        )
        vbox = QtWidgets.QVBoxLayout(frame)
        vbox.setContentsMargins(10, 8, 10, 8)
        vbox.setSpacing(6)
        lbl_id = QtWidgets.QLabel("Slot -")
        lbl_state = QtWidgets.QLabel("Unknown")
        lbl_id.setMinimumHeight(28)
        lbl_state.setMinimumHeight(28)
        lbl_id.setAttribute(QtCore.Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)
        lbl_state.setAttribute(QtCore.Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)
        frame.setCursor(QtCore.Qt.CursorShape.PointingHandCursor)
        vbox.addWidget(lbl_id)
        vbox.addWidget(lbl_state)
        row = i // cards_columns
        col = i % cards_columns
        cards_layout.addWidget(frame, row, col)
        frame.mousePressEvent = lambda _event, idx=i: on_card_clicked(idx)
        page_cards[i] = {"frame": frame, "lbl_id": lbl_id, "lbl_state": lbl_state}

    cards_scroll.setWidget(cards_widget)
    left_layout.addWidget(cards_scroll)
    splitter.addWidget(left)

    right = QtWidgets.QWidget()
    right_layout = QtWidgets.QVBoxLayout(right)
    right_layout.setContentsMargins(0, 0, 0, 0)
    right_layout.setSpacing(6)
    lbl_selected = QtWidgets.QLabel("Selected slot: -")
    lbl_selected.setStyleSheet("font-weight: bold;")
    right_layout.addWidget(lbl_selected)

    right_layout.addWidget(QtWidgets.QLabel("Hex"))
    pte_hex = QtWidgets.QPlainTextEdit()
    pte_hex.setReadOnly(True)
    right_layout.addWidget(pte_hex)

    right_layout.addWidget(QtWidgets.QLabel("Text"))
    pte_text = QtWidgets.QPlainTextEdit()
    pte_text.setReadOnly(True)
    right_layout.addWidget(pte_text)

    input_row = QtWidgets.QHBoxLayout()
    rb_hex = QtWidgets.QRadioButton("Hex")
    rb_text = QtWidgets.QRadioButton("Text")
    rb_hex.setChecked(True)
    input_row.addWidget(QtWidgets.QLabel("Input"))
    input_row.addWidget(rb_hex)
    input_row.addWidget(rb_text)
    input_row.addStretch(1)
    right_layout.addLayout(input_row)

    pte_input = QtWidgets.QPlainTextEdit()
    right_layout.addWidget(pte_input)

    actions = QtWidgets.QHBoxLayout()
    btn_read_slot = QtWidgets.QPushButton("Read Slot")
    btn_write_slot = QtWidgets.QPushButton("Write Slot")
    btn_erase_slot = QtWidgets.QPushButton("Erase Slot")
    actions.addWidget(btn_read_slot)
    actions.addWidget(btn_write_slot)
    actions.addWidget(btn_erase_slot)
    right_layout.addLayout(actions)
    right_layout.addStretch(1)
    splitter.addWidget(right)
    splitter.setStretchFactor(0, 2)
    splitter.setStretchFactor(1, 1)

    window.layoutMemData.addWidget(splitter)

    cmb_bank.currentIndexChanged.connect(on_bank_changed)
    cmb_page.currentIndexChanged.connect(on_page_changed)
    btn_refresh_page.clicked.connect(on_btn_refresh_page_click)
    btn_refresh_bank.clicked.connect(on_btn_refresh_bank_click)
    btn_refresh_all.clicked.connect(on_btn_refresh_all_click)
    btn_read_slot.clicked.connect(on_btn_read_slot_click)
    btn_write_slot.clicked.connect(on_btn_write_slot_click)
    btn_erase_slot.clicked.connect(on_btn_erase_slot_click)

    bus.on("session_changed", on_session_changed)
    bus.on("device_changed", on_device_changed)

    refresh_cards()
    update_detail()
    update_action_enabled()
