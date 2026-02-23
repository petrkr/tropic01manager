from __future__ import annotations

from PyQt6 import QtWidgets, QtCore
from tropicsquare.constants import MCOUNTER_MAX
from tropicsquare.exceptions import TropicSquareCounterInvalidError


def setup_mcounter(window, bus, get_ts):
    mcounter_cards = {}
    mcounter_states = {}
    mcounter_values = {}

    def refresh_mcounter_card(index: int):
        card = mcounter_cards.get(index)
        if not card:
            return
        frame = card["frame"]
        status = card["status"]
        btn_read = card["btn_read"]
        btn_init = card["btn_init"]
        btn_update = card["btn_update"]
        btn_refresh_one = card["btn_refresh_one"]

        state = mcounter_states.get(index, "unknown")

        btn_read.setVisible(False)
        btn_init.setVisible(False)
        btn_update.setVisible(False)
        btn_refresh_one.setVisible(False)

        frame_selector = f"QFrame#{frame.objectName()}"
        if state == "value":
            frame.setStyleSheet(
                f"{frame_selector} {{ border: 1px solid #2e7d32; border-radius: 8px; padding: 8px; "
                f"background-color: rgba(46, 125, 50, 0.13); }}"
            )
            value = mcounter_values.get(index, "?")
            status.setText(f"● Value: {value}")
            status.setStyleSheet(
                "color: #2e7d32; font-weight: bold; border: 1px solid rgba(210, 210, 210, 0.82); "
                "border-radius: 6px; padding: 6px 8px;"
            )
            btn_init.setVisible(True)
            btn_read.setVisible(True)
            btn_update.setVisible(True)
            btn_init.setEnabled(True)
            btn_read.setEnabled(True)
            btn_update.setEnabled(True)
        elif state == "zero":
            frame.setStyleSheet(
                f"{frame_selector} {{ border: 1px solid #b00020; border-radius: 8px; padding: 8px; "
                f"background-color: rgba(176, 0, 32, 0.11); }}"
            )
            status.setText("● Depleted (0)")
            status.setStyleSheet(
                "color: #b00020; font-weight: bold; border: 1px solid rgba(210, 210, 210, 0.82); "
                "border-radius: 6px; padding: 6px 8px;"
            )
            btn_init.setVisible(True)
            btn_read.setVisible(True)
            btn_init.setEnabled(True)
            btn_read.setEnabled(True)
        elif state == "invalid":
            frame.setStyleSheet(
                f"{frame_selector} {{ border: 1px solid #c07a00; border-radius: 8px; padding: 8px; "
                f"background-color: rgba(192, 122, 0, 0.11); }}"
            )
            status.setText("● Invalid")
            status.setStyleSheet(
                "color: #c07a00; font-weight: bold; border: 1px solid rgba(210, 210, 210, 0.82); "
                "border-radius: 6px; padding: 6px 8px;"
            )
            btn_init.setVisible(True)
            btn_init.setEnabled(True)
        elif state == "no-session":
            frame.setStyleSheet(
                f"{frame_selector} {{ border: 1px solid #666666; border-radius: 8px; padding: 8px; "
                f"background-color: rgba(102, 102, 102, 0.09); }}"
            )
            status.setText("● No session")
            status.setStyleSheet(
                "color: #666666; font-weight: bold; border: 1px solid rgba(210, 210, 210, 0.82); "
                "border-radius: 6px; padding: 6px 8px;"
            )
        else:
            frame.setStyleSheet(
                f"{frame_selector} {{ border: 1px solid #7a7a7a; border-radius: 8px; padding: 8px; "
                f"background-color: rgba(122, 122, 122, 0.11); }}"
            )
            status.setText("● Unknown")
            status.setStyleSheet(
                "color: #666666; font-weight: bold; border: 1px solid rgba(210, 210, 210, 0.82); "
                "border-radius: 6px; padding: 6px 8px;"
            )
            btn_refresh_one.setVisible(True)
            btn_refresh_one.setEnabled(True)

    def refresh_mcounter_overview():
        for idx in range(MCOUNTER_MAX + 1):
            refresh_mcounter_card(idx)

    def read_mcounter_slot(index: int):
        ts = get_ts()
        value = ts.mcounter_get(index)
        mcounter_states[index] = "zero" if value == 0 else "value"
        mcounter_values[index] = value
        refresh_mcounter_card(index)
        return value

    def on_btnMCounterReadFromOverview_click(index):
        ts = get_ts()
        idx = int(index)
        try:
            value = read_mcounter_slot(idx)
            QtWidgets.QMessageBox.information(window, f"MCounter {idx}", f"Value: {value}")
        except TropicSquareCounterInvalidError:
            mcounter_states[idx] = "invalid"
            mcounter_values.pop(idx, None)
            refresh_mcounter_card(idx)
            QtWidgets.QMessageBox.information(window, "MCounter Read", f"Counter {idx} is invalid.")
        except Exception as e:
            QtWidgets.QMessageBox.critical(window, "MCounter Read Failed", str(e))

    def on_btnMCounterInitFromOverview_click(index):
        ts = get_ts()
        idx = int(index)
        text, ok = QtWidgets.QInputDialog.getText(
            window,
            f"Initialize MCounter {idx}",
            "Initial value (0..4294967295):",
            text="0",
        )
        if not ok:
            return
        value_text = text.strip()
        if not value_text:
            QtWidgets.QMessageBox.warning(window, "Invalid Input", "Initial value is required.")
            return
        try:
            value = int(value_text, 0)
        except ValueError:
            QtWidgets.QMessageBox.warning(window, "Invalid Input", "Invalid integer value.")
            return
        if value < 0 or value > 0xFFFFFFFF:
            QtWidgets.QMessageBox.warning(window, "Invalid Input", "Initial value must be 0..4294967295.")
            return
        try:
            ts.mcounter_init(idx, value)
            read_mcounter_slot(idx)
            QtWidgets.QMessageBox.information(window, "MCounter Init", f"Counter {idx} initialized to {value}.")
        except Exception as e:
            QtWidgets.QMessageBox.critical(window, "MCounter Init Failed", str(e))

    def on_btnMCounterUpdateFromOverview_click(index):
        ts = get_ts()
        idx = int(index)
        try:
            ts.mcounter_update(idx)
            value = read_mcounter_slot(idx)
            QtWidgets.QMessageBox.information(window, "MCounter Update", f"Counter {idx} updated to {value}.")
        except TropicSquareCounterInvalidError:
            mcounter_states[idx] = "invalid"
            mcounter_values.pop(idx, None)
            refresh_mcounter_card(idx)
            QtWidgets.QMessageBox.warning(window, "MCounter Update", f"Counter {idx} is invalid.")
        except Exception as e:
            QtWidgets.QMessageBox.critical(window, "MCounter Update Failed", str(e))

    def on_btnMCounterRefreshOne_click(index):
        idx = int(index)
        window.lblMCounterRefreshStatus.setText(f"Reading counter {idx + 1}/{MCOUNTER_MAX + 1}...")
        QtWidgets.QApplication.processEvents()
        try:
            read_mcounter_slot(idx)
        except TropicSquareCounterInvalidError:
            mcounter_states[idx] = "invalid"
            mcounter_values.pop(idx, None)
            refresh_mcounter_card(idx)
        except Exception:
            mcounter_states[idx] = "unknown"
            mcounter_values.pop(idx, None)
            refresh_mcounter_card(idx)
        window.lblMCounterRefreshStatus.setText("Done")

    def on_btnMCounterRefreshAll_click():
        total = MCOUNTER_MAX + 1
        window.btnMCounterRefreshAll.setEnabled(False)
        window.pbMCounterRefresh.setRange(0, total)
        window.pbMCounterRefresh.setValue(0)
        window.lblMCounterRefreshStatus.setText("Starting...")
        QtWidgets.QApplication.processEvents()

        try:
            for idx in range(total):
                window.lblMCounterRefreshStatus.setText(f"Reading counter {idx + 1}/{total}...")
                window.pbMCounterRefresh.setValue(idx)
                QtWidgets.QApplication.processEvents()
                try:
                    read_mcounter_slot(idx)
                except TropicSquareCounterInvalidError:
                    mcounter_states[idx] = "invalid"
                    mcounter_values.pop(idx, None)
                    refresh_mcounter_card(idx)
                except Exception:
                    mcounter_states[idx] = "unknown"
                    mcounter_values.pop(idx, None)
                    refresh_mcounter_card(idx)
            window.pbMCounterRefresh.setValue(total)
            window.lblMCounterRefreshStatus.setText("Done")
        finally:
            window.btnMCounterRefreshAll.setEnabled(True)

    def create_mcounter_status_tab():
        tab_layout = window.layoutMCounter
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
        btn_refresh_all = QtWidgets.QPushButton("Refresh All")
        progress = QtWidgets.QProgressBar()
        progress.setMinimum(0)
        progress.setMaximum(MCOUNTER_MAX + 1)
        progress.setValue(0)
        progress.setTextVisible(False)
        progress.setFixedWidth(180)
        lbl_status = QtWidgets.QLabel("Idle")
        top_row.addWidget(btn_refresh_all)
        top_row.addWidget(progress)
        top_row.addWidget(lbl_status)
        top_row.addStretch(1)
        tab_layout.addLayout(top_row)

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

        cols = 3
        for idx in range(MCOUNTER_MAX + 1):
            frame = QtWidgets.QFrame()
            frame.setObjectName(f"mcounterFrame{idx}")
            frame.setFrameShape(QtWidgets.QFrame.Shape.StyledPanel)
            frame.setStyleSheet("QFrame { border: 1px solid #bdbdbd; border-radius: 8px; padding: 8px; }")
            frame.setMinimumWidth(180)
            frame.setFixedHeight(120)
            frame.setSizePolicy(
                QtWidgets.QSizePolicy.Policy.Preferred,
                QtWidgets.QSizePolicy.Policy.Fixed,
            )
            vbox = QtWidgets.QVBoxLayout(frame)
            vbox.setContentsMargins(6, 6, 6, 6)
            vbox.setSpacing(4)

            title = QtWidgets.QLabel(f"Counter {idx}")
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
            btn_read = QtWidgets.QPushButton("Read")
            btn_init = QtWidgets.QPushButton("Init")
            btn_update = QtWidgets.QPushButton("Decrement")
            btn_refresh_one = QtWidgets.QPushButton("Refresh")
            for btn in (btn_read, btn_init, btn_update, btn_refresh_one):
                btn.setSizePolicy(
                    QtWidgets.QSizePolicy.Policy.Expanding,
                    QtWidgets.QSizePolicy.Policy.Fixed,
                )
                btn.setMinimumWidth(0)
            action_row.addWidget(btn_read, 0, 0)
            action_row.addWidget(btn_init, 0, 1)
            action_row.addWidget(btn_update, 0, 2)
            action_row.addWidget(btn_refresh_one, 1, 0, 1, 3)
            action_row.setColumnStretch(0, 1)
            action_row.setColumnStretch(1, 1)
            action_row.setColumnStretch(2, 1)

            vbox.addWidget(title)
            vbox.addWidget(status)
            vbox.addLayout(action_row)

            row = idx // cols
            col = idx % cols
            overview_layout.addWidget(frame, row, col)

            mcounter_cards[idx] = {
                "frame": frame,
                "status": status,
                "btn_read": btn_read,
                "btn_init": btn_init,
                "btn_update": btn_update,
                "btn_refresh_one": btn_refresh_one,
            }
            mcounter_states.setdefault(idx, "unknown")

            btn_read.clicked.connect(lambda _=False, i=idx: on_btnMCounterReadFromOverview_click(i))
            btn_init.clicked.connect(lambda _=False, i=idx: on_btnMCounterInitFromOverview_click(i))
            btn_update.clicked.connect(lambda _=False, i=idx: on_btnMCounterUpdateFromOverview_click(i))
            btn_refresh_one.clicked.connect(lambda _=False, i=idx: on_btnMCounterRefreshOne_click(i))

        scroll = QtWidgets.QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QtWidgets.QFrame.Shape.NoFrame)
        scroll_content = QtWidgets.QWidget()
        scroll_content_layout = QtWidgets.QVBoxLayout(scroll_content)
        scroll_content_layout.setContentsMargins(0, 0, 0, 0)
        scroll_content_layout.setSpacing(0)
        scroll_content_layout.addWidget(overview_group)
        scroll.setWidget(scroll_content)

        tab_layout.addWidget(scroll)

        window.btnMCounterRefreshAll = btn_refresh_all
        window.pbMCounterRefresh = progress
        window.lblMCounterRefreshStatus = lbl_status
        btn_refresh_all.clicked.connect(on_btnMCounterRefreshAll_click)
        refresh_mcounter_overview()

    def reset_mcounter_state(state: str):
        for idx in range(MCOUNTER_MAX + 1):
            mcounter_states[idx] = state
            mcounter_values.pop(idx, None)
        refresh_mcounter_overview()

    def on_session_changed(has_session=False, **_):
        reset_mcounter_state("unknown" if has_session else "no-session")
        window.btnMCounterRefreshAll.setEnabled(has_session)

    def on_device_changed(connected=False, **_):
        reset_mcounter_state("no-session")
        window.btnMCounterRefreshAll.setEnabled(False)

    create_mcounter_status_tab()
    bus.on("session_changed", on_session_changed)
    bus.on("device_changed", on_device_changed)
    on_device_changed(connected=False)
