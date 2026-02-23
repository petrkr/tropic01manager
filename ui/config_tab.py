from __future__ import annotations

import copy

from PyQt6 import QtWidgets, QtCore, QtGui
from tropicsquare.constants import config as cfg_constants


def setup_config_tab(window, bus, get_ts):
    def set_session_controls(enabled: bool):
        window.btnRConfigRead.setEnabled(enabled)
        window.btnRConfigWrite.setEnabled(enabled)
        window.btnRConfigErase.setEnabled(enabled)
        window.btnIConfigRead.setEnabled(enabled)
        window.btnIConfigWrite.setEnabled(enabled)
        window.btnRConfigBulkReadAll.setEnabled(enabled)
        window.btnRConfigBulkDiscard.setEnabled(enabled)
        window.btnRConfigBulkApply.setEnabled(enabled)
        window.tblRConfigBulk.setEnabled(enabled)

    def clear_layout(layout):
        while layout.count():
            item = layout.takeAt(0)
            widget = item.widget()
            if widget:
                widget.deleteLater()
            else:
                child_layout = item.layout()
                if child_layout:
                    clear_layout(child_layout)

    def is_permission_field(field):
        return hasattr(field, "get_slot_permission") and hasattr(field, "set_slot_permission")

    def is_permission_dict(value):
        if not isinstance(value, dict):
            return False
        keys = ("pkey_slot_0", "pkey_slot_1", "pkey_slot_2", "pkey_slot_3")
        return all(key in value for key in keys)

    def get_permission_specs(config):
        specs = []
        if isinstance(config, dict):
            for key, value in config.items():
                if is_permission_dict(value):
                    specs.append(("dict", key))
            return specs

        try:
            data_keys = list(config.to_dict().keys())
        except Exception:
            data_keys = []

        for key in data_keys:
            if not hasattr(config, key):
                continue
            field = getattr(config, key)
            if is_permission_field(field):
                specs.append(("attr", key))
            elif isinstance(field, dict) and is_permission_dict(field):
                specs.append(("attr_dict", key))

        if specs:
            return specs

        for key in ("permissions", "cfg_permissions", "func_permissions"):
            if not hasattr(config, key):
                continue
            field = getattr(config, key)
            if is_permission_field(field):
                specs.append(("attr", key))
            elif isinstance(field, dict) and is_permission_dict(field):
                specs.append(("attr_dict", key))
        return specs

    def get_permission_value(config, spec_type, key, slot):
        slot_key = f"pkey_slot_{slot}"
        if spec_type == "dict":
            return bool(config.get(key, {}).get(slot_key, False))
        field = getattr(config, key)
        if is_permission_field(field):
            return field.get_slot_permission(slot)
        if isinstance(field, dict):
            return bool(field.get(slot_key, False))
        return False

    def add_permission_row(grid, row, label_text, config, spec_type, key, editable=False):
        label = QtWidgets.QLabel(label_text)
        grid.addWidget(label, row, 0)
        checkboxes = []
        for i in range(4):
            cb = QtWidgets.QCheckBox(f"P{i}")
            cb.setChecked(get_permission_value(config, spec_type, key, i))
            cb.setEnabled(editable)
            grid.addWidget(cb, row, i + 1)
            checkboxes.append(cb)
        return checkboxes

    def render_uap_permissions(parent_layout, config, editable=False):
        wrapper = QtWidgets.QVBoxLayout()
        wrapper.setContentsMargins(0, 0, 0, 0)
        wrapper.setSpacing(6)

        header_row = QtWidgets.QHBoxLayout()
        header_row.setContentsMargins(0, 0, 0, 0)
        header_row.setSpacing(12)
        header_title = QtWidgets.QLabel("Pairing key slots")
        header_title.setStyleSheet("font-weight: bold;")
        header_row.addWidget(header_title)
        header_row.addStretch(1)
        for i in range(4):
            h = QtWidgets.QLabel(f"P{i}")
            h.setAlignment(QtCore.Qt.AlignmentFlag.AlignHCenter | QtCore.Qt.AlignmentFlag.AlignVCenter)
            h.setMinimumWidth(36)
            header_row.addWidget(h)
        wrapper.addLayout(header_row)

        line = QtWidgets.QFrame()
        line.setFrameShape(QtWidgets.QFrame.Shape.HLine)
        line.setFrameShadow(QtWidgets.QFrame.Shadow.Sunken)
        wrapper.addWidget(line)

        grid = QtWidgets.QGridLayout()
        grid.setContentsMargins(0, 0, 0, 0)
        grid.setHorizontalSpacing(12)
        grid.setVerticalSpacing(6)
        grid.setColumnStretch(0, 1)

        row = 0
        fields = []
        for spec_type, key in get_permission_specs(config):
            label = key.replace("_", " ")
            checkboxes = add_permission_row(grid, row, label, config, spec_type, key, editable=editable)
            fields.append(((spec_type, key), checkboxes))
            row += 1
        wrapper.addLayout(grid)
        wrapper.addStretch(1)

        parent_layout.addLayout(wrapper)
        return fields

    def render_key_values(parent_layout, config, editable=False):
        if isinstance(config, dict):
            data = config
        else:
            try:
                data = config.to_dict()
            except Exception:
                data = {"value": str(config)}

        form = QtWidgets.QFormLayout()
        fields = []
        for key, value in data.items():
            key_label = QtWidgets.QLabel(str(key))
            if editable and isinstance(value, bool):
                cb = QtWidgets.QCheckBox()
                cb.setChecked(value)
                if isinstance(config, dict):
                    fields.append((("scalar_dict", key, "bool"), cb))
                elif hasattr(config, key):
                    fields.append((("scalar_attr", key, "bool"), cb))
                else:
                    cb.setEnabled(False)
                form.addRow(key_label, cb)
            elif editable and isinstance(value, int):
                if str(key) == "gpo_func":
                    combo = QtWidgets.QComboBox()
                    gpo_options = [
                        (0, "0x0"),
                        (1, "0x1"),
                        (2, "0x2"),
                        (3, "0x3"),
                        (4, "0x4"),
                        (5, "ALWAYS_LOW (0x5) - Always in logic low state"),
                        (6, "ALWAYS_HIGH (0x6) - Always in logic high state"),
                        (7, "INTERRUPT (0x7) - L2 result active high interrupt"),
                    ]
                    for option_value, option_label in gpo_options:
                        combo.addItem(option_label, option_value)
                    current_idx = combo.findData(int(value))
                    if current_idx >= 0:
                        combo.setCurrentIndex(current_idx)
                    if isinstance(config, dict):
                        fields.append((("scalar_dict", key, "int"), combo))
                    elif hasattr(config, key):
                        fields.append((("scalar_attr", key, "int"), combo))
                    else:
                        combo.setEnabled(False)
                    form.addRow(key_label, combo)
                else:
                    sb = QtWidgets.QSpinBox()
                    sb.setRange(0, 0x7FFFFFFF)
                    sb.setValue(max(sb.minimum(), min(int(value), sb.maximum())))
                    if isinstance(config, dict):
                        fields.append((("scalar_dict", key, "int"), sb))
                    elif hasattr(config, key):
                        fields.append((("scalar_attr", key, "int"), sb))
                    else:
                        sb.setEnabled(False)
                    form.addRow(key_label, sb)
            else:
                form.addRow(key_label, QtWidgets.QLabel(str(value)))
        parent_layout.addLayout(form)
        return fields

    def render_config_details(layout, config, editable=False):
        clear_layout(layout)
        if get_permission_specs(config):
            return render_uap_permissions(layout, config, editable=editable)
        return render_key_values(layout, config, editable=editable)

    def build_uap_config_from_ui(config, fields):
        if isinstance(config, dict):
            new_config = copy.deepcopy(config)
        else:
            new_config = config.__class__(config._value)
        for key, checkboxes in fields:
            spec_type = "attr"
            field_key = key
            if isinstance(key, tuple) and len(key) == 2:
                spec_type, field_key = key

            if spec_type == "dict":
                if field_key not in new_config or not isinstance(new_config[field_key], dict):
                    new_config[field_key] = {}
                for i, cb in enumerate(checkboxes):
                    new_config[field_key][f"pkey_slot_{i}"] = cb.isChecked()
                continue

            if isinstance(checkboxes, list):
                field = getattr(new_config, field_key)
                if is_permission_field(field):
                    for i, cb in enumerate(checkboxes):
                        field.set_slot_permission(i, cb.isChecked())
                    setattr(new_config, field_key, field)
                elif isinstance(field, dict):
                    updated = dict(field)
                    for i, cb in enumerate(checkboxes):
                        updated[f"pkey_slot_{i}"] = cb.isChecked()
                    setattr(new_config, field_key, updated)
                continue

            control = checkboxes
            if isinstance(key, tuple) and len(key) == 3 and key[0] in ("scalar_dict", "scalar_attr"):
                target_type, target_key, value_type = key
                if isinstance(control, QtWidgets.QCheckBox):
                    new_value = control.isChecked()
                elif isinstance(control, QtWidgets.QSpinBox):
                    new_value = int(control.value())
                elif isinstance(control, QtWidgets.QComboBox):
                    new_value = int(control.currentData())
                else:
                    continue

                if value_type == "bool":
                    new_value = bool(new_value)
                elif value_type == "int":
                    new_value = int(new_value)

                if target_type == "scalar_dict" and isinstance(new_config, dict):
                    new_config[target_key] = new_value
                elif target_type == "scalar_attr" and hasattr(new_config, target_key):
                    setattr(new_config, target_key, new_value)
        return new_config

    def get_config_value_from_ui(config, fields):
        if fields:
            return build_uap_config_from_ui(config, fields)
        return config

    def set_raw_config_label(label, config):
        try:
            raw_value = int.from_bytes(config.to_bytes(), "big")
            label.setText(f"0x{raw_value:08X}")
        except Exception:
            if hasattr(config, "_value"):
                label.setText(f"0x{config._value:08X}")

    def clone_config(config):
        if hasattr(config, "_value"):
            try:
                return config.__class__(config._value)
            except Exception:
                pass
        return config

    def config_raw_key(config):
        try:
            return ("bytes", bytes(config.to_bytes()))
        except Exception:
            if hasattr(config, "_value"):
                return ("value", int(config._value))
            return ("str", str(config))

    def config_raw_text(config):
        key_type, key_value = config_raw_key(config)
        if key_type == "bytes":
            return "0x" + key_value.hex().upper()
        if key_type == "value":
            return f"0x{key_value:08X}"
        return str(key_value)

    def bind_uap_fields_to_raw_label(fields, on_change):
        for _, controls in fields:
            if isinstance(controls, list):
                for cb in controls:
                    cb.toggled.connect(on_change)
                continue
            if isinstance(controls, QtWidgets.QCheckBox):
                controls.toggled.connect(on_change)
            elif isinstance(controls, QtWidgets.QSpinBox):
                controls.valueChanged.connect(lambda _=0: on_change())
            elif isinstance(controls, QtWidgets.QComboBox):
                controls.currentIndexChanged.connect(lambda _=0: on_change())

    def refresh_rconfig_raw_label():
        config = getattr(window, "_rconfig_current", None)
        fields = getattr(window, "_rconfig_fields", [])
        if config is None:
            return
        set_raw_config_label(window.lblRConfigRaw, get_config_value_from_ui(config, fields))

    def refresh_iconfig_raw_label():
        config = getattr(window, "_iconfig_current", None)
        fields = getattr(window, "_iconfig_fields", [])
        if config is None:
            return
        set_raw_config_label(window.lblIConfigRaw, get_config_value_from_ui(config, fields))

    def get_cfg_constants():
        items = []
        for name, value in cfg_constants.__dict__.items():
            if name.startswith("CFG_") and isinstance(value, int):
                items.append((name, value))
        return sorted(items, key=lambda x: x[1])

    def get_rconfig_bulk_dirty_addresses():
        snapshot = getattr(window, "_rconfig_bulk_snapshot", {})
        current = getattr(window, "_rconfig_bulk_current", {})
        dirty = []
        for _, address in getattr(window, "_cfg_items", []):
            if address not in snapshot or address not in current:
                continue
            if config_raw_key(snapshot[address]) != config_raw_key(current[address]):
                dirty.append(address)
        return dirty

    def refresh_rconfig_bulk_status():
        snapshot = getattr(window, "_rconfig_bulk_snapshot", {})
        if not snapshot:
            window.lblRConfigBulkStatus.setText("No snapshot loaded")
            return
        dirty_count = len(get_rconfig_bulk_dirty_addresses())
        window.lblRConfigBulkStatus.setText(
            f"Snapshot loaded ({len(snapshot)} regs), modified: {dirty_count}"
        )

    def refresh_rconfig_bulk_row(address):
        row_by_addr = getattr(window, "_rconfig_bulk_row_by_addr", {})
        row = row_by_addr.get(address)
        if row is None:
            return
        current = getattr(window, "_rconfig_bulk_current", {}).get(address)
        snapshot = getattr(window, "_rconfig_bulk_snapshot", {}).get(address)
        if current is None:
            window.tblRConfigBulk.item(row, 2).setText("-")
            window.tblRConfigBulk.item(row, 3).setText("-")
            window.tblRConfigBulk.item(row, 4).setText("no data")
            return

        window.tblRConfigBulk.item(row, 2).setText(config_raw_text(current))
        window.tblRConfigBulk.item(row, 3).setText(current.__class__.__name__)
        state_item = window.tblRConfigBulk.item(row, 4)
        if snapshot is None:
            state_item.setText("loaded")
            state_item.setForeground(QtGui.QBrush(QtGui.QColor("#666666")))
        elif config_raw_key(snapshot) != config_raw_key(current):
            state_item.setText("modified")
            state_item.setForeground(QtGui.QBrush(QtGui.QColor("#b36b00")))
        else:
            state_item.setText("clean")
            state_item.setForeground(QtGui.QBrush(QtGui.QColor("#1b7f1b")))

    def refresh_rconfig_bulk_table():
        for _, address in getattr(window, "_cfg_items", []):
            refresh_rconfig_bulk_row(address)
        refresh_rconfig_bulk_status()

    def persist_rconfig_bulk_editor():
        address = getattr(window, "_rconfig_bulk_selected_address", None)
        if address is None:
            return
        fields = getattr(window, "_rconfig_bulk_fields", [])
        if not fields:
            return
        current = getattr(window, "_rconfig_bulk_current", {})
        config = current.get(address)
        if config is None:
            return
        current[address] = build_uap_config_from_ui(config, fields)
        window._rconfig_bulk_current = current
        refresh_rconfig_bulk_row(address)
        window.lblRConfigBulkRaw.setText(f"Raw: {config_raw_text(current[address])}")
        refresh_rconfig_bulk_status()

    def on_rconfig_bulk_editor_changed():
        persist_rconfig_bulk_editor()

    def on_tblRConfigBulk_selection_changed():
        if not hasattr(window, "tblRConfigBulk"):
            return
        persist_rconfig_bulk_editor()
        selected_rows = window.tblRConfigBulk.selectionModel().selectedRows()
        if not selected_rows:
            window._rconfig_bulk_selected_address = None
            window._rconfig_bulk_fields = []
            window.lblRConfigBulkSelected.setText("Selected: -")
            window.lblRConfigBulkRaw.setText("Raw: -")
            clear_layout(window.layoutRConfigBulkDetails)
            return
        row = selected_rows[0].row()
        addr_item = window.tblRConfigBulk.item(row, 1)
        if addr_item is None:
            return
        address = addr_item.data(QtCore.Qt.ItemDataRole.UserRole)
        current = getattr(window, "_rconfig_bulk_current", {})
        config = current.get(address)
        name = getattr(window, "_rconfig_bulk_name_by_addr", {}).get(address, f"0x{address:02X}")
        window._rconfig_bulk_selected_address = address
        window.lblRConfigBulkSelected.setText(f"Selected: {name} (0x{address:02X})")
        if config is None:
            window._rconfig_bulk_fields = []
            window.lblRConfigBulkRaw.setText("Raw: -")
            clear_layout(window.layoutRConfigBulkDetails)
            return
        window._rconfig_bulk_fields = render_config_details(window.layoutRConfigBulkDetails, config, editable=True)
        bind_uap_fields_to_raw_label(window._rconfig_bulk_fields, on_rconfig_bulk_editor_changed)
        window.lblRConfigBulkRaw.setText(f"Raw: {config_raw_text(config)}")

    def select_rconfig_bulk_row(address):
        row_by_addr = getattr(window, "_rconfig_bulk_row_by_addr", {})
        row = row_by_addr.get(address)
        if row is None:
            return
        window.tblRConfigBulk.clearSelection()
        window.tblRConfigBulk.setCurrentCell(row, 0)
        window.tblRConfigBulk.selectRow(row)

    def on_btnRConfigBulkReadAll_click():
        ts = get_ts()
        total = len(getattr(window, "_cfg_items", []))
        window.btnRConfigBulkReadAll.setEnabled(False)
        window.pbRConfigBulkProgress.setRange(0, total if total else 1)
        window.pbRConfigBulkProgress.setValue(0)
        window.lblRConfigBulkProgress.setText("Starting...")
        QtWidgets.QApplication.processEvents()
        try:
            snapshot = {}
            current = {}
            for idx, (_, address) in enumerate(getattr(window, "_cfg_items", []), start=1):
                window.lblRConfigBulkProgress.setText(f"Reading register {idx}/{total}...")
                window.pbRConfigBulkProgress.setValue(idx - 1)
                QtWidgets.QApplication.processEvents()
                cfg = ts.r_config_read(address)
                snapshot[address] = clone_config(cfg)
                current[address] = clone_config(cfg)
            window._rconfig_bulk_snapshot = snapshot
            window._rconfig_bulk_current = current
            window._rconfig_bulk_selected_address = None
            window._rconfig_bulk_fields = []
            refresh_rconfig_bulk_table()
            if window.tblRConfigBulk.rowCount() > 0:
                first_addr = getattr(window, "_cfg_items", [("", None)])[0][1]
                if first_addr is not None:
                    select_rconfig_bulk_row(first_addr)
            window.pbRConfigBulkProgress.setValue(total if total else 1)
            window.lblRConfigBulkProgress.setText("Done")
        except Exception as e:
            QtWidgets.QMessageBox.critical(window, "R-Config Read All Failed", str(e))
            window.lblRConfigBulkProgress.setText("Failed")
        finally:
            window.btnRConfigBulkReadAll.setEnabled(window.btnRConfigRead.isEnabled())

    def on_btnRConfigBulkDiscard_click():
        snapshot = getattr(window, "_rconfig_bulk_snapshot", {})
        if not snapshot:
            QtWidgets.QMessageBox.warning(window, "R-Config Discard", "Read all registers first")
            return
        current_addr = getattr(window, "_rconfig_bulk_selected_address", None)
        window._rconfig_bulk_selected_address = None
        window._rconfig_bulk_fields = []
        window.lblRConfigBulkSelected.setText("Selected: -")
        window.lblRConfigBulkRaw.setText("Raw: -")
        clear_layout(window.layoutRConfigBulkDetails)
        window._rconfig_bulk_current = {addr: clone_config(cfg) for addr, cfg in snapshot.items()}
        refresh_rconfig_bulk_table()
        if current_addr is not None:
            select_rconfig_bulk_row(current_addr)

    def on_btnRConfigBulkApply_click():
        ts = get_ts()
        snapshot = getattr(window, "_rconfig_bulk_snapshot", {})
        current = getattr(window, "_rconfig_bulk_current", {})
        if not snapshot or not current:
            QtWidgets.QMessageBox.warning(window, "R-Config Apply", "Read all registers first")
            return
        persist_rconfig_bulk_editor()
        dirty_addresses = get_rconfig_bulk_dirty_addresses()
        if not dirty_addresses:
            QtWidgets.QMessageBox.information(window, "R-Config Apply", "No modified registers")
            return
        confirm = QtWidgets.QMessageBox.warning(
            window,
            "R-Config Apply",
            f"Modified registers: {len(dirty_addresses)}\n"
            "Apply will erase whole R-CONFIG and write all registers from snapshot.\n"
            "Continue?",
            QtWidgets.QMessageBox.StandardButton.Yes | QtWidgets.QMessageBox.StandardButton.No,
        )
        if confirm != QtWidgets.QMessageBox.StandardButton.Yes:
            return
        total = len(getattr(window, "_cfg_items", []))
        progress_total = total + 1 if total else 1
        window.btnRConfigBulkApply.setEnabled(False)
        window.pbRConfigBulkProgress.setRange(0, progress_total)
        window.pbRConfigBulkProgress.setValue(0)
        window.lblRConfigBulkProgress.setText("Erasing...")
        QtWidgets.QApplication.processEvents()
        try:
            ts.r_config_erase()
            window.pbRConfigBulkProgress.setValue(1)
            for idx, (_, address) in enumerate(getattr(window, "_cfg_items", []), start=1):
                window.lblRConfigBulkProgress.setText(f"Writing register {idx}/{total}...")
                window.pbRConfigBulkProgress.setValue(idx + 1)
                QtWidgets.QApplication.processEvents()
                ts.r_config_write(address, current[address])
            window._rconfig_bulk_snapshot = {addr: clone_config(cfg) for addr, cfg in current.items()}
            refresh_rconfig_bulk_table()
            window.pbRConfigBulkProgress.setValue(progress_total)
            window.lblRConfigBulkProgress.setText("Done")
            QtWidgets.QMessageBox.information(window, "R-Config Apply", "Configuration applied successfully")
        except Exception as e:
            QtWidgets.QMessageBox.critical(window, "R-Config Apply Failed", str(e))
            window.lblRConfigBulkProgress.setText("Failed")
        finally:
            window.btnRConfigBulkApply.setEnabled(window.btnRConfigRead.isEnabled())

    def on_btnRConfigRead_click():
        ts = get_ts()
        try:
            address = window.cmbRConfigReg.currentData()
            config = ts.r_config_read(address)
            window._rconfig_current = config
            window._rconfig_fields = render_config_details(window.layoutRConfigDetails, config, editable=True)
            bind_uap_fields_to_raw_label(window._rconfig_fields, refresh_rconfig_raw_label)
            refresh_rconfig_raw_label()
        except Exception as e:
            QtWidgets.QMessageBox.critical(window, "R-Config Read Failed", str(e))

    def on_btnIConfigRead_click():
        ts = get_ts()
        try:
            address = window.cmbIConfigReg.currentData()
            config = ts.i_config_read(address)
            window._iconfig_current = config
            window._iconfig_fields = render_config_details(window.layoutIConfigDetails, config, editable=True)
            bind_uap_fields_to_raw_label(window._iconfig_fields, refresh_iconfig_raw_label)
            refresh_iconfig_raw_label()
        except Exception as e:
            QtWidgets.QMessageBox.critical(window, "I-Config Read Failed", str(e))

    def on_btnRConfigWrite_click():
        ts = get_ts()
        config = getattr(window, "_rconfig_current", None)
        fields = getattr(window, "_rconfig_fields", [])
        if config is None:
            QtWidgets.QMessageBox.warning(window, "R-Config Write", "Read config first")
            return
        if not fields:
            QtWidgets.QMessageBox.warning(window, "R-Config Write", "Write not supported for this config")
            return
        try:
            address = window.cmbRConfigReg.currentData()
            new_config = build_uap_config_from_ui(config, fields)
            ts.r_config_write(address, new_config)
            QtWidgets.QMessageBox.information(window, "R-Config Write", "Config written successfully")
            on_btnRConfigRead_click()
        except Exception as e:
            QtWidgets.QMessageBox.critical(window, "R-Config Write Failed", str(e))

    def on_btnRConfigErase_click():
        ts = get_ts()
        confirm = QtWidgets.QMessageBox.warning(
            window,
            "R-Config Erase",
            "Erase whole R-CONFIG?\nThis sets all bits of all COs to 1.\nContinue?",
            QtWidgets.QMessageBox.StandardButton.Yes | QtWidgets.QMessageBox.StandardButton.No,
        )
        if confirm != QtWidgets.QMessageBox.StandardButton.Yes:
            return
        try:
            ts.r_config_erase()
            QtWidgets.QMessageBox.information(window, "R-Config Erase", "R-CONFIG erased successfully")
            on_btnRConfigRead_click()
        except Exception as e:
            QtWidgets.QMessageBox.critical(window, "R-Config Erase Failed", str(e))

    def on_btnIConfigWrite_click():
        ts = get_ts()
        config = getattr(window, "_iconfig_current", None)
        fields = getattr(window, "_iconfig_fields", [])
        if config is None:
            QtWidgets.QMessageBox.warning(window, "I-Config Write", "Read config first")
            return
        if not fields:
            QtWidgets.QMessageBox.warning(window, "I-Config Write", "Write not supported for this config")
            return
        confirm = QtWidgets.QMessageBox.warning(
            window,
            "I-Config Write",
            "I-CONFIG is OTP. This is irreversible.\nContinue?",
            QtWidgets.QMessageBox.StandardButton.Yes | QtWidgets.QMessageBox.StandardButton.No,
        )
        if confirm != QtWidgets.QMessageBox.StandardButton.Yes:
            return
        if not hasattr(ts, "i_config_write"):
            QtWidgets.QMessageBox.warning(window, "I-Config Write", "Current API does not provide i_config_write")
            return
        try:
            address = window.cmbIConfigReg.currentData()
            new_config = build_uap_config_from_ui(config, fields)
            ts.i_config_write(address, new_config)
            QtWidgets.QMessageBox.information(window, "I-Config Write", "Config written successfully")
            on_btnIConfigRead_click()
        except Exception as e:
            QtWidgets.QMessageBox.critical(window, "I-Config Write Failed", str(e))

    cfg_items = get_cfg_constants()
    window._cfg_items = cfg_items
    for name, value in cfg_items:
        window.cmbRConfigReg.addItem(f"{name} (0x{value:02X})", value)
        window.cmbIConfigReg.addItem(f"{name} (0x{value:02X})", value)
    window._rconfig_bulk_name_by_addr = {value: name for name, value in cfg_items}
    window._rconfig_bulk_row_by_addr = {}
    window._rconfig_bulk_snapshot = {}
    window._rconfig_bulk_current = {}
    window._rconfig_bulk_selected_address = None
    window._rconfig_bulk_fields = []
    window.layoutRConfigBulk.setContentsMargins(0, 0, 0, 0)
    window.layoutRConfigBulk.setSpacing(6)
    window.layoutRConfigBulkTop.setContentsMargins(0, 0, 0, 0)
    window.layoutRConfigBulkTop.setSpacing(8)
    window.layoutRConfigBulkLeft.setContentsMargins(0, 0, 0, 0)
    window.layoutRConfigBulkLeft.setSpacing(8)
    window.layoutRConfigBulkRight.setContentsMargins(0, 0, 0, 0)
    window.layoutRConfigBulkRight.setSpacing(8)
    window.layoutRConfigBulkDetails.setContentsMargins(0, 0, 0, 0)
    window.layoutRConfigBulkDetails.setSpacing(0)
    window.layoutRConfigBulkDetails.setAlignment(QtCore.Qt.AlignmentFlag.AlignTop)
    window.layoutRConfigBulk.setStretch(0, 0)
    window.layoutRConfigBulk.setStretch(1, 1)
    window.pbRConfigBulkProgress.setMinimum(0)
    window.pbRConfigBulkProgress.setMaximum(len(cfg_items) if cfg_items else 1)
    window.pbRConfigBulkProgress.setValue(0)
    window.pbRConfigBulkProgress.setTextVisible(False)
    window.pbRConfigBulkProgress.setFixedWidth(180)
    window.lblRConfigBulkProgress.setText("Idle")
    window.tblRConfigBulk.setRowCount(len(cfg_items))
    window.tblRConfigBulk.setColumnCount(5)
    window.tblRConfigBulk.setHorizontalHeaderLabels(["Reg", "Addr", "Raw", "Type", "State"])
    for row, (name, value) in enumerate(cfg_items):
        name_item = QtWidgets.QTableWidgetItem(name)
        addr_item = QtWidgets.QTableWidgetItem(f"0x{value:02X}")
        raw_item = QtWidgets.QTableWidgetItem("-")
        type_item = QtWidgets.QTableWidgetItem("-")
        state_item = QtWidgets.QTableWidgetItem("no data")
        addr_item.setData(QtCore.Qt.ItemDataRole.UserRole, value)
        for item in (name_item, addr_item, raw_item, type_item, state_item):
            item.setFlags(item.flags() & ~QtCore.Qt.ItemFlag.ItemIsEditable)
        window.tblRConfigBulk.setItem(row, 0, name_item)
        window.tblRConfigBulk.setItem(row, 1, addr_item)
        window.tblRConfigBulk.setItem(row, 2, raw_item)
        window.tblRConfigBulk.setItem(row, 3, type_item)
        window.tblRConfigBulk.setItem(row, 4, state_item)
        window._rconfig_bulk_row_by_addr[value] = row
    window.tblRConfigBulk.horizontalHeader().setSectionResizeMode(0, QtWidgets.QHeaderView.ResizeMode.Stretch)
    window.tblRConfigBulk.horizontalHeader().setSectionResizeMode(1, QtWidgets.QHeaderView.ResizeMode.ResizeToContents)
    window.tblRConfigBulk.horizontalHeader().setSectionResizeMode(2, QtWidgets.QHeaderView.ResizeMode.ResizeToContents)
    window.tblRConfigBulk.horizontalHeader().setSectionResizeMode(3, QtWidgets.QHeaderView.ResizeMode.ResizeToContents)
    window.tblRConfigBulk.horizontalHeader().setSectionResizeMode(4, QtWidgets.QHeaderView.ResizeMode.ResizeToContents)
    window.tblRConfigBulk.verticalHeader().setVisible(False)
    window.btnRConfigRead.clicked.connect(on_btnRConfigRead_click)
    window.btnIConfigRead.clicked.connect(on_btnIConfigRead_click)
    window.btnRConfigWrite.clicked.connect(on_btnRConfigWrite_click)
    window.btnRConfigErase.clicked.connect(on_btnRConfigErase_click)
    window.btnIConfigWrite.clicked.connect(on_btnIConfigWrite_click)
    window.btnRConfigBulkReadAll.clicked.connect(on_btnRConfigBulkReadAll_click)
    window.btnRConfigBulkDiscard.clicked.connect(on_btnRConfigBulkDiscard_click)
    window.btnRConfigBulkApply.clicked.connect(on_btnRConfigBulkApply_click)
    window.tblRConfigBulk.itemSelectionChanged.connect(on_tblRConfigBulk_selection_changed)

    def on_device_changed(connected=False, **_):
        set_session_controls(False)
    def on_session_changed(has_session=False, **_):
        set_session_controls(has_session)
    bus.on("device_changed", on_device_changed)
    bus.on("session_changed", on_session_changed)
    on_device_changed(connected=False)
