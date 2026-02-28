from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass

from PyQt6 import QtWidgets, QtGui, QtCore
from tropicsquare.constants import MCOUNTER_MAX, MEM_DATA_MAX_SIZE
from tropicsquare.crc import CRC
from tropicsquare.exceptions import TropicSquareError


HOST_SETTINGS_KEY = "mac_and_destroy/pin_v1"
ZERO_KEY = b"\x00" * 32
ENTROPY_MIX_KEY = b"mad-pin-v1"
BLOB_MAGIC = b"MAD1"
BLOB_VERSION = 1
BLOB_FIXED_SIZE = 4 + 1 + 1 + 1 + 1 + 1 + 32 + 17  # hdr + t + reserved (without crc16)

@dataclass
class PinStateBlob:
    n: int
    t: bytes
    ciphertexts: list[bytes]
    base_slot: int = 0
    mcounter_slot: int = 0
    flags: int = 0
    reserved: bytes = b"\x00" * 17

    def __post_init__(self):
        if self.n < 1 or self.n > 128:
            raise ValueError("n must be in range 1-128")
        if len(self.t) != 32:
            raise ValueError("t must be 32 bytes")
        if len(self.ciphertexts) != self.n:
            raise ValueError("ciphertexts count must match n")
        if any(len(item) != 32 for item in self.ciphertexts):
            raise ValueError("each ciphertext must be 32 bytes")
        if self.base_slot < 0 or self.base_slot > 127:
            raise ValueError("base_slot must be in range 0-127")
        if self.mcounter_slot < 0 or self.mcounter_slot > MCOUNTER_MAX:
            raise ValueError(f"mcounter_slot must be in range 0-{MCOUNTER_MAX}")
        if self.flags < 0 or self.flags > 255:
            raise ValueError("flags must be in range 0-255")
        if len(self.reserved) != 17:
            raise ValueError("reserved must be 17 bytes")

    def to_bytes(self) -> bytes:
        payload = bytearray()
        payload.extend(BLOB_MAGIC)
        payload.append(BLOB_VERSION)
        payload.append(self.n)
        payload.append(self.base_slot)
        payload.append(self.mcounter_slot)
        payload.append(self.flags)
        payload.extend(self.t)
        payload.extend(self.reserved)
        for item in self.ciphertexts:
            payload.extend(item)

        crc = int.from_bytes(CRC.crc16(bytes(payload)), "little")
        payload.extend(crc.to_bytes(2, "little"))
        if len(payload) > MEM_DATA_MAX_SIZE:
            raise ValueError("encoded blob exceeds MEM Data slot size")
        return bytes(payload)

    @classmethod
    def from_bytes(cls, raw: bytes) -> "PinStateBlob":
        if len(raw) < BLOB_FIXED_SIZE + 2:
            raise ValueError("blob too short")
        payload = raw[:-2]

        if payload[:4] != BLOB_MAGIC:
            raise ValueError("invalid blob magic")

        stored_crc = int.from_bytes(raw[-2:], "little")
        calc_crc = int.from_bytes(CRC.crc16(payload), "little")
        if stored_crc != calc_crc:
            raise ValueError("blob CRC16 mismatch")

        if payload[4] != BLOB_VERSION:
            raise ValueError("unsupported blob version")

        n = int(payload[5])
        base_slot = int(payload[6])
        mcounter_slot = int(payload[7])
        flags = int(payload[8])
        t = payload[9:41]
        reserved = payload[41:58]
        expected_size = BLOB_FIXED_SIZE + n * 32 + 2
        if len(raw) != expected_size:
            raise ValueError("blob size does not match n")

        ciphertexts = []
        offset = BLOB_FIXED_SIZE
        for _ in range(n):
            ciphertexts.append(payload[offset:offset + 32])
            offset += 32

        return cls(
            n=n,
            t=t,
            ciphertexts=ciphertexts,
            base_slot=base_slot,
            mcounter_slot=mcounter_slot,
            flags=flags,
            reserved=reserved,
        )


def _kdf(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def _xor32(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _parse_hex(value: str, field_name: str) -> bytes:
    cleaned = value.strip().replace(" ", "").replace("\n", "")
    if not cleaned:
        return b""
    if len(cleaned) % 2 != 0:
        raise ValueError(f"{field_name} must have even HEX length")
    try:
        return bytes.fromhex(cleaned)
    except ValueError:
        raise ValueError(f"{field_name} must be valid HEX")


def _validate_state(state):
    n = int(state["n"])
    i = int(state["i"])
    t = state["t"]
    c = state["c"]
    if n < 1 or n > 128:
        raise ValueError("Invalid state: n out of range")
    if i < 0 or i > n:
        raise ValueError("Invalid state: i out of range")
    if len(t) != 32:
        raise ValueError("Invalid state: t length")
    if len(c) != n:
        raise ValueError("Invalid state: c length")
    if any(len(x) != 32 for x in c):
        raise ValueError("Invalid state: c_i length")


def _state_to_payload(state, *, include_n=True, include_i=True):
    _validate_state(state)
    payload = {
        "v": 1,
        "t": state["t"].hex(),
        "c": [x.hex() for x in state["c"]],
    }
    if include_n:
        payload["n"] = int(state["n"])
    if include_i:
        payload["i"] = int(state["i"])
    return payload


def _payload_to_state(payload):
    if int(payload.get("v", 0)) != 1:
        raise ValueError("Stored state has unsupported version")
    c = [bytes.fromhex(x) for x in payload["c"]]
    n = int(payload["n"]) if "n" in payload else len(c)
    i = int(payload["i"]) if "i" in payload else n
    t = bytes.fromhex(payload["t"])
    state = {"n": n, "i": i, "t": t, "c": c}
    _validate_state(state)
    return state


def _calc_state_max_n_mem():
    max_n = 0
    for n in range(1, 129):
        try:
            probe = PinStateBlob(
                n=n,
                t=b"\x00" * 32,
                ciphertexts=[b"\x00" * 32 for _ in range(n)],
            )
            if len(probe.to_bytes()) <= MEM_DATA_MAX_SIZE:
                max_n = n
        except ValueError:
            continue
    return max_n


STATE_MAX_N_MEM = _calc_state_max_n_mem()


def setup_mac_and_destroy_pin(window, bus, get_ts):
    layout = window.layoutMacAndDestroyPin
    layout.setAlignment(QtCore.Qt.AlignmentFlag.AlignTop)
    layout.setRowStretch(11, 1)

    settings = QtCore.QSettings("tropic01manager", "tropic01manager")

    lbl_storage = QtWidgets.QLabel("State storage")
    cmb_storage = QtWidgets.QComboBox()
    cmb_storage.addItem("Host settings", "host")
    cmb_storage.addItem("Tropic MEM Data", "tropic")
    saved_storage = str(settings.value("mac_and_destroy/pin_storage", "host"))
    storage_idx = cmb_storage.findData(saved_storage)
    if storage_idx >= 0:
        cmb_storage.setCurrentIndex(storage_idx)

    lbl_storage_slot = QtWidgets.QLabel("Data slot (0-511)")
    le_storage_slot = QtWidgets.QLineEdit()
    le_storage_slot.setValidator(QtGui.QIntValidator(0, 511))
    le_storage_slot.setText(str(settings.value("mac_and_destroy/pin_storage_slot", "0")))
    lbl_counter_slot = QtWidgets.QLabel(f"MCounter slot (0-{MCOUNTER_MAX})")
    le_counter_slot = QtWidgets.QLineEdit()
    le_counter_slot.setValidator(QtGui.QIntValidator(0, MCOUNTER_MAX))
    le_counter_slot.setText(str(settings.value("mac_and_destroy/pin_storage_counter_slot", "0")))

    lbl_entropy = QtWidgets.QLabel("Entropy source")
    cmb_entropy = QtWidgets.QComboBox()
    cmb_entropy.addItem("TropicSquare random (recommended)", "ts")
    cmb_entropy.addItem("Host secrets", "host")
    cmb_entropy.addItem("TS random + Host secrets (mix)", "mix")
    cmb_entropy.addItem("Custom/User secret (HEX 32B)", "user")
    saved_entropy = str(settings.value("mac_and_destroy/pin_entropy", "ts"))
    idx = cmb_entropy.findData(saved_entropy)
    if idx >= 0:
        cmb_entropy.setCurrentIndex(idx)

    lbl_user_secret = QtWidgets.QLabel("User secret (HEX, 32 bytes)")
    le_user_secret = QtWidgets.QLineEdit()
    le_user_secret.setPlaceholderText("64 hex chars")
    le_user_secret.setText(str(settings.value("mac_and_destroy/pin_entropy_user_secret", "")))

    lbl_attempts = QtWidgets.QLabel("Attempts (n, 1-128)")
    le_attempts = QtWidgets.QLineEdit()
    le_attempts.setValidator(QtGui.QIntValidator(1, 128))
    le_attempts.setText(str(settings.value("mac_and_destroy/pin_attempts", "5")))

    lbl_pin = QtWidgets.QLabel("PIN")
    le_pin = QtWidgets.QLineEdit()
    le_pin.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)

    lbl_a = QtWidgets.QLabel("Additional data A (HEX, optional)")
    le_a = QtWidgets.QLineEdit()
    le_a.setPlaceholderText("e.g. 01A2FF")

    btn_setup = QtWidgets.QPushButton("New PIN Setup")
    btn_verify = QtWidgets.QPushButton("PIN Entry Check")

    lbl_remaining_name = QtWidgets.QLabel("Remaining attempts")
    lbl_remaining = QtWidgets.QLabel("-")
    lbl_status_name = QtWidgets.QLabel("Status")
    lbl_status = QtWidgets.QLabel("No PIN state")
    lbl_key = QtWidgets.QLabel("Derived key k (HEX)")
    le_key = QtWidgets.QLineEdit()
    le_key.setReadOnly(True)

    layout.addWidget(lbl_storage, 0, 0)
    layout.addWidget(cmb_storage, 0, 1, 1, 2)
    layout.addWidget(lbl_storage_slot, 1, 0)
    layout.addWidget(le_storage_slot, 1, 1, 1, 2)
    layout.addWidget(lbl_counter_slot, 2, 0)
    layout.addWidget(le_counter_slot, 2, 1, 1, 2)
    layout.addWidget(lbl_entropy, 3, 0)
    layout.addWidget(cmb_entropy, 3, 1, 1, 2)
    layout.addWidget(lbl_user_secret, 4, 0)
    layout.addWidget(le_user_secret, 4, 1, 1, 2)
    layout.addWidget(lbl_attempts, 5, 0)
    layout.addWidget(le_attempts, 5, 1, 1, 2)
    layout.addWidget(lbl_pin, 6, 0)
    layout.addWidget(le_pin, 6, 1, 1, 2)
    layout.addWidget(lbl_a, 7, 0)
    layout.addWidget(le_a, 7, 1, 1, 2)
    layout.addWidget(btn_setup, 8, 1)
    layout.addWidget(btn_verify, 8, 2)
    layout.addWidget(lbl_remaining_name, 9, 0)
    layout.addWidget(lbl_remaining, 9, 1, 1, 2)
    layout.addWidget(lbl_status_name, 10, 0)
    layout.addWidget(lbl_status, 10, 1, 1, 2)
    layout.addWidget(lbl_key, 11, 0)
    layout.addWidget(le_key, 11, 1, 1, 2)
    sync_counter_slot_from_state = False

    def current_storage_slot():
        slot_text = le_storage_slot.text().strip()
        if not slot_text:
            raise ValueError("Data slot is required for Tropic storage")
        slot = int(slot_text)
        if slot < 0 or slot > 511:
            raise ValueError("Data slot must be in range 0-511")
        return slot

    def current_counter_slot():
        slot_text = le_counter_slot.text().strip()
        if not slot_text:
            raise ValueError("MCounter slot is required for Tropic storage")
        slot = int(slot_text)
        if slot < 0 or slot > MCOUNTER_MAX:
            raise ValueError(f"MCounter slot must be in range 0-{MCOUNTER_MAX}")
        return slot

    def load_state_from_host():
        raw = settings.value(HOST_SETTINGS_KEY, "")
        if not raw:
            return None
        payload = json.loads(str(raw))
        return _payload_to_state(payload)

    def save_state_to_host(state):
        payload = _state_to_payload(state)
        settings.setValue(HOST_SETTINGS_KEY, json.dumps(payload))

    def load_state_from_tropic(ts, slot: int):
        raw = ts.mem_data_read(slot)
        if not raw:
            return None
        blob = PinStateBlob.from_bytes(raw)
        return {
            "n": blob.n,
            "i": blob.n,
            "t": blob.t,
            "c": blob.ciphertexts,
            "mcounter_slot": blob.mcounter_slot,
        }

    def save_state_to_tropic(ts, slot: int, state):
        blob = PinStateBlob(
            n=int(state["n"]),
            t=state["t"],
            ciphertexts=list(state["c"]),
            base_slot=0,
            mcounter_slot=current_counter_slot(),
        )
        encoded = blob.to_bytes()
        try:
            ts.mem_data_erase(slot)
        except Exception:
            pass
        ts.mem_data_write(encoded, slot)

    def load_state():
        mode = cmb_storage.currentData()
        if mode == "host":
            return load_state_from_host()
        ts = get_ts()
        if ts is None:
            raise ValueError("Tropic storage selected: connect device and start session")
        slot = current_storage_slot()
        state = load_state_from_tropic(ts, slot)
        if not state:
            return None
        counter = ts.mcounter_get(current_counter_slot())
        if counter < 0 or counter > state["n"]:
            raise ValueError("MCounter value is out of range for stored state")
        state["i"] = counter
        return state

    def save_state(state):
        mode = cmb_storage.currentData()
        if mode == "host":
            save_state_to_host(state)
            return
        ts = get_ts()
        if ts is None:
            raise ValueError("Tropic storage selected: connect device and start session")
        slot = current_storage_slot()
        save_state_to_tropic(ts, slot, state)

    def update_entropy_ui():
        is_user = cmb_entropy.currentData() == "user"
        lbl_user_secret.setVisible(is_user)
        le_user_secret.setVisible(is_user)

    def update_storage_ui():
        nonlocal sync_counter_slot_from_state
        is_tropic = cmb_storage.currentData() == "tropic"
        lbl_storage_slot.setVisible(is_tropic)
        le_storage_slot.setVisible(is_tropic)
        lbl_counter_slot.setVisible(is_tropic)
        le_counter_slot.setVisible(is_tropic)
        if is_tropic:
            sync_counter_slot_from_state = True
        refresh_state_label()

    def on_storage_slot_changed(_):
        nonlocal sync_counter_slot_from_state
        sync_counter_slot_from_state = True
        refresh_state_label()

    cmb_entropy.currentIndexChanged.connect(update_entropy_ui)
    cmb_storage.currentIndexChanged.connect(update_storage_ui)
    le_storage_slot.textChanged.connect(on_storage_slot_changed)
    le_counter_slot.textChanged.connect(lambda _: refresh_state_label())
    update_entropy_ui()

    def refresh_state_label():
        nonlocal sync_counter_slot_from_state
        try:
            state = load_state()
        except Exception as e:
            lbl_remaining.setText("-")
            lbl_status.setText(str(e))
            return
        if not state:
            lbl_remaining.setText("-")
            lbl_status.setText("No PIN state")
            return
        if (
            cmb_storage.currentData() == "tropic"
            and sync_counter_slot_from_state
            and "mcounter_slot" in state
        ):
            slot_text = str(state["mcounter_slot"])
            if le_counter_slot.text() != slot_text:
                le_counter_slot.blockSignals(True)
                le_counter_slot.setText(slot_text)
                le_counter_slot.blockSignals(False)
            sync_counter_slot_from_state = False
            try:
                state = load_state()
            except Exception as e:
                lbl_remaining.setText("-")
                lbl_status.setText(str(e))
                return
        lbl_remaining.setText(f"{state['i']} / {state['n']}")
        lbl_status.setText("State loaded")
        le_attempts.setText(str(state["n"]))

    def read_pin_and_a():
        pin = le_pin.text().encode("utf-8")
        if not pin:
            raise ValueError("PIN is required")
        additional = _parse_hex(le_a.text(), "Additional data A")
        return pin, additional

    def on_setup_click():
        ts = get_ts()
        try:
            attempts_text = le_attempts.text().strip()
            if not attempts_text:
                raise ValueError("Attempts count is required")
            n = int(attempts_text)
            if n < 1 or n > 128:
                raise ValueError("Attempts must be in range 1-128")
            settings.setValue("mac_and_destroy/pin_attempts", str(n))
            storage_mode = cmb_storage.currentData()
            settings.setValue("mac_and_destroy/pin_storage", str(storage_mode))
            settings.setValue("mac_and_destroy/pin_storage_slot", le_storage_slot.text())
            settings.setValue("mac_and_destroy/pin_storage_counter_slot", le_counter_slot.text())
            if storage_mode == "tropic" and n > STATE_MAX_N_MEM:
                raise ValueError(
                    f"Tropic MEM Data storage supports max n={STATE_MAX_N_MEM} in one slot"
                )
            entropy_mode = cmb_entropy.currentData()
            settings.setValue("mac_and_destroy/pin_entropy", str(entropy_mode))
            settings.setValue("mac_and_destroy/pin_entropy_user_secret", le_user_secret.text())

            pin, additional = read_pin_and_a()
            pin_input = pin + additional

            if entropy_mode == "ts":
                s = ts.get_random(32)
            elif entropy_mode == "host":
                s = secrets.token_bytes(32)
            elif entropy_mode == "user":
                s = _parse_hex(le_user_secret.text(), "User secret")
                if len(s) != 32:
                    raise ValueError("User secret must be exactly 32 bytes (64 hex chars)")
            else:
                ts_random = ts.get_random(32)
                host_random = secrets.token_bytes(32)
                s = _kdf(ENTROPY_MIX_KEY, ts_random + host_random)
            if len(s) != 32:
                raise ValueError("Entropy source did not return 32 bytes")
            t = _kdf(s, b"\x00")
            u = _kdf(s, b"\x01")
            v = _kdf(ZERO_KEY, pin_input)

            ciphertexts = []
            for slot in range(n):
                ts.mac_and_destroy(slot, u)
                w_i = ts.mac_and_destroy(slot, v)
                k_i = _kdf(w_i, pin_input)
                ciphertexts.append(_xor32(k_i, s))
                ts.mac_and_destroy(slot, u)

            state = {"n": n, "i": n, "t": t, "c": ciphertexts}
            save_state(state)
            if storage_mode == "tropic":
                ts.mcounter_init(current_counter_slot(), n)

            k = _kdf(s, b"\x02")
            le_key.setText(k.hex())
            lbl_status.setText("Setup OK")
            refresh_state_label()
        except ValueError as e:
            QtWidgets.QMessageBox.warning(window, "Invalid Input", str(e))
        except TropicSquareError as e:
            QtWidgets.QMessageBox.critical(window, "PIN Setup Failed", str(e))
        except Exception as e:
            QtWidgets.QMessageBox.critical(window, "PIN Setup Failed", str(e))

    def on_verify_click():
        ts = get_ts()
        try:
            state = load_state()
            if not state:
                raise ValueError("No stored PIN state. Run New PIN Setup first")
            if state["i"] <= 0:
                raise ValueError("No attempts remaining")

            pin, additional = read_pin_and_a()
            pin_input = pin + additional

            storage_mode = cmb_storage.currentData()
            if storage_mode == "host":
                i = state["i"] - 1
                state["i"] = i
                save_state(state)
            else:
                counter_slot = current_counter_slot()
                ts.mcounter_update(counter_slot)
                i = ts.mcounter_get(counter_slot)
                if i < 0 or i > state["n"] - 1:
                    raise ValueError("MCounter update returned invalid value")
                state["i"] = i
            refresh_state_label()

            v = _kdf(ZERO_KEY, pin_input)
            w_i = ts.mac_and_destroy(i, v)
            k_i = _kdf(w_i, pin_input)
            s = _xor32(k_i, state["c"][i])
            t = _kdf(s, b"\x00")

            if t != state["t"]:
                le_key.clear()
                lbl_status.setText("PIN check failed")
                refresh_state_label()
                return

            u = _kdf(s, b"\x01")
            for slot in range(i, state["n"]):
                ts.mac_and_destroy(slot, u)

            if storage_mode == "host":
                state["i"] = state["n"]
                save_state(state)
            else:
                ts.mcounter_init(current_counter_slot(), state["n"])
            refresh_state_label()

            k = _kdf(s, b"\x02")
            le_key.setText(k.hex())
            lbl_status.setText("PIN check OK")
        except ValueError as e:
            QtWidgets.QMessageBox.warning(window, "Invalid State/Input", str(e))
        except TropicSquareError as e:
            QtWidgets.QMessageBox.critical(window, "PIN Check Failed", str(e))
        except Exception as e:
            QtWidgets.QMessageBox.critical(window, "PIN Check Failed", str(e))

    btn_setup.clicked.connect(on_setup_click)
    btn_verify.clicked.connect(on_verify_click)

    def on_device_changed(connected=False, **_):
        btn_setup.setEnabled(False)
        btn_verify.setEnabled(False)

    def on_session_changed(has_session=False, **_):
        btn_setup.setEnabled(has_session)
        btn_verify.setEnabled(has_session)
        refresh_state_label()

    bus.on("device_changed", on_device_changed)
    bus.on("session_changed", on_session_changed)
    on_device_changed(connected=False)
    update_storage_ui()
    refresh_state_label()
