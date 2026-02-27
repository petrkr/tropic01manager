from __future__ import annotations

from hashlib import sha256
from typing import Optional

from tropicsquare.constants.pairing_keys import (
    FACTORY_PAIRING_KEY_INDEX,
    FACTORY_PAIRING_PRIVATE_KEY_ENG_SAMPLE,
    FACTORY_PAIRING_PRIVATE_KEY_PROD0,
    FACTORY_PAIRING_PUBLIC_KEY_ENG_SAMPLE,
    FACTORY_PAIRING_PUBLIC_KEY_PROD0,
)
from tropicsquare.ports.cpython import TropicSquareCPython
from tropicsquare.transports.network import NetworkSpiTransport
from tropicsquare.transports.tcp import TcpTransport


class TropicClientError(RuntimeError):
    pass


class _HKDF:
    @classmethod
    def derive(cls, salt, key_material, length=32):
        prk = cls._extract(salt, key_material)
        return cls._expand(prk, b"", length)

    @classmethod
    def _extract(cls, salt, ikm):
        hash_len = 32
        if salt is None or len(salt) == 0:
            salt = b"\x00" * hash_len
        return cls._hmac_sha256(salt, ikm)

    @classmethod
    def _expand(cls, prk, info, length):
        hash_len = 32
        n = (length + hash_len - 1) // hash_len
        if n > 255:
            raise ValueError("Cannot expand to more than 255 * hash length bytes")
        t = b""
        okm = b""
        for i in range(1, n + 1):
            t = cls._hmac_sha256(prk, t + info + bytes([i]))
            okm += t
        return okm[:length]

    @classmethod
    def _hmac_sha256(cls, key, message):
        blocksize = 64
        if len(key) > blocksize:
            key = sha256(key).digest()
        if len(key) < blocksize:
            key = key + (b"\x00" * (blocksize - len(key)))
        o_key_pad = bytes([b ^ 0x5C for b in key])
        i_key_pad = bytes([b ^ 0x36 for b in key])
        inner_hash = sha256(i_key_pad + message).digest()
        return sha256(o_key_pad + inner_hash).digest()


class TropicSquareAndroid(TropicSquareCPython):
    def _hkdf(self, salt, shared_secret, length=1):
        result = _HKDF.derive(salt, shared_secret, length * 32)
        if length > 1:
            return [result[i * 32:(i + 1) * 32] for i in range(length)]
        return result


class TropicClient:
    def __init__(self) -> None:
        self._transport: Optional[object] = None
        self._ts: Optional[TropicSquareCPython] = None

    def connect(self, transport_name: str, host: str, port: int) -> None:
        self.disconnect()
        name = transport_name.lower()
        try:
            if name == "tcp":
                self._transport = TcpTransport(host, port)
            elif name == "network":
                self._transport = NetworkSpiTransport(host, port)
            else:
                raise TropicClientError(f"Unsupported transport: {transport_name}")
            self._ts = TropicSquareAndroid(self._transport)
        except Exception as exc:
            self.disconnect()
            raise TropicClientError(f"Connect failed: {exc}") from exc

    def read_chipid(self):
        if self._ts is None:
            raise TropicClientError("Not connected")
        try:
            return self._ts.chipid
        except Exception as exc:
            raise TropicClientError(f"chipid failed: {exc}") from exc

    def has_session(self) -> bool:
        return self._ts is not None and hasattr(self._ts, "_secure_session") and self._ts._secure_session is not None

    def start_session(
        self, profile: str, index: int | None = None, priv_hex: str = "", pub_hex: str = ""
    ) -> tuple[int, bytes]:
        if self._ts is None:
            raise TropicClientError("Not connected")
        try:
            key_index, priv, pub = self._resolve_pairing(profile, index, priv_hex, pub_hex)
            self._ts.start_secure_session(key_index, bytes(priv), bytes(pub))
            return key_index, bytes(pub)
        except Exception as exc:
            raise TropicClientError(f"start session failed: {exc}") from exc

    def abort_session(self) -> None:
        if self._ts is None:
            raise TropicClientError("Not connected")
        try:
            self._ts.abort_secure_session()
        except Exception as exc:
            raise TropicClientError(f"abort session failed: {exc}") from exc

    @property
    def ts(self) -> TropicSquareCPython:
        """Access to TropicSquare instance"""
        if self._ts is None:
            raise TropicClientError("Not connected")
        return self._ts

    def disconnect(self) -> None:
        if self._ts is not None and hasattr(self._ts, "_secure_session") and self._ts._secure_session:
            try:
                self._ts.abort_secure_session()
            except Exception:
                pass
        self._ts = None

        if self._transport is None:
            return
        try:
            if hasattr(self._transport, "close"):
                self._transport.close()
            elif hasattr(self._transport, "_close"):
                self._transport._close()
        except Exception:
            pass
        self._transport = None

    @staticmethod
    def _parse_hex_bytes(text: str, label: str) -> bytes:
        cleaned = text.strip().replace(" ", "").replace("\n", "")
        if not cleaned:
            raise TropicClientError(f"{label} required")
        if len(cleaned) % 2 != 0:
            raise TropicClientError(f"{label} must have even length")
        try:
            return bytes.fromhex(cleaned)
        except ValueError as exc:
            raise TropicClientError(f"invalid hex in {label}") from exc

    def _resolve_pairing(
        self,
        profile: str,
        index: int | None,
        priv_hex: str,
        pub_hex: str,
    ) -> tuple[int, bytes, bytes]:
        if profile == "prod0":
            return (FACTORY_PAIRING_KEY_INDEX, FACTORY_PAIRING_PRIVATE_KEY_PROD0, FACTORY_PAIRING_PUBLIC_KEY_PROD0)
        if profile == "eng":
            return (FACTORY_PAIRING_KEY_INDEX, FACTORY_PAIRING_PRIVATE_KEY_ENG_SAMPLE, FACTORY_PAIRING_PUBLIC_KEY_ENG_SAMPLE)
        if profile == "custom":
            if index is None or index < 0 or index > 3:
                raise TropicClientError("custom index must be 0-3")
            priv = self._parse_hex_bytes(priv_hex, "custom priv")
            pub = self._parse_hex_bytes(pub_hex, "custom pub")
            if len(priv) != 32 or len(pub) != 32:
                raise TropicClientError("custom priv/pub must be 32 bytes")
            return (index, priv, pub)
        raise TropicClientError(f"unknown pairing profile: {profile}")
