"""Keyed pseudonyms for IP addresses, so datasets can be shared or published.

The mapping is deterministic for a given key (the same host always gets the same
pseudonym, so top-talker analysis still works) and keeps the internal/external split.
Without the key it cannot be reversed.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress

from .protocols import is_internal


class Anonymiser:
    def __init__(self, key: str) -> None:
        if len(key) < 8:
            raise ValueError("the anonymisation key must have at least 8 characters")
        self._key = key.encode("utf-8")
        self._cache: dict[str, str] = {}

    def _digest(self, address: str) -> bytes:
        return hmac.new(self._key, address.encode("ascii", "replace"), hashlib.sha256).digest()

    def __call__(self, address: str) -> str:
        cached = self._cache.get(address)
        if cached is not None:
            return cached
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return "invalid"
        digest = self._digest(address)
        internal = is_internal(address)
        if ip.version == 4:
            if internal:
                result = f"10.{digest[0]}.{digest[1]}.{digest[2] or 1}"
            else:
                result = f"198.{18 + digest[0] % 2}.{digest[1]}.{digest[2] or 1}"
        else:
            if internal:
                result = str(ipaddress.IPv6Address(b"\xfd" + digest[:15]))
            else:
                result = str(ipaddress.IPv6Address(bytes.fromhex("20010db8") + digest[:12]))
        if len(self._cache) < 100_000:
            self._cache[address] = result
        return result
