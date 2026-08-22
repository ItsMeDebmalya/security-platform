"""DKIM key record parsing, per RFC 6376.

Key strength is the interesting part. Nothing in the record states it: the
`p=` tag is a base64 DER public key, and the only way to know whether it is a
1024-bit key that a modern attacker can factor is to measure the modulus.

We walk the DER by hand rather than take a dependency on a crypto library for
one length calculation. Where the key does not parse we report the strength as
**unknown** rather than zero - "we could not measure it" is a different claim
from "it is weak", and conflating them is how a scanner earns a reputation for
crying wolf.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass, field
from typing import Any

VERSION = "DKIM1"
ED25519_BITS = 256


@dataclass(frozen=True)
class DkimKeyRecord:
    raw: str
    tags: dict[str, str] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    key_bits: int | None = None

    @property
    def valid(self) -> bool:
        return not self.errors

    @property
    def key_type(self) -> str:
        return self.tags.get("k", "rsa").lower()

    @property
    def revoked(self) -> bool:
        """An empty p= revokes the key. Deliberate, not broken."""
        return "p" in self.tags and not self.tags["p"].strip()

    @property
    def testing(self) -> bool:
        return "y" in {f.strip().lower() for f in self.tags.get("t", "").split(":")}

    def to_dict(self) -> dict[str, Any]:
        return {
            "raw": self.raw,
            "valid": self.valid,
            "tags": {
                k: (v if k != "p" else f"<{len(v)} base64 chars>") for k, v in self.tags.items()
            },
            "errors": list(self.errors),
            "key_type": self.key_type,
            "key_bits": self.key_bits,
            "revoked": self.revoked,
            "testing": self.testing,
        }


def parse_dkim_key(text: str) -> DkimKeyRecord:
    raw = text.strip()
    tags: dict[str, str] = {}
    errors: list[str] = []

    for part in raw.split(";"):
        part = part.strip()
        if not part:
            continue
        if "=" not in part:
            errors.append(f"cannot parse tag {part!r}")
            continue
        name, _, value = part.partition("=")
        tags[name.strip().lower()] = value.strip()

    if "v" in tags and tags["v"].upper() != VERSION:
        errors.append(f"v={tags['v']!r} is not {VERSION}")

    if "p" not in tags:
        errors.append("no p= tag; a key record must carry a public key")
        return DkimKeyRecord(raw=raw, tags=tags, errors=errors)

    key_type = tags.get("k", "rsa").lower()
    if key_type not in ("rsa", "ed25519"):
        errors.append(f"unknown key type {key_type!r}")

    key_bits: int | None = None
    encoded = tags["p"].strip()
    if encoded:
        try:
            der = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError):
            errors.append("p= is not valid base64")
        else:
            key_bits = ED25519_BITS if key_type == "ed25519" else _rsa_modulus_bits(der)

    return DkimKeyRecord(raw=raw, tags=tags, errors=errors, key_bits=key_bits)


# --- just enough DER to measure a modulus ----------------------------------


def _read_length(data: bytes, index: int) -> tuple[int, int]:
    first = data[index]
    index += 1
    if first < 0x80:
        return first, index
    count = first & 0x7F
    return int.from_bytes(data[index : index + count], "big"), index + count


def _read_tlv(data: bytes, index: int) -> tuple[int, bytes, int]:
    tag = data[index]
    length, index = _read_length(data, index + 1)
    return tag, data[index : index + length], index + length


def _rsa_modulus_bits(der: bytes) -> int | None:
    """Bit length of the RSA modulus in a DER SubjectPublicKeyInfo.

    Accepts both shapes seen in the wild: a full SubjectPublicKeyInfo (what
    `openssl rsa -pubout -outform DER` emits, and what almost every DKIM
    record carries) and a bare PKCS#1 RSAPublicKey.
    """
    try:
        tag, outer, _ = _read_tlv(der, 0)
        if tag != 0x30:
            return None

        tag, first, index = _read_tlv(outer, 0)
        if tag == 0x30:
            # SubjectPublicKeyInfo: AlgorithmIdentifier, then a BIT STRING
            # whose contents are the PKCS#1 key.
            tag, bit_string, _ = _read_tlv(outer, index)
            if tag != 0x03 or not bit_string:
                return None
            tag, inner, _ = _read_tlv(bit_string[1:], 0)  # skip the unused-bits octet
            if tag != 0x30:
                return None
            tag, modulus, _ = _read_tlv(inner, 0)
        else:
            modulus = first

        if tag != 0x02 or not modulus:
            return None
        return len(modulus.lstrip(b"\x00")) * 8
    except (IndexError, ValueError):
        return None
