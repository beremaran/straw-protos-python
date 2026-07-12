"""Protocol-level registration signing helpers shared by Straw Python consumers."""

from __future__ import annotations

from . import _ed25519
from .straw.v1 import straw_pb2 as pb

_REGISTRATION_SIGNING_DOMAIN = b"straw.v1.register\n"


def registration_signing_payload(req: pb.RegisterRequest | None) -> bytes:
    if req is None:
        return _REGISTRATION_SIGNING_DOMAIN
    parts = [
        _REGISTRATION_SIGNING_DOMAIN,
        req.worker_id.encode(), b"\n",
        req.credential_id.encode(), b"\n",
        req.executor_type.encode(), b"\n",
        str(req.protocol_major).encode(), b".", str(req.protocol_minor).encode(), b"\n",
        str(len(req.nonce)).encode(), b":", req.nonce, b"\n",
        str(req.issued_at_unix_ms).encode(),
    ]
    if req.protocol_minor >= 1 and req.supported_fingerprint_profiles:
        profiles = sorted(set(req.supported_fingerprint_profiles))
        parts.extend((b"\n", str(len(profiles)).encode()))
        for profile in profiles:
            encoded = profile.encode()
            parts.extend((b"\n", str(len(encoded)).encode(), b":", encoded))
    return b"".join(parts)


def sign_registration(seed: bytes, req: pb.RegisterRequest) -> bytes:
    return _ed25519.sign(seed, registration_signing_payload(req))


def verify_registration_signature(public_key: bytes, req: pb.RegisterRequest, signature: bytes) -> bool:
    if len(public_key) != 32:
        return False
    return _ed25519.verify(public_key, registration_signing_payload(req), signature)
