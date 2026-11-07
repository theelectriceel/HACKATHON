from __future__ import annotations

import hashlib
import hmac
import json
import os
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS = ROOT / "artifacts"
ARTIFACTS.mkdir(exist_ok=True)


def canonical(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def digest(value) -> str:
    return hashlib.sha256((value if isinstance(value, str) else canonical(value)).encode()).hexdigest()


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def local_key() -> bytes:
    path = ARTIFACTS / "runtime-key"
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return path.read_bytes()
    key = os.urandom(32)
    with os.fdopen(fd, "wb") as handle:
        handle.write(key)
    return key


def sign(value, key: bytes) -> str:
    return hmac.new(key, canonical(value).encode(), hashlib.sha256).hexdigest()


def receipt(payload: dict, key: bytes) -> dict:
    return {"payload": payload, "signature": sign(payload, key), "scheme": "local-HMAC-SHA256", "limitations": "Binds recorded bytes; does not prove semantic safety or prevent deletion by the local operator."}


def verify_receipt(value: dict, key: bytes, context: str | None = None) -> bool:
    try:
        valid = hmac.compare_digest(value["signature"], sign(value["payload"], key))
        return valid and (context is None or digest(context) == value["payload"].get("context_digest"))
    except (KeyError, TypeError, ValueError):
        return False
