# keys.py
from __future__ import annotations

import base64
import os
from dataclasses import dataclass
from pathlib import Path

KEY_SIZE = 32  # AES-256


class KeyErrorE11(Exception):
    """Raised when key is invalid or cannot be loaded."""


@dataclass
class KeyMaterial:
    key: bytes  # 32 bytes


def generate_key() -> KeyMaterial:
    """Generate a random 32-byte key (AES-256)."""
    return KeyMaterial(key=os.urandom(KEY_SIZE))


def save_key(key: KeyMaterial, out_path: Path) -> Path:
    """
    Save key to file in base64-url format.
    If out_path is a directory, create <dir>/mykey.key.
    """
    if out_path.exists() and out_path.is_dir():
        out_path = out_path / "mykey.key"

    out_path.parent.mkdir(parents=True, exist_ok=True)
    encoded = base64.urlsafe_b64encode(key.key).decode("ascii")
    out_path.write_text(encoded + "\n", encoding="utf-8")
    return out_path


def load_key_from_file(key_path: Path) -> KeyMaterial:
    """Load key from file and validate length."""
    if not key_path.exists():
        raise FileNotFoundError(f"Key file not found: {key_path}")
    if not key_path.is_file():
        raise IsADirectoryError(f"Expected key file but got directory: {key_path}")

    raw = key_path.read_text(encoding="utf-8").strip()
    try:
        key_bytes = base64.urlsafe_b64decode(raw.encode("ascii"))
    except Exception as e:
        raise KeyErrorE11(f"Failed to decode key file: {e}") from e

    if len(key_bytes) != KEY_SIZE:
        raise KeyErrorE11(f"Invalid key length: expected {KEY_SIZE} bytes, got {len(key_bytes)}")

    return KeyMaterial(key=key_bytes)
