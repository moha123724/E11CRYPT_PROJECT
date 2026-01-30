# crypto_files.py
from __future__ import annotations

import os
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from keys import KeyMaterial, KeyErrorE11

MAGIC = b"E11ENC1"
NONCE_SIZE = 12
TAG_SIZE = 16
CHUNK_SIZE = 1024 * 1024  # 1MB


class FileFormatError(Exception):
    """Raised when encrypted file format is invalid/corrupted."""


def encrypt_file(in_path: Path, out_path: Path, key: KeyMaterial) -> None:
    """Encrypt a single file with AES-256-GCM (streaming)."""
    if not in_path.exists():
        raise FileNotFoundError(f"Input file not found: {in_path}")
    if not in_path.is_file():
        raise IsADirectoryError(f"Expected a file but got: {in_path}")

    out_path.parent.mkdir(parents=True, exist_ok=True)

    nonce = os.urandom(NONCE_SIZE)
    encryptor = Cipher(algorithms.AES(key.key), modes.GCM(nonce)).encryptor()

    with in_path.open("rb") as fin, out_path.open("wb") as fout:
        fout.write(MAGIC)
        fout.write(nonce)

        while True:
            chunk = fin.read(CHUNK_SIZE)
            if not chunk:
                break
            fout.write(encryptor.update(chunk))

        encryptor.finalize()
        fout.write(encryptor.tag)


def _read_and_validate_header(fin) -> bytes:
    magic = fin.read(len(MAGIC))
    if magic != MAGIC:
        raise FileFormatError("Not a valid E11 encrypted file (bad header).")

    nonce = fin.read(NONCE_SIZE)
    if len(nonce) != NONCE_SIZE:
        raise FileFormatError("Corrupted encrypted file (nonce missing).")
    return nonce


def decrypt_file(in_path: Path, out_path: Path, key: KeyMaterial) -> None:
    """Decrypt a file encrypted by encrypt_file()."""
    if not in_path.exists():
        raise FileNotFoundError(f"Encrypted file not found: {in_path}")
    if not in_path.is_file():
        raise IsADirectoryError(f"Expected a file but got: {in_path}")

    out_path.parent.mkdir(parents=True, exist_ok=True)

    file_size = in_path.stat().st_size
    min_size = len(MAGIC) + NONCE_SIZE + TAG_SIZE
    if file_size < min_size:
        raise FileFormatError("Encrypted file is too small/corrupted.")

    with in_path.open("rb") as fin:
        nonce = _read_and_validate_header(fin)

        header_len = len(MAGIC) + NONCE_SIZE
        ciphertext_len = file_size - header_len - TAG_SIZE
        if ciphertext_len < 0:
            raise FileFormatError("Corrupted encrypted file (length mismatch).")

        # Read tag from end
        fin.seek(file_size - TAG_SIZE)
        tag = fin.read(TAG_SIZE)
        if len(tag) != TAG_SIZE:
            raise FileFormatError("Corrupted encrypted file (tag missing).")

        fin.seek(header_len)
        decryptor = Cipher(algorithms.AES(key.key), modes.GCM(nonce, tag)).decryptor()

        remaining = ciphertext_len
        with out_path.open("wb") as fout:
            while remaining > 0:
                to_read = min(CHUNK_SIZE, remaining)
                chunk = fin.read(to_read)
                if not chunk:
                    raise FileFormatError("Corrupted encrypted file (unexpected EOF).")
                remaining -= len(chunk)
                fout.write(decryptor.update(chunk))

            try:
                decryptor.finalize()
            except InvalidTag as e:
                raise KeyErrorE11("Decryption failed: wrong key or file was modified.") from e
