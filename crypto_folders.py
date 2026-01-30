# crypto_folders.py
from __future__ import annotations

import tempfile
import zipfile
from pathlib import Path

from keys import KeyMaterial
from crypto_files import encrypt_file, decrypt_file, FileFormatError


def zip_directory(src_dir: Path, zip_path: Path) -> None:
    """Zip a directory into a .zip file."""
    if not src_dir.exists():
        raise FileNotFoundError(f"Folder not found: {src_dir}")
    if not src_dir.is_dir():
        raise NotADirectoryError(f"Expected a folder but got: {src_dir}")

    zip_path.parent.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for file_path in src_dir.rglob("*"):
            if file_path.is_file():
                zf.write(file_path, file_path.relative_to(src_dir))


def unzip_to_directory(zip_path: Path, out_dir: Path) -> None:
    """Extract zip safely (Zip Slip protection)."""
    if not zip_path.exists():
        raise FileNotFoundError(f"Zip not found: {zip_path}")
    if not zip_path.is_file():
        raise IsADirectoryError(f"Expected a zip file but got directory: {zip_path}")

    out_dir.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(zip_path, "r") as zf:
        out_resolved = out_dir.resolve()

        for member in zf.infolist():
            dest = (out_dir / member.filename).resolve()
            if not str(dest).startswith(str(out_resolved)):
                raise FileFormatError("Unsafe zip content detected (path traversal).")

        zf.extractall(out_dir)


def encrypt_directory(dir_path: Path, out_path: Path, key: KeyMaterial) -> None:
    """Zip the folder then encrypt the zip."""
    if not dir_path.exists():
        raise FileNotFoundError(f"Folder not found: {dir_path}")
    if not dir_path.is_dir():
        raise NotADirectoryError(f"Expected a folder but got: {dir_path}")

    out_path.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory() as td:
        tmp_zip = Path(td) / (dir_path.name + ".zip")
        zip_directory(dir_path, tmp_zip)
        encrypt_file(tmp_zip, out_path, key)


def decrypt_directory(enc_path: Path, out_dir: Path, key: KeyMaterial) -> None:
    """Decrypt to zip then extract."""
    if not enc_path.exists():
        raise FileNotFoundError(f"Encrypted file not found: {enc_path}")
    if not enc_path.is_file():
        raise IsADirectoryError(f"Expected a file but got directory: {enc_path}")

    out_dir.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory() as td:
        tmp_zip = Path(td) / "decrypted.zip"
        decrypt_file(enc_path, tmp_zip, key)
        unzip_to_directory(tmp_zip, out_dir)
