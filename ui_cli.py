# ui_cli.py
from __future__ import annotations

from pathlib import Path
from typing import Optional

from prompt_toolkit import prompt
from prompt_toolkit.history import FileHistory

from keys import generate_key, save_key, load_key_from_file, KeyErrorE11, KeyMaterial
from crypto_files import encrypt_file, decrypt_file, FileFormatError
from crypto_folders import encrypt_directory, decrypt_directory


# History file (will be deleted on exit)
HISTORY_FILE = Path(".e11crypt_history")
HISTORY = FileHistory(str(HISTORY_FILE))


def cleanup_history() -> None:
    """Delete history file when exiting."""
    try:
        if HISTORY_FILE.exists():
            HISTORY_FILE.unlink()
            print("[+] تم حذف ملف الـ History تلقائيًا.")
    except Exception:
        print("[!] لم يتم حذف ملف الـ History (صلاحيات أو خطأ غير متوقع).")


def banner() -> None:
    print("=" * 68)
    print("E11Crypt — أداة تشفير/فك تشفير ملفات ومجلدات (Interactive + History)")
    print("AES-256-GCM | لا يمكن فتح الملف إلا بالمفتاح (Key)")
    print("=" * 68)


def menu() -> str:
    print("\nاختر عملية:")
    print("  1) إنشاء Key وحفظه")
    print("  2) تشفير ملف")
    print("  3) فك تشفير ملف")
    print("  4) تشفير مجلد (Zip ثم Encrypt)")
    print("  5) فك تشفير مجلد (Decrypt ثم Extract)")
    print("  0) خروج")
    return prompt("\nاكتب رقم الخيار: ", history=HISTORY).strip()


def prompt_text(msg: str, default: Optional[str] = None) -> str:
    if default:
        val = prompt(f"{msg} (Enter للاقتراح: {default}): ", history=HISTORY).strip()
        return val if val else default
    return prompt(msg, history=HISTORY).strip()


def prompt_path(msg: str, default: Optional[Path] = None) -> Path:
    d = str(default) if default else None
    while True:
        s = prompt_text(msg, default=d)
        s = s.strip().strip('"').strip("'")
        if s:
            return Path(s)
        print("[!] رجاءً أدخل قيمة صحيحة.")


def yes_no(msg: str, default: bool = True) -> bool:
    suffix = " [Y/n]" if default else " [y/N]"
    ans = prompt(f"{msg}{suffix}: ", history=HISTORY).strip().lower()
    if not ans:
        return default
    return ans in ("y", "yes", "نعم", "ok", "ا", "1")


def suggest_out_file(in_path: Path, ext: str) -> Path:
    return in_path.with_name(in_path.name + ext)


def load_key_interactive() -> KeyMaterial:
    while True:
        try:
            kp = prompt_path("مسار ملف الـ Key (مثال: /path/mykey.key): ")
            return load_key_from_file(kp)
        except Exception as e:
            print(f"[!] خطأ في قراءة الـ Key: {e}")
            if not yes_no("تريد المحاولة مرة أخرى؟", default=True):
                raise


def action_gen_key() -> None:
    outp = prompt_path("احفظ الـ Key فين؟ (اكتب مسار ملف أو مجلد): ")
    k = generate_key()
    saved_path = save_key(k, outp)
    print(f"[+] تم إنشاء المفتاح وحفظه: {saved_path}")
    print("[!] احتفظ به بأمان — من يمتلكه يستطيع فك التشفير.")


def action_encrypt_file() -> None:
    key = load_key_interactive()
    inp = prompt_path("مسار الملف المراد تشفيره: ")
    outp = prompt_path("مسار ملف الإخراج المشفّر", default=suggest_out_file(inp, ".enc"))
    encrypt_file(inp, outp, key)
    print(f"[+] تم التشفير: {inp} -> {outp}")


def action_decrypt_file() -> None:
    key = load_key_interactive()
    inp = prompt_path("مسار الملف المشفّر (.enc): ")
    default_out = inp.with_suffix("") if inp.suffix == ".enc" else inp.with_name(inp.name + ".dec")
    outp = prompt_path("مسار ملف الإخراج بعد فك التشفير", default=default_out)
    decrypt_file(inp, outp, key)
    print(f"[+] تم فك التشفير: {inp} -> {outp}")


def action_encrypt_dir() -> None:
    key = load_key_interactive()
    inp = prompt_path("مسار المجلد المراد تشفيره: ")
    outp = prompt_path("مسار ملف الإخراج للمجلد المشفّر", default=inp.with_name(inp.name + ".enc"))
    encrypt_directory(inp, outp, key)
    print(f"[+] تم تشفير المجلد: {inp} -> {outp}")


def action_decrypt_dir() -> None:
    key = load_key_interactive()
    inp = prompt_path("مسار ملف المجلد المشفّر (.enc): ")
    outp = prompt_path("مسار مجلد الإخراج لفك الملفات داخله: ")
    decrypt_directory(inp, outp, key)
    print(f"[+] تم فك تشفير المجلد داخل: {outp}")


def run_interactive() -> int:
    banner()
    while True:
        try:
            choice = menu()

            if choice == "1":
                action_gen_key()
            elif choice == "2":
                action_encrypt_file()
            elif choice == "3":
                action_decrypt_file()
            elif choice == "4":
                action_encrypt_dir()
            elif choice == "5":
                action_decrypt_dir()
            elif choice == "0":
                cleanup_history()
                print("مع السلامة 👋")
                return 0
            else:
                print("[!] خيار غير صحيح.")

        except KeyboardInterrupt:
            cleanup_history()
            print("\n[!] تم الإلغاء بواسطة المستخدم.")
            return 130
        except (FileNotFoundError, IsADirectoryError, NotADirectoryError, PermissionError) as e:
            print(f"[!] خطأ في المسار/الصلاحيات: {e}")
        except (KeyErrorE11, FileFormatError) as e:
            print(f"[!] خطأ: {e}")
        except Exception as e:
            print(f"[!] خطأ غير متوقع: {e}")
            return 10
