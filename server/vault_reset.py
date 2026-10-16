"""
Reset hasła głównego użytkownika z panelu administratora (klucz odzyskiwania firmy przechowywany na serwerze).

Klucz prywatny firmy leży w ustawieniach serwera zaszyfrowany hasłem działu IT (Argon2id + AES-GCM – ten sam
format co plik .ksorgkey z aplikacji). Przy resecie administrator podaje hasło IT, serwer w pamięci:
  1. odszyfrowuje klucz firmy i nim klucz danych sejfu (klucz dostępu „org” w nagłówku sejfu v2),
  2. ustawia w sejfie znacznik „wymuś zmianę hasła” i podnosi licznik zapisów,
  3. zastępuje klucz dostępu „hasło” nowym – dla hasła tymczasowego.
Niczego z tego nie zapisuje poza nową, zaszyfrowaną wersją sejfu.

Format musi być zgodny z core/crypto.py aplikacji (testy krzyżowe w tests/test_vault_reset.py).
"""

import base64
import json
import os
import secrets
import struct
from typing import Any, Dict, Optional, Tuple

from argon2 import low_level as argon_low
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from server.settings import ORG_PUBLIC_PREFIX, org_key_id

MAGIC = b"SECVAULT"
VERSION_V2 = 2
MAX_HEADER_BYTES = 64 * 1024
SALT_LEN, NONCE_LEN, KEY_LEN = 32, 12, 32
KDF_T, KDF_M, KDF_P = 3, 65536, 4
KDF_LIMITS = {"t": (2, 64), "m": (19456, 4 * 1024 * 1024), "p": (1, 64)}
ORG_SLOT_INFO = b"KeyStead org recovery v1"
FORCE_CHANGE_KEY = "force_password_change"   # ui/recovery_ui.py w aplikacji
MIN_IT_PASSWORD = 12
MIN_TEMP_PASSWORD = 10
TEMP_ALPHABET = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"


class ResetError(Exception):
    """Komunikat dla administratora (bez szczegółów kryptograficznych)."""


class WrongItPassword(ResetError):
    pass


def _e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _d(text: str) -> bytes:
    return base64.b64decode(str(text).encode("ascii"), validate=True)


def _argon(secret: str, salt: bytes, t: int, m: int, p: int) -> bytes:
    return argon_low.hash_secret_raw(secret=secret.encode("utf-8"), salt=salt, time_cost=t, memory_cost=m,
                                     parallelism=p, hash_len=KEY_LEN, type=argon_low.Type.ID)


def _kdf_new(secret: str) -> Tuple[Dict[str, Any], bytes]:
    salt = os.urandom(SALT_LEN)
    return {"kdf": {"t": KDF_T, "m": KDF_M, "p": KDF_P, "salt": _e(salt)}}, _argon(secret, salt, KDF_T, KDF_M, KDF_P)


def _kdf_from(entry: Dict[str, Any], secret: str) -> bytes:
    kdf = entry.get("kdf") or {}
    try:
        t, m, p = int(kdf["t"]), int(kdf["m"]), int(kdf["p"])
        salt = _d(kdf["salt"])
    except (KeyError, TypeError, ValueError):
        raise ResetError("Uszkodzony klucz odzyskiwania firmy.")
    for name, value in (("t", t), ("m", m), ("p", p)):
        lo, hi = KDF_LIMITS[name]
        if not lo <= value <= hi:
            raise ResetError("Nieprawidłowe parametry klucza odzyskiwania firmy.")
    if len(salt) != SALT_LEN:
        raise ResetError("Uszkodzony klucz odzyskiwania firmy.")
    return _argon(secret, salt, t, m, p)


# --------------------------------------------------------------------- klucz firmy
def generate_key_file(it_password: str) -> Tuple[str, Dict[str, Any]]:
    """Nowa para kluczy firmy. Zwraca (klucz publiczny 'ksrec1:…', plik klucza zaszyfrowany hasłem IT)."""
    if len(it_password or "") < MIN_IT_PASSWORD:
        raise ResetError(f"Hasło działu IT musi mieć co najmniej {MIN_IT_PASSWORD} znaków.")
    private = X25519PrivateKey.generate()
    priv_raw = private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                     serialization.NoEncryption())
    pub_raw = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    public = ORG_PUBLIC_PREFIX + _e(pub_raw)
    meta, kek = _kdf_new(it_password)
    nonce = os.urandom(NONCE_LEN)
    key_file = {"type": "keystead-org-recovery-key", "version": 1, "key_id": org_key_id(public), "public": public,
                **meta, "nonce": _e(nonce),
                "private": _e(AESGCM(kek).encrypt(nonce, priv_raw, b"keystead-org-private"))}
    return public, key_file


def load_private_key(key_file: Dict[str, Any], it_password: str) -> X25519PrivateKey:
    if not isinstance(key_file, dict) or key_file.get("type") != "keystead-org-recovery-key":
        raise ResetError("To nie jest plik klucza odzyskiwania firmy KeyStead (.ksorgkey).")
    kek = _kdf_from(key_file, it_password or "")
    try:
        raw = AESGCM(kek).decrypt(_d(key_file["nonce"]), _d(key_file["private"]), b"keystead-org-private")
        private = X25519PrivateKey.from_private_bytes(raw)
    except Exception:
        raise WrongItPassword("Nieprawidłowe hasło działu IT.")
    public = ORG_PUBLIC_PREFIX + _e(private.public_key().public_bytes(serialization.Encoding.Raw,
                                                                       serialization.PublicFormat.Raw))
    if key_file.get("public") and key_file["public"] != public:
        raise ResetError("Plik klucza firmy jest uszkodzony (klucz publiczny nie pasuje do prywatnego).")
    return private


def public_key_of(private: X25519PrivateKey) -> str:
    return ORG_PUBLIC_PREFIX + _e(private.public_key().public_bytes(serialization.Encoding.Raw,
                                                                     serialization.PublicFormat.Raw))


# --------------------------------------------------------------------- sejf v2
def _parse(blob: bytes):
    if blob[:len(MAGIC)] != MAGIC or len(blob) < len(MAGIC) + 5 or blob[len(MAGIC)] != VERSION_V2:
        return None
    offset = len(MAGIC)
    _, header_len = struct.unpack(">BI", blob[offset:offset + 5])
    offset += 5
    if header_len > MAX_HEADER_BYTES or len(blob) < offset + header_len + NONCE_LEN + 16:
        raise ResetError("Uszkodzony nagłówek sejfu.")
    try:
        slots = json.loads(blob[offset:offset + header_len].decode("utf-8"))["slots"]
        if not isinstance(slots, list) or not all(isinstance(s, dict) for s in slots):
            raise ValueError
    except (ValueError, KeyError, UnicodeDecodeError):
        raise ResetError("Uszkodzony nagłówek sejfu.")
    offset += header_len
    nonce = blob[offset:offset + NONCE_LEN]
    offset += NONCE_LEN
    return slots, blob[:offset], nonce, blob[offset:]   # AAD = wszystko do nonce włącznie (jak w aplikacji)


def vault_recovery_status(blob: Optional[bytes]) -> Dict[str, Any]:
    """Czy sejf da się zresetować (bez żadnych kluczy – tylko jawny nagłówek)."""
    if not blob:
        return {"format": 0, "org_key_id": None}
    try:
        parsed = _parse(blob)
    except ResetError:
        return {"format": -1, "org_key_id": None}
    if parsed is None:
        return {"format": 1, "org_key_id": None}
    org = next((s for s in parsed[0] if s.get("type") == "org"), None)
    return {"format": 2, "org_key_id": org.get("key_id") if org else None}


def _wrap(kek: bytes, dek: bytes, label: str) -> Dict[str, str]:
    nonce = os.urandom(NONCE_LEN)
    return {"nonce": _e(nonce), "wrapped": _e(AESGCM(kek).encrypt(nonce, dek, f"keystead-slot:{label}".encode()))}


def generate_temp_password(length: int = 14) -> str:
    return "".join(secrets.choice(TEMP_ALPHABET) for _ in range(length))


class OpenedVault:
    """Sejf otwarty kluczem firmy: zawartość (JSON) + klucz danych i klucze dostępu do ponownego zaszyfrowania."""

    def __init__(self, data: Dict[str, Any], dek: bytes, slots: list):
        self.data, self.dek, self.slots = data, dek, slots

    def seal(self, slots: Optional[list] = None) -> bytes:
        """Nowa wersja: licznik zapisów +1 (inne urządzenia przyjmą ją jako zwykłą zmianę)."""
        self.data["revision"] = int(self.data.get("revision", 0) or 0) + 1
        header = json.dumps({"slots": slots if slots is not None else self.slots}, separators=(",", ":")).encode("utf-8")
        nonce = os.urandom(NONCE_LEN)
        prefix = MAGIC + struct.pack(">BI", VERSION_V2, len(header)) + header + nonce
        plaintext = json.dumps(self.data, ensure_ascii=False, indent=2).encode("utf-8")
        return prefix + AESGCM(self.dek).encrypt(nonce, plaintext, prefix)


def open_vault(blob: bytes, private: X25519PrivateKey) -> OpenedVault:
    """Odszyfrowanie sejfu kluczem firmy (wyłącznie w pamięci)."""
    parsed = _parse(blob)
    if parsed is None:
        raise ResetError("Sejf jest w starym formacie, bez klucza firmy – użytkownik musi raz odblokować go "
                         "w aplikacji KeyStead Manager 1.2 lub nowszej.")
    slots, aad, nonce, ciphertext = parsed
    pub_raw = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    key_id = org_key_id(ORG_PUBLIC_PREFIX + _e(pub_raw))
    org = next((s for s in slots if s.get("type") == "org"), None)
    if org is None:
        raise ResetError("Sejf nie zawiera jeszcze klucza firmy – użytkownik musi raz odblokować go w aplikacji "
                         "po włączeniu odzyskiwania dostępu.")
    if org.get("key_id") != key_id:
        raise ResetError(f"Sejf jest zabezpieczony innym kluczem firmy ({org.get('key_id')}) niż zapisany na serwerze "
                         f"({key_id}).")
    try:
        eph_pub = _d(org["eph"])
        shared = private.exchange(X25519PublicKey.from_public_bytes(eph_pub))
        kek = HKDF(algorithm=hashes.SHA256(), length=KEY_LEN, salt=eph_pub + pub_raw, info=ORG_SLOT_INFO).derive(shared)
        dek = AESGCM(kek).decrypt(_d(org["nonce"]), _d(org["wrapped"]), b"keystead-slot:org")
        data = json.loads(AESGCM(dek).decrypt(nonce, ciphertext, aad).decode("utf-8"))
    except Exception:
        raise ResetError("Nie udało się odszyfrować sejfu kluczem firmy – plik uszkodzony lub zmodyfikowany.")
    if not isinstance(data, dict):
        raise ResetError("Nieprawidłowa zawartość sejfu.")
    return OpenedVault(data, dek, slots)


def reset_password(blob: bytes, private: X25519PrivateKey, temp_password: str) -> bytes:
    """Nowa wersja sejfu otwierana hasłem tymczasowym; aplikacja wymusi ustawienie własnego hasła."""
    if len(temp_password or "") < MIN_TEMP_PASSWORD:
        raise ResetError(f"Hasło tymczasowe musi mieć co najmniej {MIN_TEMP_PASSWORD} znaków.")
    vault = open_vault(blob, private)
    settings = vault.data.get("settings") if isinstance(vault.data.get("settings"), dict) else {}
    settings[FORCE_CHANGE_KEY] = True
    vault.data["settings"] = settings
    meta, pw_kek = _kdf_new(temp_password)
    new_slots = [s for s in vault.slots if s.get("type") != "password"]
    new_slots.append({"type": "password", **meta, **_wrap(pw_kek, vault.dek, "password")})
    return vault.seal(new_slots)
