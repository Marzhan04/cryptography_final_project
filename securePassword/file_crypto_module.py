import os
import base64
import hashlib
import hmac
from dataclasses import dataclass

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode()

def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode())

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass
class EncryptResult:
    filename: str
    salt: str
    nonce: str
    ciphertext: str
    hmac: str
    file_hash: str
    kdf: str
    algo: str


class FileCryptoModule:
    """
    Module 3: File Encryption
    - KDF: PBKDF2-HMAC-SHA256
    - Encryption: AES-256-GCM
    - Integrity: HMAC-SHA256 + SHA256(file)
    """

    def __init__(self, iterations: int = 200_000):
        self.iterations = iterations

    def _derive_keys(self, password: str, salt: bytes) -> tuple[bytes, bytes]:
        """
        Derive 64 bytes: first 32 -> AES key, next 32 -> HMAC key
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=64,
            salt=salt,
            iterations=self.iterations,
        )
        key_material = kdf.derive(password.encode())
        enc_key = key_material[:32]
        mac_key = key_material[32:]
        return enc_key, mac_key

    def encrypt_file(self, file_bytes: bytes, password: str, filename: str) -> dict:
        if not password or len(password) < 6:
            raise ValueError("Encryption password is required (min 6 chars).")

        salt = os.urandom(16)
        nonce = os.urandom(12)  # recommended size for GCM
        enc_key, mac_key = self._derive_keys(password, salt)

        aesgcm = AESGCM(enc_key)
        ct = aesgcm.encrypt(nonce, file_bytes, None)  # includes GCM tag inside ct

        # File hash of plaintext (for extra integrity validation)
        file_hash = sha256_hex(file_bytes)

        # HMAC over (salt | nonce | ciphertext)
        mac = hmac.new(mac_key, salt + nonce + ct, hashlib.sha256).hexdigest()

        result = EncryptResult(
            filename=filename,
            salt=b64e(salt),
            nonce=b64e(nonce),
            ciphertext=b64e(ct),
            hmac=mac,
            file_hash=file_hash,
            kdf=f"PBKDF2-SHA256:{self.iterations}",
            algo="AES-256-GCM",
        )
        return result.__dict__

    def decrypt_file(self, payload: dict, password: str) -> dict:
        """
        payload must contain: salt, nonce, ciphertext, hmac, file_hash, filename
        """
        required = ["salt", "nonce", "ciphertext", "hmac", "file_hash", "filename"]
        for k in required:
            if k not in payload:
                raise ValueError(f"Missing field in payload: {k}")

        salt = b64d(payload["salt"])
        nonce = b64d(payload["nonce"])
        ct = b64d(payload["ciphertext"])
        provided_mac = payload["hmac"]
        expected_file_hash = payload["file_hash"]

        enc_key, mac_key = self._derive_keys(password, salt)

        # Verify HMAC BEFORE decrypt
        expected_mac = hmac.new(mac_key, salt + nonce + ct, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(provided_mac, expected_mac):
            raise ValueError("Integrity check failed (HMAC mismatch). File may be modified or wrong password.")

        aesgcm = AESGCM(enc_key)
        pt = aesgcm.decrypt(nonce, ct, None)

        # Verify SHA-256 of plaintext matches recorded hash
        actual_file_hash = sha256_hex(pt)
        if actual_file_hash != expected_file_hash:
            raise ValueError("Integrity check failed (SHA-256 mismatch).")

        return {
            "filename": payload["filename"],
            "plaintext_base64": b64e(pt),
            "file_hash": actual_file_hash,
            "status": "ok"
        }
