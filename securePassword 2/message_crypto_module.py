import os
import base64
import json
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class MessageCryptoModule:
    """
    Module 2: Secure Messaging
    - Key Exchange: ECDH (NIST P-256)
    - Key Derivation: HKDF-SHA256
    - Encryption: AES-256-GCM
    - Signature: ECDSA-SHA256
    """

    def generate_keys(self):
        """Generates Private (SEC1) and Public (X.509) keys in PEM format."""
        priv_key = ec.generate_private_key(ec.SECP256R1())
        
        priv_pem = priv_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()

        pub_pem = priv_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

        return priv_pem, pub_pem

    def _load_priv(self, pem: str):
        return serialization.load_pem_private_key(pem.encode(), password=None)

    def _load_pub(self, pem: str):
        return serialization.load_pem_public_key(pem.encode())

    def encrypt_message(self, sender_priv_pem: str, recipient_pub_pem: str, message: str) -> dict:
        sender_priv = self._load_priv(sender_priv_pem)
        recipient_pub = self._load_pub(recipient_pub_pem)

        # 1. ECDH: Derive shared secret
        # (Sender's Private Key + Recipient's Public Key)
        shared_secret = sender_priv.exchange(ec.ECDH(), recipient_pub)

        # 2. HKDF: Derive AES Key from shared secret
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"handshake data",
        ).derive(shared_secret)

        # 3. Encrypt Message (AES-GCM)
        aesgcm = AESGCM(derived_key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, message.encode(), None)

        # 4. Sign the ciphertext (Authenticity/Non-repudiation)
        signature = sender_priv.sign(
            ciphertext,
            ec.ECDSA(hashes.SHA256())
        )

        return {
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "signature": base64.b64encode(signature).decode(),
        }

    def decrypt_message(self, recipient_priv_pem: str, sender_pub_pem: str, payload: dict) -> str:
        recipient_priv = self._load_priv(recipient_priv_pem)
        sender_pub = self._load_pub(sender_pub_pem)

        ct = base64.b64decode(payload["ciphertext"])
        nonce = base64.b64decode(payload["nonce"])
        sig = base64.b64decode(payload["signature"])

        # 1. Verify Signature FIRST (using Sender's Public Key)
        try:
            sender_pub.verify(sig, ct, ec.ECDSA(hashes.SHA256()))
        except Exception:
            raise ValueError("Digital Signature Verification Failed! Message assumes forged.")

        # 2. ECDH: Derive SAME shared secret
        # (Recipient's Private Key + Sender's Public Key)
        shared_secret = recipient_priv.exchange(ec.ECDH(), sender_pub)

        # 3. HKDF: Derive same AES Key
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"handshake data",
        ).derive(shared_secret)

        # 4. Decrypt
        aesgcm = AESGCM(derived_key)
        plaintext = aesgcm.decrypt(nonce, ct, None)
        
        return plaintext.decode()
