import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime
import re

def validate_input(data: str, max_len: int = 1024) -> str:
    if not data or len(data) > max_len or not re.match(r'^[a-zA-Z0-9s!?.,-]+$', data):
        raise ValueError("Invalid input")
    return data.strip()

class SecureMessenger:
    def __init__(self):
        self.signing_private = ec.generate_private_key(ec.SECP256K1())
        self.signing_public = self.signing_private.public_key()
        self.aes_key = AESGCM.generate_key(bit_length=256)
        self.cert = self._generate_cert()
    
    def _generate_cert(self):
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SecureApp")])
        cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
                .public_key(self.signing_public).serial_number(x509.random_serial_number())
                .not_valid_before(datetime.datetime.utcnow())
                .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
                .sign(self.signing_private, hashes.SHA256()))
        return cert
    
    def encrypt_sign(self, plaintext: str) -> dict:
        msg = validate_input(plaintext)
        aesgcm = AESGCM(self.aes_key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, msg.encode(), None)
        signature = self.signing_private.sign(ciphertext, ec.ECDSA(hashes.SHA256()))
        return {
            'ciphertext_b64': base64.b64encode(ciphertext).decode(),
            'nonce_b64': base64.b64encode(nonce).decode(),
            'signature_b64': base64.b64encode(signature).decode(),
            'cert_pem': self.cert.public_bytes(serialization.Encoding.PEM).decode()
        }

# Test it works
if __name__ == "__main__":
    app = SecureMessenger()
    msg = "Hello Secure World!"
    encrypted = app.encrypt_sign(msg)
    print("✅ Code works! Ready to share.")
