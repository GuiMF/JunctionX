"""Synthetic, never executed: explicit facts with aliases and byte units."""
import hashlib as digest
import hmac
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

weak = digest.md5(b"example")
modern = digest.sha384(b"example")
tag = hmac.new(b"fixture", b"example", digest.sha256)
private = rsa.generate_private_key(public_exponent=65537, key_size=1024)
curve = ed25519.Ed25519PrivateKey.generate()
aead = AESGCM(b"0123456789abcdef0123456789abcdef")
kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=b"salt", iterations=600_000)
