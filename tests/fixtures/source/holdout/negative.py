"""Imports, text, and lookalike methods are not cryptographic operations."""
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa
text = "hashlib.md5(b'data')"
# rsa.generate_private_key(public_exponent=65537, key_size=1024)
reference = hashlib.sha256

def unrelated(hashlib):
    return hashlib.md5(b"ordinary application method")
