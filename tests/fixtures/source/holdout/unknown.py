import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa

def selected(name, key, bits):
    digest = hashlib.new(name)
    cipher = AESGCM(key)
    private = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    return digest, cipher, private
