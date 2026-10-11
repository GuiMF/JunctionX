"""Bounded SSH KEXINIT offer registry; it never asserts negotiated algorithms.

Mappings: RFCs 4253, 4344, 5656, 6668, 8268, 8332, 8709, 8731 and OpenSSH
PROTOCOL (including its SSH ChaCha20-Poly1305 draft reference).
Unknown names stay explicit in evidence.
"""

KEX = {
    "curve25519-sha256": {"algorithm": "X25519", "usage": "key_establishment"},
    "curve25519-sha256@libssh.org": {"algorithm": "X25519", "usage": "key_establishment"},
    "curve448-sha512": {"algorithm": "X448", "usage": "key_establishment"},
}
for name, bits in (
    ("diffie-hellman-group1-sha1", 1024), ("diffie-hellman-group14-sha1", 2048),
    ("diffie-hellman-group14-sha256", 2048), ("diffie-hellman-group15-sha512", 3072),
    ("diffie-hellman-group16-sha512", 4096), ("diffie-hellman-group17-sha512", 6144),
    ("diffie-hellman-group18-sha512", 8192),
):
    KEX[name] = {"algorithm": "DHE", "usage": "key_establishment", "key_bits": bits}
for digest in ("sha1", "sha256"):
    KEX[f"diffie-hellman-group-exchange-{digest}"] = {"algorithm": "DHE", "usage": "key_establishment"}

HOST_KEYS = {
    "ssh-rsa": {"algorithm": "RSA", "usage": "signature", "hash_algorithm": "SHA-1"},
    "rsa-sha2-256": {"algorithm": "RSA", "usage": "signature", "hash_algorithm": "SHA-256"},
    "rsa-sha2-512": {"algorithm": "RSA", "usage": "signature", "hash_algorithm": "SHA-512"},
    "ssh-dss": {"algorithm": "DSA", "usage": "signature", "hash_algorithm": "SHA-1"},
    "ssh-ed25519": {"algorithm": "Ed25519", "usage": "signature"},
    "ssh-ed448": {"algorithm": "Ed448", "usage": "signature"},
}
for bits in (256, 384, 521):
    KEX[f"ecdh-sha2-nistp{bits}"] = {
        "algorithm": "ECDHE", "usage": "key_establishment", "named_group": f"secp{bits}r1",
    }
    HOST_KEYS[f"ecdsa-sha2-nistp{bits}"] = {
        "algorithm": "ECDSA", "usage": "signature", "named_group": f"secp{bits}r1",
    }

CIPHERS = {
    "3des-cbc": {"algorithm": "3DES", "usage": "encryption", "mode": "CBC"},
    # OpenSSH's construction uses two keys and is not the TLS AEAD variant.
    "chacha20-poly1305@openssh.com": {"algorithm": "ChaCha20-Poly1305-OpenSSH", "usage": "encryption"},
}
for bits in (128, 192, 256):
    for mode in ("cbc", "ctr"):
        CIPHERS[f"aes{bits}-{mode}"] = {
            "algorithm": "AES", "usage": "encryption", "key_bits": bits, "mode": mode.upper(),
        }
for bits in (128, 256):
    CIPHERS[f"aes{bits}-gcm@openssh.com"] = {
        "algorithm": "AES", "usage": "encryption", "key_bits": bits, "mode": "GCM",
    }

MACS = {}
for name, digest in (("hmac-sha1", "SHA-1"), ("hmac-md5", "MD5"),
                     ("hmac-sha2-256", "SHA-256"), ("hmac-sha2-512", "SHA-512")):
    for suffix in ("", "-etm@openssh.com"):
        MACS[name + suffix] = {"algorithm": "HMAC", "usage": "mac", "hash_algorithm": digest}

# Extension and strict-KEX signaling names are not key-exchange algorithms.
SSH_SIGNALS = {"ext-info-c", "ext-info-s", "kex-strict-c-v00@openssh.com", "kex-strict-s-v00@openssh.com"}
SSH_FIELDS = (
    ("kex_algorithms", KEX, "key_establishment"),
    ("server_host_key_algorithms", HOST_KEYS, "signature"),
    ("encryption_algorithms_client_to_server", CIPHERS, "encryption"),
    ("encryption_algorithms_server_to_client", CIPHERS, "encryption"),
    ("mac_algorithms_client_to_server", MACS, "mac"),
    ("mac_algorithms_server_to_client", MACS, "mac"),
)
