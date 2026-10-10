"""Python occurrence, scope, and parameter regressions for the bounded scanner."""

import pytest

from adapters.source_common import SourceParseError
from adapters.source_python import detect


def test_alias_hashes_and_mac_constructor_reference():
    findings = detect("""import hashlib as digest
from hmac import new as mac
digest.md5(b'private input')
digest.sha1(b'data')
mac(b'secret', b'data', digest.sha256)
""")
    assert [(item.line, item.algorithm, item.usage) for item in findings] == [
        (3, "MD5", "hash"), (4, "SHA-1", "hash"), (5, "HMAC", "mac")]
    assert findings[-1].parameters.hash_algorithm == "SHA-256"
    assert findings[-1].parameters.key_bits == 48
    assert "secret" not in repr(findings)
    assert "private input" not in repr(findings)


def test_rsa_generation_does_not_infer_usage_or_cross_function_receiver():
    findings = detect("""from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
def generate():
    return rsa.generate_private_key(public_exponent=65537, key_size=1024)
def sign(key, message):
    return key.sign(message, padding.PKCS1v15(), hashes.SHA1())
""")
    assert [(item.line, item.algorithm, item.usage) for item in findings] == [
        (4, "RSA", "unknown"), (6, "SHA-1", "hash")]
    assert findings[0].parameters.key_bits == 1024


def test_application_sign_method_with_padding_is_not_a_crypto_api():
    assert detect("""from cryptography.hazmat.primitives.asymmetric import padding
class Ledger:
    def sign(self, note):
        return note
ledger = Ledger()
ledger.sign(padding.PKCS1v15())
ledger.verify(padding.PSS(mgf=custom, salt_length=32))
""") == []


def test_resolved_rsa_sign_and_verify_keep_sha1_parameters():
    findings = detect("""from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
key = rsa.generate_private_key(65537, 2048)
key.sign(payload, padding.PKCS1v15(), hashes.SHA1())
public = key.public_key()
public.verify(signature, payload, padding.PKCS1v15(), hashes.SHA1())
""")
    assert [(item.line, item.algorithm, item.usage) for item in findings] == [
        (3, "RSA", "unknown"), (4, "RSA", "signature"), (4, "SHA-1", "hash"),
        (6, "RSA", "signature"), (6, "SHA-1", "hash")]
    for index in (1, 3):
        assert findings[index].parameters.key_bits == 2048
        assert findings[index].parameters.hash_algorithm == "SHA-1"


def test_direct_receiver_and_ed25519():
    findings = detect("""from cryptography.hazmat.primitives.asymmetric import rsa, ed25519
key = rsa.generate_private_key(65537, 2048)
key.sign(payload, padding, digest)
public = key.public_key()
public.verify(signature, payload, padding, digest)
key = object()
key.sign(payload)
ed = ed25519.Ed25519PrivateKey.generate()
ed.sign(payload)
""")
    assert [(item.line, item.algorithm) for item in findings] == [
        (2, "RSA"), (3, "RSA"), (5, "RSA"), (8, "Ed25519"), (9, "Ed25519")]
    assert findings[2].parameters.key_bits == 2048


def test_aes_modes_lengths_and_unknown_default_argument():
    findings = detect("""import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
SIZE = 32
key = os.urandom(SIZE)
Cipher(algorithms.AES(key), modes.GCM(nonce))
AESGCM(b'0123456789abcdef')
def encryption(key=b'0123456789abcdef'):
    return Cipher(algorithms.AES(key), modes.ECB())
""")
    assert [(item.line, item.algorithm, item.parameters.mode, item.parameters.key_bits) for item in findings] == [
        (6, "AES", "GCM", 256), (7, "AES", "GCM", 128), (9, "AES", "ECB", None)]


def test_pbkdf2_nested_hash_and_byte_conversion():
    findings = detect("""import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC as KDF
ITERATIONS = 600000
KDF(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITERATIONS)
hashlib.pbkdf2_hmac('sha1', password, salt, 100, dklen=16)
""")
    assert [(item.line, item.algorithm) for item in findings] == [(5, "PBKDF2"), (5, "SHA-256"), (6, "PBKDF2")]
    assert findings[0].parameters.model_dump(exclude_none=True) == {
        "key_bits": 256, "hash_algorithm": "SHA-256", "iterations": 600000}
    assert findings[-1].parameters.model_dump(exclude_none=True) == {
        "key_bits": 128, "hash_algorithm": "SHA-1", "iterations": 100}


def test_unknown_factories_and_parameters_stay_unknown():
    findings = detect("""import hashlib, hmac
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher
hashlib.new(config.algorithm, data)
hashlib.pbkdf2_hmac(config.hash, password, salt, config.iterations)
hmac.new(key, data, config.hash)
rsa.generate_private_key(65537, configured_bits)
Cipher(algorithm, mode)
""")
    assert [item.algorithm for item in findings] == ["unknown", "PBKDF2", "HMAC", "RSA", "unknown"]
    assert all(not item.parameters.model_dump(exclude_none=True) for item in findings)


def test_imports_comments_strings_and_lookalikes_are_not_calls():
    assert detect("""import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa
# hashlib.md5(b'secret')
text = 'rsa.generate_private_key(key_size=1024)'
reference = hashlib.sha1
custom.md5(data)
def rsa():
    pass
rsa.generate_private_key(65537, 1024)
""") == []


def test_lexical_shadowing_and_rebinding():
    findings = detect("""import hashlib as h
h.md5(data)
def parameter(h):
    h.md5(data)
def lexical():
    h.md5(data)
    h = custom
def local_import():
    import hashlib as h
    h.sha256(data)
h = custom
h.sha1(data)
""")
    assert [(item.line, item.algorithm) for item in findings] == [(2, "MD5"), (10, "SHA-256")]


def test_constant_source_order_scopes_and_branch_merging():
    findings = detect("""from cryptography.hazmat.primitives.asymmetric import rsa
BITS = 1024
rsa.generate_private_key(65537, BITS)
BITS = unknown
rsa.generate_private_key(65537, BITS)
BITS = 2048
def local():
    rsa.generate_private_key(65537, BITS)
    BITS = 4096
    rsa.generate_private_key(65537, BITS)
if choice:
    BITS = 2048
else:
    BITS = 4096
rsa.generate_private_key(65537, BITS)
""")
    assert [item.parameters.key_bits for item in findings] == [1024, None, None, 4096, None]


def test_conditional_import_is_not_unconditionally_bound():
    findings = detect("""if choice:
    import hashlib as h
    h.md5(data)
h.md5(data)
""")
    assert [(item.line, item.algorithm) for item in findings] == [(3, "MD5")]


def test_comprehension_scope_lambda_and_class_method_scope():
    findings = detect("""import hashlib as h
values = [h.md5(data) for h in custom]
values = [h.md5(data) for data in inputs]
f = lambda h: h.md5(data)
class Container:
    h = custom
    h.md5(data)
    def method(self):
        return h.sha256(data)
h.sha1(data)
""")
    assert [(item.line, item.algorithm) for item in findings] == [(3, "MD5"), (9, "SHA-256"), (10, "SHA-1")]


def test_loop_with_exception_and_delete_shadowing():
    findings = detect("""import hashlib as h
for h in custom:
    h.md5(data)
import hashlib as h
with resource() as h:
    h.md5(data)
import hashlib as h
try:
    consume()
except Error as h:
    h.md5(data)
h.md5(data)
import hashlib as h
del h
h.md5(data)
""")
    assert findings == []


@pytest.mark.parametrize("text", ["import hashlib\nhashlib.md5('SECRET'", "\x00SECRET", "def broken(:\n    pass"])
def test_parse_errors_are_sanitized(text):
    with pytest.raises(SourceParseError) as caught:
        detect(text)
    assert str(caught.value) == "Python source could not be parsed or analyzed"
    assert "SECRET" not in str(caught.value)


def test_invalid_numeric_parameters_are_unknown_without_crashing():
    findings = detect("""import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa
rsa.generate_private_key(65537, True)
hashlib.pbkdf2_hmac('sha256', password, salt, 0, dklen=0)
""")
    assert findings[0].parameters.key_bits is None
    assert findings[1].parameters.iterations is None
    assert findings[1].parameters.key_bits is None


def test_conditional_expression_bindings_are_not_unconditional():
    findings = detect("""import hashlib
flag and (h := hashlib)
h.md5(data)
(h := hashlib) if flag else (h := custom)
h.sha1(data)
""")
    assert findings == []


def test_function_and_pattern_bindings_shadow_imports():
    findings = detect("""import hashlib
def hashlib():
    hashlib.md5(data)
import hashlib as h
def local(value):
    h.md5(data)
    match value:
        case {'hash': h}:
            h.md5(data)
""")
    assert findings == []


def test_comprehension_walrus_shadows_outer_import():
    findings = detect("""import hashlib as h
def local():
    h.md5(data)
    [(h := custom) for x in values]
[(h := custom) for x in values]
h.md5(data)
""")
    assert findings == []


def test_dynamic_and_relative_imports_are_not_resolved():
    assert detect("""from . import hashlib
hashlib.md5(data)
h = __import__('hashlib')
h.sha1(data)
import importlib
importlib.import_module('hashlib').md5(data)
""") == []
