"""Additional PR #6 API patterns retain PR #5's binding safeguards."""

import pytest

from adapters.source_jvm_go import detect_go


@pytest.mark.parametrize("method", ["EncryptOAEP", "DecryptOAEP", "EncryptPKCS1v15", "DecryptPKCS1v15"])
def test_rsa_encryption_operations_alias_and_oaep_digest(method):
    oaep = method.endswith("OAEP")
    args = "sha256.New(), random, key, data, nil" if oaep else "random, key, data"
    result = detect_go(f'''package example
import r "crypto/rsa"
import "crypto/sha256"
func process() {{ r.{method}({args}) }}
''')
    rsa = [finding for finding in result if finding.algorithm == "RSA"]
    assert len(rsa) == 1 and rsa[0].usage == "encryption"
    assert rsa[0].parameters.key_bits is None
    assert rsa[0].parameters.hash_algorithm == ("SHA-256" if oaep else None)
    assert len(result) == (2 if oaep else 1)


@pytest.mark.parametrize("method,algorithm", [
    ("New512_224", "SHA-512/224"), ("Sum512_224", "SHA-512/224"),
    ("New512_256", "SHA-512/256"), ("Sum512_256", "SHA-512/256"),
])
def test_truncated_sha512_exact_method_names(method, algorithm):
    result = detect_go(f'package example\nimport h "crypto/sha512"\nfunc hash() {{ h.{method}(data) }}')
    assert [(f.algorithm, f.usage) for f in result] == [(algorithm, "hash")]


def test_new_patterns_do_not_match_strings_lookalikes_or_shadowed_imports():
    assert detect_go('''package example
import r "crypto/rsa"
import h "crypto/sha512"
func process(r Fake, h Fake) {
    r.EncryptOAEP(hash, random, key, data, nil)
    h.Sum512_224(data)
}
var message = "r.EncryptPKCS1v15(random, key, data)"
''') == []
    assert detect_go('package example\nimport "crypto/sha512"\nfunc hash() { sha512.New512_fake() }') == []


def test_hash_reference_in_hmac_is_parameter_not_standalone_hash_call():
    result = detect_go('''package example
import "crypto/sha512"
import "crypto/hmac"
func mac() { hmac.New(sha512.New512_256, key) }
''')
    assert len(result) == 1 and result[0].algorithm == "HMAC"
    assert result[0].parameters.hash_algorithm == "SHA-512/256"
