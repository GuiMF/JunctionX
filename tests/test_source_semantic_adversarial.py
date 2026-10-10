"""Independent counterexamples for newly inferred source semantics.

These fixtures exercise the public detectors and are separate from the pinned
organizer benchmark. Near misses must keep the original primitive findings.
"""

import pytest

from adapters.source_jvm_go import detect_go
from adapters.source_python import detect


PY_IMPORT = "from cryptography.hazmat.primitives.asymmetric import rsa\n"
PY_FACTORY = "def factory():\n    return rsa.generate_private_key(65537, 2048)\n"
PY_SIGNER = "def dispatch(receiver):\n    return receiver.sign(payload)\n"


def signatures(source):
    return [f for f in detect(source) if f.usage == "signature"]


@pytest.mark.parametrize("factory", [
    "@replace\n" + PY_FACTORY,
    "def factory():\n    yield rsa.generate_private_key(65537, 2048)\n",
    "async def factory():\n    return rsa.generate_private_key(65537, 2048)\n",
    "def factory():\n    if condition:\n        return foreign\n    return rsa.generate_private_key(65537, 2048)\n",
    "def factory():\n    return factory()\n",
])
def test_python_unproved_factory_cannot_establish_receiver(factory):
    assert signatures(PY_IMPORT + factory + PY_SIGNER + "dispatch(factory())\n") == []


@pytest.mark.parametrize("tail", [
    "factory = foreign\ndispatch(factory())\n",
    "dispatch = foreign\ndispatch(factory())\n",
    "if condition:\n    factory = foreign\ndispatch(factory())\n",
    "dispatch(factory())\ndispatch(unknown)\n",
    "dispatch(unknown)\ndispatch(factory())\n",
])
def test_python_rebinding_or_unknown_call_context_blocks_new_signature(tail):
    assert signatures(PY_IMPORT + PY_FACTORY + PY_SIGNER + tail) == []


def test_python_recursive_wrapper_fails_closed_without_losing_direct_api():
    source = PY_IMPORT + PY_FACTORY + """
def relay(value):
    return relay(value)
dispatch = relay
dispatch(factory())
"""
    findings = detect(source)
    assert [(f.algorithm, f.usage) for f in findings] == [("RSA", "unknown")]


@pytest.mark.parametrize("unknown_context", [
    "callbacks = [dispatch]\ncallbacks[0](unknown)\n",
    "callbacks = {'cb': dispatch}\ncallbacks['cb'](unknown)\n",
    "callback = lambda: dispatch(unknown)\ncallback()\n",
    "@decorator\ndef wrapper():\n    dispatch(unknown)\nwrapper()\n",
])
def test_python_escaped_or_skipped_call_context_does_not_claim_agreement(unknown_context):
    source = PY_IMPORT + PY_FACTORY + PY_SIGNER + "dispatch(factory())\n" + unknown_context
    assert signatures(source) == []


ECB = '''package fixture
import symmetric "crypto/aes"
func transform(input, secret []byte) []byte {
    primitive, err := symmetric.NewCipher(secret)
    if err != nil { return nil }
    output := make([]byte, len(input))
    for offset := 0; offset < len(input); offset += symmetric.BlockSize {
        primitive.Encrypt(output[offset:offset+symmetric.BlockSize], input[offset:offset+symmetric.BlockSize])
    }
    return output
}
'''


def ecb(source):
    return [f for f in detect_go(source) if f.parameters.mode == "ECB"]


def test_go_renamed_independent_blocks_are_ecb():
    findings = detect_go(ECB)
    assert len(ecb(ECB)) == 1
    assert [(f.algorithm, f.usage) for f in findings] == [("AES", "encryption"), ("AES", "encryption")]


@pytest.mark.parametrize("before,after", [
    ("primitive.Encrypt", "foreign.Encrypt"),
    ("for offset :=", "primitive = foreign\n    for offset :="),
    ("offset += symmetric.BlockSize", "offset++"),
    ("input[offset:offset+symmetric.BlockSize]", "input[:symmetric.BlockSize]"),
    ("primitive.Encrypt", "xorWithPrevious(input, output, offset)\n        primitive.Encrypt"),
    ("primitive.Encrypt", "return output\n        primitive.Encrypt"),
])
def test_go_block_loop_near_misses_are_not_ecb(before, after):
    source = ECB.replace(before, after)
    assert ecb(source) == []
    assert any(f.algorithm == "AES" for f in detect_go(source))


PBKDF = '''package fixture
import keyed "crypto/hmac"
import digest "crypto/sha256"
import wire "encoding/binary"
func stretch(secret, seasoning []byte, rounds, width int) []byte {
    chunk := digest.Size
    count := (width + chunk - 1) / chunk
    output := make([]byte, 0, count*chunk)
    for part := 1; part <= count; part++ {
        worker := keyed.New(digest.New, secret)
        worker.Write(seasoning)
        var ordinal [4]byte
        wire.BigEndian.PutUint32(ordinal[:], uint32(part))
        worker.Write(ordinal[:])
        previous := worker.Sum(nil)
        accumulator := make([]byte, chunk)
        copy(accumulator, previous)
        for round := 1; round < rounds; round++ {
            worker := keyed.New(digest.New, secret)
            worker.Write(previous)
            previous = worker.Sum(nil)
            for index := range accumulator {
                accumulator[index] ^= previous[index]
            }
        }
        output = append(output, accumulator...)
    }
    return output[:width]
}
func use(secret, salt []byte) []byte {
    return stretch(secret, salt, 1234, 24)
}
'''


def pbkdf(source):
    return [f for f in detect_go(source) if f.algorithm == "PBKDF2"]


def test_go_renamed_dependency_linked_pbkdf2():
    findings = pbkdf(PBKDF)
    assert len(findings) == 1
    assert findings[0].parameters.model_dump(exclude_none=True) == {
        "hash_algorithm": "SHA-256", "iterations": 1234, "key_bits": 192,
    }


@pytest.mark.parametrize("before,after", [
    ("wire.BigEndian", "wire.LittleEndian"),
    ("var ordinal [4]byte", "var ordinal [8]byte"),
    ("uint32(part)", "uint32(0)"),
    ("worker.Write(seasoning)", "worker.Write(secret)"),
    ("worker.Write(ordinal[:])", "worker.Write(seasoning)"),
    ("worker.Write(previous)", "worker.Write(seasoning)"),
    ("copy(accumulator, previous)", "copy(previous, accumulator)"),
    ("accumulator[index] ^= previous[index]", "accumulator[index] += previous[index]"),
    ("round < rounds", "round <= rounds"),
    ("part := 1", "part := 0"),
    ("output = append(output, accumulator...)", "output = append(output, previous...)"),
    ("return output[:width]", "return seasoning"),
])
def test_go_pbkdf2_dependencies_cannot_be_replaced_by_token_presence(before, after):
    source = PBKDF.replace(before, after)
    assert pbkdf(source) == []
    assert sum(f.algorithm == "HMAC" for f in detect_go(source)) == 2


def test_go_local_function_shadowing_cannot_inherit_pbkdf2_summary():
    source = PBKDF.replace("return stretch(secret, salt, 1234, 24)",
                           "stretch := foreign\n    return stretch(secret, salt, 1234, 24)")
    assert pbkdf(source) == []


def test_go_fake_endian_package_cannot_prove_counter_encoding():
    assert pbkdf(PBKDF.replace('"encoding/binary"', '"example/binary"')) == []


def test_go_shadowed_nil_changes_hmac_sum_semantics():
    # hash.Hash.Sum appends to its argument; a salt named nil is not empty.
    assert pbkdf(PBKDF.replace("seasoning", "nil")) == []


def test_go_grouped_package_variable_can_shadow_builtin_after_first_initializer():
    source = PBKDF.replace("func stretch", """var (
    unrelated = 1
    copy = func(dst, src []byte) int { return 0 }
)
func stretch""")
    assert pbkdf(source) == []


def test_go_deep_unsupported_control_flow_keeps_baseline_api_findings():
    source = ('package fixture\nimport "crypto/aes"\nfunc f(key []byte) {\n'
              'block, err := aes.NewCipher(key)\n' + '{\n' * 1200
              + 'println(err)\n' + '}\n' * 1200 + 'println(block)\n}\n')
    assert [(f.algorithm, f.usage) for f in detect_go(source)] == [("AES", "encryption")]
