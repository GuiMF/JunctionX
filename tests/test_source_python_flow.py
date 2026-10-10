"""Contextual key provenance must add evidence without weakening scope rules."""

import ast

import pytest

from adapters.source_python import _KeyFlow, _Scanner, detect


IMPORTS = """from cryptography.hazmat.primitives.asymmetric import rsa, ed25519, padding
from cryptography.hazmat.primitives import hashes
"""
FACTORY = """def make_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)
"""
SIGNER = """def apply_signature(key, message):
    return key.sign(message, padding.PKCS1v15(), hashes.SHA256())
"""


def signatures(source):
    return [finding for finding in detect(IMPORTS + source) if finding.usage == "signature" and finding.rule == "python-signature"]


def test_factory_argument_flow_keeps_parameter_uncertainty():
    findings = signatures(FACTORY + SIGNER + "apply_signature(make_key(), b'payload')\n")
    assert len(findings) == 1
    assert findings[0].algorithm == "RSA"
    assert findings[0].parameters.key_bits is None
    assert findings[0].parameters.hash_algorithm == "SHA-256"


def test_renamed_tuple_return_and_verifier_in_try():
    source = """def new_pair():
    secret = rsa.generate_private_key(65537, 3072)
    return secret, secret.public_key()
def issue(material, content):
    return material.sign(content, padding.PKCS1v15(), hashes.SHA1())
def check(material, content, stamp):
    try:
        material.verify(stamp, content, padding.PKCS1v15(), hashes.SHA1())
        return True
    except Exception:
        return False
private, public = new_pair()
stamp = issue(private, b'message')
assert check(public, b'message', stamp)
"""
    findings = signatures(source)
    assert [finding.api for finding in findings] == ["cryptography.RSA.sign", "cryptography.RSA.verify"]
    assert all(finding.parameters.key_bits is None for finding in findings)


def test_nested_returns_keyword_and_positional_only_arguments():
    source = FACTORY + """def forward(value, /):
    return value
def sign_it(message, *, key):
    return key.sign(message, padding.PKCS1v15(), hashes.SHA256())
def outer(value):
    return forward(value)
sign_it(b'payload', key=outer(make_key()))
"""
    assert len(signatures(source)) == 1


def test_direct_return_receiver_and_nested_tuple_unpacking():
    source = FACTORY + """def wrapped():
    key = make_key()
    return ((key, key.public_key()), None)
(a, b), ignored = wrapped()
a.sign(payload, padding.PKCS1v15(), hashes.SHA256())
b.verify(signature, payload, padding.PKCS1v15(), hashes.SHA256())
make_key().sign(payload, padding.PKCS1v15(), hashes.SHA256())
"""
    assert len(signatures(source)) == 3


def test_repeated_contexts_emit_once_and_do_not_claim_one_size():
    source = SIGNER + """a = rsa.generate_private_key(65537, 1024)
b = rsa.generate_private_key(65537, 4096)
apply_signature(a, payload)
apply_signature(b, payload)
apply_signature(a, payload)
"""
    findings = signatures(source)
    assert len(findings) == 1
    assert findings[0].parameters.key_bits is None


@pytest.mark.parametrize("unknown_call", [
    "apply_signature(custom, payload)",
    "apply_signature(*arguments)",
    "apply_signature(**arguments)",
    "apply_signature(make_key())",
    "apply_signature(make_key(), payload, extra)",
    "apply_signature(make_key(), payload, key=custom)",
    "apply_signature(key=make_key(), message=payload, unsupported=True)",
    "apply_signature(ed25519.Ed25519PrivateKey.generate(), payload)",
])
def test_incompatible_or_unknown_context_rejects_new_occurrence(unknown_call):
    for calls in [f"apply_signature(make_key(), payload)\n{unknown_call}\n", f"{unknown_call}\napply_signature(make_key(), payload)\n"]:
        assert signatures(FACTORY + SIGNER + calls) == []


@pytest.mark.parametrize("definition", [
    "@decorator\ndef make_key():\n    return rsa.generate_private_key(65537, 2048)\n",
    "async def make_key():\n    return rsa.generate_private_key(65537, 2048)\n",
    "def make_key():\n    yield rsa.generate_private_key(65537, 2048)\n",
    "def make_key():\n    if flag:\n        return rsa.generate_private_key(65537, 2048)\n    return custom\n",
    "def make_key():\n    key = rsa.generate_private_key(65537, 2048)\n    if flag:\n        key = custom\n    return key\n",
    "def make_key():\n    return make_key()\n",
    "def make_key():\n    global rsa\n    return rsa.generate_private_key(65537, 2048)\n",
])
def test_unsupported_factory_semantics_stay_unknown(definition):
    assert signatures(definition + SIGNER + "apply_signature(make_key(), payload)\n") == []


@pytest.mark.parametrize("statement", [
    "make_key = custom",
    "if flag:\n    make_key = custom",
    "rsa = custom",
    "rsa.generate_private_key = custom",
    "del make_key",
])
def test_reassigned_factory_or_import_stays_unknown(statement):
    assert signatures(FACTORY + SIGNER + statement + "\napply_signature(make_key(), payload)\n") == []


def test_parameter_and_local_rebinding_do_not_reuse_global_fact():
    source = FACTORY + """key = make_key()
def apply_signature(key, message):
    key = custom
    return key.sign(message, padding.PKCS1v15(), hashes.SHA256())
apply_signature(key, payload)
"""
    assert signatures(source) == []


def test_unknown_transitive_context_invalidates_inferred_callee():
    source = FACTORY + SIGNER + """def wrapper(key):
    return apply_signature(key, payload)
wrapper(make_key())
wrapper(*unresolved)
"""
    assert signatures(source) == []


@pytest.mark.parametrize("escape", [
    "callback = apply_signature\ncallback(custom, payload)",
    "register(apply_signature)",
    "callbacks = [apply_signature]\ncallbacks[0](custom, payload)",
    "callbacks = {'cb': apply_signature}\ncallbacks['cb'](custom, payload)",
    "callback = lambda: apply_signature(custom, payload)\ncallback()",
    "@decorator\ndef callback():\n    apply_signature(custom, payload)\ncallback()",
])
def test_escaped_function_has_untracked_contexts(escape):
    assert signatures(FACTORY + SIGNER + "apply_signature(make_key(), payload)\n" + escape) == []


def test_default_parameters_are_not_evaluated_at_call_time():
    source = FACTORY + """def apply_signature(key=custom):
    return key.sign(payload, padding.PKCS1v15(), hashes.SHA256())
apply_signature(make_key())
apply_signature()
"""
    assert signatures(source) == []


def test_padding_and_method_names_never_establish_key_provenance():
    source = """def make_key():
    return application.key()
""" + SIGNER + "apply_signature(make_key(), payload)\n"
    assert signatures(source) == []


@pytest.mark.parametrize("budget, limit", [("MAX_CALLS", 3), ("MAX_DEPTH", 0), ("MAX_VISITS", 20)])
def test_bounded_pass_preserves_all_original_findings_when_budget_expires(monkeypatch, budget, limit):
    source = IMPORTS + FACTORY + SIGNER + "apply_signature(make_key(), payload)\n" * 8
    baseline = _Scanner()
    baseline.visit(ast.parse(source))
    monkeypatch.setattr(_KeyFlow, budget, limit)
    assert detect(source) == sorted(baseline.findings, key=lambda item: (item.line, item.column, item.slot))


def test_recursion_preserves_original_direct_findings():
    source = IMPORTS + """key = rsa.generate_private_key(65537, 2048)
key.sign(payload, padding.PKCS1v15(), hashes.SHA256())
def recurse(value):
    return recurse(value)
recurse(key)
"""
    baseline = _Scanner()
    baseline.visit(ast.parse(source))
    assert detect(source) == sorted(baseline.findings, key=lambda item: (item.line, item.column, item.slot))


def test_initial_interprocedural_rollout_preserves_baseline_ed25519_scope():
    source = IMPORTS + """def make_key():
    return ed25519.Ed25519PrivateKey.generate()
def sign(key):
    return key.sign(payload)
sign(make_key())
"""
    baseline = _Scanner()
    baseline.visit(ast.parse(source))
    assert detect(source) == sorted(baseline.findings, key=lambda item: (item.line, item.column, item.slot))


def test_mutable_return_container_is_not_treated_as_stable_tuple():
    source = FACTORY + """def collection():
    return [make_key()]
keys = collection()
keys.clear()
(key,) = keys
key.sign(payload, padding.PKCS1v15(), hashes.SHA256())
"""
    assert signatures(source) == []
