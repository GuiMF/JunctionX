"""Explicit EC APIs require key provenance and the actual operation argument."""

import pytest

from adapters.source_python import detect
from core.models import ScanInput, ScanRequest
from core.service import ScanService
from export.cyclonedx import export_cyclonedx, validate_cyclonedx


IMPORTS = """from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
"""


@pytest.mark.parametrize("curve,bits", [("SECP256R1", 256), ("SECP384R1", 384), ("SECP521R1", 521)])
def test_ec_generation_sign_verify_and_exchange(curve, bits):
    findings = detect(IMPORTS + f"""key = ec.generate_private_key(ec.{curve}())
key.sign(payload, ec.ECDSA(hashes.SHA256()))
public = key.public_key()
public.verify(signature, payload, ec.ECDSA(hashes.SHA256()))
key.exchange(ec.ECDH(), peer)
""")
    assert [(f.algorithm, f.usage) for f in findings] == [
        ("EC", "unknown"), ("ECDSA", "signature"), ("SHA-256", "hash"),
        ("ECDSA", "signature"), ("SHA-256", "hash"), ("ECDH", "key_establishment"),
    ]
    for finding in [f for f in findings if f.algorithm != "SHA-256"]:
        assert finding.parameters.key_bits == bits
        assert finding.parameters.named_group == curve
    assert all(f.parameters.hash_algorithm == "SHA-256" for f in findings if f.algorithm == "ECDSA")


def test_ec_aliases_keywords_and_local_bindings():
    findings = detect("""from cryptography.hazmat.primitives.asymmetric.ec import derive_private_key as derive, SECP384R1 as Curve, ECDSA as Signature, ECDH as Exchange
from cryptography.hazmat.primitives.hashes import SHA384
curve = Curve()
key = derive(private_value=123456789, curve=curve)
signature_algorithm = Signature(algorithm=SHA384())
key.sign(data=payload, signature_algorithm=signature_algorithm)
key.public_key().verify(signature=stamp, data=payload, signature_algorithm=signature_algorithm)
key.exchange(peer_public_key=peer, algorithm=Exchange())
""")
    assert [f.algorithm for f in findings] == ["EC", "SHA-384", "ECDSA", "ECDSA", "ECDH"]
    assert all(f.parameters.named_group == "SECP384R1" for f in findings if f.algorithm != "SHA-384")
    assert all(f.parameters.hash_algorithm == "SHA-384" for f in findings if f.algorithm == "ECDSA")
    assert "123456789" not in repr(findings)


@pytest.mark.parametrize("curve", ["configured_curve", "ec.SECP256K1()", "application.SECP256R1()"])
def test_ec_unknown_curve_preserves_operation_but_no_invented_parameters(curve):
    findings = detect(IMPORTS + f"""key = ec.generate_private_key({curve})
key.sign(payload, ec.ECDSA(configured_hash))
key.exchange(ec.ECDH(), peer)
""")
    assert [f.algorithm for f in findings] == ["EC", "ECDSA", "ECDH"]
    assert all(f.parameters.model_dump(exclude_none=True) == {} for f in findings)


@pytest.mark.parametrize("body", [
    "key = application.key()\nkey.sign(payload, ec.ECDSA(hashes.SHA256()))",
    "key = application.key()\nkey.exchange(ec.ECDH(), peer)",
    "def sign(key):\n    key.sign(payload, ec.ECDSA(hashes.SHA256()))",
    "def exchange(key):\n    key.exchange(ec.ECDH(), peer)",
    "key = ec.generate_private_key(ec.SECP256R1())\nkey = application.key()\nkey.sign(payload, ec.ECDSA(hashes.SHA256()))",
    "key = ec.generate_private_key(ec.SECP256R1())\nkey.sign = custom\nkey.sign(payload, ec.ECDSA(hashes.SHA256()))",
    "key = ec.generate_private_key(ec.SECP256R1())\nec = custom\nkey.sign(payload, ec.ECDSA(hashes.SHA256()))",
    "key = ec.generate_private_key(ec.SECP256R1())\nkey.sign(ec.ECDSA(hashes.SHA256()), custom)",
    "key = ec.generate_private_key(ec.SECP256R1())\nkey.exchange(peer, ec.ECDH())",
    "key = ec.generate_private_key(ec.SECP256R1()).public_key()\nkey.sign(payload, ec.ECDSA(hashes.SHA256()))\nkey.exchange(ec.ECDH(), peer)",
    "key = ec.generate_private_key(ec.SECP256R1())\nkey.verify(signature, payload, ec.ECDSA(hashes.SHA256()))",
])
def test_ec_near_misses_do_not_invent_signatures_or_exchanges(body):
    assert all(f.algorithm not in {"ECDSA", "ECDH"} for f in detect(IMPORTS + body))


def test_ec_curve_constructor_shadowing_keeps_metadata_unknown():
    findings = detect(IMPORTS + """ec.SECP256R1 = custom
key = ec.generate_private_key(ec.SECP256R1())
key.sign(payload, ec.ECDSA(hashes.SHA256()))
""")
    assert all(f.algorithm not in {"EC", "ECDSA"} for f in findings)


def test_ec_does_not_expand_interprocedural_inference():
    findings = detect(IMPORTS + """def factory():
    return ec.generate_private_key(ec.SECP256R1())
def sign(key):
    key.sign(payload, ec.ECDSA(hashes.SHA256()))
sign(factory())
""")
    assert [f.algorithm for f in findings] == ["EC", "SHA-256"]


def test_ec_service_assessment_and_export_keep_private_material_out():
    secret = "98765432123456789"
    result = ScanService().run_scan(ScanRequest(inputs=[ScanInput(
        name="elliptic.py", source_type="source", format="raw", content=IMPORTS + f"""key = ec.derive_private_key({secret}, ec.SECP256R1())
key.sign(payload, ec.ECDSA(hashes.SHA256()))
key.exchange(ec.ECDH(), peer)
""",
    )]))
    assert result.status == "completed"
    assert all(f.quantum_status == "vulnerable" for f in result.findings if f.algorithm != "SHA-256")
    assert secret not in result.model_dump_json()
    exported = export_cyclonedx(result)
    validate_cyclonedx(exported)
    assert secret not in repr(exported)
