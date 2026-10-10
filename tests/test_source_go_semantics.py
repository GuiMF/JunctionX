"""Canonical algorithm variants and fail-closed structural checks.

All examples are independent of benchmark fixture files and identifiers.
"""
import re

import pytest

from adapters.source_jvm_go import detect_go


KDF = '''package sample
import (
    "crypto/hmac"
    "crypto/sha256"
    "encoding/binary"
)
func expand(p, s []byte, c, n int) []byte {
    h := sha256.Size
    blocks := (n + h - 1) / h
    result := make([]byte, 0, blocks*h)
    for b := 1; b <= blocks; b++ {
        first := hmac.New(sha256.New, p)
        first.Write(s)
        var counter [4]byte
        binary.BigEndian.PutUint32(counter[:], uint32(b))
        first.Write(counter[:])
        u := first.Sum(nil)
        accumulator := make([]byte, h)
        copy(accumulator, u)
        for r := 1; r < c; r++ {
            next := hmac.New(sha256.New, p)
            next.Write(u)
            u = next.Sum(nil)
            for j := range accumulator {
                accumulator[j] = accumulator[j] ^ u[j]
            }
        }
        result = append(result, accumulator...)
    }
    return result[:n]
}
func caller(p, s []byte) []byte {
    return expand(p, s, 5000, 48)
}
'''

BLOCKS = '''package sample
import "crypto/aes"
func enc(src, key []byte) ([]byte, error) {
    b, err := aes.NewCipher(key)
    if err != nil { return nil, err }
    dst := make([]byte, len(src))
    for i := 0; i < len(src); i += aes.BlockSize {
        b.Encrypt(dst[i:i+aes.BlockSize], src[i:i+aes.BlockSize])
    }
    return dst, nil
}
'''


def inferred(source, algorithm):
    return [f for f in detect_go(source) if f.algorithm == algorithm and f.rule != "go-api-call"]


@pytest.mark.parametrize("package,digest", [("sha1", "SHA-1"), ("sha256", "SHA-256"), ("sha512", "SHA-512")])
def test_pbkdf2_hash_variants_and_explicit_xor(package, digest):
    findings = inferred(KDF.replace("sha256", package), "PBKDF2")
    assert len(findings) == 1
    assert findings[0].parameters.model_dump(exclude_none=True) == {
        "hash_algorithm": digest, "iterations": 5000, "key_bits": 384,
    }


def test_pbkdf2_renaming_comments_and_semicolons_do_not_change_proof():
    renamed = re.sub(r"\b(expand|first|next|u|accumulator|result|counter|blocks|b|r|j|h|p|s|c|n)\b",
                     lambda m: "renamed_" + m[0], KDF)
    renamed = renamed.replace("renamed_u =", "/* dependency retained */ renamed_u =")
    renamed = renamed.replace("renamed_first.Write(renamed_s)\n", "renamed_first.Write(renamed_s); ")
    assert len(inferred(renamed, "PBKDF2")) == 1


@pytest.mark.parametrize("before,after", [
    ("first.Sum(nil)", "first.Sum(s)"),
    ("next.Sum(nil)", "first.Sum(nil)"),
    ("next := hmac.New(sha256.New, p)", "next := hmac.New(sha256.New, s)"),
    ("copy(accumulator, u)", "copy(accumulator, u)\n        u[0] = 0"),
    ("u = next.Sum(nil)", "u := next.Sum(nil)"),
    ("accumulator[j] = accumulator[j] ^ u[j]", "accumulator[j] = accumulator[j] ^ u[0]"),
    ("blocks := (n + h - 1) / h", "blocks := (n + h) / h"),
    ("return result[:n]", "return result"),
    ("first.Write(counter[:])", "other.Write(counter[:])"),
])
def test_pbkdf2_requires_entire_linked_algorithm(before, after):
    assert not inferred(KDF.replace(before, after), "PBKDF2")


@pytest.mark.parametrize("name", ["copy", "append", "make", "uint32", "nil"])
def test_pbkdf2_shadowed_predeclared_names_fail_closed(name):
    source = KDF.replace("func expand", f"var {name} = custom\nfunc expand")
    assert not inferred(source, "PBKDF2")


def test_pbkdf2_unknown_arguments_keep_parameters_unknown():
    source = KDF.replace("5000, 48", "rounds, size")
    finding, = inferred(source, "PBKDF2")
    assert finding.parameters.iterations is None
    assert finding.parameters.key_bits is None
    assert finding.parameters.hash_algorithm == "SHA-256"


def test_pbkdf2_local_alias_retains_summary_and_rebinding_invalidates_it():
    source = KDF.replace("return expand(p, s, 5000, 48)", "alias := expand\n return alias(p, s, 5000, 48)")
    assert len(inferred(source, "PBKDF2")) == 1
    assert not inferred(source.replace("return alias", "alias = foreign\n return alias"), "PBKDF2")


def test_ecb_occurrence_keeps_factory_metadata_unchanged():
    findings = detect_go(BLOCKS)
    assert len(findings) == 2
    assert findings[0].parameters.mode is None
    assert findings[1].parameters.mode == "ECB"
    assert findings[0].line != findings[1].line


def test_supplemental_budget_does_not_erase_ordinary_api_findings(monkeypatch):
    from adapters import source_go_semantics
    monkeypatch.setattr(source_go_semantics, "SEMANTIC_TOKEN_LIMIT", 16)
    findings = detect_go(BLOCKS)
    assert len(findings) == 1
    assert findings[0].algorithm == "AES"
    assert findings[0].parameters.mode is None
    assert findings[0].rule == "go-api-call"


@pytest.mark.parametrize("before,after", [
    ("b.Encrypt", "mix(src, previous)\n        b.Encrypt"),
    ("b.Encrypt", "b = other\n        b.Encrypt"),
    ("b.Encrypt", "b.Decrypt"),
    ("dst := make([]byte, len(src))", "dst := src"),
    ("dst := make([]byte, len(src))", "expose(b)\n    dst := make([]byte, len(src))"),
    ("return dst, nil", "xor(dst, src)\n    return dst, nil"),
    ("i += aes.BlockSize", "i += 8"),
    ("dst[i:i+aes.BlockSize]", "dst[:aes.BlockSize]"),
    ("src[i:i+aes.BlockSize]", "counter[:aes.BlockSize]"),
])
def test_ecb_near_matches_keep_base_detection_without_claiming_mode(before, after):
    source = BLOCKS.replace(before, after)
    assert not inferred(source, "AES")
    assert any(f.algorithm == "AES" and f.parameters.mode is None for f in detect_go(source))
