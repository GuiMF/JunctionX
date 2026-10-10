#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
adapters/source.py  -  QuantumTrace, workstream 02 (descoberta em codigo-fonte)

O QUE FAZ
  1. Le os ficheiros .py / .java / .go de uma pasta.
  2. Procura usos de criptografia com regras proprias (regex), ignorando
     comentarios e linhas de import.
  3. Completa o que o CryptoScan nao extrai: tamanho RSA, modo AES,
     iteracoes PBKDF2, valores de constantes (KEY_BITS = 256, ...).
  4. (Opcional) cruza o resultado com o JSON do CryptoScan:
        - linha que ambos detetaram  -> fica registado na evidencia
        - linha que SO o CryptoScan viu -> vai para coverage.unmatched_scanner_hits
          (cobertura em aberto, nunca esquecida nem inventada)
  5. Escreve findings no formato Finding v1.

O QUE NAO FAZ
  Este adapter OBSERVA, nao avalia. quantum_status, challenge_tier,
  rationale e recommendation ficam a null: quem os preenche e o Core (Pessoa 4).
  Tambem nao ha analise de fluxo de dados: ligar uma chave criada numa funcao
  ao uso noutra funcao nao e feito (ver KNOWN_GAPS).

USO
  python source.py <pasta>                                  # so regras proprias
  python source.py <pasta> --cryptoscan-json cs_out.json    # com cruzamento
  python source.py <pasta> --cryptoscan-exe C:\\...\\cryptoscan.exe
  python source.py <pasta> --out source_findings.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

ADAPTER_VERSION = "0.1.0"
RULES_VERSION = "source-rules-v1"
LANGS = {".py": "python", ".java": "java", ".go": "go"}
SKIP_DIRS = {".git", "node_modules", "vendor", "__pycache__", ".venv", "venv"}

SUPPORTED_PATTERNS = {
    "python": [
        "rsa.generate_private_key (key_size)", "Ed25519PrivateKey.generate",
        "hashlib.md5/sha1/sha2/sha3", "hashes.X() (fora de PBKDF2/HMAC)",
        "hmac.new / hmac.HMAC", "PBKDF2HMAC", "hashlib.pbkdf2_hmac",
        "algorithms.AES + modes.X", "AESGCM(...)", "AESGCM.generate_key",
    ],
    "java": [
        "KeyPairGenerator RSA (+initialize) / Ed25519", "Signature.getInstance (XwithRSA, Ed25519)",
        "MessageDigest.getInstance", "Mac.getInstance (HmacX)",
        "SecretKeyFactory PBKDF2WithHmacX (+PBEKeySpec)", "Cipher.getInstance (AES/MODO/..., RSA/...)",
        "KeyGenerator AES (+init)", "new SecretKeySpec(constante, \"AES\")",
    ],
    "go": [
        "rsa.GenerateKey", "rsa.Sign/Verify (PKCS1v15, PSS)", "rsa.Encrypt/Decrypt (OAEP, PKCS1v15)",
        "ed25519.GenerateKey/Sign/Verify", "md5/sha1/sha256/sha512 Sum*/New*",
        "hmac.New(pkg.New, ...)", "pbkdf2.Key", "aes.NewCipher (+cipher.NewGCM/CBC/CTR; ECB inferido)",
    ],
}

KNOWN_GAPS = [
    "Sem analise de fluxo de dados: o tamanho de uma chave so e extraido quando esta na mesma "
    "chamada, numa constante simples do mesmo ficheiro, ou num argumento por omissao da funcao.",
    "Constantes: so inteiros simples e literais de bytes/strings no mesmo ficheiro (sem expressoes).",
    "Docstrings Python multi-linha e strings multi-linha contam como codigo.",
    "Nomes de algoritmos dentro de strings normais (ex.: print) podem gerar falsos positivos.",
    "PBKDF2 implementado a mao (ex.: loop de HMAC) nao e reconhecido como PBKDF2; so se ve o HMAC.",
    "Algoritmos fora da lista suportada (ECDSA, DSA, DH, ChaCha20...) nao geram finding; "
    "se o CryptoScan os viu, aparecem em coverage.unmatched_scanner_hits.",
    "ECB em Go e INFERIDO (block.Encrypt direto, sem cipher.NewXxx na funcao): confianca media.",
]


# ----------------------------------------------------------------- utilitarios
def norm_hash(name):
    """'SHA256' / 'sha-1' / 'MD5' -> nome canonico, ou None se desconhecido."""
    if not name:
        return None
    n = re.sub(r"[-_/]", "", name.strip().lower())
    table = {
        "md5": "MD5", "sha1": "SHA-1", "sha224": "SHA-224", "sha256": "SHA-256",
        "sha384": "SHA-384", "sha512": "SHA-512", "sha512224": "SHA-512/224",
        "sha512256": "SHA-512/256", "sha3224": "SHA3-224", "sha3256": "SHA3-256",
        "sha3384": "SHA3-384", "sha3512": "SHA3-512",
    }
    return table.get(n)


def go_hash_name(pkg, fn):
    """(pacote Go, funcao) -> hash. Ex.: ('sha512', 'Sum384') -> 'SHA-384'."""
    if pkg == "md5":
        return "MD5"
    if pkg == "sha1":
        return "SHA-1"
    if pkg == "sha256":
        return "SHA-224" if "224" in fn else "SHA-256"
    if pkg == "sha512":
        for suffix, name in (("512_224", "SHA-512/224"), ("512_256", "SHA-512/256"), ("384", "SHA-384")):
            if suffix in fn:
                return name
        return "SHA-512"
    return None


def hmac_name(h):
    return "HMAC-" + h.replace("-", "") if h else "HMAC"


def split_args(s):
    """Divide 'a, f(b, c), "x,y"' nos argumentos de topo: ['a', 'f(b, c)', '"x,y"']."""
    out, buf, depth, quote = [], [], 0, None
    for ch in s:
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = None
            continue
        if ch in "\"'":
            quote = ch
            buf.append(ch)
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if ch == "," and depth == 0:
            out.append("".join(buf).strip())
            buf = []
        else:
            buf.append(ch)
    last = "".join(buf).strip()
    if last:
        out.append(last)
    return out


def kwarg(args, name):
    m = re.search(rf"\b{name}\s*=\s*([\w.]+)", args)
    return m.group(1) if m else None


def strip_comments(lines, lang):
    """Remove comentarios mantendo o numero de linhas (e o conteudo das strings)."""
    out, in_block = [], False
    for raw in lines:
        res, i, quote = [], 0, None
        while i < len(raw):
            c, two = raw[i], raw[i:i + 2]
            if in_block:
                if two == "*/":
                    in_block = False
                    i += 2
                else:
                    i += 1
                continue
            if quote:
                res.append(c)
                if c == "\\" and quote != "`" and i + 1 < len(raw):
                    res.append(raw[i + 1])
                    i += 2
                    continue
                if c == quote:
                    quote = None
                i += 1
                continue
            if c in "\"'" or (c == "`" and lang == "go"):
                quote = c
                res.append(c)
                i += 1
                continue
            if lang == "python" and c == "#":
                break
            if lang in ("java", "go"):
                if two == "//":
                    break
                if two == "/*":
                    in_block = True
                    i += 2
                    continue
            res.append(c)
            i += 1
        out.append("".join(res))
    return out


# ------------------------------------------------------------- observacoes
@dataclass
class Obs:
    algorithm: str
    usage: str                     # key_establishment|signature|encryption|hash|mac|kdf|unknown
    rule_id: str
    lines: list                    # [(n_linha, nota_ou_None), ...] ; a 1.a e a linha principal
    key_bits: int | None = None
    mode: str | None = None
    hash: str | None = None
    iterations: int | None = None
    confidence: str = "high"
    tag: str = ""                  # so para o passo de fusao AES em Java


class Ctx:
    """Um ficheiro: linhas originais, linhas sem comentarios e constantes simples."""

    def __init__(self, rel, lang, raw):
        self.rel, self.lang, self.raw = rel, lang, raw
        self.lines = strip_comments(raw, lang)
        self.ints, self.strs, self.blens = {}, {}, {}   # nome -> (valor, linha)
        self._constants()

    def _constants(self):
        for n, line in enumerate(self.lines, 1):
            if self.lang == "python":
                m = re.match(r"\s*([A-Za-z_]\w*)\s*(?::\s*[\w\[\]]+)?\s*=\s*(\d[\d_]*)\s*$", line)
                if m:
                    self.ints.setdefault(m.group(1), (int(m.group(2).replace("_", "")), n))
                m = re.match(r"""\s*([A-Za-z_]\w*)\s*(?::\s*\w+)?\s*=\s*b(["'])([^"'\\]*)\2\s*$""", line)
                if m:
                    self.blens.setdefault(m.group(1), (len(m.group(3)), n))
            elif self.lang == "java":
                m = re.search(r"\bstatic\s+final\s+int\s+(\w+)\s*=\s*(\d[\d_]*)\s*;", line)
                if m:
                    self.ints.setdefault(m.group(1), (int(m.group(2).replace("_", "")), n))
                m = re.search(r'\bstatic\s+final\s+String\s+(\w+)\s*=\s*"([^"]*)"\s*;', line)
                if m:
                    self.strs.setdefault(m.group(1), (m.group(2), n))
                m = re.search(r'\bbyte\[\]\s+(\w+)\s*=\s*"([^"\\]*)"\s*\.getBytes\(', line)
                if m and m.group(2).isascii():
                    self.blens.setdefault(m.group(1), (len(m.group(2)), n))
            else:  # go
                m = re.match(r"\s*const\s+(\w+)(?:\s+\w+)?\s*=\s*(\d+)\s*$", line)
                if m:
                    self.ints.setdefault(m.group(1), (int(m.group(2)), n))
                m = re.search(r'\b(?:var|const)\s+(\w+)\s*=\s*\[\]byte\("([^"\\]*)"\)', line)
                if m:
                    self.blens.setdefault(m.group(1), (len(m.group(2)), n))
                m = re.search(r'\b(?:var|const)\s+(\w+)\s*=\s*"([^"\\]*)"', line)
                if m:
                    self.blens.setdefault(m.group(1), (len(m.group(2)), n))

    # --- ajudas de leitura
    def int_of(self, tok):
        """'1024' -> (1024, None) ; 'KEY_BITS' -> (256, linha_da_constante) ; senao (None, None)."""
        if not tok:
            return None, None
        tok = tok.strip()
        if re.fullmatch(r"\d[\d_]*", tok):
            return int(tok.replace("_", "")), None
        if tok in self.ints:
            return self.ints[tok]
        return None, None

    def call_args(self, i, col):
        """Texto dentro dos parenteses da chamada cujo '(' esta na linha i, coluna col (max. 8 linhas)."""
        depth, buf = 0, []
        for j in range(i, min(i + 8, len(self.lines))):
            s = self.lines[j]
            for k in range(col if j == i else 0, len(s)):
                ch = s[k]
                if ch == "(":
                    depth += 1
                    if depth == 1:
                        continue
                elif ch == ")":
                    depth -= 1
                    if depth == 0:
                        return "".join(buf)
                if depth >= 1:
                    buf.append(ch)
            buf.append(" ")
        return "".join(buf)

    def in_call(self, i, names):
        """True se a linha i esta dentro (ou e o inicio) de uma chamada a um dos nomes."""
        pat = re.compile(rf"\b(?:{names})\(")
        if pat.search(self.lines[i]):
            return True
        for j in range(i - 1, max(i - 4, -1), -1):
            s = self.lines[j]
            if pat.search(s) and s.count("(") > s.count(")"):
                return True
        return False

    def key_bits_from_arg(self, i, tok):
        """Tamanho em bits da chave passada como 'tok' (python/java). -> (bits, [linhas], confianca)."""
        if not tok:
            return None, [], "high"
        if tok in self.blens:
            length, ln = self.blens[tok]
            return length * 8, [ln], "high"
        for j in range(i, max(i - 15, -1), -1):          # parametro com valor por omissao
            m = re.match(r"\s*def\s+\w+\s*\((.*)\)", self.lines[j])
            if m:
                d = re.search(rf"\b{re.escape(tok)}\b\s*(?::\s*[^=,]+)?=\s*(\w+)", m.group(1))
                if d and d.group(1) in self.blens:
                    length, ln = self.blens[d.group(1)]
                    return length * 8, [j + 1, ln], "medium"
                break
        return None, [], "high"

    def lines_of(self, n, *extra, note=None):
        out = [(n, note)]
        out += [(e, None) for e in extra if e]
        return out


# ------------------------------------------------------------------ Python
def scan_python(c):
    out = []
    for i, line in enumerate(c.lines):
        n = i + 1
        s = line.strip()
        if s.startswith("import ") or (s.startswith("from ") and " import " in s):
            continue

        for m in re.finditer(r"\brsa\.generate_private_key\(", line):
            args = c.call_args(i, m.end() - 1)
            bits, cl = c.int_of(kwarg(args, "key_size"))
            out.append(Obs("RSA", "unknown", "py-rsa-keygen", c.lines_of(n, cl), key_bits=bits))

        for m in re.finditer(r"\bEd25519PrivateKey\.generate\(", line):
            out.append(Obs("Ed25519", "signature", "py-ed25519-keygen", c.lines_of(n)))

        for m in re.finditer(r"\b(\w+)\.(?:sign|verify)\s*\(", line):
            args = c.call_args(i, m.end() - 1)
            if "padding." in args or "padding" in line:
                hm = re.search(r"\bhashes\.(\w+)", args)
                h = norm_hash(hm.group(1)) if hm else None
                out.append(Obs("RSA", "signature", "py-rsa-signature", c.lines_of(n), hash=h))
            elif any("ed25519" in l.lower() for l in c.lines) and m.group(1) in ("private_key", "public_key", "priv", "pub", "key"):
                out.append(Obs("Ed25519", "signature", "py-ed25519-signature", c.lines_of(n)))

        for m in re.finditer(r"\bhashlib\.(md5|sha1|sha224|sha256|sha384|sha512|sha3_\d+)\(", line):
            h = norm_hash(m.group(1)) or m.group(1).upper()
            out.append(Obs(h, "hash", "py-hashlib", c.lines_of(n), hash=h))

        for m in re.finditer(r"\bhashes\.(MD5|SHA1|SHA224|SHA256|SHA384|SHA512)\(\)", line):
            if c.in_call(i, "PBKDF2HMAC|HKDF|HMAC|sign|verify"):
                continue                      # o hash ja faz parte do finding PBKDF2/HMAC/assinatura
            h = norm_hash(m.group(1))
            out.append(Obs(h, "hash", "py-hashes-class", c.lines_of(n), hash=h))

        for m in re.finditer(r"\bhmac\.(?:new|HMAC)\(", line):
            args = c.call_args(i, m.end() - 1)
            hm = (re.search(r"\bhashlib\.(\w+)", args) or re.search(r"\bhashes\.(\w+)", args)
                  or re.search(r"digestmod\s*=\s*['\"](\w+)['\"]", args))
            h = norm_hash(hm.group(1)) if hm else None
            out.append(Obs(hmac_name(h), "mac", "py-hmac", c.lines_of(n), hash=h))

        for m in re.finditer(r"\bPBKDF2HMAC\(", line):
            args = c.call_args(i, m.end() - 1)
            hm = re.search(r"algorithm\s*=\s*hashes\.(\w+)", args)
            h = norm_hash(hm.group(1)) if hm else None
            it, l1 = c.int_of(kwarg(args, "iterations"))
            ln_bytes, l2 = c.int_of(kwarg(args, "length"))     # 'length' e em BYTES
            out.append(Obs("PBKDF2-HMAC-" + h.replace("-", "") if h else "PBKDF2", "kdf", "py-pbkdf2",
                           c.lines_of(n, l1, l2, note="length em bytes" if ln_bytes else None),
                           key_bits=ln_bytes * 8 if ln_bytes else None, iterations=it, hash=h))

        for m in re.finditer(r"\bhashlib\.pbkdf2_hmac\(", line):
            a = split_args(c.call_args(i, m.end() - 1))
            name = a[0].strip("'\"") if a else None
            h = norm_hash(name)
            it, l1 = c.int_of(a[3] if len(a) > 3 else kwarg(" ".join(a), "iterations"))
            dk, l2 = c.int_of(kwarg(" ".join(a), "dklen"))
            out.append(Obs("PBKDF2-HMAC-" + h.replace("-", "") if h else "PBKDF2", "kdf", "py-pbkdf2",
                           c.lines_of(n, l1, l2), key_bits=dk * 8 if dk else None, iterations=it, hash=h))

        for m in re.finditer(r"\balgorithms\.AES\(", line):
            a = split_args(c.call_args(i, m.end() - 1))
            bits, extra, conf = c.key_bits_from_arg(i, a[0] if a else None)
            mode = None
            for j in range(max(i - 2, 0), min(i + 3, len(c.lines))):
                mm = re.search(r"\bmodes\.(\w+)\(", c.lines[j])
                if mm:
                    mode = mm.group(1).upper()
                    break
            out.append(Obs("AES", "encryption", "py-aes", c.lines_of(n, *extra),
                           key_bits=bits, mode=mode, confidence=conf if bits else "high"))

        for m in re.finditer(r"\bAESGCM\(", line):
            a = split_args(c.call_args(i, m.end() - 1))
            bits, extra, conf = c.key_bits_from_arg(i, a[0] if a else None)
            if bits is None:
                for kn in ("KEY_LEN", "key_len", "KEY_SIZE", "key_size"):
                    if kn in c.ints:
                        kv, kln = c.ints[kn]
                        bits = kv * 8 if kv in (16, 24, 32) else kv
                        extra = [kln]
                        conf = "medium"
                        break
            out.append(Obs("AES", "encryption", "py-aesgcm", c.lines_of(n, *extra),
                           key_bits=bits, mode="GCM", confidence=conf if bits else "high"))

        for m in re.finditer(r"\bAESGCM\.generate_key\(", line):
            bits, cl = c.int_of(kwarg(c.call_args(i, m.end() - 1), "bit_length"))
            out.append(Obs("AES", "unknown", "py-aesgcm-keygen", c.lines_of(n, cl), key_bits=bits, mode="GCM"))
    return out


# -------------------------------------------------------------------- Java
JAVA_AES = re.compile(r"^AES(?:_(\d+))?(?:/([A-Za-z0-9]+)/([A-Za-z0-9]+))?$")
JAVA_PBE = re.compile(r"new\s+PBEKeySpec\(\s*[^,()]+,\s*[^,()]+,\s*(\w+)\s*,\s*(\w+)\s*\)")


def scan_java(c):
    out, used_consts = [], set()
    for i, line in enumerate(c.lines):
        n = i + 1
        s = line.strip()
        if s.startswith("import ") or s.startswith("package "):
            continue

        for m in re.finditer(r'\bKeyPairGenerator\.getInstance\(\s*"([\w-]+)"', line):
            alg = m.group(1)
            if alg.upper() == "RSA":
                bits, cl, init_line = None, None, None
                for j in range(i, min(i + 8, len(c.lines))):
                    mm = re.search(r"\.initialize\(\s*(\w+)", c.lines[j])
                    if mm:
                        bits, cl = c.int_of(mm.group(1))
                        init_line = j + 1
                        break
                out.append(Obs("RSA", "unknown", "java-rsa-keygen", c.lines_of(n, init_line, cl), key_bits=bits))
            elif alg.lower() in ("ed25519", "eddsa"):
                out.append(Obs("Ed25519", "unknown", "java-ed25519-keygen", c.lines_of(n)))

        for m in re.finditer(r'\bSignature\.getInstance\(\s*"([\w-]+)"', line):
            name = m.group(1)
            sm = re.fullmatch(r"(\w+?)with(RSA|ECDSA|DSA)(?:andMGF1)?", name, re.I)
            if sm and sm.group(2).upper() == "RSA":
                h = norm_hash(sm.group(1))
                out.append(Obs("RSA", "signature", "java-signature", c.lines_of(n), hash=h))
                if h:
                    out.append(Obs(h, "hash", "java-signature-hash",
                                   c.lines_of(n, note="hash usado na assinatura " + name), hash=h))
            elif name.lower() in ("ed25519", "eddsa"):
                out.append(Obs("Ed25519", "signature", "java-signature", c.lines_of(n)))
            elif name.upper().startswith("RSASSA-PSS"):
                out.append(Obs("RSA", "signature", "java-signature", c.lines_of(n)))

        for m in re.finditer(r'\bMessageDigest\.getInstance\(\s*"([\w-]+)"', line):
            h = norm_hash(m.group(1)) or m.group(1).upper()
            out.append(Obs(h, "hash", "java-messagedigest", c.lines_of(n), hash=h))

        for m in re.finditer(r'\bMac\.getInstance\(\s*"Hmac(\w+)"', line):
            h = norm_hash(m.group(1))
            out.append(Obs(hmac_name(h), "mac", "java-mac", c.lines_of(n), hash=h))

        for m in re.finditer(r'\bSecretKeyFactory\.getInstance\(\s*"PBKDF2WithHmac(\w+)"', line):
            h = norm_hash(m.group(1))
            it = kb = spec_line = cl1 = cl2 = None
            for j in range(max(i - 8, 0), min(i + 9, len(c.lines))):
                mm = JAVA_PBE.search(c.lines[j])
                if mm:
                    it, cl1 = c.int_of(mm.group(1))
                    kb, cl2 = c.int_of(mm.group(2))      # PBEKeySpec: tamanho em BITS
                    spec_line = j + 1
                    break
            out.append(Obs("PBKDF2-HMAC-" + h.replace("-", "") if h else "PBKDF2", "kdf", "java-pbkdf2",
                           c.lines_of(n, spec_line, cl1, cl2), key_bits=kb, iterations=it, hash=h))

        for m in re.finditer(r'\bCipher\.getInstance\(\s*(?:"([^"]+)"|(\w+))\s*\)', line):
            if m.group(1):
                trans, cl = m.group(1), None
            elif m.group(2) in c.strs:
                trans, cl = c.strs[m.group(2)]
                used_consts.add(m.group(2))
            else:
                continue
            am = JAVA_AES.match(trans)
            if am:
                mode = am.group(2).upper() if am.group(2) else None
                bits = int(am.group(1)) if am.group(1) else None
                note = None if mode else "sem modo explicito; o default do provider JCE costuma ser ECB"
                out.append(Obs("AES", "encryption", "java-aes-transformation", c.lines_of(n, cl, note=note),
                               key_bits=bits, mode=mode, confidence="high" if mode else "medium",
                               tag="aes_transform"))
            elif trans.upper().startswith("RSA"):
                out.append(Obs("RSA", "encryption", "java-rsa-cipher", c.lines_of(n, cl)))

        for m in re.finditer(r'\bKeyGenerator\.getInstance\(\s*"AES"\s*\)', line):
            bits, cl, init_line = None, None, None
            for j in range(i, min(i + 6, len(c.lines))):
                mm = re.search(r"\.init\(\s*(\w+)", c.lines[j])
                if mm:
                    bits, cl = c.int_of(mm.group(1))
                    init_line = j + 1
                    break
            out.append(Obs("AES", "unknown", "java-aes-keygen", c.lines_of(n, init_line, cl),
                           key_bits=bits, tag="aes_key"))

        for m in re.finditer(r'\bnew\s+SecretKeySpec\(\s*(\w+)\s*,\s*"AES"\s*\)', line):
            if m.group(1) in c.blens:
                length, ln = c.blens[m.group(1)]
                out.append(Obs("AES", "unknown", "java-aes-key-material", c.lines_of(n, ln),
                               key_bits=length * 8, tag="aes_key"))

    # constante com transformacao AES declarada mas sem Cipher.getInstance(constante) visto
    for name, (val, ln) in c.strs.items():
        am = JAVA_AES.match(val)
        if am and name not in used_consts:
            mode = am.group(2).upper() if am.group(2) else None
            out.append(Obs("AES", "encryption", "java-aes-transformation-decl",
                           c.lines_of(ln, note="constante declarada; uso em Cipher.getInstance nao visto"),
                           mode=mode, confidence="medium", tag="aes_transform"))
    return merge_java_aes(out)


def merge_java_aes(obs):
    """Se o ficheiro tem transformacoes AES sem tamanho e 1 chave AES com tamanho, propaga o tamanho."""
    tr = [o for o in obs if o.tag == "aes_transform"]
    ky = [o for o in obs if o.tag == "aes_key" and o.key_bits]
    if tr and len(ky) == 1:
        k = ky[0]
        for t in tr:
            if t.key_bits is None:
                t.key_bits = k.key_bits
                t.lines += [(n, nt or "tamanho da chave ligado por estar no mesmo ficheiro") for n, nt in k.lines]
                t.rule_id += "+" + k.rule_id
                t.confidence = "medium"
        obs = [o for o in obs if o is not k]
    return obs


# ---------------------------------------------------------------------- Go
def scan_go(c):
    out, in_import = [], False
    for i, line in enumerate(c.lines):
        n = i + 1
        s = line.strip()
        if in_import:
            if s.startswith(")"):
                in_import = False
            continue
        if re.match(r"import\s*\(", s):
            in_import = True
            continue
        if s.startswith("import "):
            continue

        for m in re.finditer(r"\brsa\.GenerateKey\(", line):
            a = split_args(c.call_args(i, m.end() - 1))
            bits, cl = c.int_of(a[1] if len(a) > 1 else None)
            out.append(Obs("RSA", "unknown", "go-rsa-keygen", c.lines_of(n, cl), key_bits=bits))

        for m in re.finditer(r"\brsa\.(SignPKCS1v15|SignPSS|VerifyPKCS1v15|VerifyPSS)\(", line):
            args = c.call_args(i, m.end() - 1)
            hm = re.search(r"\bcrypto\.(MD5|SHA1|SHA224|SHA256|SHA384|SHA512)\b", args)
            h = norm_hash(hm.group(1)) if hm else None
            out.append(Obs("RSA", "signature", "go-rsa-signature", c.lines_of(n), hash=h))
            if h:
                out.append(Obs(h, "hash", "go-signature-hash",
                               c.lines_of(n, note="hash passado a assinatura/verificacao RSA"), hash=h))

        for m in re.finditer(r"\brsa\.(EncryptOAEP|DecryptOAEP|EncryptPKCS1v15|DecryptPKCS1v15)\(", line):
            out.append(Obs("RSA", "encryption", "go-rsa-encryption", c.lines_of(n)))

        for m in re.finditer(r"\bed25519\.(GenerateKey|NewKeyFromSeed|Sign|Verify)\(", line):
            usage = "signature" if m.group(1) in ("Sign", "Verify") else "unknown"
            out.append(Obs("Ed25519", usage, "go-ed25519", c.lines_of(n)))

        for m in re.finditer(r"\b(md5|sha1|sha256|sha512)\.(Sum\w*|New\w*)\(", line):
            h = go_hash_name(m.group(1), m.group(2))
            out.append(Obs(h, "hash", "go-hash", c.lines_of(n), hash=h))

        for m in re.finditer(r"\bhmac\.New\(\s*(\w+)\.(New\w*)", line):
            h = go_hash_name(m.group(1), m.group(2))
            out.append(Obs(hmac_name(h), "mac", "go-hmac", c.lines_of(n), hash=h))

        for m in re.finditer(r"\bpbkdf2\.Key\(", line):
            a = split_args(c.call_args(i, m.end() - 1))
            it, l1 = c.int_of(a[2] if len(a) > 2 else None)
            kl, l2 = c.int_of(a[3] if len(a) > 3 else None)          # em BYTES
            hm = re.search(r"(\w+)\.(New\w*)", a[4]) if len(a) > 4 else None
            h = go_hash_name(hm.group(1), hm.group(2)) if hm else None
            out.append(Obs("PBKDF2-HMAC-" + h.replace("-", "") if h else "PBKDF2", "kdf", "go-pbkdf2",
                           c.lines_of(n, l1, l2, note="keyLen em bytes" if kl else None),
                           key_bits=kl * 8 if kl else None, iterations=it, hash=h))

        for m in re.finditer(r"\baes\.NewCipher\(", line):
            end = min(i + 80, len(c.lines))
            for j in range(i + 1, end):                      # fim da funcao: '}' na coluna 0
                if c.lines[j].startswith("}"):
                    end = j + 1
                    break
            mode, mode_line, note, conf = None, None, None, "high"
            for j in range(i, end):
                mm = re.search(r"\bcipher\.New(GCM|CBC|CTR|CFB|OFB)\w*\(", c.lines[j])
                if mm:
                    mode, mode_line = mm.group(1), j + 1
                    break
            if mode is None:
                for j in range(i, end):
                    if re.search(r"\b\w+\.(?:Encrypt|Decrypt)\(", c.lines[j]):
                        mode, mode_line, conf = "ECB", j + 1, "medium"
                        note = "ECB inferido: bloco cifrado diretamente, sem cipher.NewXxx na funcao"
                        break
            extra = [mode_line] if mode_line and mode_line != n else []
            # tentar inferir tamanho de chave por constante no ficheiro
            k_bits, k_line = None, None
            for kn in ("keyLen", "key_len", "KEY_LEN", "keySize"):
                if kn in c.ints:
                    kv, kln = c.ints[kn]
                    k_bits = kv * 8 if kv in (16, 24, 32) else kv
                    k_line = kln
                    break
            if not k_bits:
                for kn, (klen, kln) in c.blens.items():
                    if "key" in kn.lower() and klen in (16, 24, 32):
                        k_bits = klen * 8
                        k_line = kln
                        break
            if k_line and k_line not in extra:
                extra.append(k_line)
            o = Obs("AES", "encryption", "go-aes", c.lines_of(n, *extra),
                    key_bits=k_bits, mode=mode, confidence="medium" if (note or k_bits) else conf)
            if note:
                o.lines.append((mode_line, note))
                o.lines = [(a, b) for a, b in o.lines if not (a == mode_line and b is None)]
            out.append(o)
    return out


# ------------------------------------------------------------ montagem final
SCANNERS = {"python": scan_python, "java": scan_java, "go": scan_go}


def to_finding(o, c):
    primary = o.lines[0]
    first = primary[0]
    extra_lines = sorted(o.lines[1:], key=lambda x: (x[0], x[1] is None))
    seen, evidence = set(), []
    for n, note in [primary] + extra_lines:
        if n in seen and note is None:
            continue
        seen.add(n)
        detail = c.raw[n - 1].strip()[:140] + (f"   [{note}]" if note else "")
        evidence.append({"file": c.rel, "locator": f"line {n}", "detail": detail})

    # ID estavel da ocorrencia no codigo (nao muda mesmo que o algoritmo seja alterado num refactor)
    asset_identity = f"{c.rel}:L{first}"
    raw_asset = json.dumps(["source", asset_identity], sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    asset_id = "asset-" + hashlib.sha256(raw_asset.encode("utf-8")).hexdigest()[:32]

    slot = o.rule_id
    raw_fid = json.dumps([asset_id, o.usage, slot, "declared"], sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    fid = "finding-" + hashlib.sha256(raw_fid.encode("utf-8")).hexdigest()[:32]

    return {
        "schema_version": "1.0",
        "id": fid,
        "asset_id": asset_id,
        "source_type": "source",
        "algorithm": o.algorithm,
        "parameters": {
            "key_bits": o.key_bits,
            "mode": o.mode,
            "named_group": None,
            "hash_algorithm": o.hash,
            "iterations": o.iterations,
        },
        "usage": o.usage,
        "evidence_kind": "declared",
        "evidence": evidence,
        "confidence": o.confidence,
        # Default do contrato v1 (a classificacao e feita no Core):
        "quantum_status": "unknown",
        "challenge_tier": "unknown",
        "classical_issues": [],
        "posture_issues": [],
        "owner": None,
        "observed_at": None,
        "rule_id": f"{RULES_VERSION}:{o.rule_id}",
        "rationale": None,
        "recommendation": None,
        "references": [],
    }


def norm_path(p):
    return os.path.normcase(os.path.abspath(p))


def is_noise_hit(hit):
    """Hits do CryptoScan que sao imports, dependencias ou so nomes de tipos."""
    if str(hit.get("category", "")).lower() in ("library import", "dependency"):
        return True
    ctx = str(hit.get("context", "")).strip()
    return (ctx.startswith("import ") or ctx.startswith("package ") or ctx.startswith("func ")
            or (ctx.startswith("from ") and " import " in ctx)
            or re.fullmatch(r'"[\w./-]+"', ctx) is not None)


def run_cryptoscan(exe, root):
    out = Path(tempfile.mkdtemp()) / "cryptoscan.json"
    subprocess.run([exe, "scan", str(root), "-v", "--format", "json", "--output", str(out)],
                   capture_output=True, text=True)
    if not out.exists():
        raise RuntimeError("o CryptoScan nao produziu JSON (verifica o caminho do executavel)")
    return out


def scan_source(root, cryptoscan_json=None, cryptoscan_exe=None):
    root = Path(root)
    errors, files = [], []
    for p in sorted(root.rglob("*")):
        if p.is_file() and p.suffix in LANGS and not (set(p.relative_to(root).parts) & SKIP_DIRS):
            files.append(p)

    findings, by_file, per_lang = [], [], {"python": 0, "java": 0, "go": 0}
    for p in files:
        lang = LANGS[p.suffix]
        try:
            raw = p.read_text(encoding="utf-8", errors="replace").splitlines()
            c = Ctx(p.relative_to(root).as_posix(), lang, raw)
            obs = SCANNERS[lang](c)
        except Exception as e:                    # um ficheiro mau nao apaga o resto
            errors.append({"file": str(p), "error": f"{type(e).__name__}: {e}"})
            continue
        per_lang[lang] += 1
        seen = set()
        for o in obs:
            f = to_finding(o, c)
            if f["id"] in seen:
                continue
            seen.add(f["id"])
            findings.append(f)
            by_file.append((norm_path(p), f))

    # ---- cruzamento com o CryptoScan (opcional)
    cs_info, unmatched = None, []
    try:
        if cryptoscan_exe and not cryptoscan_json:
            cryptoscan_json = run_cryptoscan(cryptoscan_exe, root)
        if cryptoscan_json:
            data = json.loads(Path(cryptoscan_json).read_text(encoding="utf-8"))
            cs_info = data.get("tool", {})
            covered = {}
            for fpath, f in by_file:
                for ev in f["evidence"]:
                    parts = Path(ev["file"]).parts
                    rkey = next(("/".join(parts[i:]).lower() for i in range(len(parts)) if parts[i] in ("go", "java", "python")), Path(ev["file"]).as_posix().lower())
                    covered.setdefault((rkey, int(ev["locator"].split()[1])), f)
            for hit in data.get("findings", []):
                fp = str(hit.get("file", ""))
                if Path(fp).suffix not in LANGS or is_noise_hit(hit):
                    continue
                parts = Path(fp).parts
                rkey = next(("/".join(parts[i:]).lower() for i in range(len(parts)) if parts[i] in ("go", "java", "python")), Path(fp).as_posix().lower())
                line_no = int(hit.get("line", 0))
                key = (rkey, line_no)
                if key in covered:
                    f = covered[key]
                    f["evidence"].append({
                        "file": f["evidence"][0]["file"], "locator": f"line {line_no}",
                        "detail": f"CryptoScan {cs_info.get('version', '')} ({hit.get('id')}) "
                                  f"tambem detetou esta linha"})
                else:
                    unmatched.append({"file": rkey,
                                      "line": line_no, "scanner_id": hit.get("id"),
                                      "scanner_type": hit.get("type"), "context": str(hit.get("context", "")).strip()})
    except Exception as e:
        errors.append({"file": str(cryptoscan_json or cryptoscan_exe), "error": f"cruzamento CryptoScan falhou: {e}"})

    findings.sort(key=lambda f: (f["evidence"][0]["file"], int(f["evidence"][0]["locator"].split()[1]), f["algorithm"]))
    return {
        "adapter": "source", "adapter_version": ADAPTER_VERSION, "rules_version": RULES_VERSION,
        "cryptoscan": cs_info,
        "findings": findings,
        "coverage": {
            "files_scanned": per_lang, "files_failed": len(errors),
            "supported_patterns": SUPPORTED_PATTERNS,
            "unmatched_scanner_hits": unmatched,
            "known_gaps": KNOWN_GAPS,
        },
        "errors": errors,
    }


def to_normalized_fixture(res, input_name="source-scan.json"):
    """Converte o resultado do scan no formato NormalizedFixture esperado pelo Core/API."""
    total_files = sum(res["coverage"]["files_scanned"].values())
    return {
        "fixture_format": "quantumtrace.normalized.v1",
        "result": {
            "findings": res["findings"],
            "coverage": [
                {
                    "source_type": "source",
                    "input_name": input_name,
                    "unit": "files",
                    "assessed": total_files,
                    "unknown": 0,
                    "unsupported": 0,
                    "failed": res["coverage"]["files_failed"],
                }
            ],
            "errors": [],
            "relationships": [],
            "tool_versions": {
                "source-adapter": ADAPTER_VERSION,
                "source-rules": RULES_VERSION,
            },
        },
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description="QuantumTrace - adapter de codigo-fonte")
    ap.add_argument("root", help="pasta com os ficheiros .py/.java/.go")
    ap.add_argument("--cryptoscan-json", help="JSON gerado pelo CryptoScan (cruzamento opcional)")
    ap.add_argument("--cryptoscan-exe", help="caminho do cryptoscan.exe (corre-o automaticamente)")
    ap.add_argument("--out", default="source_findings.json", help="ficheiro de saida")
    ap.add_argument("--fixture", help="exporta fixture normalizada (compativel com POST /api/scans do Core)")
    args = ap.parse_args(argv)

    res = scan_source(args.root, args.cryptoscan_json, args.cryptoscan_exe)
    Path(args.out).write_text(json.dumps(res, indent=2, ensure_ascii=False), encoding="utf-8")

    if args.fixture:
        fix = to_normalized_fixture(res, input_name=Path(args.fixture).name)
        Path(args.fixture).write_text(json.dumps(fix, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"{len(res['findings'])} findings em {sum(res['coverage']['files_scanned'].values())} ficheiros "
          f"({res['coverage']['files_scanned']}) -> {args.out}")
    if args.fixture:
        print(f"  Fixture para o Core gravada em -> {args.fixture}")
    for f in res["findings"]:
        ev = f["evidence"][0]
        p = f["parameters"]
        det = ", ".join(f"{k}={v}" for k, v in p.items() if v is not None and k != "named_group")
        print(f"  {ev['file']}:{ev['locator'].split()[1]:>3}  {f['algorithm']:<22} {f['usage']:<10} "
          f"{f['confidence']:<6} {det}")
    if res["coverage"]["unmatched_scanner_hits"]:
        print(f"  + {len(res['coverage']['unmatched_scanner_hits'])} linhas so vistas pelo CryptoScan "
              f"(coverage.unmatched_scanner_hits)")
    for e in res["errors"]:
        print("  ERRO:", e)
    return 0


if __name__ == "__main__":
    sys.exit(main())