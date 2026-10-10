"""Bounded Java/Go API recognition, not a compiler or whole-program analysis.

Only imported APIs (or fully qualified Java APIs), literals, simple local bindings
and direct receiver configuration are recognized. No source is executed. Missing
semantic information remains unknown. Locations refer to the factory/call token.
"""
from __future__ import annotations

from dataclasses import dataclass
import ast
import re

from core.models import Parameters
from adapters.source_common import Detection, SourceParseError


@dataclass(frozen=True)
class Token:
    text: str
    line: int
    column: int
    value: object = None
    kind: str = "symbol"


@dataclass
class Value:
    kind: str
    data: object


JAVA = {
    "java.security.MessageDigest", "java.security.Signature",
    "java.security.KeyPairGenerator", "javax.crypto.Cipher", "javax.crypto.Mac",
    "javax.crypto.KeyGenerator", "javax.crypto.SecretKeyFactory",
    "javax.crypto.spec.PBEKeySpec", "javax.crypto.spec.SecretKeySpec",
}
GO = {"crypto", "crypto/rsa", "crypto/ed25519", "crypto/aes", "crypto/cipher",
      "crypto/md5", "crypto/sha1", "crypto/sha256", "crypto/sha512", "crypto/hmac",
      "crypto/pbkdf2", "golang.org/x/crypto/pbkdf2"}


def _tokens(text: str, language: str) -> list[Token]:
    result: list[Token] = []
    i, line, column = 0, 1, 1
    stack: list[str] = []
    while i < len(text):
        start, ln, col = i, line, column
        c = text[i]
        kind, value = "symbol", None
        if text.startswith("//", i):
            end = text.find("\n", i)
            i = len(text) if end < 0 else end
            kind = "skip"
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            if end < 0:
                raise SourceParseError("Unterminated source comment")
            i = end + 2
            kind = "skip"
        elif c in "\"'`":
            quote = '"""' if language == "java" and text.startswith('"""', i) else c
            if quote == "`" and language != "go":
                raise SourceParseError("Invalid source literal")
            i += len(quote)
            while i < len(text) and not text.startswith(quote, i):
                if text[i] == "\\" and quote != "`":
                    i += 2
                elif text[i] == "\n" and len(quote) == 1 and quote != "`":
                    raise SourceParseError("Unterminated source literal")
                else:
                    i += 1
            if i >= len(text):
                raise SourceParseError("Unterminated source literal")
            i += len(quote)
            raw = text[start:i]
            kind = "literal"
            if quote == "`":
                value = raw[1:-1].replace("\r", "")
            elif quote == '"""':
                # Java text block indentation/escape semantics are not inferred.
                value = None
            else:
                try:
                    value = ast.literal_eval(raw)
                    if language == "java" and re.search(r"\\(?:u|U|x|a|v|N)", raw):
                        value = None
                    if language == "go" and re.search(r"\\(?:x|[0-7])", raw):
                        # Go byte escapes need byte-preserving decoding, whereas
                        # Python strings would expand them to UTF-8 code points.
                        value = None
                except (ValueError, SyntaxError):
                    value = None
        elif c.isalpha() or c in "_$":
            i += 1
            while i < len(text) and (text[i].isalnum() or text[i] in "_$"):
                i += 1
            kind = "id"
        elif c.isdigit():
            i += 1
            while i < len(text) and (text[i].isalnum() or text[i] == "_"):
                i += 1
            kind = "number"
            raw = text[start:i].replace("_", "").rstrip("lL")
            try:
                # Leading-zero/octal forms differ by language; do not guess.
                value = None if len(raw) > 1 and raw.startswith("0") and not raw.lower().startswith("0x") else int(raw, 16 if raw.lower().startswith("0x") else 10)
            except ValueError:
                pass
        elif c.isspace():
            i += 1
            kind = "newline" if c == "\n" else "skip"
        else:
            i += 1
            if c in "([{":
                stack.append(c)
            elif c in ")]}":
                if not stack or stack.pop() != {")": "(", "]": "[", "}": "{"}[c]:
                    raise SourceParseError("Unbalanced source delimiters")
            if text[start:i + 1] in {":=", "==", "!=", "<=", ">=", "+=", "-=", "++", "--", "*=", "/="}:
                i += 1
        chunk = text[start:i]
        if kind != "skip":
            result.append(Token(chunk, ln, col, value, kind))
        if "\n" in chunk:
            line += chunk.count("\n")
            column = len(chunk.rsplit("\n", 1)[1]) + 1
        else:
            column += len(chunk)
    if stack:
        raise SourceParseError("Unbalanced source delimiters")
    return result


def _split(ts: list[Token], delimiter: str = ",") -> list[list[Token]]:
    out, part, depth = [], [], 0
    for t in ts:
        if t.text == delimiter and depth == 0:
            out.append(part)
            part = []
            continue
        part.append(t)
        if t.text in "([{" and t.kind == "symbol":
            depth += 1
        elif t.text in ")]}" and t.kind == "symbol":
            depth -= 1
    return out + [part]


def _hash(name: object) -> str | None:
    if not isinstance(name, str):
        return None
    key = name.upper().replace("-", "").replace("_", "")
    return {"MD5": "MD5", "SHA1": "SHA-1", "SHA224": "SHA-224",
            "SHA256": "SHA-256", "SHA384": "SHA-384", "SHA512": "SHA-512"}.get(key)


def _positive(x: object) -> int | None:
    return x if type(x) is int and 0 < x < 2**63 else None


class Scanner:
    def __init__(self, text: str, language: str):
        self.ts = _tokens(text, language)
        self.language = language
        self.env: dict[str, object] = {}
        self.findings: list[Detection] = []
        self.memo: dict[tuple[int, int], object] = {}
        self.conditional = 0
        self.immutable: set[str] = set()
        self.configured: dict[tuple[int, str], set[object]] = {}

    def resolve(self, ts: list[Token]) -> object:
        if not ts:
            return None
        name = "".join(t.text for t in ts)
        if len(ts) == 1:
            t = ts[0]
            return t.value if t.kind in {"number", "literal"} else self.env.get(name)
        if any(t.kind != "id" if i % 2 == 0 else t.text != "." for i, t in enumerate(ts)):
            return None
        first = self.env.get(ts[0].text)
        if isinstance(first, Value) and first.kind == "api" and len(ts) >= 3 and ts[1].text == ".":
            return Value("api", str(first.data) + name[len(ts[0].text):])
        if self.language == "java" and any(name == x or name.startswith(x + ".") for x in JAVA):
            # An explicitly shadowed package name also blocks qualified matching.
            if ts[0].text not in self.env:
                return Value("api", name)
        return None

    def value(self, ts: list[Token]) -> object:
        ts = [t for t in ts if t.kind != "newline"]
        if not ts:
            return None
        if ts[0].text == "new":
            ts = ts[1:]
        simple = self.resolve(ts)
        if simple is not None:
            return simple
        # Parentheses and known byte allocations/conversions only.
        if ts[0].text == "(" and ts[-1].text == ")":
            return self.value(ts[1:-1])
        if self.language == "java" and len(ts) >= 4 and ts[0].text == "byte" and ts[1].text == "[" and ts[-1].text == "]":
            n = _positive(self.value(ts[2:-1]))
            return Value("bytes", n) if n else None
        if self.language == "go" and len(ts) >= 6 and "".join(t.text for t in ts[:4]) == "[]byte(" and ts[-1].text == ")":
            s = self.value(ts[4:-1])
            return Value("bytes", len(s.encode("utf-8"))) if isinstance(s, str) else None
        if self.language == "java" and len(ts) >= 5 and ts[0].kind == "literal" and ts[1].text == "." and ts[2].text == "getBytes":
            s = ts[0].value
            charset = "".join(t.text for t in ts[4:-1])
            supported = charset in {"StandardCharsets.UTF_8", "java.nio.charset.StandardCharsets.UTF_8", '"UTF-8"', '"UTF8"'}
            ascii_charset = charset in {"StandardCharsets.US_ASCII", "java.nio.charset.StandardCharsets.US_ASCII", '"US-ASCII"'}
            if isinstance(s, str) and (supported or (ascii_charset and s.isascii())):
                return Value("bytes", len(s.encode("utf-8")))
        if ts[0].text == "make" and len(ts) > 5 and ts[1].text == "(" and ts[-1].text == ")":
            args = _split(ts[2:-1])
            if len(args) >= 2 and "".join(t.text for t in args[0]) == "[]byte":
                n = _positive(self.value(args[1]))
                return Value("bytes", n) if n else None
        for i, t in enumerate(ts):
            if t.text == "(" and i > 0:
                end = self.close(ts, i)
                if end == len(ts) - 1:
                    return self.call(ts[:i], _split(ts[i + 1:end]))
                break
        return None

    @staticmethod
    def close(ts: list[Token], i: int) -> int:
        depth = 0
        for j in range(i, len(ts)):
            if ts[j].text == "(" and ts[j].kind == "symbol":
                depth += 1
            elif ts[j].text == ")" and ts[j].kind == "symbol":
                depth -= 1
                if depth == 0:
                    return j
        return len(ts)

    def emit(self, token: Token, algorithm: str, usage: str, api: str, **parameters: object) -> Value:
        finding = Detection(token.line, token.column, algorithm, usage,
                            Parameters(**parameters), api=api,
                            rule=f"{self.language}-api-call")
        self.findings.append(finding)
        return Value("finding", finding)

    def configure(self, finding: Detection, **parameters: object) -> None:
        for field, value in parameters.items():
            history = self.configured.setdefault((id(finding), field), set())
            history.add(None if self.conditional else value)
            setattr(finding.parameters, field, value if len(history) == 1 and None not in history else None)

    def call(self, name: list[Token], args: list[list[Token]]) -> object:
        if not name:
            return None
        key = (name[0].line, name[0].column)
        if key in self.memo:
            return self.memo[key]
        self.memo[key] = None
        result = self._call(name, args)
        self.memo[key] = result
        return result

    def _call(self, name: list[Token], args: list[list[Token]]) -> object:
        ref = self.resolve(name)
        vals = [self.value(a) for a in args]
        arg = lambda i: vals[i] if i < len(vals) else None
        token = name[0]
        if isinstance(ref, Value) and ref.kind == "api":
            api = str(ref.data)
            if self.language == "java":
                if api == "javax.crypto.spec.PBEKeySpec":
                    return Value("pbe", (_positive(arg(2)), _positive(arg(3))))
                if api == "javax.crypto.spec.SecretKeySpec":
                    if isinstance(arg(0), Value) and arg(0).kind == "bytes":
                        if len(vals) == 2:
                            return Value("key", arg(0).data * 8)
                        if len(vals) == 4 and type(arg(1)) is int and arg(1) >= 0 and _positive(arg(2)) and arg(1) + arg(2) <= arg(0).data:
                            return Value("key", arg(2) * 8)
                    return None
                cls, _, method = api.rpartition(".")
                if cls not in JAVA or method != "getInstance":
                    return None
                requested = arg(0)
                normalized = requested.upper().replace("-", "") if isinstance(requested, str) else ""
                if cls.endswith("MessageDigest"):
                    return self.emit(token, _hash(requested) or "unknown", "hash", api)
                if cls.endswith("Signature"):
                    algorithm = "RSA" if re.fullmatch(r"SHA(?:1|224|256|384|512)WITHRSA", normalized) else "Ed25519" if normalized == "ED25519" else "unknown"
                    digest = _hash(normalized.split("WITH")[0]) if "WITH" in normalized else None
                    return self.emit(token, algorithm, "signature", api, hash_algorithm=digest)
                if cls.endswith("Cipher"):
                    parts = normalized.split("/")
                    algorithm = "AES" if parts[0] == "AES" else "RSA" if parts[0] == "RSA" else "unknown"
                    return self.emit(token, algorithm, "encryption", api, mode=parts[1] if len(parts) > 1 and parts[1] in {"ECB", "GCM", "CBC", "CTR", "CFB", "OFB"} else None)
                if cls.endswith("Mac"):
                    digest = _hash(normalized.removeprefix("HMAC")) if normalized.startswith("HMAC") else None
                    return self.emit(token, "HMAC" if digest else "unknown", "mac", api, hash_algorithm=digest)
                if cls.endswith("SecretKeyFactory"):
                    digest = _hash(normalized.removeprefix("PBKDF2WITHHMAC")) if normalized.startswith("PBKDF2WITHHMAC") else None
                    return self.emit(token, "PBKDF2" if digest else "unknown", "kdf", api, hash_algorithm=digest)
                return self.emit(token, {"RSA": "RSA", "ED25519": "Ed25519", "AES": "AES"}.get(normalized, "unknown"), "signature" if normalized == "ED25519" else "unknown", api)
            package, _, method = api.rpartition(".")
            if package == "crypto/rsa":
                if method in {"GenerateKey", "GenerateMultiPrimeKey"}:
                    return self.emit(token, "RSA", "unknown", api, key_bits=_positive(arg(1 if method == "GenerateKey" else 2)))
                if method in {"SignPKCS1v15", "SignPSS", "VerifyPKCS1v15", "VerifyPSS"}:
                    v = arg(2 if method.startswith("Sign") else 1)
                    digest = _hash(str(v.data).removeprefix("crypto.")) if isinstance(v, Value) and v.kind == "api" and str(v.data).startswith("crypto.") else None
                    return self.emit(token, "RSA", "signature", api, hash_algorithm=digest)
                if method in {"EncryptOAEP", "DecryptOAEP", "EncryptPKCS1v15", "DecryptPKCS1v15"}:
                    v = arg(0)
                    digest = (v.data.algorithm if method.endswith("OAEP") and isinstance(v, Value)
                              and v.kind == "finding" and v.data.usage == "hash" else None)
                    return self.emit(token, "RSA", "encryption", api, hash_algorithm=digest)
            if package == "crypto/ed25519" and method in {"GenerateKey", "NewKeyFromSeed", "Sign", "Verify", "VerifyWithOptions"}:
                return self.emit(token, "Ed25519", "signature", api)
            hash_methods = {"crypto/md5": {"New": "MD5", "Sum": "MD5"}, "crypto/sha1": {"New": "SHA-1", "Sum": "SHA-1"}, "crypto/sha256": {"New": "SHA-256", "Sum256": "SHA-256", "New224": "SHA-224", "Sum224": "SHA-224"}, "crypto/sha512": {"New": "SHA-512", "Sum512": "SHA-512", "New384": "SHA-384", "Sum384": "SHA-384", "New512_224": "SHA-512/224", "Sum512_224": "SHA-512/224", "New512_256": "SHA-512/256", "Sum512_256": "SHA-512/256"}}
            if method in hash_methods.get(package, {}):
                return self.emit(token, hash_methods[package][method], "hash", api)
            if package == "crypto/aes" and method == "NewCipher":
                v = arg(0)
                return self.emit(token, "AES", "encryption", api, key_bits=v.data * 8 if isinstance(v, Value) and v.kind == "bytes" else None)
            if package == "crypto/cipher" and method in {"NewGCM", "NewGCMWithNonceSize", "NewGCMWithTagSize"}:
                v = arg(0)
                if isinstance(v, Value) and v.kind == "finding" and v.data.algorithm == "AES":
                    self.configure(v.data, mode="GCM")
                    return v
                return self.emit(token, "unknown", "encryption", api, mode="GCM")
            if (package == "crypto/hmac" and method == "New") or (package in {"crypto/pbkdf2", "golang.org/x/crypto/pbkdf2"} and method == "Key"):
                is_mac = package == "crypto/hmac"
                digest_value = arg(0 if is_mac or package == "crypto/pbkdf2" else 4)
                digest = None
                if isinstance(digest_value, Value) and digest_value.kind == "api":
                    hp, _, hm = str(digest_value.data).rpartition(".")
                    digest = hash_methods.get(hp, {}).get(hm)
                elif isinstance(digest_value, Value) and digest_value.kind == "finding" and digest_value.data.usage == "hash":
                    digest = digest_value.data.algorithm
                params = {"hash_algorithm": digest}
                if not is_mac:
                    modern = package == "crypto/pbkdf2"
                    length = _positive(arg(4 if modern else 3))
                    params.update(iterations=_positive(arg(3 if modern else 2)), key_bits=length * 8 if length else None)
                return self.emit(token, "HMAC" if is_mac else "PBKDF2", "mac" if is_mac else "kdf", api, **params)
        # Direct receiver configuration enriches only the same known local object.
        if len(name) == 3 and name[1].text == ".":
            obj = self.env.get(name[0].text)
            method = name[2].text
            if isinstance(obj, Value) and obj.kind == "finding":
                f = obj.data
                if method in {"initialize", "init"} and f.api.endswith(("KeyPairGenerator.getInstance", "KeyGenerator.getInstance")):
                    self.configure(f, key_bits=_positive(arg(0)))
                elif method == "init" and f.api.endswith("Cipher.getInstance"):
                    v = arg(1)
                    self.configure(f, key_bits=v.data if isinstance(v, Value) and v.kind == "key" else None)
                elif method == "generateSecret" and f.api.endswith("SecretKeyFactory.getInstance"):
                    v = arg(0)
                    if isinstance(v, Value) and v.kind == "pbe":
                        self.configure(f, iterations=v.data[0], key_bits=v.data[1])
        return None

    def statement(self, ts: list[Token]) -> None:
        previous = self.conditional
        if ts and (ts[0].text in {"if", "for", "while"} or any(t.text == "?" for t in ts)):
            self.conditional += 1
        try:
            self._statement(ts)
        finally:
            self.conditional = previous

    def _statement(self, ts: list[Token]) -> None:
        ts = [t for t in ts if t.kind != "newline"]
        if not ts:
            return
        if self.language == "go" and ts[0].text == "const" and len(ts) > 1 and ts[1].text == "(":
            # Grouped constants are separated by original source lines.
            group: list[Token] = []
            for token in ts[2:-1]:
                if group and token.line != group[-1].line:
                    self.statement([ts[0]] + group)
                    group = []
                group.append(token)
            self.statement([ts[0]] + group)
            return
        # Imports are the authority for all short API names.
        if ts[0].text == "import":
            body = ts[1:]
            if self.language == "java":
                path = "".join(t.text for t in body)
                if path in JAVA:
                    self.env[path.rsplit(".", 1)[1]] = Value("api", path)
            else:
                for i, t in enumerate(body):
                    if t.kind == "literal" and t.value in GO:
                        alias = body[i - 1].text if i and body[i - 1].kind == "id" else str(t.value).rsplit("/", 1)[-1]
                        if alias != "_" and not (i and body[i - 1].text == "."):
                            self.env[alias] = Value("api", t.value)
            return
        # Process assignment only after evaluating its RHS in the current scope.
        depth, assignment = 0, None
        for i, t in enumerate(ts):
            if t.text in {"(", "["}:
                depth += 1
            elif t.text in {")", "]"}:
                depth -= 1
            elif depth == 0 and t.text in {"=", ":=", "+=", "-=", "*=", "/="}:
                assignment = i
                break
        value = self.value(ts[assignment + 1:]) if assignment is not None and ts[assignment].text in {"=", ":="} else None
        # Visit each explicit call, including nested calls, but never string tokens.
        for i, t in enumerate(ts):
            if t.text != "(" or t.kind != "symbol" or i == 0:
                continue
            j = i - 1
            if ts[j].kind != "id":
                continue
            while j >= 2 and ts[j - 1].text == "." and ts[j - 2].kind == "id":
                j -= 2
            if j and ts[j - 1].text == ".":
                continue
            end = self.close(ts, i)
            self.call(ts[j:i], _split(ts[i + 1:end]))
        if assignment is not None:
            lhs = ts[:assignment]
            names = []
            for part in _split(lhs):
                ids = [t.text for t in part if t.kind == "id"]
                if ids:
                    names.append(ids[-1] if self.language == "java" else ids[1] if ids[0] in {"var", "const"} and len(ids) > 1 else ids[0])
            for i, name in enumerate(names):
                self.env[name] = value if i == 0 else None
                if any(t.text == ("final" if self.language == "java" else "const") for t in lhs):
                    self.immutable.add(name)
                else:
                    self.immutable.discard(name)
        else:
            # Declarations and increments invalidate prior imported/constant values.
            for i, t in enumerate(ts):
                if t.text in {"++", "--"} and i:
                    self.env[ts[i - 1].text] = None
            ids = [t.text for t in ts if t.kind == "id"]
            if "(" not in [t.text for t in ts] and len(ids) >= 2:
                if self.language == "java" and ts[-1].kind == "id":
                    self.env[ts[-1].text] = None
                elif self.language == "go" and ids[0] == "var":
                    self.env[ids[1]] = None

    def run(self) -> list[Detection]:
        pending: list[Token] = []
        scopes: list[tuple[dict[str, object], bool, int, set[str]]] = []
        depth = 0
        for t in self.ts:
            if t.kind == "symbol" and t.text in {"(", "["}:
                depth += 1
            elif t.kind == "symbol" and t.text in {")", "]"}:
                depth -= 1
            if t.text == "{" and t.kind == "symbol" and depth == 0:
                header = pending
                texts = [x.text for x in header]
                controls = {"if", "for", "while", "switch", "catch", "synchronized"}
                function = "(" in texts and (
                    "func" in texts if self.language == "go" else
                    bool(texts) and texts[0] not in controls and "=" not in texts
                    and texts.index("(") >= 2 and "." not in texts[:texts.index("(")]
                )
                previous_conditional = self.conditional
                if texts and texts[0] in controls | {"else", "try", "select"}:
                    self.conditional += 1
                if not function:
                    self.statement(header)
                scopes.append((self.env.copy(), function, previous_conditional, self.immutable.copy()))
                pending = []
                if function:
                    self.env = {name: value for name, value in self.env.items()
                                if name in self.immutable or isinstance(value, Value) and value.kind == "api"}
                    a = texts.index("(")
                    b = self.close(header, a)
                    if self.language == "go" and texts.index("func") + 1 == a:
                        receiver = [x.text for x in header[a + 1:b] if x.kind == "id"]
                        if receiver:
                            self.env[receiver[0]] = None
                        # Method signatures have a receiver followed by the real
                        # parameter list; do not mistake the receiver for args.
                        try:
                            a = texts.index("(", b + 1)
                            b = self.close(header, a)
                        except ValueError:
                            a, b = 0, 0
                    for part in _split(header[a + 1:b]):
                        identifiers = [x.text for x in part if x.kind == "id"]
                        if identifiers:
                            name = identifiers[-1] if self.language == "java" else identifiers[0]
                            self.env[name] = None
                continue
            if t.text == "}" and t.kind == "symbol" and depth == 0:
                self.statement(pending)
                pending = []
                if scopes:
                    previous, function, self.conditional, self.immutable = scopes.pop()
                    # Changes to inherited names are uncertain after a branch.
                    # Method-local names disappear rather than leaking to siblings.
                    for name in (() if function else previous.keys() & self.env.keys()):
                        if self.env[name] != previous[name]:
                            previous[name] = None
                    self.env = previous
                continue
            if depth == 0 and (t.text == ";" or (t.kind == "newline" and self.language == "go")):
                self.statement(pending)
                pending = []
            elif t.kind != "newline" or depth:
                pending.append(t)
        self.statement(pending)
        return sorted(self.findings, key=lambda f: (f.line, f.column))


def detect_java(text: str) -> list[Detection]:
    return Scanner(text, "java").run()


def detect_go(text: str) -> list[Detection]:
    return Scanner(text, "go").run()
