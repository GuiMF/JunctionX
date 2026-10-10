"""Conservative recognition of two explicit Go algorithm idioms.

This is a bounded token/statement recognizer, not a Go compiler. PBKDF2 requires
an entire, dependency-linked implementation of RFC 8018 section 5.2. ECB requires
an AES receiver encrypting disjoint input/output slices, no other loop operations,
and a directly returned fresh output buffer (NIST SP 800-38A section 6.1).
Unsupported control flow, rebinding, helper calls and alternative implementations
remain unknown. Identifiers, import aliases, formatting and comments are immaterial.
No submitted source is executed.
"""
from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from typing import TYPE_CHECKING

from adapters.source_common import Detection
from core.models import Parameters

if TYPE_CHECKING:
    from adapters.source_jvm_go import Token

# Supplemental inference must never prevent the existing API scan from running.
# Large files retain ordinary API findings without allocating another token tree.
SEMANTIC_TOKEN_LIMIT = 50_000


@dataclass
class Node:
    tokens: list[Token]
    children: list[Node] | None = None


def _tree(tokens: list[Token]) -> list[Node]:
    """Keep for-header semicolons, unlike ordinary statement terminators."""
    root: list[Node] = []
    stack = [root]
    pending: list[Token] = []
    depth = 0
    for token in tokens:
        word = token.text
        if token.kind == "symbol" and word in {"(", "["}:
            depth += 1
        elif token.kind == "symbol" and word in {")", "]"}:
            depth -= 1
        if token.kind == "symbol" and depth == 0 and word == "{":
            node = Node(pending, [])
            stack[-1].append(node)
            stack.append(node.children)
            pending = []
        elif token.kind == "symbol" and depth == 0 and word == "}":
            if pending:
                stack[-1].append(Node(pending))
            pending = []
            if len(stack) > 1:
                stack.pop()
        elif depth == 0 and (token.kind == "newline" or word == ";"):
            if word == ";" and pending and pending[0].text in {"for", "if", "switch"}:
                pending.append(token)
            elif pending:
                stack[-1].append(Node(pending))
                pending = []
        elif token.kind != "newline":
            pending.append(token)
    if pending:
        stack[-1].append(Node(pending))
    return root


def _flat(node: Node) -> list[Token]:
    tokens = []
    pending = [node]
    while pending:
        current = pending.pop()
        tokens.extend(current.tokens)
        pending.extend(reversed(current.children or []))
    return tokens


@lru_cache(maxsize=128)
def _pattern_tokens(pattern: str) -> tuple[Token, ...]:
    from adapters.source_jvm_go import _tokens
    return tuple(_tokens(pattern.replace("$", "META_"), "go"))


def _match(tokens: list[Token], pattern: str, bindings: dict[str, str]) -> bool:
    """Match a fixed expression, binding only single identifier metavariables."""
    expected = _pattern_tokens(pattern)
    if len(tokens) != len(expected):
        return False
    proposed = dict(bindings)
    for actual, want in zip(tokens, expected):
        if want.text.startswith("META_"):
            key = want.text[5:]
            if actual.kind != "id" or actual.text == "_":
                return False
            if key in proposed and proposed[key] != actual.text:
                return False
            proposed[key] = actual.text
        elif actual.text != want.text:
            return False
    bindings.update(proposed)
    return True


def _sequence(nodes: list[Node], specs: list, bindings: dict[str, str]) -> bool:
    if len(nodes) != len(specs):
        return False
    for node, spec in zip(nodes, specs):
        pattern, children = spec if isinstance(spec, tuple) else (spec, None)
        if not _match(node.tokens, pattern, bindings):
            return False
        if (node.children is None) != (children is None):
            return False
        if children is not None and not _sequence(node.children, children, bindings):
            return False
    return True


def _imports(nodes: list[Node]) -> dict[str, str]:
    result = {}
    for node in nodes:
        ts = node.tokens
        if not ts or ts[0].text != "import":
            continue
        for i, t in enumerate(ts[1:], 1):
            if t.kind != "literal" or not isinstance(t.value, str):
                continue
            previous = ts[i - 1]
            if previous.text in {".", "_"}:
                continue
            alias = previous.text if previous.kind == "id" and previous.text != "import" else t.value.rsplit("/", 1)[-1]
            result[alias] = t.value
    return result


def _parameters(node: Node) -> list[tuple[str, str]] | None:
    from adapters.source_jvm_go import Scanner, _split
    ts = node.tokens
    if len(ts) < 5 or ts[0].text != "func" or ts[1].kind != "id" or ts[2].text != "(":
        return None
    end = Scanner.close(ts, 2)
    if end >= len(ts):
        return None
    result = []
    inherited = ""
    for group in reversed(_split(ts[3:end])):
        if not group:
            continue
        if group[0].kind != "id":
            return None
        if len(group) > 1:
            inherited = "".join(t.text for t in group[1:])
        if inherited not in {"[]byte", "int", "string", "error"}:
            return None
        result.append((group[0].text, inherited))
    return list(reversed(result))


def _unshadowed(node: Node, aliases: set[str], params: list[tuple[str, str]]) -> bool:
    if aliases & {name for name, _ in params}:
        return False
    # Conservative file/function binding guard, including short multi-assignments,
    # local funcs, range bindings, and imported package aliases used as var names.
    ts = _flat(node)
    for i, token in enumerate(ts):
        if token.text not in aliases:
            continue
        if i + 1 < len(ts) and ts[i + 1].text == ".":
            continue
        # Every reference to a required package must be a qualified selector;
        # every reference to a required builtin must be a direct invocation.
        if token.text in {"make", "copy", "append", "uint32", "len"} and i + 1 < len(ts) and ts[i + 1].text == "(":
            continue
        return False
    return True


def _pbkdf2(node: Node, imports: dict[str, str]) -> tuple[str, int, int] | None:
    params = _parameters(node)
    if params is None or len(params) != 4 or [t for _, t in params] != ["[]byte", "[]byte", "int", "int"]:
        return None
    if "".join(t.text for t in node.tokens).split(")", 1)[-1] != "[]byte":
        return None
    reverse = {path: alias for alias, path in imports.items()}
    for path, digest in (("crypto/sha1", "SHA-1"), ("crypto/sha256", "SHA-256"), ("crypto/sha512", "SHA-512")):
        if any(p not in reverse for p in (path, "crypto/hmac", "encoding/binary")):
            continue
        base = dict(zip(("password", "salt", "iterations", "length"), (p[0] for p in params)))
        base.update(hash=reverse[path], hmac=reverse["crypto/hmac"], binary=reverse["encoding/binary"])
        aliases = {base[k] for k in ("hash", "hmac", "binary")} | {"make", "copy", "append", "uint32"}
        if not _unshadowed(node, aliases, params):
            continue
        for xor in ("$acc[$j] ^= $u[$j]", "$acc[$j] = $acc[$j] ^ $u[$j]"):
            bindings = dict(base)
            specs = [
                "$size := $hash.Size",
                "$blocks := ($length + $size - 1) / $size",
                "$out := make([]byte, 0, $blocks * $size)",
                ("for $block := 1; $block <= $blocks; $block++", [
                    "$mac := $hmac.New($hash.New, $password)",
                    "$mac.Write($salt)",
                    "var $counter [4]byte",
                    "$binary.BigEndian.PutUint32($counter[:], uint32($block))",
                    "$mac.Write($counter[:])",
                    "$u := $mac.Sum(nil)",
                    "$acc := make([]byte, $size)",
                    "copy($acc, $u)",
                    ("for $round := 1; $round < $iterations; $round++", [
                        "$next := $hmac.New($hash.New, $password)",
                        "$next.Write($u)",
                        "$u = $next.Sum(nil)",
                        ("for $j := range $acc", [xor]),
                    ]),
                    "$out = append($out, $acc...)",
                ]),
                "return $out[:$length]",
            ]
            if _sequence(node.children or [], specs, bindings):
                # Distinct semantic values must not alias via shadowed identifiers.
                # The inner HMAC is intentionally permitted to shadow the outer one.
                distinct = [v for k, v in bindings.items() if k != "next"]
                if set(bindings.values()) & {"nil", "byte", "int", "make", "copy", "append", "uint32"}:
                    continue
                if len(distinct) != len(set(distinct)):
                    continue
                if bindings["next"] in set(distinct) - {bindings["mac"]}:
                    continue
                return digest, 2, 3
    return None


def _ecb(node: Node, imports: dict[str, str]) -> list[Detection]:
    params = _parameters(node)
    body = node.children or []
    if params is None or len(body) < 3:
        return []
    aes = next((alias for alias, path in imports.items() if path == "crypto/aes"), None)
    if aes is None or not _unshadowed(node, {aes, "len", "make"}, params):
        return []
    loop, returned = body[-2:]
    bindings = {"aes": aes}
    if not _match(loop.tokens, "for $i := 0; $i < len($src); $i += $aes.BlockSize", bindings):
        return []
    if not _sequence(loop.children or [], ["$cipher.Encrypt($dst[$i:$i+$aes.BlockSize], $src[$i:$i+$aes.BlockSize])"], bindings):
        return []
    if not (_match(returned.tokens, "return $dst, nil", dict(bindings)) or _match(returned.tokens, "return $dst", dict(bindings))):
        return []
    if len(set(bindings.values())) != len(bindings):
        return []
    # A fresh output allocation immediately before the loop rules out aliasing,
    # offset buffers, in-place chaining, and output passed to an unknown helper.
    if not _match(body[-3].tokens, "$dst := make([]byte, len($src))", bindings) or body[-3].children is not None:
        return []
    cipher = bindings["cipher"]
    factory = None
    for before in body[:-3]:
        if any(t.text == cipher for t in _flat(before)):
            capture = dict(bindings)
            if factory is not None or before.children is not None or not _match(before.tokens, "$cipher, $err := $aes.NewCipher($key)", capture):
                return []
            factory = before
    if factory is None or cipher in {name for name, _ in params}:
        return []
    # No earlier reference to dst can alias the newly declared destination.
    if any(t.text == bindings["dst"] for n in body[:-3] for t in _flat(n)):
        return []
    token = loop.children[0].tokens[0]
    return [Detection(token.line, token.column, "AES", "encryption", Parameters(mode="ECB"),
                      api="crypto/aes.Block.Encrypt", rule="go-independent-block-loop",
                      slot="independent-block-loop")]


def analyze(tokens: list[Token]) -> tuple[dict[str, tuple[str, int, int]], list[Detection]]:
    if len(tokens) > SEMANTIC_TOKEN_LIMIT:
        return {}, []
    nodes = _tree(tokens)
    imports = _imports(nodes)
    # Package-level names can shadow builtins or invalidate imports. Do not infer
    # semantics for such files; the ordinary API scanner remains available.
    reserved = set(imports) | {"make", "copy", "append", "uint32", "len", "nil", "byte", "int"}
    for node in nodes:
        if not node.tokens or node.tokens[0].text in {"package", "import"}:
            continue
        header = node.tokens
        if header[0].text == "func":
            if len(header) > 1 and header[1].text in reserved:
                return {}, []
        elif len(header) > 1 and header[1].text == "(":
            # Grouped declarations can contain arbitrary initializer expressions,
            # including function literals. Reject reserved identifiers anywhere
            # in the group rather than guessing where each declaration begins.
            if reserved & {t.text for t in _flat(node)[2:] if t.kind == "id"}:
                return {}, []
        elif any(t.text in reserved for t in header[1:] if t.kind == "id"):
            # Selector uses in initializers are fine; declarations are checked
            # up to their assignment only.
            prefix = []
            for t in header[1:]:
                if t.text == "=":
                    break
                prefix.append(t.text)
            if reserved & set(prefix):
                return {}, []
    summaries, findings = {}, []
    for node in nodes:
        if not node.tokens or node.tokens[0].text != "func":
            continue
        summary = _pbkdf2(node, imports)
        if summary:
            summaries[node.tokens[1].text] = summary
        findings.extend(_ecb(node, imports))
    return summaries, findings
