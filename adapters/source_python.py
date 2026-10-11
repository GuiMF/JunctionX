"""Bounded Python AST discovery, with no source execution or import loading.

Bindings follow lexical scope and source order. Only explicit, local facts are
resolved. A separate bounded pass follows direct local calls for key provenance;
this is not an interprocedural type checker or a runtime proof.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass

from adapters.source_common import Detection, SourceParseError
from core.models import Parameters


@dataclass(frozen=True)
class _API:
    path: str


@dataclass(frozen=True)
class _Size:
    length: int


@dataclass(frozen=True)
class _Object:
    kind: str
    bits: int | None = None
    mode: str | None = None
    digest: str | None = None
    group: str | None = None


_UNKNOWN = None
_HASHES = {"md5": "MD5", "sha1": "SHA-1", "sha224": "SHA-224",
           "sha256": "SHA-256", "sha384": "SHA-384", "sha512": "SHA-512",
           "sha3_224": "SHA3-224", "sha3_256": "SHA3-256",
           "sha3_384": "SHA3-384", "sha3_512": "SHA3-512"}
_PRIMITIVES = "cryptography.hazmat.primitives."
_HASH_PREFIX = _PRIMITIVES + "hashes."
_CIPHER = _PRIMITIVES + "ciphers."
_RSA = _PRIMITIVES + "asymmetric.rsa.generate_private_key"
_ED = _PRIMITIVES + "asymmetric.ed25519.Ed25519PrivateKey."
_EC = _PRIMITIVES + "asymmetric.ec."
_EC_CURVES = {"SECP256R1": 256, "SECP384R1": 384, "SECP521R1": 521}
_PBKDF = _PRIMITIVES + "kdf.pbkdf2.PBKDF2HMAC"


def _hash_name(value: object) -> str | None:
    if isinstance(value, str):
        normalized = value.lower().replace("-", "").replace("_", "")
        return next((name for key, name in _HASHES.items() if key.replace("_", "") == normalized), None)
    return None


def _positive(value: object) -> int | None:
    return value if type(value) is int and value > 0 else None


class _BoundNames(ast.NodeVisitor):
    """Names local anywhere in a function shadow outer imports throughout it."""

    def __init__(self) -> None:
        self.names: set[str] = set()
        self.external: set[str] = set()

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self.names.add(node.id)

    def visit_Import(self, node: ast.Import) -> None:
        self.names.update(alias.asname or alias.name.split(".")[0] for alias in node.names)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        self.names.update(alias.asname or alias.name for alias in node.names)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.names.add(node.name)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.names.add(node.name)

    def visit_Lambda(self, node: ast.Lambda) -> None:
        pass

    def visit_Global(self, node: ast.Global) -> None:
        self.external.update(node.names)

    visit_Nonlocal = visit_Global

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if node.name:
            self.names.add(node.name)
        self.generic_visit(node)

    def visit_ListComp(self, node: ast.ListComp) -> None:
        # Comprehension targets have their own lexical scope.
        # Assignment expressions are the exception: they bind in the parent.
        for child in ast.walk(node):
            if isinstance(child, ast.NamedExpr):
                self.visit(child.target)

    visit_SetComp = visit_ListComp
    visit_DictComp = visit_ListComp
    visit_GeneratorExp = visit_ListComp

    def visit_Match(self, node: ast.Match) -> None:
        for case in node.cases:
            for pattern in ast.walk(case.pattern):
                name = getattr(pattern, "name", None) or getattr(pattern, "rest", None)
                if name:
                    self.names.add(name)
        self.generic_visit(node)


class _Scanner(ast.NodeVisitor):
    def __init__(self) -> None:
        self.env: dict[str, object] = {"bytes": _API("builtins.bytes"), "len": _API("builtins.len")}
        self.findings: list[Detection] = []
        self.suppressed: set[int] = set()
        self.function_parent: dict[str, object] | None = None

    def _arg(self, node: ast.Call, index: int, name: str) -> object:
        for keyword in node.keywords:
            if keyword.arg == name:
                return self._value(keyword.value)
        return self._value(node.args[index]) if len(node.args) > index else _UNKNOWN

    def _path(self, node: ast.AST) -> str:
        value = self._value(node)
        return value.path if isinstance(value, _API) else ""

    def _digest(self, value: object) -> str | None:
        if isinstance(value, _Object) and value.kind == "hash":
            return value.digest
        if isinstance(value, _API):
            if value.path.startswith("hashlib."):
                return _HASHES.get(value.path.removeprefix("hashlib."))
            if value.path.startswith(_HASH_PREFIX):
                return _hash_name(value.path.removeprefix(_HASH_PREFIX))
        return _hash_name(value)

    def _bytes_bits(self, value: object) -> int | None:
        if isinstance(value, bytes):
            return _positive(len(value) * 8)
        if isinstance(value, _Size):
            return _positive(value.length * 8)
        return None

    def _value(self, node: ast.AST | None) -> object:
        if isinstance(node, ast.Name):
            return self.env.get(node.id)
        if isinstance(node, ast.Constant) and isinstance(node.value, (int, str, bytes)):
            return node.value
        if isinstance(node, ast.Attribute):
            base = self._value(node.value)
            if isinstance(base, _API):
                return _API(base.path + "." + node.attr)
        if isinstance(node, ast.Call):
            path = self._path(node.func)
            digest = self._digest(_API(path))
            if digest:
                return _Object("hash", digest=digest)
            if path == "hashlib.new":
                return _Object("hash", digest=_hash_name(self._arg(node, 0, "name")))
            if path == _RSA:
                return _Object("RSA", bits=_positive(self._arg(node, 1, "key_size")))
            if path in {_ED + "generate", _ED + "from_private_bytes"}:
                return _Object("Ed25519")
            if path.startswith(_EC) and path.removeprefix(_EC) in _EC_CURVES:
                group = path.removeprefix(_EC)
                return _Object("curve", bits=_EC_CURVES[group], group=group)
            if path in {_EC + "generate_private_key", _EC + "derive_private_key"}:
                curve = self._arg(node, int(path.endswith("derive_private_key")), "curve")
                return _Object("EC", bits=curve.bits if isinstance(curve, _Object) and curve.kind == "curve" else None,
                               group=curve.group if isinstance(curve, _Object) and curve.kind == "curve" else None)
            if path == _EC + "ECDSA":
                return _Object("ecdsa", digest=self._digest(self._arg(node, 0, "algorithm")))
            if path == _EC + "ECDH":
                return _Object("ecdh")
            if path.startswith(_CIPHER + "modes.") and path.removeprefix(_CIPHER + "modes.") in {"ECB", "GCM", "CBC", "CTR", "CCM"}:
                return _Object("mode", mode=path.rsplit(".", 1)[-1])
            if path in {_CIPHER + "algorithms.AES", _CIPHER + "aead.AESGCM"}:
                return _Object("AES", bits=self._bytes_bits(self._arg(node, 0, "key")),
                               mode="GCM" if path.endswith("AESGCM") else None)
            if path == _CIPHER + "Cipher":
                algorithm = self._arg(node, 0, "algorithm")
                mode = self._arg(node, 1, "mode")
                if isinstance(algorithm, _Object) and algorithm.kind == "AES":
                    return _Object("AES", bits=algorithm.bits,
                                   mode=mode.mode if isinstance(mode, _Object) and mode.kind == "mode" else None)
            if path == _CIPHER + "aead.AESGCM.generate_key":
                bits = _positive(self._arg(node, 0, "bit_length"))
                return _Size(bits // 8) if bits and bits % 8 == 0 else None
            if path in {"os.urandom", "secrets.token_bytes", "builtins.bytes"}:
                length = _positive(self._arg(node, 0, "nbytes" if path == "secrets.token_bytes" else "size"))
                return _Size(length) if length else None
            if path == "builtins.len":
                value = self._arg(node, 0, "obj")
                if isinstance(value, (bytes, str)):
                    return len(value)
                if isinstance(value, _Size):
                    return value.length
            if isinstance(node.func, ast.Attribute) and node.func.attr == "public_key":
                receiver = self._value(node.func.value)
                if isinstance(receiver, _Object) and receiver.kind == "EC":
                    return _Object("EC-public", bits=receiver.bits, group=receiver.group)
                if isinstance(receiver, _Object) and receiver.kind in {"RSA", "Ed25519"}:
                    return receiver
        return _UNKNOWN

    def _emit(self, node: ast.Call, algorithm: str, usage: str, api: str,
              rule: str, **parameters: object) -> None:
        self.findings.append(Detection(node.lineno, node.col_offset + 1, algorithm, usage,
                                       Parameters(**parameters), api=api, rule=rule))

    def visit_Call(self, node: ast.Call) -> None:
        path = self._path(node.func)
        obj = self._value(node)
        if id(node) not in self.suppressed:
            if isinstance(obj, _Object) and obj.kind == "hash":
                self._emit(node, obj.digest or "unknown", "hash", path, "python-hash")
            elif path == _RSA:
                self._emit(node, "RSA", "unknown", path, "python-rsa-generation", key_bits=obj.bits)
            elif path in {_ED + "generate", _ED + "from_private_bytes"}:
                self._emit(node, "Ed25519", "signature", path, "python-ed25519")
            elif path in {_EC + "generate_private_key", _EC + "derive_private_key"}:
                self._emit(node, "EC", "unknown", path, "python-ec-generation",
                           key_bits=obj.bits, named_group=obj.group)
            elif path in {_CIPHER + "algorithms.AES", _CIPHER + "aead.AESGCM", _CIPHER + "Cipher"}:
                if isinstance(obj, _Object) and obj.kind == "AES":
                    self._emit(node, "AES", "encryption", path, "python-aes", key_bits=obj.bits, mode=obj.mode)
                elif path == _CIPHER + "Cipher":
                    self._emit(node, "unknown", "encryption", path, "python-cipher")
                if path == _CIPHER + "Cipher":
                    nested = next((kw.value for kw in node.keywords if kw.arg == "algorithm"),
                                  node.args[0] if node.args else None)
                    if isinstance(nested, ast.Call) and self._path(nested.func) == _CIPHER + "algorithms.AES":
                        self.suppressed.add(id(nested))
            elif path in {"hashlib.pbkdf2_hmac", _PBKDF}:
                digest = self._digest(self._arg(node, 0, "algorithm" if path == _PBKDF else "hash_name"))
                length = _positive(self._arg(node, 1 if path == _PBKDF else 4,
                                             "length" if path == _PBKDF else "dklen"))
                self._emit(node, "PBKDF2", "kdf", path, "python-pbkdf2", hash_algorithm=digest,
                           key_bits=length * 8 if length else None,
                           iterations=_positive(self._arg(node, 3, "iterations")))
            elif path in {"hmac.new", "hmac.digest", _PRIMITIVES + "hmac.HMAC"}:
                cryptography = path.startswith(_PRIMITIVES)
                digest = self._digest(self._arg(node, 1 if cryptography else 2,
                                               "algorithm" if cryptography else "digest" if path == "hmac.digest" else "digestmod"))
                self._emit(node, "HMAC", "mac", path, "python-hmac", hash_algorithm=digest,
                           key_bits=self._bytes_bits(self._arg(node, 0, "key")))
            elif isinstance(node.func, ast.Attribute) and node.func.attr in {"sign", "verify"}:
                receiver = self._value(node.func.value)
                values = [self._value(arg) for arg in node.args]
                values += [self._value(kw.value) for kw in node.keywords]
                # Padding alone cannot establish a receiver's API: application
                # methods may accept cryptographic objects for other purposes.
                if isinstance(receiver, _Object) and receiver.kind in {"RSA", "Ed25519"}:
                    algorithm = receiver.kind
                    digest = next((value.digest for value in values if isinstance(value, _Object) and value.kind == "hash"), None)
                    # A canonical API description never includes user identifiers.
                    self._emit(node, algorithm, "signature", "cryptography." + algorithm + "." + node.func.attr,
                               "python-signature", key_bits=receiver.bits,
                               hash_algorithm=digest)
                elif isinstance(receiver, _Object) and receiver.kind == ("EC" if node.func.attr == "sign" else "EC-public"):
                    signature_algorithm = self._arg(node, 1 if node.func.attr == "sign" else 2, "signature_algorithm")
                    if isinstance(signature_algorithm, _Object) and signature_algorithm.kind == "ecdsa":
                        self._emit(node, "ECDSA", "signature", "cryptography.EC." + node.func.attr,
                                   "python-signature", key_bits=receiver.bits, named_group=receiver.group,
                                   hash_algorithm=signature_algorithm.digest)
            elif isinstance(node.func, ast.Attribute) and node.func.attr == "exchange":
                receiver = self._value(node.func.value)
                exchange_algorithm = self._arg(node, 0, "algorithm")
                if (isinstance(receiver, _Object) and receiver.kind == "EC"
                        and isinstance(exchange_algorithm, _Object) and exchange_algorithm.kind == "ecdh"):
                    self._emit(node, "ECDH", "key_establishment", "cryptography.EC.exchange",
                               "python-ecdh", key_bits=receiver.bits, named_group=receiver.group)
        self.generic_visit(node)

    def _bind(self, target: ast.AST, value: object = None) -> None:
        if isinstance(target, ast.Name):
            self.env[target.id] = value
        elif isinstance(target, (ast.Tuple, ast.List)):
            for item in target.elts:
                self._bind(item)
        elif isinstance(target, (ast.Attribute, ast.Subscript)):
            # Mutating imported modules or known receivers invalidates their root.
            root = target.value
            while isinstance(root, (ast.Attribute, ast.Subscript)):
                root = root.value
            if isinstance(root, ast.Name):
                self.env[root.id] = None

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.env[alias.asname or alias.name.split(".")[0]] = _API(alias.name if alias.asname else alias.name.split(".")[0])

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        for alias in node.names:
            if alias.name == "*":
                # A star import can replace any existing name.
                self.env = dict.fromkeys(self.env)
            else:
                self.env[alias.asname or alias.name] = _API((node.module or "") + "." + alias.name) if not node.level else None

    def visit_Assign(self, node: ast.Assign) -> None:
        self.visit(node.value)
        value = self._value(node.value)
        for target in node.targets:
            self._bind(target, value)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            self.visit(node.value)
            self._bind(node.target, self._value(node.value))

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        self.visit(node.value)
        self._bind(node.target)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        self.visit(node.value)
        self._bind(node.target, self._value(node.value))

    def visit_Delete(self, node: ast.Delete) -> None:
        for target in node.targets:
            self._bind(target)

    def _body(self, statements: list[ast.stmt]) -> None:
        for statement in statements:
            self.visit(statement)

    def _function(self, node: ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda) -> None:
        if not isinstance(node, ast.Lambda):
            for expression in node.decorator_list:
                self.visit(expression)
        for default in [*node.args.defaults, *node.args.kw_defaults]:
            if default is not None:
                self.visit(default)
        outer = self.env
        self.env = dict(self.function_parent if self.function_parent is not None else outer)
        if not isinstance(node, ast.Lambda):
            # The function's own global/closure name already refers to it when
            # its body runs, even if the definition replaced an imported module.
            self.env[node.name] = None
        bindings = _BoundNames()
        body = [node.body] if isinstance(node, ast.Lambda) else node.body
        for statement in body:
            bindings.visit(statement)
        for name in bindings.names | bindings.external:
            self.env[name] = None
        args = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
        args += [arg for arg in (node.args.vararg, node.args.kwarg) if arg is not None]
        for arg in args:
            self.env[arg.arg] = None
        previous_parent = self.function_parent
        self.function_parent = None
        for statement in body:
            self.visit(statement)
        self.function_parent = previous_parent
        self.env = outer
        if not isinstance(node, ast.Lambda):
            self.env[node.name] = None

    visit_FunctionDef = _function
    visit_AsyncFunctionDef = _function
    visit_Lambda = _function

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        for expression in [*node.decorator_list, *node.bases, *(kw.value for kw in node.keywords)]:
            self.visit(expression)
        outer, parent = self.env, self.function_parent
        self.function_parent = outer if parent is None else parent
        self.env = dict(outer)
        self._body(node.body)
        self.env, self.function_parent = outer, parent
        self.env[node.name] = None

    def _branches(self, branches: list[list[ast.stmt]]) -> None:
        before = dict(self.env)
        results = []
        for statements in branches:
            self.env = dict(before)
            self._body(statements)
            results.append(self.env)
        names = set().union(*(env.keys() for env in results))
        self.env = {name: results[0].get(name) if all(env.get(name) == results[0].get(name) for env in results) else None for name in names}

    def visit_If(self, node: ast.If) -> None:
        self.visit(node.test)
        self._branches([node.body, node.orelse])

    def visit_IfExp(self, node: ast.IfExp) -> None:
        self.visit(node.test)
        self._branches([[node.body], [node.orelse]])

    def visit_BoolOp(self, node: ast.BoolOp) -> None:
        self.visit(node.values[0])
        for value in node.values[1:]:
            self._branches([[value], []])

    def _invalidate_body(self, statements: list[ast.stmt]) -> None:
        bindings = _BoundNames()
        for statement in statements:
            bindings.visit(statement)
        for name in bindings.names | bindings.external:
            self.env[name] = None

    def visit_For(self, node: ast.For) -> None:
        self.visit(node.iter)
        self._bind(node.target)
        self._invalidate_body(node.body)
        self._branches([node.body, []])
        self._body(node.orelse)

    visit_AsyncFor = visit_For

    def visit_While(self, node: ast.While) -> None:
        self._invalidate_body(node.body)
        self.visit(node.test)
        self._branches([node.body, []])
        self._body(node.orelse)

    def visit_With(self, node: ast.With) -> None:
        for item in node.items:
            self.visit(item.context_expr)
            if item.optional_vars:
                self._bind(item.optional_vars)
        self._body(node.body)

    visit_AsyncWith = visit_With

    def visit_Try(self, node: ast.Try) -> None:
        # Exceptions may occur partway through the body; discard assigned facts.
        self._invalidate_body(node.body)
        before = dict(self.env)
        self._body(node.body)
        self._body(node.orelse)
        alternatives = [dict(self.env), before]
        for handler in node.handlers:
            self.env = dict(before)
            if handler.type:
                self.visit(handler.type)
            if handler.name:
                self.env[handler.name] = None
            self._body(handler.body)
            if handler.name:
                self.env[handler.name] = None
            alternatives.append(dict(self.env))
        names = set().union(*(env.keys() for env in alternatives))
        self.env = {name: alternatives[0].get(name) if all(env.get(name) == alternatives[0].get(name) for env in alternatives) else None for name in names}
        self._body(node.finalbody)

    visit_TryStar = visit_Try

    def _comprehension(self, node: ast.ListComp | ast.SetComp | ast.DictComp | ast.GeneratorExp) -> None:
        outer = self.env
        self.visit(node.generators[0].iter)
        self.env = dict(outer)
        for index, generator in enumerate(node.generators):
            if index:
                self.visit(generator.iter)
            self._bind(generator.target)
            for condition in generator.ifs:
                self.visit(condition)
        for expression in ([node.key, node.value] if isinstance(node, ast.DictComp) else [node.elt]):
            self.visit(expression)
        self.env = outer
        for child in ast.walk(node):
            if isinstance(child, ast.NamedExpr):
                # A comprehension can be empty; never assume a walrus ran.
                self._bind(child.target)

    visit_ListComp = _comprehension
    visit_SetComp = _comprehension
    visit_DictComp = _comprehension
    visit_GeneratorExp = _comprehension

    def visit_Match(self, node: ast.Match) -> None:
        self.visit(node.subject)
        # Pattern captures may shadow imports. Do not infer pattern values.
        for case in node.cases:
            for pattern in ast.walk(case.pattern):
                name = getattr(pattern, "name", None) or getattr(pattern, "rest", None)
                if name:
                    self.env[name] = None
        before = dict(self.env)
        for case in node.cases:
            self.env = dict(before)
            if case.guard:
                self.visit(case.guard)
            self._body(case.body)
        self.env = before
        for case in node.cases:
            self._invalidate_body(case.body)



@dataclass(frozen=True)
class _Function:
    node: ast.FunctionDef


class _FlowLimit(Exception):
    """An unresolved recursive or oversized call graph invalidates flow evidence."""


class _KeyFlow(_Scanner):
    """Add signature evidence from bounded direct, module-local calls.

    This pass deliberately carries key *kind* across call boundaries, not key
    size or arbitrary constants. Only RSA signatures are admitted by this initial
    rollout. A source occurrence is admitted only if every analyzed call
    context agrees. Uncalled functions retain the baseline scan.
    No code is executed, imported, or inferred from names or padding objects.
    """

    MAX_DEPTH = 8
    MAX_CALLS = 256
    MAX_VISITS = 50_000

    def __init__(self) -> None:
        super().__init__()
        self.globals: dict[str, object] = self.env
        self.active: list[ast.FunctionDef] = []
        self.frame = 0
        self.next_frame = 0
        self.calls = 0
        self.visits = 0
        self.failed = False
        self.cache: dict[tuple[int, int], object] = {}
        self.observations: dict[tuple[int, int], list[Detection | None]] = {}

    @staticmethod
    def _eligible(node: ast.AST) -> bool:
        excluded = (ast.Yield, ast.YieldFrom, ast.Global, ast.Nonlocal,
                    ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
        return (isinstance(node, ast.FunctionDef) and not node.decorator_list
                and not any(isinstance(child, excluded) for statement in node.body for child in ast.walk(statement)))

    def visit_Module(self, node: ast.Module) -> None:
        # If a local callable escapes or is referenced by a body we cannot
        # analyze, its call contexts are incomplete. Decline supplemental
        # evidence for the file, including aliases hidden in containers.
        parents = {child: parent for parent in ast.walk(node) for child in ast.iter_child_nodes(parent)}
        if len(parents) > self.MAX_VISITS:
            raise _FlowLimit
        definitions = [child for child in parents if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))]
        names = {child.name for child in definitions}
        eligible = {child for child in definitions if self._eligible(child)}
        for child in parents:
            if not isinstance(child, ast.Name) or not isinstance(child.ctx, ast.Load) or child.id not in names:
                continue
            parent = parents[child]
            if not isinstance(parent, ast.Call) or parent.func is not child:
                self.failed = True
                return
            ancestor = parent
            while ancestor in parents:
                ancestor = parents[ancestor]
                if isinstance(ancestor, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)) and ancestor not in eligible:
                    self.failed = True
                    return
        self._body(node.body)

    def visit(self, node: ast.AST) -> object:
        self.visits += 1
        if self.visits > self.MAX_VISITS:
            raise _FlowLimit
        return super().visit(node)

    def _cross_boundary(self, value: object) -> object:
        if isinstance(value, _Function):
            self.failed = True
        if isinstance(value, _Object) and value.kind in {"RSA", "Ed25519"}:
            return _Object(value.kind)
        if isinstance(value, tuple):
            return tuple(self._cross_boundary(item) for item in value)
        return None

    def _value(self, node: ast.AST | None) -> object:
        if isinstance(node, ast.Tuple):
            return tuple(self._value(item) for item in node.elts)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            function = self.env.get(node.func.id)
            # Aliases and indirect callbacks are outside this bounded model.
            if isinstance(function, _Function) and function.node.name == node.func.id:
                cache_key = (self.frame, id(node))
                if cache_key not in self.cache:
                    try:
                        self.cache[cache_key] = self._invoke(function.node, node)
                    except _FlowLimit:
                        self.failed = True
                        if self.active:
                            raise
                        self.cache[cache_key] = None
                return self.cache[cache_key]
        return super()._value(node)

    def _bind(self, target: ast.AST, value: object = None) -> None:
        if isinstance(value, _Function):
            self.failed = True  # An escaping callable has untracked contexts.
        if isinstance(target, (ast.Tuple, ast.List)) and isinstance(value, tuple):
            if len(target.elts) == len(value) and not any(isinstance(item, ast.Starred) for item in target.elts):
                for item, fact in zip(target.elts, value):
                    self._bind(item, fact)
                return
        super()._bind(target, value)

    def _function(self, node: ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda) -> None:
        if isinstance(node, ast.Lambda):
            return
        for expression in [*node.decorator_list, *node.args.defaults, *node.args.kw_defaults]:
            if expression is not None:
                self.visit(expression)
        self.env[node.name] = None
        # Closures, decorators, coroutines and generators need different call
        # semantics; do not interpret them as ordinary executed function bodies.
        if not self.active and self._eligible(node):
            self.env[node.name] = _Function(node)

    visit_FunctionDef = _function
    visit_AsyncFunctionDef = _function
    visit_Lambda = _function

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        # Class bodies and descriptors are covered only by the baseline pass.
        self.env[node.name] = None

    def _arguments(self, function: ast.FunctionDef, call: ast.Call) -> dict[str, object] | None:
        spec = function.args
        if spec.vararg or spec.kwarg or any(isinstance(arg, ast.Starred) for arg in call.args):
            return None
        if any(keyword.arg is None for keyword in call.keywords):
            return None
        positional = [*spec.posonlyargs, *spec.args]
        if len(call.args) > len(positional):
            return None
        values = {arg.arg: self._cross_boundary(self._value(value))
                  for arg, value in zip(positional, call.args)}
        allowed = {arg.arg for arg in [*spec.args, *spec.kwonlyargs]}
        for keyword in call.keywords:
            if keyword.arg not in allowed or keyword.arg in values:
                return None
            values[keyword.arg] = self._cross_boundary(self._value(keyword.value))
        required = positional[:len(positional) - len(spec.defaults)]
        required += [arg for arg, default in zip(spec.kwonlyargs, spec.kw_defaults) if default is None]
        if any(arg.arg not in values for arg in required):
            return None
        # Defaults are evaluated at definition time. Omitted defaults remain
        # unknown instead of incorrectly evaluating them in the caller's scope.
        for arg in [*positional, *spec.kwonlyargs]:
            values.setdefault(arg.arg, None)
        return values

    def _invoke(self, function: ast.FunctionDef, call: ast.Call) -> object:
        if function in self.active or len(self.active) >= self.MAX_DEPTH or self.calls >= self.MAX_CALLS:
            raise _FlowLimit
        self.calls += 1
        arguments = self._arguments(function, call)
        if arguments is None:
            # A skipped call can hide unknown contexts for transitive callees.
            self.failed = True
            return None
        outer, previous_frame = self.env, self.frame
        if not self.active:
            self.globals = self.env
        bindings = _BoundNames()
        for statement in function.body:
            bindings.visit(statement)
        self.env = dict(self.globals)
        for name in bindings.names | bindings.external:
            self.env[name] = None
        self.env.update(arguments)
        self.next_frame += 1
        self.frame = self.next_frame
        self.active.append(function)
        try:
            self._body(function.body)
            returns = [child for statement in function.body for child in ast.walk(statement) if isinstance(child, ast.Return)]
            if len(returns) == 1 and function.body[-1] is returns[0]:
                return self._cross_boundary(self._value(returns[0].value))
            return None
        finally:
            self.active.pop()
            self.env, self.frame = outer, previous_frame

    def _body(self, statements: list[ast.stmt]) -> None:
        for statement in statements:
            self.visit(statement)
            if isinstance(statement, (ast.Return, ast.Raise, ast.Break, ast.Continue)):
                break

    def visit_Return(self, node: ast.Return) -> None:
        if node.value is not None:
            self.visit(node.value)

    def visit_Call(self, node: ast.Call) -> None:
        if any(isinstance(self._value(arg), _Function) for arg in [*node.args, *(kw.value for kw in node.keywords)]):
            self.failed = True
        signature = isinstance(node.func, ast.Attribute) and node.func.attr in {"sign", "verify"}
        if signature:
            self.observations.setdefault((node.lineno, node.col_offset + 1), []).append(None)
        super().visit_Call(node)

    def _emit(self, node: ast.Call, algorithm: str, usage: str, api: str,
              rule: str, **parameters: object) -> None:
        if rule == "python-signature":
            self.observations[(node.lineno, node.col_offset + 1)][-1] = Detection(
                node.lineno, node.col_offset + 1, algorithm, usage,
                Parameters(**parameters), api=api, rule=rule)

    def additions(self) -> list[Detection]:
        if self.failed:
            return []
        result = []
        for observations in self.observations.values():
            first = observations[0]
            if first is not None and first.algorithm == "RSA" and all(item == first for item in observations):
                result.append(first)
        return result


def detect(text: str) -> list[Detection]:
    """Return explicit supported API occurrences; reject syntax without source echo."""
    try:
        tree = ast.parse(text)
        scanner = _Scanner()
        scanner.visit(tree)
        flow = _KeyFlow()
        try:
            flow.visit(tree)
        except (_FlowLimit, RecursionError):
            # Supplemental analysis must never erase baseline API evidence.
            flow.failed = True
        existing = {(item.line, item.column) for item in scanner.findings if item.usage == "signature"}
        scanner.findings.extend(item for item in flow.additions() if (item.line, item.column) not in existing)
    except (SyntaxError, ValueError, TypeError, RecursionError):
        raise SourceParseError("Python source could not be parsed or analyzed") from None
    return sorted(scanner.findings, key=lambda finding: (finding.line, finding.column, finding.slot))
