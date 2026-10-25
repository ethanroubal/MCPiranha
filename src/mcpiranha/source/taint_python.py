"""Taint analysis for Python MCP servers: tool arguments that reach a shell, SQL, path or URL.

Tool handlers are found by how servers register them (`@server.tool()`, `server.add_tool(fn)`,
the low-level `@server.call_tool()` and its `arguments` dict). Their parameters are tainted, and
taint follows assignments, simple dictionary fields, common iterable callbacks and helper
arguments/returns across package files (two levels). Values are tracked conservatively across
assignments; this is not a full control-flow or heap analysis.

What's reported is injection, not capability. Every value gets a shape:

- whole: the argument itself (`exec(command)` in a shell tool, `fetch(url)` in a fetch tool) is
  the tool doing what it says; the toxic-flow rules already account for that. Not reported.
- mixed: the argument spliced into text the developer wrote (`f"git log {branch}"`,
  `"SELECT ... " + name`): the developer meant a fixed command, query or host. Reported.
- based: the argument joined to a base directory (`os.path.join(ROOT, name)`): the developer
  meant to confine it. Reported unless a recognized guard protects that value before use.

Sanitization is sink-specific: shell quoting does not protect paths or URL hosts.
"""

from __future__ import annotations

import ast
import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field, replace
from functools import partial
from typing import Literal

from mcpiranha.core.models import SourceHit, SourceHitKind
from mcpiranha.source import analysis as limits
from mcpiranha.source.analysis import Analysis
from mcpiranha.source.path_guards_python import EMPTY_CHECKED, CheckedPaths, PathGuards
from mcpiranha.source.shell_context import advance

Shape = Literal["whole", "mixed", "based"]
_RANK = {"whole": 1, "based": 2, "mixed": 3}

Domain = Literal["shell", "sql", "path", "url"]
_DOMAINS: tuple[Domain, ...] = ("shell", "sql", "path", "url")
_NUMERIC = frozenset({"int", "float", "bool", "len"})
_SANITIZERS: dict[Domain, frozenset[str]] = {
    "shell": _NUMERIC | {"shlex.quote"},
    "sql": _NUMERIC,
    "path": _NUMERIC | {"os.path.basename", "posixpath.basename", "ntpath.basename"},
    "url": frozenset(),
}
_SHELL_CALLS = frozenset({"run", "call", "check_call", "check_output", "Popen"})
_ALWAYS_SHELL = frozenset({"os.system", "system", "os.popen", "popen", "getoutput",
                           "getstatusoutput", "create_subprocess_shell"})  # fmt: skip
_SQL_CALLS = frozenset({"execute", "executemany", "executescript", "raw", "query", "text",
                        "exec_driver_sql", "read_sql", "read_sql_query", "fetch", "fetchrow",
                        "fetchval"})  # fmt: skip
_SQL_WORDS = re.compile(r"\b(select|insert|update|delete|create|drop|alter|where|from|pragma|"
                        r"values|join|order\s+by)\b", re.IGNORECASE)  # fmt: skip
_PATH_CALLS = frozenset({"open", "read_text", "read_bytes", "write_text", "write_bytes", "remove",
                         "unlink", "rmdir", "rmtree", "listdir", "scandir", "makedirs", "mkdir",
                         "rename", "replace", "copy", "copyfile", "copytree", "move", "iterdir",
                         "send_file", "FileResponse"})  # fmt: skip
_URL_CALLS = frozenset({"get", "post", "put", "patch", "delete", "head", "request", "urlopen",
                        "Request", "stream", "fetch"})  # fmt: skip
_CONTEXT_PARAMS = frozenset({"self", "cls", "ctx", "context"})


def _name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return _name(node.func)
    return ""


def _short(node: ast.AST) -> str:
    return _name(node).rsplit(".", 1)[-1]


@dataclass
class _Flow:
    """Taint state inside one function: which names hold tool input, and in what shape."""

    tool: str
    source: dict[str, str]  # tainted name -> the tool argument it came from
    shapes: dict[str, Shape] = field(default_factory=dict[str, Shape])
    domain: Domain = "shell"
    quote_context: bool = False
    analysis: Analysis | None = None
    where: str = "source"
    fields: dict[str, tuple[Shape, str] | None] = field(
        default_factory=dict[str, tuple[Shape, str] | None]
    )
    values: dict[str, tuple[ast.AST, ...]] = field(default_factory=dict[str, tuple[ast.AST, ...]])
    returns: Callable[[ast.Call, _Flow], list[tuple[_Flow, ast.AST]]] | None = None
    shadowed: frozenset[str] = frozenset()
    safe: Callable[[ast.AST], bool] | None = None
    visiting: set[int] = field(default_factory=set[int])

    def key(self) -> tuple[object, ...]:
        return (
            self.tool,
            self.domain,
            self.quote_context,
            tuple(sorted(self.source.items())),
            tuple(sorted(self.shapes.items())),
            tuple(sorted(self.fields.items())),
            tuple((k, tuple(id(v) for v in values)) for k, values in sorted(self.values.items())),
        )

    def copy_fields(self, param: str, arg: ast.AST, outer: _Flow) -> None:
        key = _slot(arg)
        if key:
            for slot, taint in outer.fields.items():
                if slot.startswith(key + "."):
                    self.fields[param + slot[len(key) :]] = taint

    def clip(self, text: str) -> str:
        return self.analysis.text(text, self.where) if self.analysis else text

    def text_of(self, node: ast.AST, seen: frozenset[str] = frozenset()) -> str:
        if self.analysis and not self.analysis.visit(1, self.where):
            return ""
        text = _literal_text(node)
        text = self.clip(text)
        if len(seen) > limits.MAX_ALIAS_DEPTH:
            if self.analysis:
                self.analysis.limit("alias-depth", self.where, "literal alias depth limit reached")
            return text
        for item in ast.walk(node):
            key = _slot(item)
            if key in self.values and key not in seen:
                for value in self.values[key]:
                    text = self.clip(text + " " + self.text_of(value, seen | {key}))
        if isinstance(node, ast.Call) and self.returns:
            for inner, value in self.returns(node, self):
                text = self.clip(text + " " + inner.text_of(value, seen))
        return text

    def taint_of(self, node: ast.AST) -> tuple[Shape, str] | None:
        if self.analysis and not self.analysis.visit(1, self.where):
            return None
        if len(self.visiting) > limits.MAX_EXPRESSION_DEPTH:
            if self.analysis:
                self.analysis.limit(
                    "expression-depth", self.where, "expression depth limit reached"
                )
            return None
        if id(node) in self.visiting:
            return None
        self.visiting.add(id(node))
        try:
            return self._taint_of(node)
        finally:
            self.visiting.remove(id(node))

    def _taint_of(self, node: ast.AST) -> tuple[Shape, str] | None:
        """(shape, argument) if `node` carries tool input."""
        if self.safe and self.safe(node):
            return None
        key = _slot(node)
        base = _slot(node.value) if isinstance(node, (ast.Attribute, ast.Subscript)) else key
        if wildcard := self.fields.get(base + ".*"):
            return wildcard
        if key in self.fields:
            return self.fields[key]
        if isinstance(node, ast.Name) and self.quote_context and node.id in self.values:
            found = [t for value in self.values[node.id] if (t := self.taint_of(value))]
            if found:
                return max(found, key=lambda t: _RANK[t[0]])
        if isinstance(node, ast.Name) and node.id in self.source:
            return self.shapes.get(node.id, "whole"), self.source[node.id]
        if isinstance(node, ast.Name):
            found = [t for k, t in self.fields.items() if k.startswith(node.id + ".") and t]
            return max(found, key=lambda t: _RANK[t[0]]) if found else None
        if isinstance(node, (ast.Attribute, ast.Subscript)):
            inner = self.taint_of(node.value)
            if inner and isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Constant):
                return inner[0], str(node.slice.value)  # arguments["branch"]
            return inner
        if isinstance(node, ast.Call):
            if (
                _name(node.func) in _SANITIZERS[self.domain]
                and _name(node.func).split(".")[0] not in self.shadowed
                and _name(node.func).split(".")[0] not in self.values
                and not (
                    self.domain == "shell"
                    and self.quote_context
                    and _name(node.func) not in _NUMERIC
                )
            ):
                return None
            if isinstance(node.func, ast.Attribute):
                if node.func.attr == "format" and isinstance(node.func.value, ast.Constant):
                    found = [t for a in [*node.args, *(k.value for k in node.keywords)]
                             if (t := self.taint_of(a))]  # fmt: skip
                    return ("mixed", found[0][1]) if found else None
                if node.func.attr == "join" and node.args:
                    if _name(node.func.value) in ("os.path", "path", "posixpath"):
                        return self._joined(node.args)
                    return self._mixed_parts(node.args[0])
                # str methods keep the shape: x.strip(), x.lower()
                inner = self.taint_of(node.func.value)
                if inner:
                    return inner
            if _short(node.func) in ("Path", "PurePath", "PosixPath") and node.args:
                return self._joined(node.args)
            if _short(node.func) in ("str", "repr", "format"):
                found = [t for a in node.args if (t := self.taint_of(a))]
                return found[0] if found else None
            if self.returns:
                returned = self.returns(node, self)
                if returned:
                    found = [t for inner, value in returned if (t := inner.taint_of(value))]
                    return max(found, key=lambda t: _RANK[t[0]]) if found else None
            # Unknown transformations retain input; absence of a summary is not sanitization.
            found = [t for value in node.args if (t := self.taint_of(value))]
            return max(found, key=lambda t: _RANK[t[0]]) if found else None
        if isinstance(node, ast.JoinedStr):
            return self._mixed_parts(node)
        if self.domain == "shell" and isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return self._shell_parts(_concat_parts(node))
        if isinstance(node, ast.BinOp):
            left, right = self.taint_of(node.left), self.taint_of(node.right)
            if isinstance(node.op, ast.Div) and right and not left:
                return "based", right[1]  # Path(ROOT) / name
            if isinstance(node.op, (ast.Add, ast.Mod)) and (left or right):
                has_text = any(isinstance(n, ast.Constant) and isinstance(n.value, str)
                               for n in ast.walk(node))  # fmt: skip
                found = left or right
                assert found is not None
                return ("mixed" if has_text else found[0]), found[1]
            return left or right
        if isinstance(node, ast.Dict):
            found = [t for e in node.values if (t := self.taint_of(e))]
            return max(found, key=lambda t: _RANK[t[0]]) if found else None
        if isinstance(node, (ast.List, ast.Tuple)):
            found = [t for e in node.elts if (t := self.taint_of(e))]
            return found[0] if found else None
        return None

    def _joined(self, parts: list[ast.expr]) -> tuple[Shape, str] | None:
        found = [(i, t) for i, p in enumerate(parts) if (t := self.taint_of(p))]
        if not found:
            return None
        i, (shape, arg) = found[0]
        return ("based" if i > 0 else shape), arg

    def _mixed_parts(self, node: ast.AST) -> tuple[Shape, str] | None:
        """f-strings and " ".join([...]): each interpolated expression is judged whole, so
        f"git log {shlex.quote(branch)}" is clean."""
        if isinstance(node, ast.JoinedStr):
            parts = [v.value if isinstance(v, ast.FormattedValue) else v for v in node.values]
        elif isinstance(node, (ast.List, ast.Tuple)):
            parts = list(node.elts)
        else:
            return self.taint_of(node)
        if self.domain == "shell":
            return self._shell_parts(parts)
        found = [t for part in parts if (t := self.taint_of(part))]
        if not found:
            return None
        has_text = any(isinstance(n, ast.Constant) and isinstance(n.value, str) and n.value.strip()
                       for n in parts)  # fmt: skip
        return ("mixed" if has_text else found[0][0]), found[0][1]

    def _shell_parts(self, parts: Sequence[ast.AST]) -> tuple[Shape, str] | None:
        quote, escaped = ('"' if self.quote_context else ""), False
        found: list[tuple[Shape, str]] = []
        has_text = False
        for part in parts:
            if isinstance(part, ast.Constant) and isinstance(part.value, str):
                quote, escaped = advance(part.value, quote, escaped)
                has_text |= bool(part.value.strip())
            else:
                inner = replace(
                    self, quote_context=bool(quote) or escaped, visiting=set(self.visiting)
                )
                if taint := inner.taint_of(part):
                    found.append(taint)
        if not found:
            return None
        return ("mixed" if has_text else found[0][0]), found[0][1]

    def assign(self, target: ast.AST, value: ast.AST) -> bool:
        """Propagate into `target`; True if anything changed."""
        taint = self.taint_of(value)
        key = _slot(target)
        if not key and isinstance(target, ast.Subscript):
            base = _slot(target.value)
            key = base + ".*" if base else ""
        if not key:
            return False
        self.values[key] = tuple(dict.fromkeys((*self.values.get(key, ()), value)))
        changed = False
        if isinstance(value, ast.Dict):
            for k, item in zip(value.keys, value.values, strict=True):
                if k is None and (spread := self.taint_of(item)):
                    self.fields[key + ".*"] = spread
                if isinstance(k, ast.Constant) and isinstance(k.value, str):
                    slot = key + "." + k.value
                    item_taint = self.taint_of(item)
                    old = self.fields.get(slot)
                    if slot not in self.fields or (item_taint and not old):
                        self.fields[slot] = item_taint
                        changed = True
                    self.values[slot] = tuple(dict.fromkeys((*self.values.get(slot, ()), item)))
        alias = _slot(value)
        for slot, value_taint in list(self.fields.items()):
            if alias and slot.startswith(alias + "."):
                dest = key + slot[len(alias) :]
                if dest not in self.fields or (value_taint and not self.fields[dest]):
                    self.fields[dest] = value_taint
                    changed = True
        if not isinstance(target, ast.Name):
            if key not in self.fields or (taint and not self.fields[key]):
                self.fields[key] = taint
                return True
            return changed
        if taint is None:
            return changed
        shape, arg = taint
        old = self.shapes.get(target.id) if target.id in self.source else None
        if old is not None and _RANK[old] >= _RANK[shape]:
            return changed
        self.source[target.id], self.shapes[target.id] = arg, shape
        return True


def _slot(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return _slot(node.value) + "." + node.attr
    if isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Constant):
        return _slot(node.value) + "." + str(node.slice.value)
    return ""


def _body(fn: ast.AST) -> list[ast.AST]:
    nodes: list[ast.AST] = []
    stack = [fn]
    while stack:
        node = stack.pop()
        if node is not fn and isinstance(
            node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
        ):
            continue
        nodes.append(node)
        stack.extend(reversed(list(ast.iter_child_nodes(node))))
    return nodes


def _literal_text(node: ast.AST) -> str:
    return " ".join(n.value for n in ast.walk(node)
                    if isinstance(n, ast.Constant) and isinstance(n.value, str))  # fmt: skip


def _host_is_tainted(node: ast.AST, flow: _Flow, seen: frozenset[str] = frozenset()) -> bool:
    """f"http://{host}/x", "https://" + host: the input decides which server is contacted."""
    if isinstance(node, ast.Name) and node.id in flow.source:
        if node.id not in seen and len(seen) >= limits.MAX_ALIAS_DEPTH:
            if flow.analysis:
                flow.analysis.limit("alias-depth", flow.where, "URL alias depth limit reached")
            return False
        return (
            any(
                _host_is_tainted(value, flow, seen | {node.id})
                for value in flow.values.get(node.id, ())
            )
            if node.id not in seen and len(seen) < limits.MAX_ALIAS_DEPTH
            else False
        )
    if isinstance(node, ast.Call) and flow.returns:
        return any(_host_is_tainted(value, inner) for inner, value in flow.returns(node, flow))
    if isinstance(node, ast.JoinedStr):
        prefix = ""
        for part in node.values:
            if isinstance(part, ast.Constant) and isinstance(part.value, str):
                prefix += part.value
            elif flow.taint_of(part.value if isinstance(part, ast.FormattedValue) else part):
                return re.search(r"://[^/]*$", prefix) is not None
            else:
                prefix += "x"
        return False
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        prefix = ""
        for part in _concat_parts(node):  # "https://" + host + "/x"
            if flow.taint_of(part):
                return re.search(r"://[^/]*$", prefix) is not None
            prefix += _literal_text(part) if isinstance(part, ast.Constant) else "x"
    return False


def _concat_parts(node: ast.AST) -> list[ast.AST]:
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return [*_concat_parts(node.left), *_concat_parts(node.right)]
    return [node]


class _Analyzer:
    def __init__(self, path: str, tree: ast.Module, lines: list[str]) -> None:
        self.path, self.tree, self.lines = path, tree, lines
        self.hits: list[SourceHit] = []
        self.analysis = Analysis()  # replaced by the shared package session
        self.bodies: dict[int, list[ast.AST]] = {}
        self.summaries: dict[tuple[object, ...], list[tuple[_Flow, ast.AST]]] = {}
        self.active_summaries: set[tuple[object, ...]] = set()
        self.functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.functions.setdefault(node.name, node)
        # modules imported here (`from . import tools`): tools.run(x) may be in another file
        imports = [n for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom))]
        self.modules = {(a.asname or a.name).split(".")[0] for n in imports for a in n.names}
        # every function in the package, set by analyze_package
        self.package: dict[str, tuple[_Analyzer, ast.FunctionDef | ast.AsyncFunctionDef]] = {}

    def hit(self, node: ast.AST, kind: SourceHitKind, detail: str) -> None:
        line = getattr(node, "lineno", 1)
        if any(h.line == line and h.kind == kind for h in self.hits):
            return  # reached again through another handler
        code = self.lines[line - 1].strip() if 0 < line <= len(self.lines) else ""
        self.hits.append(SourceHit(kind=kind, file=self.path, line=line, code=code[:200],
                                   detail=detail))  # fmt: skip

    def handlers(self) -> list[tuple[str, ast.FunctionDef | ast.AsyncFunctionDef, list[str]]]:
        """(tool name, function, tainted parameter names)."""
        out: list[tuple[str, ast.FunctionDef | ast.AsyncFunctionDef, list[str]]] = []
        registered = {a.id for n in ast.walk(self.tree) if isinstance(n, ast.Call)
                      and _short(n.func) == "add_tool"
                      for a in n.args[:1] if isinstance(a, ast.Name)}  # fmt: skip
        for fn in self.functions.values():
            names = {_short(d) for d in fn.decorator_list}
            params = [a.arg for a in [*fn.args.posonlyargs, *fn.args.args, *fn.args.kwonlyargs]
                      if a.arg not in _CONTEXT_PARAMS]  # fmt: skip
            if "call_tool" in names:  # low-level server: (name, arguments)
                out.append(("call_tool", fn, params[1:] or params))
            elif "tool" in names or fn.name in registered:
                out.append((fn.name, fn, params))
        return out

    def run(self) -> list[SourceHit]:
        for tool, fn, params in self.handlers():
            for domain in _DOMAINS:
                self.analyze(tool, fn, _Flow(tool, {p: p for p in params}, domain=domain))
        return self.hits

    def body(self, fn: ast.AST) -> list[ast.AST]:
        if id(fn) not in self.bodies:
            self.bodies[id(fn)] = _body(fn)
        return self.bodies[id(fn)]

    def analyze(
        self, tool: str, fn: ast.AST, flow: _Flow, checked: CheckedPaths = EMPTY_CHECKED
    ) -> None:
        key = (self.path, id(fn), flow.key(), checked)
        where = f"{self.path}:{getattr(fn, 'lineno', 1)}"
        self.analysis.submit(key, where, partial(self.evaluate, tool, fn, flow, checked))

    def evaluate(self, tool: str, fn: ast.AST, flow: _Flow, checked: CheckedPaths) -> None:
        flow.analysis, flow.where = self.analysis, self.path
        flow.shadowed = frozenset(self.functions)
        flow.returns = lambda call, current: self.return_values(call, current, 0)
        body = self.body(fn)
        self.populate(body, flow)
        if not self.analysis.visit(len(body), self.path):
            return
        guards = PathGuards(fn, lambda node: flow.taint_of(node) is not None, checked)
        if guards.limited and flow.domain == "path":
            self.analysis.limit("guards", self.path, "path-guard inference node limit reached")
        for node in body:
            if isinstance(node, ast.Call):
                at_flow = replace(
                    flow,
                    safe=partial(guards.allowlisted, at=node, domain=flow.domain),
                    visiting=set(),
                )
                self.sink(node, at_flow, guards)
                self.follow(node, at_flow, guards)

    def populate(self, body: list[ast.AST], flow: _Flow) -> None:
        for _ in range(limits.MAX_PROPAGATION_PASSES):
            if not self.analysis.visit(len(body), self.path):
                return
            changed = False
            for node in body:
                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        changed |= flow.assign(target, node.value)
                elif isinstance(node, (ast.AnnAssign, ast.AugAssign, ast.NamedExpr)):
                    if node.value is not None:
                        changed |= flow.assign(node.target, node.value)
                elif isinstance(node, (ast.For, ast.comprehension)):
                    changed |= flow.assign(node.target, node.iter)
                elif isinstance(node, ast.withitem) and node.optional_vars is not None:
                    changed |= flow.assign(node.optional_vars, node.context_expr)
            if not changed:
                return
        self.analysis.limit("assignments", self.path, "assignment propagation did not converge")

    def return_values(self, call: ast.Call, flow: _Flow, depth: int) -> list[tuple[_Flow, ast.AST]]:
        func = call.func
        base = _name(func.value) if isinstance(func, ast.Attribute) else ""
        local = isinstance(func, ast.Name) or base in ("self", "cls")
        owner = self
        callee = self.functions.get(_short(func)) if local else None
        if callee is None and (local or base in self.modules) and _short(func) in self.package:
            owner, callee = self.package[_short(func)]
        if callee is None:
            return []
        params = [
            a.arg
            for a in [*callee.args.posonlyargs, *callee.args.args]
            if a.arg not in _CONTEXT_PARAMS
        ]
        inner = _Flow(flow.tool, {}, domain=flow.domain, quote_context=flow.quote_context)
        for param, arg in zip(params, call.args, strict=False):
            if taint := flow.taint_of(arg):
                inner.source[param], inner.shapes[param] = taint[1], taint[0]
                inner.copy_fields(param, arg, flow)
        for kw in call.keywords:
            if kw.arg in params and (taint := flow.taint_of(kw.value)):
                inner.source[kw.arg], inner.shapes[kw.arg] = taint[1], taint[0]
                inner.copy_fields(kw.arg, kw.value, flow)
        key = (id(callee), inner.key(), depth)
        if key in owner.summaries:
            return owner.summaries[key]
        where = f"{owner.path}:{callee.lineno}"
        cycle = (id(callee), inner.key())
        if cycle in owner.active_summaries:
            self.analysis.limit(
                "return-cycle", where, "recursive return summary could not be resolved"
            )
            return []
        if not self.analysis.summary(depth, where):
            return []
        owner.active_summaries.add(cycle)
        before = self.analysis.stops
        try:
            inner.analysis, inner.where = self.analysis, owner.path
            inner.shadowed = frozenset(owner.functions)
            inner.returns = lambda expr, current: owner.return_values(expr, current, depth + 1)
            nodes = owner.body(callee)
            owner.populate(nodes, inner)
            result: list[tuple[_Flow, ast.AST]] = [
                (inner, n.value) for n in nodes if isinstance(n, ast.Return) and n.value is not None
            ]
            if self.analysis.stops == before:
                owner.summaries[key] = result
            return result
        finally:
            owner.active_summaries.remove(cycle)

    def follow(self, call: ast.Call, flow: _Flow, guards: PathGuards) -> None:
        callback: ast.AST | None = None
        inputs: list[ast.AST] = []
        if _name(call.func) in {"map", "filter"} and len(call.args) >= 2:
            callback, inputs = call.args[0], list(call.args[1:])
        elif _name(call.func) == "sorted" and call.args:
            callback = next((k.value for k in call.keywords if k.arg == "key"), None)
            inputs = [call.args[0]]
        if callback is not None:
            fn = (
                callback
                if isinstance(callback, ast.Lambda)
                else self.functions.get(_name(callback))
            )
            if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                inner = replace(
                    flow,
                    source=dict(flow.source),
                    shapes=dict(flow.shapes),
                    fields=dict(flow.fields),
                    values=dict(flow.values),
                    safe=None,
                    visiting=set(),
                )
                for param, value in zip(fn.args.args, inputs, strict=False):
                    name = param.arg
                    inner.source.pop(name, None)
                    inner.shapes.pop(name, None)
                    inner.values.pop(name, None)
                    inner.fields = {
                        k: v for k, v in inner.fields.items() if not k.startswith(name + ".")
                    }
                    if taint := flow.taint_of(value):
                        inner.source[name], inner.shapes[name] = taint[1], taint[0]
                self.analyze(flow.tool, fn, inner)
            return
        # helper(x) or self.helper(x); not subprocess.run(...) that shares a local name
        func = call.func
        base = _name(func.value) if isinstance(func, ast.Attribute) else ""
        local = isinstance(func, ast.Name) or base in ("self", "cls")
        owner: _Analyzer = self
        callee = self.functions.get(_short(func)) if local else None
        if callee is None and (local or base in self.modules) and _short(func) in self.package:
            owner, callee = self.package[_short(func)]  # defined in another file
        if callee is None:
            return
        params = [a.arg for a in [*callee.args.posonlyargs, *callee.args.args]
                  if a.arg not in _CONTEXT_PARAMS]  # fmt: skip
        inner = _Flow(flow.tool, {}, domain=flow.domain, quote_context=flow.quote_context)
        protected_paths: set[str] = set()
        protected_components: set[str] = set()

        def protect(param: str, arg: ast.AST) -> None:
            if guards.path_safe(arg, call):
                protected_paths.add(param)
            if guards.component_safe(arg, call):
                protected_components.add(param)

        for param, arg in zip(params, call.args, strict=False):
            if taint := flow.taint_of(arg):
                inner.source[param], inner.shapes[param] = taint[1], taint[0]
                inner.copy_fields(param, arg, flow)
                protect(param, arg)
        for kw in call.keywords:
            if kw.arg in params and (taint := flow.taint_of(kw.value)):
                inner.source[kw.arg], inner.shapes[kw.arg] = taint[1], taint[0]
                inner.copy_fields(kw.arg, kw.value, flow)
                protect(kw.arg, kw.value)
        if inner.source:
            owner.analyze(
                flow.tool,
                callee,
                inner,
                CheckedPaths(frozenset(protected_paths), frozenset(protected_components)),
            )

    def sink(self, call: ast.Call, flow: _Flow, guards: PathGuards) -> None:
        func, short = _name(call.func), _short(call.func)
        tool = flow.tool
        first = call.args[0] if call.args else next(
            (k.value for k in call.keywords if k.arg in ("args", "cmd", "url", "sql", "query")),
            None)  # fmt: skip
        if flow.domain == "path" and short in _PATH_CALLS:
            receiver = call.func.value if isinstance(call.func, ast.Attribute) else None
            for candidate in (first, receiver):  # open(ROOT / name), (ROOT / name).read_text()
                based = flow.taint_of(candidate) if candidate is not None else None
                if (
                    based
                    and based[0] == "based"
                    and candidate is not None
                    and not guards.path_safe(candidate, call)
                ):
                    self.hit(call, "path_traversal", f"tool {tool}: argument {based[1]} is joined "
                             f"to a base directory and used by {func}() without a recognized "
                             "preceding containment "
                             "guard for that value")  # fmt: skip
                    break
        if first is None:
            return
        taint = flow.taint_of(first)
        shell = any(k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value
                    for k in call.keywords)  # fmt: skip
        if (
            flow.domain == "shell"
            and taint
            and taint[0] == "mixed"
            and (
                func in _ALWAYS_SHELL or short in _ALWAYS_SHELL or (short in _SHELL_CALLS and shell)
            )
        ):
            self.hit(call, "shell_injection", f"tool {tool}: argument {taint[1]} is put into a "
                     f"shell command run by {func}()")  # fmt: skip
        elif (
            flow.domain == "shell"
            and short in _SHELL_CALLS
            and isinstance(first, (ast.List, ast.Tuple))
            and first.elts
        ):
            head = _literal_text(first.elts[0]) if len(first.elts) > 2 else ""
            if (
                head.split("/")[-1] in ("sh", "bash", "zsh")
                and _literal_text(first.elts[1]) == "-c"
            ):
                inner = flow.taint_of(first.elts[2])
                if inner and inner[0] == "mixed":
                    self.hit(call, "shell_injection", f"tool {tool}: argument {inner[1]} is put "
                             f"into a `sh -c` command run by {func}()")  # fmt: skip
        if (
            taint
            and taint[0] == "mixed"
            and flow.domain == "sql"
            and short in _SQL_CALLS
            and _SQL_WORDS.search(flow.text_of(first))
        ):
            self.hit(call, "sql_injection", f"tool {tool}: argument {taint[1]} is put into a SQL "
                     f"string run by {func}()")  # fmt: skip
        if flow.domain == "url" and short in _URL_CALLS and _host_is_tainted(first, flow):
            arg = (flow.taint_of(first) or ("", "?"))[1]
            self.hit(call, "ssrf", f"tool {tool}: argument {arg} sets the host of a URL "
                     f"requested by {func}()")  # fmt: skip


def analyze_package(
    files: list[tuple[str, str]], *, skipped: list[str] | None = None
) -> list[SourceHit]:
    """Hits across a package's files: handlers in one file, sinks in another."""
    analyzers: list[_Analyzer] = []
    for path, text in files:
        try:
            tree = ast.parse(text, filename=path)
        except (SyntaxError, ValueError):
            continue
        analyzers.append(_Analyzer(path, tree, text.splitlines()))
    package: dict[str, tuple[_Analyzer, ast.FunctionDef | ast.AsyncFunctionDef]] = {}
    for analyzer in analyzers:
        for name, fn in analyzer.functions.items():
            package.setdefault(name, (analyzer, fn))
    session = Analysis()
    for analyzer in analyzers:
        analyzer.package = package
        analyzer.analysis = session
    for analyzer in analyzers:
        analyzer.run()
    session.drain()
    if skipped is not None:
        skipped.extend(session.limits.values())
    return [h for a in analyzers for h in sorted(a.hits, key=lambda hit: hit.line)]


def analyze(path: str, text: str) -> list[SourceHit]:
    return analyze_package([(path, text)])
