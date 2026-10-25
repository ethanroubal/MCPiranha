"""Taint analysis for JavaScript / TypeScript MCP servers (see taint_python.py for the model).

Handlers: `server.tool(name, ..., handler)`, `server.registerTool(name, config, handler)`,
FastMCP-TS `addTool({ name, execute })`, and the low-level
`setRequestHandler(CallToolRequestSchema, (request) => ...)` (where `request` is the input).
The first parameter is tainted: destructured names (`({ path, url })`) or the whole object
(`args.path`, `request.params.arguments.path`). Taint follows declarations, assignments and
simple object fields/aliases, common array callbacks and helper arguments/returns across package
files (two levels). This is not a full control-flow or heap analysis.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from functools import partial
from typing import Literal

from tree_sitter import Tree

from mcpiranha.core.models import SourceHit, SourceHitKind
from mcpiranha.source import analysis as limits
from mcpiranha.source.analysis import Analysis
from mcpiranha.source.javascript import Node, callee_of, node_text, parser, string_value, walk
from mcpiranha.source.path_guards_javascript import PathGuards
from mcpiranha.source.path_guards_python import EMPTY_CHECKED, CheckedPaths
from mcpiranha.source.shell_context import advance

Shape = Literal["whole", "mixed", "based"]
_RANK = {"whole": 1, "based": 2, "mixed": 3}
_FUNCTIONS = ("arrow_function", "function_expression", "function_declaration", "function",
              "method_definition", "generator_function_declaration")  # fmt: skip

Domain = Literal["shell", "sql", "path", "url"]
_DOMAINS: tuple[Domain, ...] = ("shell", "sql", "path", "url")
_NUMERIC = frozenset(
    {"Number", "Number.parseInt", "parseInt", "Number.parseFloat", "parseFloat", "Boolean"}
)
_SANITIZERS: dict[Domain, frozenset[str]] = {
    "shell": _NUMERIC | {"shellQuote", "shellescape", "escapeShellArg"},
    "sql": _NUMERIC,
    "path": _NUMERIC | {"path.basename", "path.posix.basename", "path.win32.basename"},
    "url": frozenset(),
}
_CALLBACKS = frozenset({"map", "forEach", "flatMap", "filter", "some", "every", "find"})
_HANDLER_KEYS = ("execute", "handler", "callback", "cb", "run", "fn")
_EXEC_ALIAS = re.compile(
    r"\b(?:const|let|var)\s+([\w$]+)\s*=\s*(?:\(0,\s*)?[\w$.]*promisify\)?\s*\(\s*"
    r"(?:\(0,\s*)?(?:[\w$.]*\.)?(exec|execFile)\b"
    r"|\b(?:const|let|var)\s+([\w$]+)\s*=\s*(?:[\w$.]*\.)?(exec|execSync)\s*[;,\n]"
)
_TS_IMPORT = re.compile(r"^[\w$]+_\d+\.[\w$]+$")  # tools_1.run, from `(0, tools_1.run)(...)`
_SHELL = frozenset({"exec", "execSync"})
_SPAWN = frozenset({"spawn", "spawnSync", "execFile", "execFileSync", "execa", "execaSync"})
_ALWAYS_SHELL = frozenset({"execaCommand", "execaCommandSync"})
_SQL = frozenset({"query", "execute", "raw", "$queryRawUnsafe", "$executeRawUnsafe", "prepare",
                  "unsafe", "exec", "all", "run", "get", "each"})  # fmt: skip
_SQL_WORDS = re.compile(r"\b(select|insert|update|delete|create|drop|alter|where|from|pragma|"
                        r"values|join|order\s+by)\b", re.IGNORECASE)  # fmt: skip
_PATH = frozenset({"readFile", "readFileSync", "writeFile", "writeFileSync", "appendFile",
                   "appendFileSync", "unlink", "unlinkSync", "rm", "rmSync", "rmdir", "rmdirSync",
                   "readdir", "readdirSync", "createReadStream", "createWriteStream", "copyFile",
                   "copyFileSync", "rename", "renameSync", "mkdir", "mkdirSync", "sendFile",
                   "open", "openSync", "readJson", "readJsonSync", "outputFile",
                   "outputFileSync"})  # fmt: skip
_URL = frozenset({"fetch", "get", "post", "put", "patch", "delete", "head", "request", "got",
                  "axios", "ky"})  # fmt: skip


def _short(callee: str) -> str:
    return callee.rsplit(".", 1)[-1]


def _params(fn: Node) -> list[Node]:
    params = fn.child_by_field_name("parameters")
    if params is None:
        single = fn.child_by_field_name("parameter")
        return [single] if single is not None else []
    return [c for c in params.named_children if c.type != "comment"]


def _pattern_names(node: Node) -> list[tuple[str, str]]:
    """(local name, argument name) bound by a parameter or destructuring pattern."""
    if node.type in ("required_parameter", "optional_parameter"):
        inner = node.child_by_field_name("pattern")
        return _pattern_names(inner) if inner is not None else []
    if node.type == "assignment_pattern":
        left = node.child_by_field_name("left")
        return _pattern_names(left) if left is not None else []
    if node.type == "identifier":
        return [(node_text(node), "")]  # the whole input object
    if node.type == "object_pattern":
        out: list[tuple[str, str]] = []
        for child in node.named_children:
            if child.type == "shorthand_property_identifier_pattern":
                out.append((node_text(child), node_text(child)))
            elif child.type == "pair_pattern":
                key, value = child.child_by_field_name("key"), child.child_by_field_name("value")
                for local, _ in _pattern_names(value) if value is not None else []:
                    out.append((local, node_text(key)))
            elif child.type == "object_assignment_pattern":
                left = child.child_by_field_name("left")
                if left is not None:
                    out.append((node_text(left), node_text(left)))
        return out
    return []


@dataclass
class _Flow:
    tool: str
    source: dict[str, str]  # name -> argument ("" = the whole input object)
    shapes: dict[str, Shape] = field(default_factory=dict[str, Shape])
    domain: Domain = "shell"
    quote_context: bool = False
    analysis: Analysis | None = None
    where: str = "source"
    fields: dict[str, tuple[Shape, str] | None] = field(
        default_factory=dict[str, tuple[Shape, str] | None]
    )
    values: dict[str, tuple[Node, ...]] = field(default_factory=dict[str, tuple[Node, ...]])
    returns: Callable[[Node, _Flow], list[tuple[_Flow, Node]]] | None = None
    shadowed: frozenset[str] = frozenset()
    safe: Callable[[Node], bool] | None = None
    visiting: set[int] = field(default_factory=set[int])

    def key(self) -> tuple[object, ...]:
        return (
            self.tool,
            self.domain,
            self.quote_context,
            tuple(sorted(self.source.items())),
            tuple(sorted(self.shapes.items())),
            tuple(sorted(self.fields.items())),
            tuple((k, tuple(v.id for v in values)) for k, values in sorted(self.values.items())),
        )

    def copy_fields(self, param: str, arg: Node, outer: _Flow) -> None:
        key = _slot(arg)
        if key:
            for slot, taint in outer.fields.items():
                if slot.startswith(key + "."):
                    self.fields[param + slot[len(key) :]] = taint

    def clip(self, text: str) -> str:
        return self.analysis.text(text, self.where) if self.analysis else text

    def text_of(self, node: Node, seen: frozenset[str] = frozenset()) -> str:
        if self.analysis and not self.analysis.visit(1, self.where):
            return ""
        text = " ".join(node_text(c) for c in walk(node) if c.type == "string_fragment")
        text = self.clip(text)
        if len(seen) > limits.MAX_ALIAS_DEPTH:
            if self.analysis:
                self.analysis.limit("alias-depth", self.where, "literal alias depth limit reached")
            return text
        for item in walk(node):
            key = _slot(item)
            if key in self.values and key not in seen:
                for value in self.values[key]:
                    text = self.clip(text + " " + self.text_of(value, seen | {key}))
        if node.type == "call_expression" and self.returns:
            for inner, value in self.returns(node, self):
                text = self.clip(text + " " + inner.text_of(value, seen))
        return text

    def taint_of(self, node: Node | None) -> tuple[Shape, str] | None:
        if node is None:
            return None
        if self.analysis and not self.analysis.visit(1, self.where):
            return None
        if len(self.visiting) > limits.MAX_EXPRESSION_DEPTH:
            if self.analysis:
                self.analysis.limit(
                    "expression-depth", self.where, "expression depth limit reached"
                )
            return None
        if node.id in self.visiting:
            return None
        self.visiting.add(node.id)
        try:
            return self._taint_of(node)
        finally:
            self.visiting.remove(node.id)

    def _taint_of(self, node: Node) -> tuple[Shape, str] | None:
        if self.safe and self.safe(node):
            return None
        slot = _slot(node)
        base = _slot(node.child_by_field_name("object")) or slot
        if wildcard := self.fields.get(base + ".*"):
            return wildcard
        if slot in self.fields:
            return self.fields[slot]
        kind = node.type
        if kind in ("parenthesized_expression", "await_expression", "as_expression",
                    "non_null_expression", "satisfies_expression"):  # fmt: skip
            inner = node.named_children[0] if node.named_children else None
            return self.taint_of(inner)
        if kind == "identifier":
            name = node_text(node)
            if self.quote_context and name in self.values:
                found = [t for value in self.values[name] if (t := self.taint_of(value))]
                if found:
                    return max(found, key=lambda t: _RANK[t[0]])
            if name in self.source:
                return self.shapes.get(name, "whole"), self.source[name] or name
            found = [t for k, t in self.fields.items() if k.startswith(name + ".") and t]
            return max(found, key=lambda t: _RANK[t[0]]) if found else None
        if kind == "spread_element":
            return self.taint_of(node.named_children[0]) if node.named_children else None
        if kind in ("member_expression", "subscript_expression"):
            obj = self.taint_of(node.child_by_field_name("object"))
            if obj is None:
                return None
            prop = node.child_by_field_name("property") or node.child_by_field_name("index")
            key = (string_value(prop) or "") if prop is not None and prop.type == "string" else (
                node_text(prop))  # fmt: skip
            # args.path -> "path"; request.params.arguments.path -> "path"
            plain = key not in ("params", "arguments", "input") and not key.isdigit()
            return obj[0], key if plain else obj[1]
        if kind == "call_expression":
            callee = callee_of(node)
            args = node.child_by_field_name("arguments")
            arg_nodes = args.named_children if args is not None else []
            if (
                callee in _SANITIZERS[self.domain]
                and callee.split(".")[0] not in self.shadowed
                and callee.split(".")[0] not in self.values
                and not (self.domain == "shell" and self.quote_context and callee not in _NUMERIC)
            ):
                return None
            if callee in ("path.join", "path.resolve", "join", "resolve", "path.posix.join"):
                found = [(i, t) for i, a in enumerate(arg_nodes) if (t := self.taint_of(a))]
                if not found:
                    return None
                i, (shape, arg) = found[0]
                return ("based" if i > 0 else shape), arg
            if callee in ("String", "decodeURIComponent"):
                return self.taint_of(arg_nodes[0]) if arg_nodes else None
            func = node.child_by_field_name("function")
            if func is not None and func.type == "member_expression":
                # x.trim(), x.toLowerCase(), parts.join(" ")
                return self.taint_of(func.child_by_field_name("object"))
            if self.returns:
                returned = self.returns(node, self)
                if returned:
                    found = [t for inner, value in returned if (t := inner.taint_of(value))]
                    return max(found, key=lambda t: _RANK[t[0]]) if found else None
            found = [t for value in arg_nodes if (t := self.taint_of(value))]
            return max(found, key=lambda t: _RANK[t[0]]) if found else None
        if kind == "object":
            found = [
                t
                for pair in node.named_children
                if (
                    t := self.taint_of(
                        pair.child_by_field_name("value") if pair.type == "pair" else pair
                    )
                )
            ]
            return max(found, key=lambda t: _RANK[t[0]]) if found else None
        if kind == "shorthand_property_identifier":
            name = node_text(node)
            return (
                (self.shapes.get(name, "whole"), self.source[name]) if name in self.source else None
            )
        if kind == "template_string":
            if self.domain == "shell":
                return self._shell_parts(list(node.named_children))
            subs = [c for c in node.named_children if c.type == "template_substitution"]
            inside = [s.named_children[0] for s in subs if s.named_children]
            found = [t for e in inside if (t := self.taint_of(e))]
            if not found:
                return None
            text = any(
                c.type == "string_fragment" and node_text(c).strip() for c in node.named_children
            )
            return ("mixed" if text else found[0][0]), found[0][1]
        if kind == "binary_expression" and node_text(node.child_by_field_name("operator")) == "+":
            if self.domain == "shell":
                return self._shell_parts(_concat_parts(node))
            left = self.taint_of(node.child_by_field_name("left"))
            right = self.taint_of(node.child_by_field_name("right"))
            found = left or right
            if found is None:
                return None
            has_text = any(c.type in ("string", "template_string") for c in walk(node))
            return ("mixed" if has_text else found[0]), found[1]
        if kind == "array":
            found = [t for c in node.named_children if (t := self.taint_of(c))]
            return found[0] if found else None
        return None

    def _shell_parts(self, parts: list[Node]) -> tuple[Shape, str] | None:
        quote, escaped = ('"' if self.quote_context else ""), False
        found: list[tuple[Shape, str]] = []
        has_text = False
        for part in parts:
            literal = (
                string_value(part)
                if part.type == "string"
                else (node_text(part) if part.type == "string_fragment" else None)
            )
            if literal is not None:
                quote, escaped = advance(literal, quote, escaped)
                has_text |= bool(literal.strip())
            else:
                if part.type == "template_substitution" and part.named_children:
                    part = part.named_children[0]
                inner = replace(
                    self, quote_context=bool(quote) or escaped, visiting=set(self.visiting)
                )
                if taint := inner.taint_of(part):
                    found.append(taint)
        if not found:
            return None
        return ("mixed" if has_text else found[0][0]), found[0][1]

    def bind(self, pattern: Node | None, value: Node | None, *, appended: bool = False) -> bool:
        taint = self.taint_of(value)
        if pattern is None or value is None:
            return False
        key = _slot(pattern)
        if not key and pattern.type == "subscript_expression":
            base = _slot(pattern.child_by_field_name("object"))
            key = base + ".*" if base else ""
        changed = False
        if key:
            self.values[key] = tuple(dict.fromkeys((*self.values.get(key, ()), value)))
            if value.type == "object":
                for pair in value.named_children:
                    if pair.type == "spread_element":
                        changed |= self.set_field(key + ".*", pair)
                        continue
                    prop = pair.child_by_field_name("key")
                    item = pair.child_by_field_name("value")
                    name = string_value(prop) or node_text(prop)
                    if pair.type == "shorthand_property_identifier":
                        name, item = node_text(pair), pair
                    if name and item is not None:
                        changed |= self.set_field(key + "." + name, item)
            alias = _slot(value)
            for slot, value_taint in list(self.fields.items()):
                if alias and slot.startswith(alias + "."):
                    dest = key + slot[len(alias) :]
                    if dest not in self.fields or (value_taint and not self.fields[dest]):
                        self.fields[dest] = value_taint
                        changed = True
            if pattern.type in ("member_expression", "subscript_expression"):
                return self.set_field(key, value) or changed
        if taint is None:
            return changed
        if appended:  # appended to an existing string: text around it
            taint = ("mixed", taint[1])
        if pattern.type == "object_pattern":  # const { path } = args
            for local, arg in _pattern_names(pattern):
                if local not in self.source:
                    self.source[local], self.shapes[local] = arg or local, "whole"
                    changed = True
            return changed
        if pattern.type != "identifier":
            return changed
        name = node_text(pattern)
        old = self.shapes.get(name) if name in self.source else None
        if old is not None and _RANK[old] >= _RANK[taint[0]]:
            return changed
        self.source[name], self.shapes[name] = taint[1], taint[0]
        return True

    def set_field(self, key: str, value: Node) -> bool:
        taint = self.taint_of(value)
        self.values[key] = tuple(dict.fromkeys((*self.values.get(key, ()), value)))
        old = self.fields.get(key)
        if key not in self.fields or (taint and (not old or _RANK[taint[0]] > _RANK[old[0]])):
            self.fields[key] = taint
            return True
        return False


def _slot(node: Node | None) -> str:
    if node is None:
        return ""
    if node.type in ("identifier", "this"):
        return node_text(node)
    if node.type in ("member_expression", "subscript_expression"):
        prop = node.child_by_field_name("property") or node.child_by_field_name("index")
        key = (
            string_value(prop)
            if prop is not None and prop.type == "string"
            else (
                node_text(prop) if prop is not None and prop.type == "property_identifier" else ""
            )
        )
        base = _slot(node.child_by_field_name("object"))
        return base + "." + key if key and base else ""
    return ""


def _body(fn: Node) -> list[Node]:
    nodes: list[Node] = []
    stack = [fn]
    while stack:
        node = stack.pop()
        if node != fn and node.type in _FUNCTIONS:
            continue
        nodes.append(node)
        stack.extend(reversed(node.named_children))
    return nodes


def _concat_parts(node: Node) -> list[Node]:
    if node.type == "binary_expression" and node_text(node.child_by_field_name("operator")) == "+":
        left, right = node.child_by_field_name("left"), node.child_by_field_name("right")
        return [*(_concat_parts(left) if left else []), *(_concat_parts(right) if right else [])]
    return [node]


def _host_is_tainted(node: Node | None, flow: _Flow, seen: frozenset[str] = frozenset()) -> bool:
    """`http://${host}/x`, "https://" + host: the input decides which server is contacted."""
    if node is None:
        return False
    key = _slot(node)
    if key and key in flow.values and key not in seen:
        if len(seen) >= limits.MAX_ALIAS_DEPTH:
            if flow.analysis:
                flow.analysis.limit("alias-depth", flow.where, "URL alias depth limit reached")
            return False
        return any(_host_is_tainted(value, flow, seen | {key}) for value in flow.values[key])
    if node.type == "call_expression" and flow.returns:
        return any(_host_is_tainted(value, inner) for inner, value in flow.returns(node, flow))
    if node.type == "template_string":
        prefix = ""
        for child in node.named_children:
            if child.type == "string_fragment":
                prefix += node_text(child)
            elif child.type == "template_substitution":
                inner = child.named_children[0] if child.named_children else None
                if flow.taint_of(inner):
                    return re.search(r"://[^/]*$", prefix) is not None
                prefix += "x"
        return False
    if node.type == "binary_expression":
        prefix = ""
        for part in _concat_parts(node):  # "https://" + host + "/x"
            if flow.taint_of(part):
                return re.search(r"://[^/]*$", prefix) is not None
            prefix += string_value(part) or "x"
    return False


class _Analyzer:
    def __init__(self, path: str, source: bytes, tree: Tree) -> None:
        self.path, self.tree, self.root = path, tree, tree.root_node
        self.lines = source.decode("utf-8", "replace").splitlines()
        self.hits: list[SourceHit] = []
        self.analysis = Analysis()  # replaced by the shared package session
        self.bodies: dict[int, list[Node]] = {}
        self.summaries: dict[tuple[object, ...], list[tuple[_Flow, Node]]] = {}
        self.active_summaries: set[tuple[object, ...]] = set()
        self.functions: dict[str, Node] = {}
        self.package: dict[str, tuple[_Analyzer, Node]] = {}  # set by analyze_package
        text = source.decode("utf-8", "replace")
        # const execAsync = promisify(exec); const run = child_process.execSync
        self.shell_aliases = {(m.group(1) or m.group(3)): (m.group(2) or m.group(4))
                              for m in _EXEC_ALIAS.finditer(text)}  # fmt: skip
        for node in walk(self.root):
            if node.type in ("function_declaration", "method_definition"):
                self.functions.setdefault(node_text(node.child_by_field_name("name")), node)
            elif node.type == "variable_declarator":
                value = node.child_by_field_name("value")
                if value is not None and value.type in _FUNCTIONS:
                    self.functions.setdefault(node_text(node.child_by_field_name("name")), value)

    def hit(self, node: Node, kind: SourceHitKind, detail: str) -> None:
        row, column = node.start_point
        if any(h.line == row + 1 and h.kind == kind for h in self.hits):
            return  # reached again through another handler
        line = self.lines[row] if row < len(self.lines) else ""
        if len(line) > 200:
            line = line[max(0, column - 80) : column + 120]
        self.hits.append(SourceHit(kind=kind, file=self.path, line=row + 1, code=line.strip(),
                                   detail=detail))  # fmt: skip

    def _function(self, node: Node | None) -> Node | None:
        """A function literal, or the function a name refers to (`registerTool(n, c, execute)`)."""
        if node is None:
            return None
        if node.type in _FUNCTIONS:
            return node
        if node.type == "identifier":
            return self.functions.get(node_text(node))
        return None

    def handlers(self) -> list[tuple[str, Node]]:
        out: list[tuple[str, Node]] = []
        for node in walk(self.root):
            if node.type != "call_expression":
                continue
            callee = _short(callee_of(node))
            args = node.child_by_field_name("arguments")
            items = args.named_children if args is not None else []
            if callee in ("tool", "registerTool", "addTool") and items:
                if items[0].type == "object":  # registerTool({ name, handler }), addTool(...)
                    pairs = {node_text(p.child_by_field_name("key")): p.child_by_field_name("value")
                             for p in items[0].named_children if p.type == "pair"}  # fmt: skip
                    found = [self._function(pairs.get(key)) for key in _HANDLER_KEYS]
                    fn = next((f for f in found if f is not None), None)
                    name = string_value(pairs.get("name")) or node_text(pairs.get("name"))
                else:  # tool(name, [description], [schema], handler)
                    fn = self._function(items[-1]) if len(items) > 1 else None
                    name = string_value(items[0]) or node_text(items[0])
                if fn is not None:
                    out.append((name or "tool", fn))
            elif (
                callee == "setRequestHandler"
                and len(items) == 2
                and "CallTool" in node_text(items[0])
            ):
                fn = self._function(items[1])
                if fn is not None:
                    out.append(("call_tool", fn))
        return out

    def run(self) -> list[SourceHit]:
        for tool, fn in self.handlers():
            params = _params(fn)
            if not params:
                continue
            source = dict(_pattern_names(params[0]))
            if source:
                for domain in _DOMAINS:
                    self.analyze(fn, _Flow(tool, dict(source), domain=domain))
        return self.hits

    def body(self, fn: Node) -> list[Node]:
        if fn.id not in self.bodies:
            self.bodies[fn.id] = _body(fn)
        return self.bodies[fn.id]

    def analyze(self, fn: Node, flow: _Flow, checked: CheckedPaths = EMPTY_CHECKED) -> None:
        key = (self.path, fn.id, flow.key(), checked)
        where = f"{self.path}:{fn.start_point[0] + 1}"
        self.analysis.submit(key, where, partial(self.evaluate, fn, flow, checked))

    def evaluate(self, fn: Node, flow: _Flow, checked: CheckedPaths) -> None:
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
            if node.type in ("call_expression", "new_expression"):
                at_flow = replace(
                    flow,
                    safe=partial(guards.allowlisted, at=node, domain=flow.domain),
                    visiting=set(),
                )
                self.sink(node, at_flow, guards)
                self.follow(node, at_flow, guards)

    def populate(self, body: list[Node], flow: _Flow) -> None:
        for _ in range(limits.MAX_PROPAGATION_PASSES):
            if not self.analysis.visit(len(body), self.path):
                return
            changed = False
            for node in body:
                if node.type == "variable_declarator":
                    changed |= flow.bind(node.child_by_field_name("name"),
                                         node.child_by_field_name("value"))  # fmt: skip
                elif node.type == "assignment_expression":
                    changed |= flow.bind(node.child_by_field_name("left"),
                                         node.child_by_field_name("right"))  # fmt: skip
                elif node.type == "augmented_assignment_expression":  # command += " " + x
                    left, right = (
                        node.child_by_field_name("left"),
                        node.child_by_field_name("right"),
                    )
                    changed |= flow.bind(left, right, appended=True)
            if not changed:
                return
        self.analysis.limit("assignments", self.path, "assignment propagation did not converge")

    def return_values(self, call: Node, flow: _Flow, depth: int) -> list[tuple[_Flow, Node]]:
        name = callee_of(call)
        local = "." not in name or name.startswith("this.") or bool(_TS_IMPORT.match(name))
        owner = self
        callee = self.functions.get(_short(name)) if local else None
        if callee is None and local and _short(name) in self.package:
            owner, callee = self.package[_short(name)]
        args = call.child_by_field_name("arguments")
        if callee is None or args is None:
            return []
        inner = _Flow(flow.tool, {}, domain=flow.domain, quote_context=flow.quote_context)
        for param, arg in zip(_params(callee), args.named_children, strict=False):
            if taint := flow.taint_of(arg):
                for local_name, key in _pattern_names(param):
                    inner.source[local_name], inner.shapes[local_name] = key or taint[1], taint[0]
                    inner.copy_fields(local_name, arg, flow)
        key = (callee.id, inner.key(), depth)
        if key in owner.summaries:
            return owner.summaries[key]
        where = f"{owner.path}:{callee.start_point[0] + 1}"
        cycle = (callee.id, inner.key())
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
            result = [
                (inner, n.named_children[0])
                for n in nodes
                if n.type == "return_statement" and n.named_children
            ]
            body = callee.child_by_field_name("body")
            if body is not None and body.type != "statement_block":
                result.append((inner, body))
            if self.analysis.stops == before:
                owner.summaries[key] = result
            return result
        finally:
            owner.active_summaries.remove(cycle)

    def follow(self, call: Node, flow: _Flow, guards: PathGuards) -> None:
        # helper(x) or this.helper(x); not child_process.exec(...) sharing a local name
        name = callee_of(call)
        if _short(name) in _CALLBACKS:
            args_node = call.child_by_field_name("arguments")
            func = call.child_by_field_name("function")
            receiver = func.child_by_field_name("object") if func is not None else None
            args_list = args_node.named_children if args_node is not None else []
            callback = self._function(args_list[0]) if args_list else None
            if callback is not None:
                inner = replace(
                    flow,
                    source=dict(flow.source),
                    shapes=dict(flow.shapes),
                    fields=dict(flow.fields),
                    values=dict(flow.values),
                    safe=None,
                    visiting=set(),
                )
                taint = flow.taint_of(receiver)
                for index, param in enumerate(_params(callback)):
                    for local_name, key in _pattern_names(param):
                        inner.source.pop(local_name, None)
                        inner.shapes.pop(local_name, None)
                        inner.values.pop(local_name, None)
                        for slot in list(inner.fields):
                            if slot.startswith(local_name + "."):
                                inner.fields.pop(slot)
                        if index == 0 and taint:
                            inner.source[local_name], inner.shapes[local_name] = (
                                key or taint[1],
                                taint[0],
                            )
                self.analyze(callback, inner)
            return
        # plain names, this.x, and TypeScript's compiled imports (`(0, tools_1.run)(...)`)
        local = "." not in name or name.startswith("this.") or bool(_TS_IMPORT.match(name))
        owner: _Analyzer = self
        callee = self.functions.get(_short(name)) if local else None
        if callee is None and local and _short(name) in self.package:
            owner, callee = self.package[_short(name)]  # defined in another file
        args = call.child_by_field_name("arguments")
        if callee is None or args is None:
            return
        inner = _Flow(flow.tool, {}, domain=flow.domain, quote_context=flow.quote_context)
        protected_paths: set[str] = set()
        protected_components: set[str] = set()
        for param, arg in zip(_params(callee), args.named_children, strict=False):
            taint = flow.taint_of(arg)
            if taint is None:
                continue
            names = _pattern_names(param)
            if len(names) == 1 and names[0][1] == "":
                name = names[0][0]
                inner.source[name], inner.shapes[name] = taint[1], taint[0]
                inner.copy_fields(name, arg, flow)
                if guards.path_safe(arg, call):
                    protected_paths.add(name)
                if guards.component_safe(arg, call):
                    protected_components.add(name)
            else:  # a destructured object parameter: every field carries the input
                for local, key in names:
                    inner.source[local], inner.shapes[local] = key or taint[1], "whole"
        if inner.source:
            owner.analyze(
                callee,
                inner,
                CheckedPaths(frozenset(protected_paths), frozenset(protected_components)),
            )

    def sink(self, call: Node, flow: _Flow, guards: PathGuards) -> None:
        callee = callee_of(call)
        short = self.shell_aliases.get(_short(callee), _short(callee))
        args = call.child_by_field_name("arguments")
        items = args.named_children if args is not None else []
        first = items[0] if items else None
        taint = flow.taint_of(first)
        tool = flow.tool
        options = " ".join(node_text(a) for a in items[1:])
        is_sql = (
            flow.domain == "sql"
            and short in _SQL
            and first is not None
            and bool(_SQL_WORDS.search(flow.text_of(first)))
        )
        if taint and taint[0] == "mixed":
            if flow.domain == "sql" and short in _SQL and is_sql:
                self.hit(call, "sql_injection", f"tool {tool}: argument {taint[1]} is put into a "
                         f"SQL string run by {callee}()")  # fmt: skip
            elif flow.domain == "shell" and (
                short in _SHELL
                or short in _ALWAYS_SHELL
                or (short in _SPAWN and re.search(r"\bshell\s*:\s*true", options))
            ):
                self.hit(call, "shell_injection", f"tool {tool}: argument {taint[1]} is put into "
                         f"a shell command run by {callee}()")  # fmt: skip
        if (
            flow.domain == "shell"
            and short in _SPAWN
            and first is not None
            and string_value(first) in ("sh", "bash", "/bin/sh", "/bin/bash", "zsh")
            and len(items) > 1
            and items[1].type == "array"
        ):
            elements = items[1].named_children
            if len(elements) > 1 and string_value(elements[0]) == "-c":
                inner = flow.taint_of(elements[1])
                if inner and inner[0] == "mixed":
                    self.hit(call, "shell_injection", f"tool {tool}: argument {inner[1]} is put "
                             f"into a `sh -c` command run by {callee}()")  # fmt: skip
        if flow.domain == "url" and short in _URL and _host_is_tainted(first, flow):
            arg = (taint or ("", "?"))[1]
            self.hit(call, "ssrf", f"tool {tool}: argument {arg} sets the host of a URL requested "
                     f"by {callee}()")  # fmt: skip
        if (
            flow.domain == "path"
            and short in _PATH
            and taint
            and taint[0] == "based"
            and first is not None
            and not guards.path_safe(first, call)
        ):
            detail = (f"tool {tool}: argument {taint[1]} is joined to a base directory and used "
                      f"by {callee}() without a recognized preceding containment "
                      "guard for that value")  # fmt: skip
            self.hit(call, "path_traversal", detail)


def analyze_package(
    files: list[tuple[str, bytes]], *, skipped: list[str] | None = None
) -> list[SourceHit]:
    """Hits across a package's files: handlers in one file, sinks in another."""
    analyzers: list[_Analyzer] = []
    for path, source in files:
        typescript = path.endswith((".ts", ".mts", ".cts"))
        kind = "tsx" if path.endswith(".tsx") else "ts" if typescript else "js"
        analyzers.append(_Analyzer(path, source, parser(kind).parse(source)))
    package: dict[str, tuple[_Analyzer, Node]] = {}
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


def analyze(path: str, source: bytes) -> list[SourceHit]:
    return analyze_package([(path, source)])
