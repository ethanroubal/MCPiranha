"""JavaScript / TypeScript source analysis with tree-sitter (the code is parsed, never run).

Works on bundled and minified output too, which is what most npm MCP servers ship.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from functools import cache
from threading import local

import tree_sitter
import tree_sitter_javascript
import tree_sitter_typescript

from mcpiranha.core.models import SourceHit, SourceHitKind
from mcpiranha.source import patterns

Node = tree_sitter.Node

_DECODE = re.compile(r"\batob\s*\(|['\"](base64|hex)['\"]|\binflate|\bgunzip|\bdecompress"
                     r"|\bfetch\s*\(|\baxios\b|\bhttps?\.get\s*\(|\.text\s*\(\s*\)")  # fmt: skip
_RUNNERS = frozenset({"eval", "Function", "runInThisContext", "runInNewContext", "runInContext",
                      "compileFunction"})  # fmt: skip
_ENUMERATE = frozenset({"Object.entries", "Object.keys", "Object.values"})
_BARE_SHELL = re.compile(
    r"""\(\s*['"`](/bin/)?(ba|z)?sh|cmd(\.exe)?|powershell(\.exe)?['"`]\s*[,)]"""
)
_SOCKET = re.compile(r"\bnew\s+(net\.)?Socket\s*\(|\bnet\.(connect|createConnection)\s*\(")
_HOME_OR_ROOT = re.compile(
    r"""\(\s*(os\.homedir\(\)|homedir\(\)|process\.env\.HOME|['"`]/['"`]|['"`]~['"`])\s*[,)]"""
)
_EXECUTED_NAME = re.compile(
    r"\b(?:exec|execSync|spawn|spawnSync|execFile|execFileSync|execa|execaSync)\s*\(\s*"
    r"([A-Za-z_$][\w$]*)\s*[,)]"
)
_OBFUSCATOR = re.compile(r"\b_0x[0-9a-f]{4,6}\b")
OBFUSCATED_NAMES = 50
_WRITTEN_NAME = re.compile(
    r"\b(?:writeFile|writeFileSync|appendFile|appendFileSync|createWriteStream|copyFile"
    r"|copyFileSync|outputFile|outputFileSync|writeJson|writeJsonSync)\s*\(\s*([A-Za-z_$][\w$]*)\s*[,)]"
)


class _Parsers(local):
    def __init__(self) -> None:
        self.by_kind: dict[str, tree_sitter.Parser] = {}


_parsers = _Parsers()


@cache
def _language(kind: str) -> tree_sitter.Language:
    language = {
        "js": tree_sitter_javascript.language,
        "ts": tree_sitter_typescript.language_typescript,
        "tsx": tree_sitter_typescript.language_tsx,
    }[kind]()
    return tree_sitter.Language(language)


def parser(kind: str) -> tree_sitter.Parser:
    # Parser instances own mutable native state; collection runs in several worker threads.
    if kind not in _parsers.by_kind:
        _parsers.by_kind[kind] = tree_sitter.Parser(_language(kind))
    return _parsers.by_kind[kind]


def walk(node: Node) -> Iterator[Node]:
    cursor = node.walk()
    while True:
        assert cursor.node is not None
        yield cursor.node
        if cursor.goto_first_child() or cursor.goto_next_sibling():
            continue
        while True:
            if not cursor.goto_parent():
                return
            if cursor.goto_next_sibling():
                break


def node_text(node: Node | None) -> str:
    return node.text.decode("utf-8", "replace") if node is not None and node.text else ""


def string_value(node: Node | None) -> str | None:
    """The value of a string literal (or a template without substitutions)."""
    if node is None or node.type not in ("string", "template_string"):
        return None
    if any(c.type == "template_substitution" for c in node.children):
        return None
    return node_text(node)[1:-1]


def _key(node: Node | None) -> str:
    if node is None:
        return ""
    value = string_value(node)
    return value if value is not None else node_text(node)


def callee_of(call: Node) -> str:
    func = call.child_by_field_name("function") or call.child_by_field_name("constructor")
    text = node_text(func)
    if text.startswith("(0,") and text.endswith(")"):  # TypeScript output: (0, mod_1.fn)(...)
        text = text[3:-1].strip()
    return text if len(text) < 80 else ""


def _statement(node: Node) -> Node:
    """The enclosing statement, to see what an expression is part of."""
    current = node
    while current.parent is not None and not current.type.endswith(("statement", "declaration")):
        current = current.parent
    return current


class _Analyzer:
    def __init__(self, path: str, source: bytes) -> None:
        text = source.decode("utf-8", "replace")
        self.path, self.lines = path, text.splitlines()
        self.hits: list[SourceHit] = []
        self.shells: list[Node] = []
        # names a write call targets: fs.writeFileSync(CONFIG, ...) after const CONFIG = "..."
        self.written = {m.group(1) for m in _WRITTEN_NAME.finditer(text)}
        self.executed = {m.group(1) for m in _EXECUTED_NAME.finditer(text)}
        self.sets_approval = bool(patterns.APPROVE_SETTING.search(text))

    def hit(self, node: Node, kind: SourceHitKind, detail: str) -> None:
        row, column = node.start_point
        line = self.lines[row] if row < len(self.lines) else ""
        if len(line) > 200:  # minified: show the code around the hit, not the whole bundle
            line = line[max(0, column - 80) : column + 120]
        self.hits.append(SourceHit(kind=kind, file=self.path, line=row + 1, code=line.strip(),
                                   detail=detail))  # fmt: skip

    def visit(self, node: Node) -> None:
        kind = node.type
        if kind == "pair":
            key, value = node.child_by_field_name("key"), node.child_by_field_name("value")
            text = string_value(value)
            if text is not None and patterns.recipient(_key(key), text):
                self.hit(node, "hardcoded_recipient", f"{_key(key)}: {text}")
        elif kind == "assignment_expression":
            left, right = node.child_by_field_name("left"), node.child_by_field_name("right")
            prop = left.child_by_field_name("property") if left is not None else None
            if left is not None and left.type == "subscript_expression":
                prop = left.child_by_field_name("index")
            text = string_value(right)
            if prop is not None and text is not None and patterns.recipient(_key(prop), text):
                self.hit(node, "hardcoded_recipient", f"{_key(prop)} = {text}")
        elif kind in ("call_expression", "new_expression"):
            self.call(node)
        elif kind == "for_in_statement":
            right = node.child_by_field_name("right")
            if node_text(right) == "process.env":
                self.env_enumeration(node, "loops over process.env")
        elif kind in ("string", "template_string"):
            self.string(node)

    def call(self, node: Node) -> None:
        callee = callee_of(node)
        short = callee.rsplit(".", 1)[-1]
        args = node.child_by_field_name("arguments")
        arg_text = node_text(args)
        if callee == "JSON.stringify" and re.match(r"\(\s*process\.env\s*[,)]", arg_text):
            self.hit(node, "env_harvest", "serializes the whole environment (process.env)")
        elif callee in _ENUMERATE and re.match(r"\(\s*process\.env\s*\)", arg_text):
            self.env_enumeration(node, f"{callee}(process.env)")
        elif short in _RUNNERS and args is not None and _DECODE.search(arg_text[:2000]):
            self.hit(node, "dynamic_code", f"{short}() of decoded or downloaded code")
        elif short in ("spawn", "exec", "execFile", "fork") and _BARE_SHELL.match(arg_text):
            self.shells.append(node)  # judged at the end: a shell plus a socket
        elif short in ("rmSync", "rm", "rmdirSync", "rmdir", "remove", "removeSync",
                       "emptyDir", "emptyDirSync") and _HOME_OR_ROOT.match(arg_text):  # fmt: skip
            self.hit(node, "destructive", f"{callee}() of the home directory or /")

    def in_call(self, node: Node, calls: frozenset[str]) -> bool:
        """The literal is an argument (a few levels down) of one of `calls`, or bound to a name
        that's passed to one."""
        current = node
        for _ in range(5):
            parent = current.parent
            if parent is None:
                return False
            current = parent
            if current.type in ("call_expression", "new_expression"):
                if callee_of(current).rsplit(".", 1)[-1] in calls:
                    return True
            elif current.type == "variable_declarator":
                return node_text(current.child_by_field_name("name")) in self.executed
        return False

    def in_write(self, node: Node) -> bool:
        """The literal is part of a call that writes a file, or bound to a name that one does."""
        current = node
        for _ in range(7):
            parent = current.parent
            if parent is None:
                return False
            current = parent
            if current.type == "call_expression":
                if callee_of(current).rsplit(".", 1)[-1] in patterns.WRITE_CALLS:
                    return True
            elif current.type == "variable_declarator":
                name = node_text(current.child_by_field_name("name"))
                return name in self.written
        return False

    def env_enumeration(self, node: Node, how: str) -> None:
        context = node_text(_statement(node))[:1000]
        # Values, not just names: listing which TOKEN variables exist is a diagnostic.
        if not ("Object.entries" in how or "Object.values" in how
                or re.search(r"process\.env\s*\[", context)):  # fmt: skip
            return
        words = sorted({m.group(0).lower() for m in patterns.SECRET_WORDS.finditer(context)})
        if words:
            self.hit(node, "env_harvest",
                     f"{how}, keeping variables named like {', '.join(words)}")  # fmt: skip

    def string(self, node: Node) -> None:
        # Template literals: judge the literal parts (`https://webhook.site/${id}` still counts).
        text = node_text(node)[1:-1]
        for kind, detail in patterns.string_hits(text):
            if kind not in patterns.NEEDS_EXEC or self.in_call(node, patterns.EXEC_CALLS):
                self.hit(node, kind, detail)
        if (found := patterns.written_path_kind(text)) and self.in_write(node):
            kind, detail = found
            if kind == "client_config" and self.sets_approval:
                detail += ", in code that sets auto-approve"
            self.hit(node, kind, detail)

    def finish(self, source: str) -> None:
        if self.shells and _SOCKET.search(source):
            self.hit(self.shells[0], "reverse_shell", "spawns a shell in a file that opens sockets")
        if len(_OBFUSCATOR.findall(source[:2_000_000])) >= OBFUSCATED_NAMES:
            detail = "javascript-obfuscator output (_0x... names)"
            self.hits.append(SourceHit(kind="obfuscated", file=self.path, line=1, code="",
                                       detail=detail))  # fmt: skip


def analyze(path: str, source: bytes, *, skipped: list[str] | None = None) -> list[SourceHit]:
    kind = (
        "tsx" if path.endswith(".tsx") else "ts" if path.endswith((".ts", ".mts", ".cts")) else "js"
    )
    tree = parser(kind).parse(source)
    if tree.root_node.has_error and skipped is not None:
        skipped.append(f"{path}: JavaScript/TypeScript parse errors; partial syntax tree analyzed")
    analyzer = _Analyzer(path, source)
    for node in walk(tree.root_node):
        analyzer.visit(node)
    analyzer.finish(source.decode("utf-8", "replace"))
    return analyzer.hits
