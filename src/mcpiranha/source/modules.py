"""Static local import bindings. No imports, module evaluation or filesystem access.

Resolution uses the files supplied by source collection. Unknown external packages are left
alone; missing/ambiguous local exports and bounded re-export cycles produce coverage reasons.
"""

from __future__ import annotations

import ast
import posixpath
from dataclasses import dataclass, field

from mcpiranha.source.javascript import Node, callee_of, node_text, string_value, walk

MAX_LINK_DEPTH = 64
_EXTENSIONS = (".py", ".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".tsx", ".jsx")


@dataclass(frozen=True)
class Ref:
    module: str | None
    symbol: str = ""
    relative: int = 0


@dataclass
class Module:
    path: str
    definitions: set[str]
    python: bool = False
    bindings: dict[str, Ref] = field(default_factory=dict[str, Ref])
    exports: dict[str, Ref] = field(default_factory=dict[str, Ref])
    stars: list[Ref] = field(default_factory=list[Ref])
    constants: set[str] = field(default_factory=set[str])


@dataclass(frozen=True)
class Resolution:
    target: tuple[str, str] | None = None
    reason: str = ""
    known_value: bool = False


def _stem(path: str) -> str:
    for extension in _EXTENSIONS:
        if path.endswith(extension):
            return path[: -len(extension)]
    return path


class Graph:
    def __init__(self, modules: list[Module]) -> None:
        self.modules = {module.path: module for module in modules}
        self.paths: dict[str, list[str]] = {}
        self.cache: dict[tuple[str, str], Resolution] = {}
        for module in modules:
            stem = _stem(posixpath.normpath(module.path))
            self.paths.setdefault(stem, []).append(module.path)
            if stem.rsplit("/", 1)[-1] in ("index", "__init__"):
                self.paths.setdefault(posixpath.dirname(stem), []).append(module.path)

    def local_bindings(self, path: str) -> set[str]:
        return {
            name
            for name, ref in self.modules[path].bindings.items()
            if ref.module is not None
            and (ref.relative or self._module(path, ref.module, ref.relative)[0])
        }

    def resolve(self, path: str, name: str) -> Resolution:
        key = (path, name)
        if key not in self.cache:
            self.cache[key] = self._name(path, name, False, frozenset())
        return self.cache[key]

    def _module(self, owner: str, spec: str, relative: int) -> tuple[list[str], str]:
        if relative:
            base = posixpath.dirname(owner)
            for _ in range(relative - 1):
                base = posixpath.dirname(base)
            key = posixpath.normpath(posixpath.join(base, spec))
        else:
            key = posixpath.normpath(spec)
        key = _stem(key).removeprefix("./")
        if key == ".":
            key = ""
        matches = self.paths.get(key, [])
        if not matches and not relative and self.modules[owner].python:
            matches = [p for k, paths in self.paths.items() if k.endswith("/" + key) for p in paths]
        return sorted(set(matches)), key

    def _ref(
        self, owner: str, ref: Ref, rest: str, seen: frozenset[tuple[str, str, bool]]
    ) -> Resolution:
        name = ".".join(part for part in (ref.symbol, rest) if part)
        if ref.module is None:
            return self._name(owner, name, False, seen)
        parts = name.split(".") if name else []
        # A namespace can traverse submodules (pkg.commands.run) before an exported symbol.
        for count in range(len(parts), -1, -1):
            spec = "/".join(p for p in (ref.module, *parts[:count]) if p)
            matches, key = self._module(owner, spec, ref.relative)
            if len(matches) > 1:
                return Resolution(reason=f"ambiguous local module {key}")
            if matches:
                symbol = ".".join(parts[count:]) or "default"
                result = self._name(matches[0], symbol, True, seen)
                return (
                    result
                    if result.target or result.reason or result.known_value
                    else Resolution(reason=f"unresolved local export {symbol} in {matches[0]}")
                )
        if ref.relative:
            return Resolution(reason=f"unresolved local import {ref.module or '.'}")
        return Resolution()  # No source for an external dependency; not a local call.

    def _name(
        self, path: str, name: str, exported: bool, seen: frozenset[tuple[str, str, bool]]
    ) -> Resolution:
        key = (path, name, exported)
        if key in seen or len(seen) >= MAX_LINK_DEPTH:
            return Resolution(reason="local import/re-export cycle or resolution depth limit")
        seen = seen | {key}
        module = self.modules[path]
        if exported and not module.python:
            first, _, rest = name.partition(".")
            if first in module.exports:
                return self._ref(path, module.exports[first], rest, seen)
            if name == "default":
                return Resolution()  # ESM export-star excludes the default export.
            results = [self._ref(path, ref, name, seen) for ref in module.stars]
            targets = {r.target for r in results if r.target}
            if len(targets) > 1:
                return Resolution(reason=f"ambiguous local export {name} in {path}")
            return next(
                (r for r in results if r.target or r.known_value),
                next(
                    (
                        r
                        for r in results
                        if r.reason and not r.reason.startswith("unresolved local export")
                    ),
                    Resolution(),
                ),
            )
        first, _, rest = name.partition(".")
        if first in module.bindings:
            return self._ref(path, module.bindings[first], rest, seen)
        if name in module.definitions:
            return Resolution((path, name))
        if first in module.constants and rest in {
            "includes",
            "indexOf",
            "startsWith",
            "endsWith",
            "join",
            "split",
            "trim",
            "startswith",
            "endswith",
            "strip",
            "lower",
            "upper",
            "get",
            "keys",
            "values",
        }:
            return Resolution(known_value=True)
        results = [self._ref(path, ref, name, seen) for ref in module.stars]
        targets = {r.target for r in results if r.target}
        if len(targets) > 1:
            return Resolution(reason=f"ambiguous local import {name} in {path}")
        return next(
            (r for r in results if r.target or r.known_value),
            next(
                (
                    r
                    for r in results
                    if r.reason and not r.reason.startswith("unresolved local export")
                ),
                Resolution(),
            ),
        )


def python_module(path: str, tree: ast.Module, definitions: set[str]) -> Module:
    module = Module(path, definitions, python=True)
    # Only module-level bindings: imports local to a function must not rewrite other scopes.
    for node in tree.body:
        if (
            isinstance(node, ast.Assign)
            and isinstance(node.value, (ast.Constant, ast.List, ast.Tuple, ast.Dict, ast.Set))
            and not any(isinstance(n, (ast.Call, ast.Lambda)) for n in ast.walk(node.value))
        ):
            module.constants.update(t.id for t in node.targets if isinstance(t, ast.Name))
        if isinstance(node, ast.Import):
            for alias in node.names:
                spec = alias.name if alias.asname else alias.name.split(".")[0]
                module.bindings[alias.asname or spec] = Ref(spec.replace(".", "/"))
        elif isinstance(node, ast.ImportFrom):
            spec = (node.module or "").replace(".", "/")
            for alias in node.names:
                ref = Ref(spec, "" if alias.name == "*" else alias.name, node.level)
                if alias.name == "*":
                    module.stars.append(ref)
                else:
                    module.bindings[alias.asname or alias.name] = ref
    return module


def javascript_module(path: str, root: Node, definitions: set[str]) -> Module:
    module = Module(path, definitions)

    def imported(spec: str, symbol: str = "") -> Ref:
        return Ref(spec.removeprefix("./"), symbol, int(spec.startswith(".")))

    for node in root.named_children:
        source = string_value(node.child_by_field_name("source"))
        if node.type == "import_statement" and source:
            clause = next((c for c in node.named_children if c.type == "import_clause"), None)
            if clause is None:
                continue
            for child in clause.named_children:
                if child.type == "identifier":
                    module.bindings[node_text(child)] = imported(source, "default")
                elif child.type == "namespace_import":
                    module.bindings[node_text(child.named_children[-1])] = imported(source)
                elif child.type == "named_imports":
                    for item in child.named_children:
                        name = node_text(item.child_by_field_name("name"))
                        alias = node_text(item.child_by_field_name("alias")) or name
                        module.bindings[alias] = imported(source, name)
        elif node.type == "export_statement":
            declaration = node.child_by_field_name("declaration")
            clause = next((c for c in node.named_children if c.type == "export_clause"), None)
            if clause is not None:
                for item in clause.named_children:
                    name = node_text(item.child_by_field_name("name"))
                    alias = node_text(item.child_by_field_name("alias")) or name
                    module.exports[alias] = imported(source, name) if source else Ref(None, name)
            elif declaration is not None:
                names = [node_text(declaration.child_by_field_name("name"))]
                if declaration.type in ("lexical_declaration", "variable_declaration"):
                    names = [
                        node_text(c.child_by_field_name("name"))
                        for c in declaration.named_children
                        if c.type == "variable_declarator"
                    ]
                default = any(c.type == "default" for c in node.children)
                for name in names:
                    if name or default:
                        module.exports["default" if default else name] = Ref(
                            None, name or "default"
                        )
            elif source:
                module.stars.append(imported(source))
            elif value := node.child_by_field_name("value"):
                module.exports["default"] = Ref(
                    None,
                    "default"
                    if value.type in ("arrow_function", "function_expression")
                    else node_text(value),
                )
        # Top-level CommonJS requires (also TypeScript's emitted require bindings).
        declaration = node.child_by_field_name("declaration")
        requires = node.type in ("lexical_declaration", "variable_declaration") or (
            node.type == "export_statement"
            and declaration is not None
            and declaration.type in ("lexical_declaration", "variable_declaration")
        )
        for child in walk(node) if requires else ():
            if child.type != "variable_declarator":
                continue
            value = child.child_by_field_name("value")
            target = child.child_by_field_name("name")
            if value is None or target is None:
                continue
            if (
                target.type == "identifier"
                and value.type in ("array", "object", "string", "number", "true", "false", "null")
                and not any(
                    n.type
                    in (
                        "call_expression",
                        "arrow_function",
                        "function_expression",
                        "method_definition",
                    )
                    for n in walk(value)
                )
            ):
                module.constants.add(node_text(target))
            symbol = ""
            if value.type == "member_expression":
                symbol = node_text(value.child_by_field_name("property"))
                value = value.child_by_field_name("object")
            if value is None or value.type != "call_expression":
                continue
            if callee_of(value) in ("__importStar", "__importDefault"):
                wrapped_args = value.child_by_field_name("arguments")
                value = (
                    wrapped_args.named_children[0]
                    if wrapped_args and wrapped_args.named_children
                    else None
                )
            if value is None or value.type != "call_expression":
                continue
            args = value.child_by_field_name("arguments")
            if callee_of(value) != "require" or args is None or not args.named_children:
                continue
            spec = string_value(args.named_children[0])
            if not spec:
                continue
            if target.type == "identifier":
                module.bindings[node_text(target)] = imported(spec, symbol)
            elif target.type == "object_pattern":
                for item in target.named_children:
                    if item.type == "shorthand_property_identifier_pattern":
                        name = node_text(item)
                        module.bindings[name] = imported(spec, name)
                    elif item.type == "pair_pattern":
                        module.bindings[node_text(item.child_by_field_name("value"))] = imported(
                            spec, node_text(item.child_by_field_name("key"))
                        )
        if node.type == "expression_statement" and node.named_children:
            assignment = node.named_children[0]
            if assignment.type != "assignment_expression":
                continue
            left = node_text(assignment.child_by_field_name("left"))
            right = assignment.child_by_field_name("right")
            if right is None:
                continue
            if left.startswith(("exports.", "module.exports.")):
                module.exports[left.rsplit(".", 1)[-1]] = Ref(
                    None,
                    left
                    if right.type in ("arrow_function", "function_expression")
                    else node_text(right),
                )
            elif left == "module.exports":
                if right.type == "object":
                    for item in right.named_children:
                        if item.type == "shorthand_property_identifier":
                            module.exports[node_text(item)] = Ref(None, node_text(item))
                        elif item.type == "pair":
                            module.exports[node_text(item.child_by_field_name("key"))] = Ref(
                                None, node_text(item.child_by_field_name("value"))
                            )
                else:
                    module.exports["default"] = Ref(
                        None,
                        left
                        if right.type in ("arrow_function", "function_expression")
                        else node_text(right),
                    )
    return module
