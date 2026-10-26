"""Conservative, value-specific path guards that dominate a Python operation.

This recognizes a small set of guards; names, comments and arbitrary validation helpers
are not evidence. Filesystem races, custom path classes and arbitrary side effects remain
outside this syntactic analysis.
"""

from __future__ import annotations

import ast
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import cast

from mcpiranha.source.allowlists import safe_literals


@dataclass(frozen=True)
class CheckedPaths:
    paths: frozenset[str] = frozenset()
    components: frozenset[str] = frozenset()


def _key(node: ast.AST) -> str:
    return ast.dump(node, include_attributes=False)


def _name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return _name(node.value) + "." + node.attr
    return ""


def _pos(node: ast.AST) -> tuple[int, int]:
    if isinstance(node, ast.withitem):
        return _pos(node.context_expr)
    return getattr(node, "lineno", 0), getattr(node, "col_offset", 0)


def _names(node: ast.AST) -> set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


def _exits(body: list[ast.stmt]) -> bool:
    if not body:
        return False
    last = body[-1]
    return isinstance(last, (ast.Return, ast.Raise)) or (
        isinstance(last, ast.If) and _exits(last.body) and _exits(last.orelse)
    )


def _atoms(test: ast.AST, truth: bool) -> Iterator[tuple[ast.AST, bool]]:
    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        yield from _atoms(test.operand, not truth)
    elif isinstance(test, ast.BoolOp):
        if (isinstance(test.op, ast.And) and truth) or (isinstance(test.op, ast.Or) and not truth):
            for part in test.values:
                yield from _atoms(part, truth)
    else:
        yield test, truth


EMPTY_CHECKED = CheckedPaths()
MAX_GUARD_NODES = 2000


class PathGuards:
    def __init__(
        self,
        fn: ast.AST,
        tainted: Callable[[ast.AST], bool],
        inherited: CheckedPaths = EMPTY_CHECKED,
    ) -> None:
        self.fn, self.tainted, self.inherited = fn, tainted, inherited
        self.parents: dict[ast.AST, ast.AST] = {}
        self.nodes: list[ast.AST] = []
        self.limited = False

        stack: list[tuple[ast.AST | None, Iterator[ast.AST]]] = [(None, iter([fn]))]
        while stack:
            parent, children = stack[-1]
            node = next(children, None)
            if node is None:
                stack.pop()
                continue
            if node is not fn and isinstance(
                node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
            ):
                continue
            self.nodes.append(node)
            if len(self.nodes) > MAX_GUARD_NODES:
                self.limited = True
                break
            if parent is not None:
                self.parents[node] = parent
            stack.append((node, ast.iter_child_nodes(node)))

    def _previous(self, at: ast.AST) -> Iterator[ast.stmt]:
        node = at
        while node is not self.fn and node in self.parents:
            parent = self.parents[node]
            for field in ("body", "orelse", "finalbody"):
                statements = getattr(parent, field, None)
                if isinstance(statements, list):
                    block = cast(list[ast.stmt], statements)
                    if isinstance(node, ast.stmt) and node in block:
                        yield from block[: block.index(node)]
            node = parent

    def _guards(self, at: ast.AST) -> Iterator[tuple[ast.AST, bool, ast.AST]]:
        for statement in self._previous(at):
            if isinstance(statement, ast.If):
                if _exits(statement.body):
                    for test, truth in _atoms(statement.test, False):
                        yield test, truth, statement.test
                if _exits(statement.orelse):
                    for test, truth in _atoms(statement.test, True):
                        yield test, truth, statement.test
            elif (
                isinstance(statement, ast.Expr)
                and isinstance(statement.value, ast.Call)
                and isinstance(statement.value.func, ast.Attribute)
                and statement.value.func.attr == "relative_to"
            ):
                yield statement.value, True, statement.value
        node = at
        while node is not self.fn and node in self.parents:
            parent = self.parents[node]
            if isinstance(parent, ast.If) and (node in parent.body or node in parent.orelse):
                truth = node in parent.body
                for test, value in _atoms(parent.test, truth):
                    yield test, value, parent.test
            node = parent

    def allowlisted(self, candidate: ast.AST, at: ast.AST, domain: str) -> bool:
        if self.limited:
            return False
        for test, truth, checked_at in self._guards(at):
            if not isinstance(test, ast.Compare) or len(test.ops) != 1:
                continue
            if not (
                (isinstance(test.ops[0], ast.In) and truth)
                or (isinstance(test.ops[0], ast.NotIn) and not truth)
            ):
                continue
            choices = test.comparators[0]
            if not isinstance(choices, (ast.Set, ast.Tuple, ast.List)):
                continue
            if not all(
                isinstance(v, ast.Constant) and isinstance(v.value, str) for v in choices.elts
            ):
                continue
            values = [str(v.value) for v in choices.elts if isinstance(v, ast.Constant)]
            if (
                safe_literals(values, domain)
                and self._binding(candidate, at) == self._binding(test.left, checked_at)
                and self._unchanged([candidate, test.left], checked_at, at)
            ):
                return True
        return False

    def _writes(self, node: ast.AST) -> set[str]:
        if isinstance(node, ast.Assign):
            return set[str]().union(*(_names(t) for t in node.targets))
        if isinstance(node, (ast.AnnAssign, ast.AugAssign, ast.NamedExpr, ast.For, ast.AsyncFor)):
            return _names(node.target)
        if isinstance(node, ast.withitem):
            return _names(node.optional_vars) if node.optional_vars is not None else set()
        if isinstance(node, ast.ExceptHandler):
            return {node.name} if node.name else set()
        if isinstance(node, ast.Delete):
            return set[str]().union(*(_names(t) for t in node.targets))
        return set()

    def _unchanged(self, expressions: list[ast.AST], after: ast.AST, at: ast.AST) -> bool:
        names = set[str]().union(*(_names(e) for e in expressions))
        return not any(
            names & self._writes(n) for n in self.nodes if _pos(after) < _pos(n) < _pos(at)
        )

    def _assignment(self, name: str, at: ast.AST) -> ast.AST | None:
        assignments = [n for n in self.nodes if name in self._writes(n) and _pos(n) < _pos(at)]
        if not assignments:
            return None
        last = max(assignments, key=_pos)
        if last not in set(self._previous(at)):
            return None
        if isinstance(last, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == name for t in last.targets
        ):
            return last
        if isinstance(last, ast.AnnAssign) and isinstance(last.target, ast.Name):
            return last
        return None

    def _binding(self, node: ast.AST, at: ast.AST, depth: int = 0) -> str:
        if not isinstance(node, ast.Name) or depth > 8:
            versions = (
                sorted(self._binding(ast.Name(id=name), at, depth + 1) for name in _names(node))
                if depth <= 8
                else []
            )
            return _key(node) + repr(versions)
        assignment = self._assignment(node.id, at)
        if assignment is None:
            # Include intervening writes even when their control flow is ambiguous.
            writes = [
                _pos(n) for n in self.nodes if node.id in self._writes(n) and _pos(n) < _pos(at)
            ]
            return f"{node.id}:{max(writes) if writes else 'parameter'}"
        value = getattr(assignment, "value", None)
        if isinstance(value, ast.Name):
            return self._binding(value, assignment, depth + 1)
        return f"{node.id}:{_pos(assignment)}"

    def _root(self, node: ast.AST, at: ast.AST) -> str:
        if (
            isinstance(node, ast.Call)
            and _name(node.func).rsplit(".", 1)[-1] in ("Path", "PurePath", "PosixPath")
            and len(node.args) == 1
        ):
            return self._root(node.args[0], at)
        return self._binding(node, at)

    def _path(self, node: ast.AST, at: ast.AST, depth: int = 0) -> tuple[str, bool] | None:
        if depth > 8:
            return None
        if isinstance(node, ast.Name):
            assignment = self._assignment(node.id, at)
            value = getattr(assignment, "value", None)
            return (
                self._path(value, assignment, depth + 1)
                if value is not None and assignment is not None
                else None
            )
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
            left = self._path(node.left, at, depth + 1)
            return (left[0] if left else self._root(node.left, at)), False
        if isinstance(node, ast.Call):
            name = _name(node.func)
            if isinstance(node.func, ast.Attribute) and node.func.attr == "resolve":
                inner = self._path(node.func.value, at, depth + 1)
                return (inner[0], True) if inner else None
            if name in ("os.path.join", "posixpath.join") and len(node.args) > 1:
                return self._root(node.args[0], at), False
            if name.rsplit(".", 1)[-1] in ("Path", "PurePath", "PosixPath") and node.args:
                if len(node.args) > 1:
                    return self._root(node.args[0], at), False
                return self._path(node.args[0], at, depth + 1)
        return None

    def component_safe(self, candidate: ast.AST, at: ast.AST, *, posix: bool = False) -> bool:
        if self.limited:
            return False
        if any(
            self._binding(candidate, at) == f"{name}:parameter"
            for name in self.inherited.components
        ):
            return True
        rejected: set[str] = set()
        for test, truth, boundary in self._guards(at):
            value: ast.AST | None = None
            token: str | None = None
            if isinstance(test, ast.Compare) and len(test.ops) == 1 and len(test.comparators) == 1:
                left = test.left
                if (
                    isinstance(left, ast.Constant)
                    and isinstance(left.value, str)
                    and (
                        (isinstance(test.ops[0], ast.In) and not truth)
                        or (isinstance(test.ops[0], ast.NotIn) and truth)
                    )
                ):
                    value, token = test.comparators[0], left.value
            elif (
                isinstance(test, ast.Call)
                and isinstance(test.func, ast.Attribute)
                and test.func.attr == "startswith"
                and not truth
                and len(test.args) == 1
                and not test.keywords
                and isinstance(test.args[0], ast.Constant)
                and test.args[0].value == "."
            ):
                value, token = test.func.value, ".."
            if (
                value is not None
                and self._binding(value, boundary) == self._binding(candidate, at)
                and self._unchanged([value], boundary, at)
                and token in ("/", "\\", "..")
            ):
                rejected.add(token)
        return ({"/", ".."} if posix else {"/", "\\", ".."}) <= rejected

    def path_safe(self, candidate: ast.AST, at: ast.AST) -> bool:
        if self.limited:
            return False
        if any(
            self._binding(candidate, at) == f"{name}:parameter" for name in self.inherited.paths
        ):
            return True
        for test, truth, boundary in self._guards(at):
            if (
                not truth
                or not isinstance(test, ast.Call)
                or not isinstance(test.func, ast.Attribute)
            ):
                continue
            if (
                test.func.attr not in ("is_relative_to", "relative_to")
                or len(test.args) != 1
                or test.keywords
            ):
                continue
            checked, root = test.func.value, test.args[0]
            if self._binding(checked, boundary) != self._binding(candidate, at):
                continue
            path = self._path(checked, boundary)
            if (
                path
                and path[1]
                and path[0] == self._root(root, boundary)
                and self._unchanged([checked, root], boundary, at)
            ):
                return True
        # POSIX filename-component rejection also protects a joined path, including helpers.
        return self._safe_join(candidate, at, 0)

    def _safe_join(self, node: ast.AST, at: ast.AST, depth: int) -> bool:
        if depth > 8:
            return False
        if isinstance(node, ast.Name):
            assignment = self._assignment(node.id, at)
            value = getattr(assignment, "value", None)
            # Validate components at the operation, not at assignment (late checks are fine).
            return (
                (self._unchanged([value], assignment, at) and self._safe_join(value, at, depth + 1))
                if value is not None and assignment is not None
                else False
            )
        parts: list[ast.AST] = []
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
            parts = [node.left, node.right]
        elif isinstance(node, ast.Call):
            name = _name(node.func)
            if (
                isinstance(node.func, ast.Attribute)
                and node.func.attr == "resolve"
                and not node.args
                and not node.keywords
            ):
                return self._safe_join(node.func.value, at, depth + 1)
            if name in ("os.path.join", "posixpath.join", "Path", "pathlib.Path"):
                parts = list(node.args)
        return (
            len(parts) > 1
            and (not self.tainted(parts[0]) or self._safe_join(parts[0], at, depth + 1))
            and all(
                not self.tainted(p)
                or self.allowlisted(p, at=at, domain="path")
                or self.component_safe(
                    p, at, posix=isinstance(node, ast.Call) and _name(node.func) == "posixpath.join"
                )
                for p in parts[1:]
            )
        )
