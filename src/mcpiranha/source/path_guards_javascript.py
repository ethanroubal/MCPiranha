"""Value-specific, preceding JavaScript path guards; no function-wide text matching."""

from __future__ import annotations

from collections.abc import Callable, Iterator

from mcpiranha.source.allowlists import safe_literals
from mcpiranha.source.javascript import Node, callee_of, node_text, string_value, walk
from mcpiranha.source.path_guards_python import EMPTY_CHECKED, CheckedPaths

MAX_GUARD_NODES = 2000
_FUNCTIONS = frozenset(
    {
        "arrow_function",
        "function_expression",
        "function_declaration",
        "function",
        "method_definition",
        "class_declaration",
    }
)


def _unwrap(node: Node) -> Node:
    while node.type in ("parenthesized_expression", "await_expression", "as_expression"):
        node = node.named_children[0]
    return node


def _key(node: Node) -> str:
    return node_text(_unwrap(node))


def _args(node: Node) -> list[Node]:
    args = node.child_by_field_name("arguments")
    return list(args.named_children) if args is not None else []


def _exits(node: Node | None) -> bool:
    if node is None:
        return False
    if node.type in ("return_statement", "throw_statement"):
        return True
    if node.type in ("statement_block", "else_clause"):
        children = [n for n in node.named_children if n.type != "comment"]
        return bool(children) and _exits(children[-1])
    return (
        node.type == "if_statement"
        and _exits(node.child_by_field_name("consequence"))
        and _exits(node.child_by_field_name("alternative"))
    )


def _atoms(node: Node, truth: bool) -> Iterator[tuple[Node, bool]]:
    node = _unwrap(node)
    if node.type == "unary_expression" and node_text(node.child_by_field_name("operator")) == "!":
        argument = node.child_by_field_name("argument")
        if argument is not None:
            yield from _atoms(argument, not truth)
    elif node.type == "binary_expression" and node_text(node.child_by_field_name("operator")) in (
        "&&",
        "||",
    ):
        operator = node_text(node.child_by_field_name("operator"))
        if (operator == "&&" and truth) or (operator == "||" and not truth):
            for field in ("left", "right"):
                part = node.child_by_field_name(field)
                if part is not None:
                    yield from _atoms(part, truth)
    else:
        yield node, truth


class PathGuards:
    def __init__(
        self, fn: Node, tainted: Callable[[Node], bool], inherited: CheckedPaths = EMPTY_CHECKED
    ) -> None:
        self.fn, self.tainted, self.inherited = fn, tainted, inherited
        self.nodes: list[Node] = []
        self.limited = False

        def children(node: Node) -> Iterator[Node]:
            for index in range(node.named_child_count):
                child = node.named_child(index)
                if child is not None:
                    yield child

        stack = [iter([fn])]
        while stack:
            node = next(stack[-1], None)
            if node is None:
                stack.pop()
                continue
            if node != fn and node.type in _FUNCTIONS:
                continue
            self.nodes.append(node)
            if len(self.nodes) > MAX_GUARD_NODES:
                self.limited = True
                break
            stack.append(children(node))

    def _previous(self, at: Node) -> Iterator[Node]:
        node = at
        while node != self.fn and node.parent is not None:
            parent = node.parent
            if parent.type in ("statement_block", "program"):
                children = list(parent.named_children)
                yield from children[: children.index(node)]
            node = parent

    def _guards(self, at: Node) -> Iterator[tuple[Node, bool, Node]]:
        for statement in self._previous(at):
            if statement.type != "if_statement":
                continue
            condition = statement.child_by_field_name("condition")
            if condition is None:
                continue
            if _exits(statement.child_by_field_name("consequence")):
                for atom, truth in _atoms(condition, False):
                    yield atom, truth, condition
            if _exits(statement.child_by_field_name("alternative")):
                for atom, truth in _atoms(condition, True):
                    yield atom, truth, condition
        node = at
        while node != self.fn and node.parent is not None:
            parent = node.parent
            if parent.type == "if_statement":
                condition = parent.child_by_field_name("condition")
                if condition is not None and node != condition:
                    truth = node == parent.child_by_field_name("consequence")
                    for atom, value in _atoms(condition, truth):
                        yield atom, value, condition
            node = parent

    def allowlisted(self, candidate: Node, at: Node, domain: str) -> bool:
        if self.limited:
            return False
        for test, truth, checked_at in self._guards(at):
            if not truth or test.type != "call_expression":
                continue
            func = test.child_by_field_name("function")
            args = test.child_by_field_name("arguments")
            if func is None or func.type != "member_expression" or args is None:
                continue
            receiver = func.child_by_field_name("object")
            prop = func.child_by_field_name("property")
            items = args.named_children
            if (
                node_text(prop) != "includes"
                or receiver is None
                or receiver.type != "array"
                or len(items) != 1
            ):
                continue
            values = [string_value(v) for v in receiver.named_children]
            if any(v is None for v in values):
                continue
            if (
                safe_literals([v for v in values if v is not None], domain)
                and self._binding(candidate, at) == self._binding(items[0], checked_at)
                and self._unchanged([candidate, items[0]], checked_at, at)
            ):
                return True
        return False

    def _writes(self, node: Node) -> set[str]:
        target = None
        if node.type == "variable_declarator":
            target = node.child_by_field_name("name")
        elif node.type in ("assignment_expression", "augmented_assignment_expression"):
            target = node.child_by_field_name("left")
        elif node.type == "update_expression":
            target = node.child_by_field_name("argument")
        return (
            {
                node_text(n)
                for n in walk(target)
                if n.type in ("identifier", "this", "shorthand_property_identifier_pattern")
            }
            if target is not None
            else set()
        )

    def _unchanged(self, expressions: list[Node], after: Node, at: Node) -> bool:
        names = {
            node_text(n)
            for expression in expressions
            for n in walk(expression)
            if n.type in ("identifier", "this")
        }
        return not any(
            names & self._writes(n)
            for n in self.nodes
            if after.start_byte < n.start_byte < at.start_byte
        )

    def _assignment(self, name: str, at: Node) -> Node | None:
        writes = [n for n in self.nodes if name in self._writes(n) and n.start_byte < at.start_byte]
        if not writes:
            return None
        last = max(writes, key=lambda n: n.start_byte)
        statement = last.parent
        previous = list(self._previous(at))
        if statement not in previous:
            return None
        field = "name" if last.type == "variable_declarator" else "left"
        target = last.child_by_field_name(field)
        return last if target is not None and target.type == "identifier" else None

    def _value(self, assignment: Node) -> Node | None:
        return assignment.child_by_field_name(
            "value" if assignment.type == "variable_declarator" else "right"
        )

    def _binding(self, node: Node, at: Node, depth: int = 0) -> str:
        node = _unwrap(node)
        if node.type not in ("identifier", "this") or depth > 8:
            versions = (
                sorted(
                    self._binding(n, at, depth + 1)
                    for n in walk(node)
                    if n.type in ("identifier", "this")
                )
                if depth <= 8
                else []
            )
            return _key(node) + repr(versions)
        name = node_text(node)
        assignment = self._assignment(name, at)
        if assignment is None:
            writes = [
                n.start_byte
                for n in self.nodes
                if name in self._writes(n) and n.start_byte < at.start_byte
            ]
            return f"{name}:{max(writes) if writes else 'parameter'}"
        value = self._value(assignment)
        if value is not None and value.type == "identifier":
            return self._binding(value, assignment, depth + 1)
        return f"{name}:{assignment.start_byte}"

    def _root(self, node: Node, at: Node, depth: int = 0) -> str:
        node = _unwrap(node)
        if depth < 8:
            if node.type == "identifier":
                assignment = self._assignment(node_text(node), at)
                value = self._value(assignment) if assignment is not None else None
                if (
                    assignment is not None
                    and value is not None
                    and value.type == "call_expression"
                    and callee_of(value) == "path.resolve"
                    and len(_args(value)) == 1
                ):
                    return self._root(_args(value)[0], assignment, depth + 1)
            if node.type == "call_expression" and callee_of(node) == "path.resolve":
                args = _args(node)
                if len(args) == 1:
                    return self._root(args[0], at, depth + 1)
        return self._binding(node, at)

    def _path(self, node: Node, at: Node, depth: int = 0) -> tuple[str, bool] | None:
        node = _unwrap(node)
        if depth > 8:
            return None
        if node.type == "identifier":
            assignment = self._assignment(node_text(node), at)
            value = self._value(assignment) if assignment is not None else None
            return (
                self._path(value, assignment, depth + 1)
                if value is not None and assignment is not None
                else None
            )
        if node.type == "call_expression" and callee_of(node) in ("path.resolve", "path.join"):
            args = _args(node)
            if args:
                return self._root(args[0], at), callee_of(node) == "path.resolve"
        return None

    def component_safe(self, candidate: Node, at: Node) -> bool:
        if self.limited:
            return False
        if any(
            self._binding(candidate, at) == f"{name}:parameter"
            for name in self.inherited.components
        ):
            return True
        rejected: set[str] = set()
        for test, truth, boundary in self._guards(at):
            if truth or test.type != "call_expression":
                continue
            func = test.child_by_field_name("function")
            if func is None or func.type != "member_expression":
                continue
            value = func.child_by_field_name("object")
            prop = node_text(func.child_by_field_name("property"))
            args = _args(test)
            if len(args) != 1:
                continue
            token = string_value(args[0])
            if token == "\\\\":  # one backslash in a JS literal, spelled with two escapes
                token = "\\"
            if value is None or self._binding(value, boundary) != self._binding(candidate, at):
                continue
            if not self._unchanged([value], boundary, at):
                continue
            if prop == "includes" and token in ("/", "\\", ".."):
                rejected.add(token)
            if prop == "startsWith" and token == ".":
                rejected.add("..")
        return {"/", "\\", ".."} <= rejected

    def path_safe(self, candidate: Node, at: Node) -> bool:
        if self.limited:
            return False
        if any(
            self._binding(candidate, at) == f"{name}:parameter" for name in self.inherited.paths
        ):
            return True
        for test, truth, boundary in self._guards(at):
            if not truth or test.type != "call_expression":
                continue
            func = test.child_by_field_name("function")
            if func is None or func.type != "member_expression":
                continue
            value = func.child_by_field_name("object")
            prop = node_text(func.child_by_field_name("property"))
            args = _args(test)
            if value is None or prop != "startsWith" or len(args) != 1:
                continue
            prefix = _unwrap(args[0])
            if (
                prefix.type != "binary_expression"
                or node_text(prefix.child_by_field_name("operator")) != "+"
            ):
                continue
            base, separator = (
                prefix.child_by_field_name("left"),
                prefix.child_by_field_name("right"),
            )
            if base is None or separator is None or _key(separator) != "path.sep":
                continue
            path, root = self._path(value, boundary), self._path(base, boundary)
            if (
                path
                and root
                and path[1]
                and root[1]
                and path[0] == root[0]
                and self._binding(value, boundary) == self._binding(candidate, at)
                and self._unchanged([value, base], boundary, at)
            ):
                return True
        return self._safe_join(candidate, at, 0)

    def _safe_join(self, node: Node, at: Node, depth: int) -> bool:
        node = _unwrap(node)
        if depth > 8:
            return False
        if node.type == "identifier":
            assignment = self._assignment(node_text(node), at)
            value = self._value(assignment) if assignment is not None else None
            return (
                (self._unchanged([value], assignment, at) and self._safe_join(value, at, depth + 1))
                if value is not None and assignment is not None
                else False
            )
        args = _args(node)
        return (
            node.type == "call_expression"
            and callee_of(node) in ("path.join", "path.resolve")
            and len(args) > 1
            and not self.tainted(args[0])
            and all(not self.tainted(p) or self.component_safe(p, at) for p in args[1:])
        )
