"""Bounded work scheduling shared by the source-flow analyzers.

Limits are per language/package analysis. Cache hits do not consume additional work. Limit
messages flow into SourceTree.skipped, which makes coverage partial and is preserved on replay.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Callable

MAX_CONTEXTS = 4096
MAX_SUMMARIES = 4096
MAX_NODE_VISITS = 1_000_000
MAX_RETURN_DEPTH = 24
MAX_PROPAGATION_PASSES = 32
MAX_LITERAL_CHARS = 65536
MAX_EXPRESSION_DEPTH = 40
MAX_ALIAS_DEPTH = 8


class Analysis:
    def __init__(self) -> None:
        self.pending: deque[Callable[[], None]] = deque()
        self.seen: set[tuple[object, ...]] = set()
        self.limits: dict[str, str] = {}
        self.nodes = 0
        self.summaries = 0
        self.stops = 0

    def limit(self, kind: str, where: str, reason: str) -> None:
        self.stops += 1
        self.limits.setdefault(kind, f"{where}: {reason}; source analysis is incomplete")

    def submit(self, key: tuple[object, ...], where: str, work: Callable[[], None]) -> None:
        if key in self.seen:
            return
        if len(self.seen) >= MAX_CONTEXTS:
            self.limit("contexts", where, f"helper context limit ({MAX_CONTEXTS}) reached")
            return
        self.seen.add(key)
        self.pending.append(work)

    def visit(self, count: int, where: str) -> bool:
        if self.nodes + count > MAX_NODE_VISITS:
            self.limit("nodes", where, f"analysis node budget ({MAX_NODE_VISITS} visits) exhausted")
            return False
        self.nodes += count
        return True

    def summary(self, depth: int, where: str) -> bool:
        if depth >= MAX_RETURN_DEPTH:
            self.limit(
                "return-depth", where, f"helper return depth limit ({MAX_RETURN_DEPTH}) reached"
            )
            return False
        if self.summaries >= MAX_SUMMARIES:
            self.limit("summaries", where, f"return-summary limit ({MAX_SUMMARIES}) reached")
            return False
        self.summaries += 1
        return True

    def text(self, text: str, where: str) -> str:
        if len(text) > MAX_LITERAL_CHARS:
            self.limit(
                "literal-text",
                where,
                f"literal inference limit ({MAX_LITERAL_CHARS} chars) reached",
            )
            return text[:MAX_LITERAL_CHARS]
        return text

    def drain(self) -> None:
        while self.pending:
            self.pending.popleft()()
