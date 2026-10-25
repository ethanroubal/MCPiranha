"""Opt-in checks against real vulnerable releases and their published fixes; no execution."""

import os

import anyio
import pytest
from calibration.cve_recall import CASES

from mcpiranha.core.coverage import summarize
from mcpiranha.core.models import Launch, Origin, ServerSnapshot
from mcpiranha.core.pipeline import scan
from mcpiranha.rules import load_rules
from mcpiranha.source import collect
from mcpiranha.supply import enrich


@pytest.mark.skipif(
    os.environ.get("MCPIRANHA_QUALITY_REGISTRIES") != "1",
    reason="Set MCPIRANHA_QUALITY_REGISTRIES=1 for public registry downloads (no execution)",
)
@pytest.mark.parametrize("advisory,expected,vulnerable,fixed", CASES, ids=[c[0] for c in CASES])
def test_vulnerable_release_and_fixed_twin(
    advisory: str, expected: str, vulnerable: str, fixed: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("MCPIRANHA_OFFLINE", raising=False)

    def make_snapshot(spec: str) -> ServerSnapshot:
        return ServerSnapshot(
            id=f"quality:{spec}",
            name=spec,
            origin=Origin(kind="config", client="quality", ref=spec),
            launch=Launch(transport="stdio", command="npx", args=["-y", spec]),
            tools_listed=False,
        )

    async def fetch() -> list[ServerSnapshot]:
        snapshots, warnings = await enrich(
            [make_snapshot(vulnerable), make_snapshot(fixed)],
            dependencies=False,
        )
        snapshots, source_warnings = await collect(snapshots)
        assert not warnings + source_warnings, (advisory, warnings, source_warnings)
        return snapshots

    before, after = anyio.run(fetch)
    rules = [r for r in load_rules(plugins=False) if r.id.startswith("MCP-SRC-10")]
    results: list[set[str]] = []
    for snapshot in (before, after):
        # Missing/unparseable source must never masquerade as a clean fixed release.
        coverage = summarize(snapshot)["source"]
        assert coverage.status == "completed", (advisory, coverage)
        assert snapshot.source is not None and snapshot.source.files > 0
        result = scan([snapshot], rules)
        assert not result.errors, (advisory, result.errors)
        results.append({f.rule_id for f in result.findings})
    assert expected in results[0], (advisory, "missed vulnerable release", results[0])
    assert not results[1], (advisory, "flagged patched release", results[1])
