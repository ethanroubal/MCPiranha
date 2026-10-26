import json
from pathlib import Path
from typing import Any

from mcpiranha import REPO_URL
from mcpiranha.core.io import load_snapshots
from mcpiranha.core.pipeline import scan
from mcpiranha.report import sarif
from mcpiranha.rules import load_rules

FIXTURES = Path(__file__).parent.parent / "fixtures" / "metadata"
RULES = load_rules(plugins=False)


def _sarif(case: str, base: Path | None = None) -> dict[str, Any]:
    result = scan(load_snapshots(FIXTURES / case / "snapshots.json"), RULES)
    return json.loads(sarif.render(result, RULES, base=base))


def test_structure_and_levels() -> None:
    log = _sarif("poisoned-important")
    assert log["version"] == "2.1.0"
    [run] = log["runs"]
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert {r["ruleId"] for r in run["results"]} == rule_ids
    for r in run["results"]:
        assert r["level"] in ("error", "warning", "note")
        assert r["partialFingerprints"]["mcpiranhaFindingId/v1"]
        assert r["locations"][0]["logicalLocations"][0]["fullyQualifiedName"].startswith(
            "math-helper/add#/tools/0"
        )
    assert run["tool"]["driver"]["informationUri"] == REPO_URL
    descriptor = run["tool"]["driver"]["rules"][0]
    assert descriptor["fullDescription"]["text"]
    assert all(r["helpUri"].startswith("https://") for r in run["tool"]["driver"]["rules"])
    assert float(descriptor["properties"]["security-severity"]) > 0


def test_config_findings_point_at_the_config_file() -> None:
    [run] = _sarif("config-floating-secret")["runs"]
    uris = {
        r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in run["results"]
    }
    [uri] = uris  # "~/..." expands to an absolute path outside the base, so a file:// URI
    assert uri.startswith("file:///") and uri.endswith("claude_desktop_config.json")


def test_relative_paths_under_base(tmp_path: Path) -> None:
    config = tmp_path / ".mcp.json"
    assert sarif.artifact_uri(str(config), tmp_path) == ".mcp.json"
    assert sarif.artifact_uri("/elsewhere/x.json", tmp_path).startswith("file:///")


def test_space_and_unicode_paths_are_encoded_as_artifact_uris(tmp_path: Path) -> None:
    source = tmp_path / "source with spaces 測試" / "server.py"
    expected = "source%20with%20spaces%20%E6%B8%AC%E8%A9%A6/server.py"
    assert sarif.artifact_uri(str(source), tmp_path) == expected
    assert sarif.artifact_uri("source with spaces 測試/server.py", tmp_path) == expected


def test_windows_snapshot_paths_remain_valid_uris_on_every_host(tmp_path: Path) -> None:
    assert sarif.artifact_uri(r"C:\Users\alice\source with spaces\server.py", tmp_path).startswith(
        "file:///C:/Users/alice/source%20with%20spaces/server.py"
    )
