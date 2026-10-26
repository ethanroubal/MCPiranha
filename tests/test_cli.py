import json
import shutil
from pathlib import Path

import pytest
from typer.testing import CliRunner

from mcpiranha.cli import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK, app
from tests.helpers import snapshot_with_description

FIXTURES = Path(__file__).parent.parent / "fixtures" / "metadata"
runner = CliRunner()


def test_clean_scan_exits_zero() -> None:
    result = runner.invoke(app, ["scan", str(FIXTURES / "benign-weather" / "snapshots.json")])
    assert result.exit_code == EXIT_OK, result.output
    assert "no findings" in result.output


def test_findings_exit_one_and_json_is_valid() -> None:
    target = FIXTURES / "unicode-tag-smuggling" / "snapshots.json"
    result = runner.invoke(app, ["scan", str(target), "--format", "json"])
    assert result.exit_code == EXIT_FINDINGS, result.output
    report = json.loads(result.output)
    assert report["findings"][0]["rule_id"] == "MCP-TP-001"
    assert report["findings"][0]["severity"] == "critical"


def test_fail_on_threshold(tmp_path: Path) -> None:
    medium_only = snapshot_with_description("Search" + chr(0x200B) + "terms.")  # zero-width only
    target = tmp_path / "snapshot.json"
    target.write_text(medium_only.model_dump_json(), encoding="utf-8")
    assert runner.invoke(app, ["scan", str(target)]).exit_code == EXIT_OK
    assert runner.invoke(app, ["scan", str(target), "--fail-on", "medium"]).exit_code == (
        EXIT_FINDINGS
    )


def test_terminal_report_reveals_hidden_characters() -> None:
    target = FIXTURES / "bidi-override" / "snapshots.json"
    result = runner.invoke(app, ["scan", str(target)])
    assert "⟨U+202E⟩" in result.output
    assert "\u202e" not in result.output


def test_invalid_snapshot_exits_two(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text('{"id": "x"}', encoding="utf-8")
    assert runner.invoke(app, ["scan", str(bad)]).exit_code == EXIT_ERROR


def test_inspect_and_rules() -> None:
    target = FIXTURES / "unicode-tag-smuggling" / "snapshots.json"
    assert "⟨U+E0049⟩" in runner.invoke(app, ["inspect", str(target)]).output
    assert "MCP-TP-001" in runner.invoke(app, ["rules"]).output


def test_planned_commands_exit_two() -> None:
    assert runner.invoke(app, ["serve"]).exit_code == EXIT_ERROR


def test_bench_without_samples_is_an_error(tmp_path: Path) -> None:
    assert runner.invoke(app, ["bench", str(tmp_path)]).exit_code == EXIT_ERROR


CONFIGS = Path(__file__).parent.parent / "fixtures" / "configs"


def _project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """An isolated cwd with a project .mcp.json, and an empty fake home."""
    home, project = tmp_path / "home", tmp_path / "project"
    home.mkdir()
    project.mkdir()
    shutil.copy(CONFIGS / "project.mcp.json", project / ".mcp.json")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.chdir(project)
    return project


def test_scan_config_file() -> None:
    result = runner.invoke(
        app, ["scan", str(CONFIGS / "claude_desktop_config.json"), "-f", "json", "--no-lock"]
    )
    assert result.exit_code == EXIT_FINDINGS, result.output
    rules = {f["rule_id"] for f in json.loads(result.output)["findings"]}
    assert {"MCP-CF-001", "MCP-RP-003"} <= rules
    assert "ghp_FAKE" not in result.output


def test_scan_without_target_discovers_project_and_home(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = _project(tmp_path, monkeypatch)
    cursor = tmp_path / "home" / ".cursor"
    cursor.mkdir()
    shutil.copy(CONFIGS / "cursor.mcp.json", cursor / "mcp.json")
    result = runner.invoke(app, ["scan"])
    assert str(project / ".mcp.json") in result.output
    assert str(cursor / "mcp.json") in result.output
    assert "MCP-CF-002" in result.output  # remote-notes over plain http, from the home config


def test_scan_directory_and_sarif(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    project = _project(tmp_path, monkeypatch)
    result = runner.invoke(app, ["scan", str(project), "-f", "sarif"])
    run = json.loads(result.output)["runs"][0]
    assert {r["ruleId"] for r in run["results"]} == {"MCP-RP-003"}  # mcp/postgres, no tag
    uri = run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == ".mcp.json"


def test_lock_then_verify(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    project = _project(tmp_path, monkeypatch)
    assert runner.invoke(app, ["lock", "."]).exit_code == EXIT_OK
    assert (project / "mcp-lock.json").is_file()
    assert runner.invoke(app, ["verify", "."]).exit_code == EXIT_OK

    config = project / ".mcp.json"
    data = json.loads(config.read_text(encoding="utf-8"))
    data["mcpServers"]["postgres"]["args"][3] = "evil/postgres"
    config.write_text(json.dumps(data), encoding="utf-8")
    changed = runner.invoke(app, ["verify", "."])
    assert changed.exit_code == EXIT_FINDINGS
    assert "evil/postgres" in changed.output

    data["mcpServers"]["postgres"]["args"][3] = "mcp/postgres"
    data["mcpServers"]["new-one"] = {"command": "npx", "args": ["-y", "new-mcp@1.0.0"]}
    config.write_text(json.dumps(data), encoding="utf-8")
    added = runner.invoke(app, ["verify", "."])
    assert added.exit_code == EXIT_FINDINGS
    assert "Added since lock" in added.output and "new-one" in added.output

    # scan picks the lockfile up from the cwd by default, and reports the changed launch
    data["mcpServers"]["postgres"]["args"][3] = "evil/postgres"
    config.write_text(json.dumps(data), encoding="utf-8")
    assert "MCP-RP-001" in runner.invoke(app, ["scan", "."]).output
    assert "MCP-RP-001" not in runner.invoke(app, ["scan", ".", "--no-lock"]).output


def test_verify_without_lockfile_exits_two(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _project(tmp_path, monkeypatch)
    assert runner.invoke(app, ["verify", "."]).exit_code == EXIT_ERROR


def test_urls_need_connect() -> None:
    result = runner.invoke(app, ["scan", "https://mcp.example.com/mcp"])
    assert result.exit_code == EXIT_ERROR


def test_save_snapshots_round_trips_without_secrets(tmp_path: Path) -> None:
    out = tmp_path / "snaps"
    config = CONFIGS / "claude_desktop_config.json"
    first = runner.invoke(app, ["scan", str(config), "--save-snapshots", str(out), "-f", "json",
                                "--no-lock"])  # fmt: skip
    files = sorted(out.glob("*.json"))
    assert [f.name for f in files] == ["claude-desktop_user_filesystem.json",
                                       "claude-desktop_user_github.json"]  # fmt: skip
    assert all("ghp_FAKE" not in f.read_text(encoding="utf-8") for f in files)
    rescanned = runner.invoke(app, ["scan", str(files[1]), "-f", "json", "--no-lock"])
    before = {f["rule_id"] for f in json.loads(first.stdout)["findings"]}
    after = {f["rule_id"] for f in json.loads(rescanned.stdout)["findings"]}
    assert "MCP-CF-001" in before and "MCP-CF-001" not in after  # the secret itself was masked
    assert "MCP-RP-003" in after
