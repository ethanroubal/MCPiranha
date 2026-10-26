import json
from datetime import date
from pathlib import Path

import pytest
from typer.testing import CliRunner

from mcpiranha.cli import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK, app
from mcpiranha.core.io import load_snapshots
from mcpiranha.core.pipeline import scan
from mcpiranha.core.policy import Policy, PolicyError
from mcpiranha.rules import load_rules

FIXTURES = Path(__file__).parent.parent / "fixtures" / "metadata"
POISONED = FIXTURES / "poisoned-important" / "snapshots.json"
runner = CliRunner()


def _policy(tmp_path: Path, text: str) -> Path:
    path = tmp_path / ".mcpiranha.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def _result():
    return scan(load_snapshots(POISONED), load_rules(plugins=False))


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("suppress:\n  - rule_id: MCP-TP-004\n", "reason"),
        ("suppress:\n  - reason: because\n", "needs rule_id"),
        ("failon: high\n", "failon"),
        ("suppress: [\n", "could not read"),
    ],
)
def test_invalid_policies_are_rejected(tmp_path: Path, text: str, message: str) -> None:
    with pytest.raises(PolicyError, match=message):
        Policy.load(_policy(tmp_path, text))


def test_suppress_by_rule_glob_and_server(tmp_path: Path) -> None:
    policy = Policy.load(_policy(tmp_path, (
        "suppress:\n"
        "  - rule_id: MCP-TP-00[34]\n    server: math-*\n    reason: reviewed, false positive\n"
    )))  # fmt: skip
    result = policy.apply(_result())
    assert {f.rule_id for f in result.findings} == {"MCP-TP-005", "MCP-TP-009"}
    assert {s.finding.rule_id for s in result.suppressed} == {"MCP-TP-003", "MCP-TP-004"}
    assert all(s.reason == "reviewed, false positive" for s in result.suppressed)


def test_suppress_one_finding_by_id() -> None:
    result = _result()
    target = result.findings[0]
    policy = Policy.model_validate({"suppress": [{"finding_id": target.id, "reason": "ok"}]})
    applied = policy.apply(result)
    assert [s.finding.id for s in applied.suppressed] == [target.id]


def test_expired_suppressions_stop_applying() -> None:
    policy = Policy.model_validate(
        {"suppress": [{"rule_id": "MCP-*", "reason": "temp", "expires": "2026-01-01"}]}
    )
    applied = policy.apply(_result(), today=date(2026, 6, 1))
    assert applied.suppressed == [] and applied.findings
    assert "expired on 2026-01-01" in applied.warnings[0]
    assert policy.apply(_result(), today=date(2025, 12, 1)).findings == []


def test_cli_uses_policy_file_and_reports_suppressions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    _policy(tmp_path, "fail_on: critical\nsuppress:\n  - server: math-helper\n    reason: demo\n")
    report = runner.invoke(app, ["scan", str(POISONED), "-f", "json", "--no-lock"])
    assert report.exit_code == EXIT_OK
    data = json.loads(report.stdout)
    assert data["findings"] == [] and len(data["suppressed"]) == 4

    sarif = json.loads(runner.invoke(app, ["scan", str(POISONED), "-f", "sarif"]).stdout)
    results = sarif["runs"][0]["results"]
    assert results and all(r["suppressions"][0]["justification"] == "demo" for r in results)

    # flags win over the policy
    assert runner.invoke(app, ["scan", str(POISONED), "--policy", str(tmp_path / "none.yaml")]
                         ).exit_code == EXIT_ERROR  # fmt: skip
    unsuppressed = tmp_path / "empty.yaml"
    unsuppressed.write_text("{}\n", encoding="utf-8")
    assert runner.invoke(app, ["scan", str(POISONED), "--policy", str(unsuppressed)]
                         ).exit_code == EXIT_FINDINGS  # fmt: skip


def test_strict_fails_when_a_server_could_not_be_checked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    broken = {"command": "python3", "args": ["-c", "import sys; sys.exit(1)"]}
    config = {"mcpServers": {"broken": broken}}
    (tmp_path / ".mcp.json").write_text(json.dumps(config), encoding="utf-8")
    base = ["scan", ".", "--connect", "--sandbox", "none", "--timeout", "15"]
    assert runner.invoke(app, base).exit_code == EXIT_OK  # a warning only
    assert runner.invoke(app, [*base, "--strict"]).exit_code == EXIT_ERROR
    _policy(tmp_path, "strict: true\n")
    assert runner.invoke(app, base).exit_code == EXIT_ERROR
    assert runner.invoke(app, [*base, "--no-strict"]).exit_code == EXIT_OK


@pytest.mark.parametrize("status", ["partial", "skipped", "failed", "unknown"])
def test_required_coverage_cannot_be_suppressed(status: str) -> None:
    from mcpiranha.core.models import CoverageCheck

    result = _result()
    result.servers[0].coverage["source"] = CoverageCheck.model_validate(
        {"status": status, "reason": "fixture incomplete"}
    )
    policy = Policy.model_validate(
        {
            "require_coverage": ["source"],
            "suppress": [{"rule_id": "*", "reason": "reviewed findings"}],
        }
    )
    report = policy.apply(result)
    assert report.findings == []
    assert "required source coverage is incomplete" in report.errors[0]


def test_invalid_coverage_stage_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(PolicyError):
        Policy.load(_policy(tmp_path, "require_coverage: [typo]\n"))
    bad_flag = runner.invoke(app, ["scan", str(POISONED), "--require-coverage", "typo"])
    assert bad_flag.exit_code == EXIT_ERROR
    assert "Invalid --require-coverage" in bad_flag.output


def test_required_coverage_reports_errors_in_json_and_sarif(tmp_path: Path) -> None:
    policy = _policy(tmp_path, "require_coverage: [source]\n")
    for fmt in ("json", "sarif"):
        result = runner.invoke(
            app,
            ["scan", str(POISONED), "--policy", str(policy), "--no-lock", "--no-strict", "-f", fmt],
        )
        assert result.exit_code == EXIT_ERROR, result.output
        report = json.loads(result.stdout)
        if fmt == "json":
            assert "required source" in report["errors"][0]
        else:
            assert report["runs"][0]["invocations"][0]["executionSuccessful"] is False
