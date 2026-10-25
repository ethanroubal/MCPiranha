"""End-to-end import flows across all injection domains, with safe twins and CLI gates."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from mcpiranha.cli import app
from mcpiranha.core.coverage import summarize
from mcpiranha.core.models import Confidence, ServerSnapshot, Severity
from mcpiranha.core.pipeline import scan
from mcpiranha.rules import load_rules
from mcpiranha.source import analyze_files

RULE_IDS = {
    "shell": "MCP-SRC-101",
    "sql": "MCP-SRC-102",
    "path": "MCP-SRC-103",
    "url": "MCP-SRC-104",
}
RULES = [rule for rule in load_rules(plugins=False) if rule.id in RULE_IDS.values()]


def program(
    language: str, family: str, safe: bool, *, namespace: bool = False, returns: bool = False
) -> list[tuple[str, str]]:
    if language == "py":
        imports = (
            "from . import operations as ops"
            if namespace
            else "from .operations import perform as invoke"
        )
        call = "ops.perform(value)" if namespace else "invoke(value)"
        values = {
            "shell": '"git show " + shlex.quote(value)' if safe else '"git show " + value',
            "sql": '"SELECT * FROM records WHERE id=" + str(int(value))'
            if safe
            else '"SELECT * FROM records WHERE id=" + value',
            "path": 'Path("/data") / str(int(value))' if safe else 'Path("/data") / value',
            "url": '"https://api.example.invalid/v1/" + value'
            if safe
            else '"https://" + value + "/v1"',
        }
        sinks = {
            "shell": "os.system(ARG)",
            "sql": "db.execute(ARG)",
            "path": "open(ARG).read()",
            "url": "requests.get(ARG)",
        }
        body = sinks[family].replace("ARG", values[family])
        if safe and family == "sql" and not returns:
            body = 'db.execute("SELECT * FROM records WHERE id=?", (value,))'
        if safe and family == "path" and not returns:
            body = (
                'base = Path("/data").resolve()\n'
                "candidate = (base / value).resolve()\n"
                "if not candidate.is_relative_to(base): raise ValueError()\n"
                "return candidate.read_text()"
            )
        prelude = "import os, shlex, requests\nfrom pathlib import Path\n"
        operation = (
            prelude
            + "def perform(value):\n    "
            + ("return " + values[family] if returns else body.replace("\n", "\n    "))
            + "\n"
        )
        invocation = sinks[family].replace("ARG", call) if returns else call
        entry = (
            imports
            + "\n"
            + prelude
            + "@server.tool()\ndef lookup(value):\n    "
            + invocation
            + "\n"
        )
        return [("server.py", entry), ("operations.py", operation)]
    imports = (
        'import * as ops from "./operations.js";'
        if namespace
        else 'import {perform as invoke} from "./operations.js";'
    )
    call = "ops.perform(value)" if namespace else "invoke(value)"
    values = {
        "shell": "`git show ${shellQuote(value)}`" if safe else "`git show ${value}`",
        "sql": '"SELECT * FROM records WHERE id=" + Number(value)'
        if safe
        else '"SELECT * FROM records WHERE id=" + value',
        "path": 'path.join("/data", String(Number(value)))'
        if safe
        else 'path.join("/data", value)',
        "url": '"https://api.example.invalid/v1/" + value'
        if safe
        else '"https://" + value + "/v1"',
    }
    sinks = {
        "shell": "exec(ARG)",
        "sql": "db.query(ARG)",
        "path": "fs.readFileSync(ARG)",
        "url": "fetch(ARG)",
    }
    body = sinks[family].replace("ARG", values[family])
    if safe and family == "sql" and not returns:
        body = 'db.query("SELECT * FROM records WHERE id=?", [value])'
    if safe and family == "path" and not returns:
        body = (
            'const base = path.resolve("/data"); const candidate = path.resolve(base, value);'
            "if (!candidate.startsWith(base + path.sep)) throw Error();"
            "return fs.readFileSync(candidate)"
        )
    operation = (
        "export function perform(value) { "
        + ("return " + values[family] if returns else body)
        + "; }\n"
    )
    invocation = sinks[family].replace("ARG", call) if returns else call
    entry = imports + '\nserver.tool("lookup", {}, ({value}) => { ' + invocation + "; });\n"
    return [("server.ts", entry), ("operations.ts", operation)]


@pytest.mark.parametrize("language", ["py", "ts"])
@pytest.mark.parametrize("family", ["sql", "path", "url"])
@pytest.mark.parametrize("safe", [False, True])
@pytest.mark.parametrize("namespace", [False, True])
def test_imports_preserve_detection_and_safeguards_across_domains(
    language: str,
    family: str,
    safe: bool,
    namespace: bool,
) -> None:
    check_program(language, family, safe, namespace=namespace)


@pytest.mark.parametrize("language", ["py", "ts"])
@pytest.mark.parametrize("family", ["sql", "path", "url"])
@pytest.mark.parametrize("safe", [False, True])
def test_namespace_return_summaries_preserve_domain_specific_safety(
    language: str,
    family: str,
    safe: bool,
) -> None:
    check_program(language, family, safe, namespace=True, returns=True)


def check_program(
    language: str, family: str, safe: bool, *, namespace: bool = False, returns: bool = False
) -> None:
    files = program(language, family, safe, namespace=namespace, returns=returns)
    tree = analyze_files(iter((name, source.encode()) for name, source in files), "project")
    snapshot = ServerSnapshot.model_validate(
        {
            "id": "project",
            "name": "project",
            "origin": {"kind": "snapshot", "ref": "test"},
            "tools_listed": False,
            "source": tree,
        }
    )
    assert summarize(snapshot)["source"].status == "completed", tree.skipped
    result = scan([snapshot], RULES)
    assert not result.errors
    assert {finding.rule_id for finding in result.findings} == (
        set() if safe else {RULE_IDS[family]}
    )
    for finding in result.findings:
        assert finding.severity == Severity.HIGH
        assert finding.confidence == Confidence.MEDIUM
        filename, code = files[0 if returns else 1]
        assert finding.location.file == "project/" + filename
        assert finding.location.line is not None
        source_line = code.splitlines()[finding.location.line - 1]
        assert any(e.text.strip() == source_line.strip() for e in finding.evidence)
        assert finding.evidence and all(e.text in code for e in finding.evidence)


@pytest.mark.parametrize("language", ["py", "ts"])
@pytest.mark.parametrize("family", ["shell", "sql", "path", "url"])
@pytest.mark.parametrize("safe", [False, True])
def test_imported_flows_control_actual_high_threshold_cli_exit(
    tmp_path: Path,
    language: str,
    family: str,
    safe: bool,
) -> None:
    for filename, code in program(language, family, safe, namespace=True):
        (tmp_path / filename).write_text(code)
    result = CliRunner().invoke(
        app,
        [
            "scan",
            "path:" + str(tmp_path),
            "--offline",
            "--no-lock",
            "--strict",
            "--require-coverage",
            "source",
            "--fail-on",
            "high",
            "-f",
            "json",
        ],
    )
    assert result.exit_code == (0 if safe else 1), result.output
    report = json.loads(result.stdout)
    assert not report["errors"] and not report["warnings"]
    assert report["servers"][0]["coverage"]["source"]["status"] == "completed"
    assert {finding["rule_id"] for finding in report["findings"]} == (
        set() if safe else {RULE_IDS[family]}
    )
