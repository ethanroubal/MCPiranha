"""Basename preserves dot components; only a checked path/allowlist proves containment."""

from __future__ import annotations

import json
import ntpath
import posixpath
from collections.abc import Callable
from pathlib import Path

import pytest
from typer.testing import CliRunner

from mcpiranha.cli import app
from mcpiranha.core.coverage import summarize
from mcpiranha.core.models import Confidence, ServerSnapshot, Severity
from mcpiranha.core.pipeline import scan
from mcpiranha.rules import load_rules
from mcpiranha.source import analyze_files

RULES = [rule for rule in load_rules(plugins=False) if rule.id == "MCP-SRC-103"]
BASENAMES = [
    *(("py", name) for name in ("os.path.basename", "posixpath.basename", "ntpath.basename")),
    *(("ts", name) for name in ("path.basename", "path.posix.basename", "path.win32.basename")),
]


def code(language: str, basename: str, mode: str = "inline", guard: str = "none") -> str:
    if language == "py":
        prelude = "import os, posixpath, ntpath\nfrom pathlib import Path\n"
        definition = (
            "def leaf(value):\n    return " + basename + "(value)\n" if mode == "helper" else ""
        )
        body = ['base = Path("/data/records").resolve()']
        value = "leaf(value)" if mode == "helper" else basename + "(value)"
        if mode == "alias":
            body.append("part = " + value)
            value = "part"
        if guard == "allowlist":
            body += ["part = " + value, 'if part not in {"daily", "weekly"}: raise ValueError()']
            value = "part"
        body.append("candidate = (base / " + value + ' / "record.txt").resolve()')
        check = "if not candidate.is_relative_to(base): raise ValueError()"
        if guard == "containment":
            body.append(check)
        elif guard == "ignored":
            body.append("candidate.is_relative_to(base)")
        elif guard == "wrong-value":
            body += [
                'other = (base / "public").resolve()',
                "if not other.is_relative_to(base): raise ValueError()",
            ]
        elif guard == "reassigned":
            body += [check, 'candidate = (base / value / "record.txt").resolve()']
        body.append("result = candidate.read_text()")
        if guard == "late":
            body.append(check)
        return (
            prelude
            + definition
            + "@server.tool()\ndef lookup(value):\n"
            + "".join("    " + line + "\n" for line in body)
        )
    definition = (
        "function leaf(value) { return " + basename + "(value); }\n" if mode == "helper" else ""
    )
    body = ['const base = path.resolve("/data/records");']
    value = "leaf(value)" if mode == "helper" else basename + "(value)"
    if mode == "alias":
        body.append("const part = " + value + ";")
        value = "part"
    if guard == "allowlist":
        body += [
            "const part = " + value + ";",
            'if (!["daily", "weekly"].includes(part)) throw Error();',
        ]
        value = "part"
    body.append("let candidate = path.resolve(base, " + value + ', "record.txt");')
    check = "if (!candidate.startsWith(base + path.sep)) throw Error();"
    if guard == "containment":
        body.append(check)
    elif guard == "ignored":
        body.append("candidate.startsWith(base + path.sep);")
    elif guard == "wrong-value":
        body += [
            'const other = path.resolve(base, "public");',
            "if (!other.startsWith(base + path.sep)) throw Error();",
        ]
    elif guard == "reassigned":
        body += [check, 'candidate = path.resolve(base, value, "record.txt");']
    body.append("const result = fs.readFileSync(candidate);")
    if guard == "late":
        body.append(check)
    return definition + 'server.tool("lookup", {}, ({value}) => { ' + " ".join(body) + " });\n"


def evaluate(source: str, language: str) -> list[str]:
    filename = "server.py" if language == "py" else "server.ts"
    tree = analyze_files(iter([(filename, source.encode())]), "test")
    snapshot = ServerSnapshot.model_validate(
        {
            "id": "basename",
            "name": "basename",
            "origin": {"kind": "snapshot", "ref": "test"},
            "source": tree,
            "tools_listed": False,
        }
    )
    assert summarize(snapshot)["source"].status == "completed", tree.skipped
    result = scan([snapshot], RULES)
    assert not result.errors
    for finding in result.findings:
        assert finding.severity == Severity.HIGH and finding.confidence == Confidence.MEDIUM
        assert finding.location.file == "test/" + filename
        assert finding.evidence and all(e.text in source for e in finding.evidence)
    return [finding.rule_id for finding in result.findings]


@pytest.mark.parametrize("language,basename", BASENAMES)
@pytest.mark.parametrize("mode", ["inline", "alias", "helper"])
def test_basename_does_not_drop_taint(language: str, basename: str, mode: str) -> None:
    assert evaluate(code(language, basename, mode), language) == ["MCP-SRC-103"]


@pytest.mark.parametrize("language,basename", BASENAMES)
@pytest.mark.parametrize("guard", ["containment", "allowlist"])
def test_basename_with_a_real_safeguard_remains_quiet(
    language: str, basename: str, guard: str
) -> None:
    assert evaluate(code(language, basename, guard=guard), language) == []


@pytest.mark.parametrize("language", ["py", "ts"])
@pytest.mark.parametrize("guard", ["ignored", "wrong-value", "late", "reassigned"])
def test_ineffective_guards_do_not_make_basename_safe(language: str, guard: str) -> None:
    basename = "os.path.basename" if language == "py" else "path.basename"
    assert evaluate(code(language, basename, guard=guard), language) == ["MCP-SRC-103"]


@pytest.mark.parametrize("language", ["py", "ts"])
@pytest.mark.parametrize("guard", ["none", "containment", "allowlist"])
def test_basename_cli_high_gate(tmp_path: Path, language: str, guard: str) -> None:
    basename = "os.path.basename" if language == "py" else "path.basename"
    target = tmp_path / ("server.py" if language == "py" else "server.ts")
    target.write_text(code(language, basename, guard=guard))
    result = CliRunner().invoke(
        app,
        [
            "scan",
            str(target),
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
    assert result.exit_code == (1 if guard == "none" else 0), result.output
    report = json.loads(result.stdout)
    assert not report["errors"] and not report["warnings"]
    assert report["servers"][0]["coverage"]["source"]["status"] == "completed"


@pytest.mark.parametrize("basename", [posixpath.basename, ntpath.basename])
def test_dot_component_really_escapes_the_base(
    tmp_path: Path, basename: Callable[[str], str]
) -> None:
    # Use only temporary inert data, independent of the scanner's taint assumptions.
    base = tmp_path / "records"
    base.mkdir()
    (tmp_path / "record.txt").write_text("inert test marker")
    candidate = base / basename("..") / "record.txt"
    assert not candidate.resolve().is_relative_to(base.resolve())
    assert candidate.read_text() == "inert test marker"


@pytest.mark.parametrize("language", ["py", "ts"])
@pytest.mark.parametrize("defect", ["dot", "ignored", "late", "reassigned", "wrong-value"])
def test_invalid_allowlists_cannot_suppress_traversal(language: str, defect: str) -> None:
    basename = "os.path.basename" if language == "py" else "path.basename"
    source = code(language, basename, guard="allowlist")
    if language == "py":
        check = 'if part not in {"daily", "weekly"}: raise ValueError()'
        if defect == "dot":
            source = source.replace('"daily", "weekly"', '"daily", ".."')
        elif defect == "ignored":
            source = source.replace(check, 'part not in {"daily", "weekly"}')
        elif defect == "late":
            source = source.replace("    " + check + "\n", "") + "    " + check + "\n"
        elif defect == "reassigned":
            source = source.replace(check, check + "\n    part = value")
        else:
            source = source.replace(check, 'other = "daily"\n    ' + check.replace("part", "other"))
    else:
        check = 'if (!["daily", "weekly"].includes(part)) throw Error();'
        if defect == "dot":
            source = source.replace('"daily", "weekly"', '"daily", ".."')
        elif defect == "ignored":
            source = source.replace(check, '["daily", "weekly"].includes(part);')
        elif defect == "late":
            source = source.replace(check, "").replace(" });", " " + check + " });")
        elif defect == "reassigned":
            source = source.replace("const part", "let part").replace(
                check, check + " part = value;"
            )
        else:
            source = source.replace(
                check, 'const other = "daily"; ' + check.replace("part", "other")
            )
    assert evaluate(source, language) == ["MCP-SRC-103"]


@pytest.mark.parametrize("language", ["py", "ts"])
@pytest.mark.parametrize("family", ["shell", "sql", "url"])
def test_basename_does_not_sanitize_other_domains(language: str, family: str) -> None:
    if language == "py":
        sinks = {
            "shell": 'os.system("git show " + os.path.basename(value))',
            "sql": 'db.execute("SELECT * FROM t WHERE id=" + os.path.basename(value))',
            "url": 'requests.get("https://" + os.path.basename(value) + "/v1")',
        }
        source = (
            "import os, requests\n@server.tool()\ndef lookup(value):\n    " + sinks[family] + "\n"
        )
    else:
        sinks = {
            "shell": 'exec("git show " + path.basename(value))',
            "sql": 'db.query("SELECT * FROM t WHERE id=" + path.basename(value))',
            "url": 'fetch("https://" + path.basename(value) + "/v1")',
        }
        source = 'server.tool("lookup", {}, ({value}) => { ' + sinks[family] + "; });"
    filename = "server.py" if language == "py" else "server.ts"
    tree = analyze_files(iter([(filename, source.encode())]), "test")
    expected = {"shell": "shell_injection", "sql": "sql_injection", "url": "ssrf"}[family]
    assert not tree.skipped
    assert expected in {hit.kind for hit in tree.hits}


@pytest.mark.parametrize("language", ["py", "ts"])
@pytest.mark.parametrize("safe", [False, True])
def test_imported_basename_returns_keep_the_path_taint(language: str, safe: bool) -> None:
    if language == "py":
        operation = "import os\ndef leaf(value):\n    return os.path.basename(value)\n"
        source = code(
            language, "os.path.basename", mode="helper", guard="containment" if safe else "none"
        )
        source = source.replace(
            "def leaf(value):\n    return os.path.basename(value)\n",
            "from .operations import leaf\n",
        )
    else:
        operation = "export function leaf(value) { return path.basename(value); }"
        source = code(
            language, "path.basename", mode="helper", guard="containment" if safe else "none"
        )
        source = source.replace(
            "function leaf(value) { return path.basename(value); }",
            'import {leaf} from "./operations";',
        )
    extension = ".py" if language == "py" else ".ts"
    tree = analyze_files(
        iter(
            [
                ("server" + extension, source.encode()),
                ("operations" + extension, operation.encode()),
            ]
        ),
        "test",
    )
    assert not tree.skipped
    assert any(hit.kind == "path_traversal" for hit in tree.hits) is not safe


@pytest.mark.parametrize("language", ["py", "ts"])
@pytest.mark.parametrize("mode", ["inline", "helper"])
def test_literal_basename_values_do_not_introduce_taint(language: str, mode: str) -> None:
    basename = "os.path.basename" if language == "py" else "path.basename"
    source = code(language, basename, mode=mode).replace(
        basename + "(value)", basename + '("daily")'
    )
    assert evaluate(source, language) == []


@pytest.mark.parametrize("language", ["py", "ts"])
def test_basename_without_suffix_is_still_unsafe_for_directory_operations(language: str) -> None:
    source = (
        "import os\n@server.tool()\ndef listing(value):\n"
        '    return os.listdir(os.path.join("/data/records", os.path.basename(value)))\n'
        if language == "py"
        else 'server.tool("listing", {}, ({value}) => '
        'fs.readdirSync(path.join("/data/records", path.basename(value))));'
    )
    assert evaluate(source, language) == ["MCP-SRC-103"]


@pytest.mark.parametrize("safe", [False, True])
def test_local_basename_function_uses_its_actual_return_summary(safe: bool) -> None:
    body = '"daily"' if safe else "value"
    source = (
        'import {join} from "node:path"; import * as path from "./custom"; '
        'server.tool("lookup", {}, ({value}) => '
        'fs.readFileSync(join("/data", path.basename(value), "record.txt")));'
    )
    # A local lookalike must use its helper summary, not a trusted library exemption.
    module = "export function basename(value) { return " + body + "; }"
    tree = analyze_files(
        iter([("server.ts", source.encode()), ("custom.ts", module.encode())]), "test"
    )
    assert not tree.skipped
    assert any(hit.kind == "path_traversal" for hit in tree.hits) is not safe
