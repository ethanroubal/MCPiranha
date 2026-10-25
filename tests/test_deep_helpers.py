"""Deeper call graphs, contextual caching, and honest coverage when analysis stops."""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier

import pytest
from typer.testing import CliRunner

from mcpiranha.cli import app
from mcpiranha.core.coverage import summarize
from mcpiranha.core.models import ServerSnapshot
from mcpiranha.core.pipeline import scan
from mcpiranha.rules import load_rules
from mcpiranha.source import analysis as limits
from mcpiranha.source import analyze_files

RULES = [r for r in load_rules(plugins=False) if r.id.startswith("MCP-SRC-10")]


def chain(language: str, depth: int, *, returns: bool = False, safe: bool = False) -> str:
    if language == "py":
        code = "import os, shlex\n"
        for i in range(depth):
            tail = (
                ("shlex.quote(value)" if safe else '"prefix-" + value')
                if returns
                else (
                    'os.system("git show " + ' + ("shlex.quote(value)" if safe else "value") + ")"
                )
            )
            expression = f"helper{i + 1}(value)" if i < depth - 1 else tail
            code += (
                f"def helper{i}(value):\n    " + ("return " if returns else "") + expression + "\n"
            )
        body = 'os.system("git show " + helper0(value))' if returns else "helper0(value)"
        return code + "@server.tool()\ndef lookup(value):\n    " + body + "\n"
    code = ""
    for i in range(depth):
        tail = (
            ("shellQuote(value)" if safe else '"prefix-" + value')
            if returns
            else ("exec(`git show ${" + ("shellQuote(value)" if safe else "value") + "}`)")
        )
        expression = f"helper{i + 1}(value)" if i < depth - 1 else tail
        code += (
            f"function helper{i}(value) {{ " + ("return " if returns else "") + expression + "; }\n"
        )
    body = "exec(`git show ${helper0(value)}`)" if returns else "helper0(value)"
    return code + 'server.tool("lookup", {}, ({ value }) => { ' + body + "; });\n"


def evaluate(code: str, language: str) -> tuple[ServerSnapshot, set[str]]:
    filename = "server.py" if language == "py" else "server.ts"
    tree = analyze_files(iter([(filename, code.encode())]), "helpers")
    snapshot = ServerSnapshot.model_validate(
        {
            "id": "helpers",
            "name": "helpers",
            "origin": {"kind": "snapshot", "ref": "test"},
            "source": tree,
            "tools_listed": False,
        }
    )
    result = scan([snapshot], RULES)
    assert not result.errors
    return snapshot, {f.rule_id for f in result.findings}


@pytest.mark.parametrize("language", ["py", "ts"])
@pytest.mark.parametrize("depth", [3, 8, 80])
@pytest.mark.parametrize("safe", [False, True])
def test_deep_sink_calls_and_safe_twins(language: str, depth: int, safe: bool) -> None:
    snapshot, found = evaluate(chain(language, depth, safe=safe), language)
    assert ("MCP-SRC-101" in found) is not safe
    assert summarize(snapshot)["source"].status == "completed"


@pytest.mark.parametrize("language", ["py", "ts"])
@pytest.mark.parametrize("depth", [3, 8, 16])
@pytest.mark.parametrize("safe", [False, True])
def test_deep_return_summaries_and_safe_twins(language: str, depth: int, safe: bool) -> None:
    snapshot, found = evaluate(chain(language, depth, returns=True, safe=safe), language)
    assert ("MCP-SRC-101" in found) is not safe
    assert summarize(snapshot)["source"].status == "completed"


@pytest.mark.parametrize("language", ["py", "ts"])
def test_return_depth_exhaustion_is_visible(language: str) -> None:
    snapshot, _ = evaluate(chain(language, 30, returns=True), language)
    coverage = summarize(snapshot)["source"]
    assert coverage.status == "partial"
    assert "return depth limit" in coverage.reason
    # Limits survive snapshots even if the original source checkout is absent.
    replay = ServerSnapshot.model_validate_json(snapshot.model_dump_json())
    assert summarize(replay)["source"].status == "partial"


@pytest.mark.parametrize("language", ["py", "ts"])
@pytest.mark.parametrize(
    "budget,reason",
    [
        ("MAX_CONTEXTS", "context limit"),
        ("MAX_SUMMARIES", "return-summary limit"),
        ("MAX_NODE_VISITS", "node budget"),
        ("MAX_PROPAGATION_PASSES", "did not converge"),
    ],
)
def test_each_budget_reports_partial_coverage(
    language: str, budget: str, reason: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(limits, budget, 1 if budget == "MAX_PROPAGATION_PASSES" else 0)
    code = chain(language, 4, returns=True)
    if budget == "MAX_PROPAGATION_PASSES":
        code = (
            code.replace("def lookup(value):\n", "def lookup(value):\n    alias = value\n")
            if language == "py"
            else code.replace("=> { ", "=> { const alias = value; ")
        )
    snapshot, _ = evaluate(code, language)
    coverage = summarize(snapshot)["source"]
    assert coverage.status == "partial"
    assert reason in coverage.reason


@pytest.mark.parametrize("language", ["py", "ts"])
def test_recursive_sink_graphs_terminate_and_keep_findings(language: str) -> None:
    code = (
        "import os\ndef first(value):\n    second(value)\n"
        'def second(value):\n    first(value)\n    os.system("git show " + value)\n'
        "@server.tool()\ndef lookup(value):\n    first(value)\n"
        if language == "py"
        else "function first(value) { second(value); }\n"
        "function second(value) { first(value); exec(`git show ${value}`); }\n"
        'server.tool("lookup", {}, ({ value }) => first(value));\n'
    )
    snapshot, found = evaluate(code, language)
    assert "MCP-SRC-101" in found
    assert summarize(snapshot)["source"].status == "completed"


@pytest.mark.parametrize("language", ["py", "ts"])
def test_repeated_calls_reuse_contexts_and_summaries(
    language: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(limits, "MAX_CONTEXTS", 16)
    monkeypatch.setattr(limits, "MAX_SUMMARIES", 16)
    if language == "py":
        code = (
            'import os\ndef decorate(value):\n    return "prefix-" + value\n'
            "@server.tool()\ndef lookup(value):\n"
            + '    os.system("git show " + decorate(value))\n'
            * 80
        )
    else:
        code = (
            'function decorate(value) { return "prefix-" + value; }\n'
            'server.tool("lookup", {}, ({ value }) => {\n'
            + "exec(`git show ${decorate(value)}`);\n" * 80
            + "});\n"
        )
    snapshot, found = evaluate(code, language)
    assert "MCP-SRC-101" in found
    assert summarize(snapshot)["source"].status == "completed"


@pytest.mark.parametrize("language", ["py", "ts"])
def test_guarded_and_unguarded_helper_contexts_are_not_merged(language: str) -> None:
    code = (
        "from pathlib import Path\ndef read_file(candidate):\n    return candidate.read_text()\n"
        "@server.tool()\ndef lookup(first):\n"
        '    base = Path("/data").resolve()\n    good = (base / first).resolve()\n'
        "    if not good.is_relative_to(base): raise ValueError()\n"
        "    read_file(good)\n    read_file(base / first)\n"
        if language == "py"
        else "function readFile(candidate) { return fs.readFileSync(candidate); }\n"
        'server.tool("lookup", {}, ({ first }) => {\n'
        'const base = path.resolve("/data"); const good = path.resolve(base, first);\n'
        "if (!good.startsWith(base + path.sep)) throw Error();\n"
        "readFile(good); readFile(path.join(base, first)); });\n"
    )
    snapshot, found = evaluate(code, language)
    assert "MCP-SRC-103" in found
    assert snapshot.source is not None
    assert any("first" in hit.detail for hit in snapshot.source.hits)


@pytest.mark.parametrize("language", ["py", "ts"])
def test_source_finding_cap_preserves_findings_and_reports_partial(
    language: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    import mcpiranha.source as source

    monkeypatch.setattr(source, "MAX_HITS", 1)
    code = chain(language, 3) + (
        "\nexec(base64.b64decode(payload))\n" if language == "py" else "\neval(atob(payload));\n"
    )
    snapshot, _ = evaluate(code, language)
    assert snapshot.source is not None and len(snapshot.source.hits) == 1
    assert "finding limit" in summarize(snapshot)["source"].reason
    assert summarize(snapshot)["source"].status == "partial"


@pytest.mark.parametrize("requirement", ["--require-coverage", "--strict"])
def test_cli_cannot_pass_a_required_incomplete_analysis(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, requirement: str
) -> None:
    monkeypatch.setattr(limits, "MAX_CONTEXTS", 0)
    target = tmp_path / "server.py"
    target.write_text(chain("py", 3))
    options = [requirement, "source"] if requirement == "--require-coverage" else [requirement]
    result = CliRunner().invoke(
        app,
        [
            "scan",
            str(target),
            "--offline",
            "--no-lock",
            "-f",
            "json",
            *options,
        ],
    )
    assert result.exit_code == 2, result.output
    report = json.loads(result.stdout)
    assert report["servers"][0]["coverage"]["source"]["status"] == "partial"


@pytest.mark.parametrize("language", ["py", "ts"])
def test_call_graph_crosses_multiple_source_files(language: str) -> None:
    files = (
        [
            (
                "server.py",
                "from .operations import first\n@server.tool()\n"
                "def lookup(value):\n    first(value)\n",
            ),
            (
                "operations.py",
                "from .helpers import second\ndef first(value):\n    second(value)\n",
            ),
            ("helpers.py", "from .sink import third\ndef second(value):\n    third(value)\n"),
            ("sink.py", 'import os\ndef third(value):\n    os.system("git show " + value)\n'),
        ]
        if language == "py"
        else [
            (
                "server.ts",
                'import {first} from "./operations"; '
                'server.tool("t", {}, ({value}) => first(value));',
            ),
            (
                "operations.ts",
                'import {second} from "./helpers"; export function first(value) { second(value); }',
            ),
            (
                "helpers.ts",
                'import {third} from "./sink"; export function second(value) { third(value); }',
            ),
            ("sink.ts", "export function third(value) { exec(`git show ${value}`); }"),
        ]
    )
    tree = analyze_files(iter((path, code.encode()) for path, code in files), "project")
    assert tree.files == 4 and not tree.skipped
    hits = [h for h in tree.hits if h.kind == "shell_injection"]
    assert len(hits) == 1 and hits[0].file.startswith("sink.")


@pytest.mark.parametrize("language", ["py", "ts"])
def test_return_summary_cache_separates_clean_and_tainted_arguments(language: str) -> None:
    code = (
        'import os, shlex\ndef decorate(value):\n    return "prefix-" + value\n'
        "@server.tool()\ndef lookup(value):\n"
        '    os.system("git show " + decorate(shlex.quote(value)))\n'
        '    os.system("git show " + decorate(value))\n'
        if language == "py"
        else 'function decorate(value) { return "prefix-" + value; }\n'
        'server.tool("t", {}, ({value}) => {\n'
        "exec(`git show ${decorate(shellQuote(value))}`);\n"
        "exec(`git show ${decorate(value)}`); });"
    )
    snapshot, found = evaluate(code, language)
    assert "MCP-SRC-101" in found
    assert snapshot.source is not None and not snapshot.source.skipped
    hits = [h for h in snapshot.source.hits if h.kind == "shell_injection"]
    assert len(hits) == 1 and "quote" not in hits[0].code.lower()


@pytest.mark.parametrize("language", ["py", "ts"])
def test_literal_inference_limit_is_visible(language: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(limits, "MAX_LITERAL_CHARS", 8)
    code = (
        "@server.tool()\ndef lookup(value):\n"
        '    db.execute("SELECT * FROM records WHERE id=" + value)\n'
        if language == "py"
        else 'server.tool("lookup", {}, ({value}) => '
        'db.query("SELECT * FROM records WHERE id=" + value));'
    )
    snapshot, _ = evaluate(code, language)
    assert summarize(snapshot)["source"].status == "partial"
    assert "literal inference limit" in summarize(snapshot)["source"].reason


def test_parallel_javascript_scans_use_isolated_parsers() -> None:
    from mcpiranha.source.javascript import parser

    barrier = Barrier(4)

    def worker(_: int) -> object:
        native_parser = parser("ts")
        assert parser("ts") is native_parser
        barrier.wait(timeout=10)
        for depth in (3, 8, 30):
            snapshot, found = evaluate(chain("ts", depth), "ts")
            assert "MCP-SRC-101" in found
            assert summarize(snapshot)["source"].status == "completed"
        return native_parser

    with ThreadPoolExecutor(max_workers=4) as pool:
        parsers = list(pool.map(worker, range(4)))
    assert len({id(parser) for parser in parsers}) == 4


@pytest.mark.parametrize("language", ["py", "ts"])
@pytest.mark.parametrize("budget", ["MAX_ALIAS_DEPTH", "MAX_EXPRESSION_DEPTH"])
def test_expression_and_alias_limits_are_visible(
    language: str, budget: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(limits, budget, 0)
    code = (
        "@server.tool()\ndef lookup(value):\n"
        '    query = "SELECT * FROM records WHERE id=" + value\n    db.execute(query)\n'
        if language == "py"
        else 'server.tool("lookup", {}, ({value}) => { '
        'const query = "SELECT * FROM records WHERE id=" + value; db.query(query); });'
    )
    snapshot, _ = evaluate(code, language)
    assert summarize(snapshot)["source"].status == "partial"
    assert "depth limit" in summarize(snapshot)["source"].reason


@pytest.mark.parametrize("language", ["py", "ts"])
def test_unresolved_recursive_return_is_partial_and_keeps_other_findings(language: str) -> None:
    code = (
        "import os\ndef recurse(value):\n    nested = recurse(value)\n    return nested\n"
        "@server.tool()\ndef lookup(value):\n"
        '    result = recurse(value)\n    os.system("git show " + value)\n'
        if language == "py"
        else "function recurse(value) { const nested = recurse(value); return nested; }"
        'server.tool("lookup", {}, ({value}) => { '
        "const result = recurse(value); exec(`git show ${value}`); });"
    )
    snapshot, found = evaluate(code, language)
    assert "MCP-SRC-101" in found
    assert summarize(snapshot)["source"].status == "partial"
    assert "recursive return summary" in summarize(snapshot)["source"].reason
