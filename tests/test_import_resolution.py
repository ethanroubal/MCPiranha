"""Import spelling and unrelated modules must not change detection of the same behavior."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from mcpiranha.cli import app
from mcpiranha.core.coverage import summarize
from mcpiranha.core.models import ServerSnapshot
from mcpiranha.source import analyze_files
from mcpiranha.source.modules import Graph, Module, Ref

PY_IMPORTS = [
    ("from .operations import run", "run"),
    ("from .operations import run as invoke", "invoke"),
    ("from . import operations as ops", "ops.run"),
    ("import project.operations as ops", "ops.run"),
    ("import project.operations", "project.operations.run"),
    ("from project.operations import run as invoke", "invoke"),
]
JS_IMPORTS = [
    ('import {run} from "./operations.js";', "run"),
    ('import {run as invoke} from "./operations.js";', "invoke"),
    ('import * as ops from "./operations.js";', "ops.run"),
    ('import invoke from "./operations.js";', "invoke"),
    ('const ops = require("./operations.js");', "ops.run"),
    ('const {run: invoke} = require("./operations.js");', "invoke"),
    ('const {run} = require("./operations.js");', "run"),
    ('const ops_1 = require("./operations.js");', "(0, ops_1.run)"),
]


def helper(language: str, *, safe: bool, returns: bool = False) -> str:
    if language == "py":
        value = "shlex.quote(value)" if safe else '"prefix-" + value'
        expression = "return " + value if returns else 'os.system("git show " + ' + value + ")"
        return "import os, shlex\ndef run(value):\n    " + expression + "\n"
    value = "shellQuote(value)" if safe else '"prefix-" + value'
    expression = "return " + value if returns else "exec(`git show ${" + value + "}`)"
    return "export function run(value) { " + expression + "; }\nexport default run;\n"


def handler(language: str, imports: str, call: str, *, returns: bool = False) -> str:
    expression = call + "(value)"
    if returns:
        expression = (
            'os.system("git show " + ' + expression + ")"
            if language == "py"
            else "exec(`git show ${" + expression + "}`)"
        )
    return (
        imports + "\nimport os\n@server.tool()\ndef lookup(value):\n    " + expression + "\n"
        if language == "py"
        else imports + '\nserver.tool("lookup", {}, ({value}) => { ' + expression + "; });"
    )


def analyze(language: str, files: list[tuple[str, str]]) -> ServerSnapshot:
    extension = "py" if language == "py" else "ts"
    tree = analyze_files(
        iter((path + "." + extension, code.encode()) for path, code in files), "test"
    )
    return ServerSnapshot.model_validate(
        {
            "id": "imports",
            "name": "imports",
            "origin": {"kind": "snapshot", "ref": "test"},
            "source": tree,
            "tools_listed": False,
        }
    )


@pytest.mark.parametrize(
    "language,imports,call",
    [
        *(("py", statement, name) for statement, name in PY_IMPORTS),
        *(("ts", statement, name) for statement, name in JS_IMPORTS),
    ],
)
@pytest.mark.parametrize("safe", [False, True])
@pytest.mark.parametrize("returns", [False, True])
def test_import_variants_preserve_sink_and_return_detection(
    language: str,
    imports: str,
    call: str,
    safe: bool,
    returns: bool,
) -> None:
    snapshot = analyze(
        language,
        [
            ("project/server", handler(language, imports, call, returns=returns)),
            ("project/operations", helper(language, safe=safe, returns=returns)),
        ],
    )
    assert snapshot.source is not None
    hits = [h for h in snapshot.source.hits if h.kind == "shell_injection"]
    assert bool(hits) is not safe, snapshot.source
    assert summarize(snapshot)["source"].status == "completed", snapshot.source.skipped
    if hits:
        assert hits[0].file.startswith("project/server" if returns else "project/operations")


@pytest.mark.parametrize("language", ["py", "ts"])
@pytest.mark.parametrize("safe", [False, True])
@pytest.mark.parametrize("reverse", [False, True])
def test_duplicate_names_and_file_order_cannot_change_import_target(
    language: str,
    safe: bool,
    reverse: bool,
) -> None:
    imports = (
        "from .operations import run" if language == "py" else 'import {run} from "./operations";'
    )
    modules = [
        ("project/decoy", helper(language, safe=not safe)),
        ("project/operations", helper(language, safe=safe)),
    ]
    snapshot = analyze(
        language,
        [
            ("project/server", handler(language, imports, "run")),
            *(reversed(modules) if reverse else modules),
        ],
    )
    assert snapshot.source is not None
    hits = [h for h in snapshot.source.hits if h.kind == "shell_injection"]
    assert bool(hits) is not safe
    assert not snapshot.source.skipped
    assert all(h.file.startswith("project/operations") for h in hits)


@pytest.mark.parametrize("language", ["py", "ts"])
def test_unimported_helper_is_not_reached_by_name(language: str) -> None:
    snapshot = analyze(
        language,
        [
            ("project/server", handler(language, "", "run")),
            ("project/unrelated", helper(language, safe=False)),
        ],
    )
    assert snapshot.source is not None
    assert not [h for h in snapshot.source.hits if h.kind == "shell_injection"]


@pytest.mark.parametrize("language", ["py", "ts"])
@pytest.mark.parametrize("star", [False, True])
def test_reexports_and_package_entrypoints(language: str, star: bool) -> None:
    imports = (
        "from .public import invoke" if language == "py" else 'import {invoke} from "./public";'
    )
    exports = (
        "from ..operations import run as invoke"
        if language == "py"
        else 'export {run as invoke} from "../operations.js";'
    )
    files = [
        ("project/server", handler(language, imports, "invoke")),
        ("project/public/__init__" if language == "py" else "project/public/index", exports),
        ("project/operations", helper(language, safe=False)),
    ]
    if star:
        files[1] = (
            files[1][0],
            "from ..bridge import *" if language == "py" else 'export * from "../bridge";',
        )
        files.append(
            (
                "project/bridge",
                exports.replace("..operations", ".operations").replace(
                    "../operations.js", "./operations.js"
                ),
            )
        )
    snapshot = analyze(language, files)
    assert snapshot.source is not None
    assert any(h.kind == "shell_injection" for h in snapshot.source.hits)
    assert not snapshot.source.skipped


@pytest.mark.parametrize("language", ["py", "ts"])
@pytest.mark.parametrize("missing", ["module", "export", "cycle"])
def test_unresolved_local_imports_report_partial_coverage(language: str, missing: str) -> None:
    imports = (
        "from .operations import run as invoke"
        if language == "py"
        else ('import {run as invoke} from "./operations";')
    )
    files = [("project/server", handler(language, imports, "invoke"))]
    if missing != "module":
        code = "answer = 42" if language == "py" else "export const answer = 42;"
        if missing == "cycle":
            code = (
                "from .operations import run"
                if language == "py"
                else 'export {run} from "./operations";'
            )
        files.append(("project/operations", code))
    snapshot = analyze(language, files)
    check = summarize(snapshot)["source"]
    assert check.status == "partial", snapshot.source
    assert "local" in check.reason
    assert (
        summarize(ServerSnapshot.model_validate_json(snapshot.model_dump_json()))["source"] == check
    )


@pytest.mark.parametrize("requirement", ["--strict", "--require-coverage"])
def test_cli_rejects_incomplete_local_import_resolution(tmp_path: Path, requirement: str) -> None:
    (tmp_path / "server.py").write_text(handler("py", "from .missing import run", "run"))
    options = [requirement, "source"] if requirement == "--require-coverage" else [requirement]
    result = CliRunner().invoke(
        app, ["scan", "path:" + str(tmp_path), "--offline", "--no-lock", "-f", "json", *options]
    )
    assert result.exit_code == 2, result.output
    report = json.loads(result.stdout)
    assert report["servers"][0]["coverage"]["source"]["status"] == "partial"


def test_reexport_resolution_budget_is_visible(monkeypatch: pytest.MonkeyPatch) -> None:
    import mcpiranha.source.modules as modules

    monkeypatch.setattr(modules, "MAX_LINK_DEPTH", 1)
    graph = Graph(
        [
            Module("main.ts", set(), bindings={"run": Ref("ops", "run", 1)}),
            Module("ops.ts", {"run"}, exports={"run": Ref(None, "run")}),
        ]
    )
    assert "depth limit" in graph.resolve("main.ts", "run").reason


@pytest.mark.parametrize(
    "imports,call",
    [
        ('const invoke = require("./operations").run;', "invoke"),
        ('const ops_1 = __importStar(require("./operations"));', "(0, ops_1.run)"),
        ('const ops_1 = __importDefault(require("./operations"));', "ops_1.default"),
    ],
)
@pytest.mark.parametrize("safe", [False, True])
def test_commonjs_interop_returns(imports: str, call: str, safe: bool) -> None:
    snapshot = analyze(
        "ts",
        [
            ("project/server", handler("ts", imports, call, returns=True)),
            ("project/operations", helper("ts", safe=safe, returns=True)),
        ],
    )
    assert snapshot.source is not None
    assert any(h.kind == "shell_injection" for h in snapshot.source.hits) is not safe
    assert not snapshot.source.skipped


@pytest.mark.parametrize(
    "exports,call",
    [
        ("export default (value) => { exec(`git show ${value}`); };", "invoke"),
        ("export default function(value) { exec(`git show ${value}`); }", "invoke"),
        ("module.exports = (value) => { exec(`git show ${value}`); };", "ops"),
        ("exports.run = (value) => { exec(`git show ${value}`); };", "ops.run"),
        ("module.exports.run = function(value) { exec(`git show ${value}`); };", "ops.run"),
        ("function run(value) { exec(`git show ${value}`); } module.exports = {run};", "ops.run"),
    ],
)
def test_default_and_commonjs_function_exports(exports: str, call: str) -> None:
    imports = (
        'import invoke from "./operations";'
        if call == "invoke"
        else 'const ops = require("./operations");'
    )
    snapshot = analyze(
        "ts", [("project/server", handler("ts", imports, call)), ("project/operations", exports)]
    )
    assert snapshot.source is not None
    assert any(h.kind == "shell_injection" for h in snapshot.source.hits)
    assert not snapshot.source.skipped


@pytest.mark.parametrize("language", ["py", "ts"])
@pytest.mark.parametrize("callback", [False, True])
@pytest.mark.parametrize("safe", [False, True])
def test_imported_tool_handlers_and_iterable_callbacks(
    language: str,
    callback: bool,
    safe: bool,
) -> None:
    imports = (
        "from .operations import run as invoke"
        if language == "py"
        else 'import {run as invoke} from "./operations";'
    )
    if callback:
        code = (
            imports + "\n@server.tool()\ndef lookup(value):\n    list(map(invoke, value))\n"
            if language == "py"
            else imports + '\nserver.tool("lookup", {}, ({value}) => value.forEach(invoke));'
        )
    else:
        code = (
            imports + "\nserver.add_tool(invoke)\n"
            if language == "py"
            else imports + '\nserver.tool("lookup", {}, invoke);'
        )
    snapshot = analyze(
        language, [("project/server", code), ("project/operations", helper(language, safe=safe))]
    )
    assert snapshot.source is not None
    assert any(h.kind == "shell_injection" for h in snapshot.source.hits) is not safe
    assert not snapshot.source.skipped


@pytest.mark.parametrize("language", ["py", "ts"])
def test_external_import_never_resolves_to_unrelated_local_function(language: str) -> None:
    imports = (
        "from external_library import run as invoke"
        if language == "py"
        else 'import {run as invoke} from "external-library";'
    )
    snapshot = analyze(
        language,
        [
            ("project/server", handler(language, imports, "invoke")),
            ("project/unrelated", helper(language, safe=False)),
        ],
    )
    assert snapshot.source is not None
    assert not [h for h in snapshot.source.hits if h.kind == "shell_injection"]
    assert not snapshot.source.skipped


@pytest.mark.parametrize("language", ["py", "ts"])
def test_local_import_cannot_masquerade_as_a_sanitizer(language: str) -> None:
    code = (
        "from . import shlex\nimport os\n@server.tool()\ndef lookup(value):\n"
        '    os.system("git show " + shlex.quote(value))\n'
        if language == "py"
        else 'import {quote as shellQuote} from "./shlex";'
        'server.tool("lookup", {}, ({value}) => exec(`git show ${shellQuote(value)}`));'
    )
    fake = (
        "def quote(value):\n    return value\n"
        if language == "py"
        else "export function quote(value) { return value; }"
    )
    snapshot = analyze(language, [("project/server", code), ("project/shlex", fake)])
    assert snapshot.source is not None
    assert any(h.kind == "shell_injection" for h in snapshot.source.hits)
    assert not snapshot.source.skipped


def test_javascript_unexported_function_is_not_an_import_target() -> None:
    snapshot = analyze(
        "ts",
        [
            ("project/server", handler("ts", 'import {run} from "./operations";', "run")),
            ("project/operations", "function run(value) { exec(`git show ${value}`); }"),
        ],
    )
    assert snapshot.source is not None
    assert not [h for h in snapshot.source.hits if h.kind == "shell_injection"]
    assert summarize(snapshot)["source"].status == "partial"


def test_ambiguous_modules_are_not_resolved_by_input_order() -> None:
    graph = Graph(
        [
            Module("one/ops.py", {"run"}, python=True),
            Module("two/ops.py", {"run"}, python=True),
            Module("main.py", set(), python=True, bindings={"run": Ref("ops", "run")}),
        ]
    )
    result = graph.resolve("main.py", "run")
    assert result.target is None and "ambiguous" in result.reason


@pytest.mark.parametrize("language", ["py", "ts"])
def test_reassigned_local_callable_is_incomplete_and_retains_other_findings(language: str) -> None:
    imports = (
        "from .operations import run as invoke"
        if language == "py"
        else 'import {run as invoke} from "./operations";'
    )
    code = (
        imports + "\nimport os\n@server.tool()\ndef lookup(value):\n"
        '    invoke = value\n    invoke(value)\n    os.system("git show " + value)\n'
        if language == "py"
        else imports
        + '\nserver.tool("lookup", {}, ({value}) => { const invoke = value; invoke(value);'
        " exec(`git show ${value}`); });"
    )
    snapshot = analyze(
        language, [("project/server", code), ("project/operations", helper(language, safe=True))]
    )
    assert snapshot.source is not None
    assert any(h.kind == "shell_injection" for h in snapshot.source.hits)
    check = summarize(snapshot)["source"]
    assert check.status == "partial" and "shadowed or reassigned" in check.reason


@pytest.mark.parametrize("language", ["py", "ts"])
def test_known_constant_methods_do_not_generate_unresolved_import_warnings(language: str) -> None:
    code = (
        "from .constants import PREFIX\n@server.tool()\ndef lookup(value):\n"
        "    return PREFIX.startswith(value)\n"
        if language == "py"
        else 'import {TYPES} from "./constants";'
        'server.tool("lookup", {}, ({value}) => TYPES.includes(value));'
    )
    constants = (
        'PREFIX = "public"\n' if language == "py" else 'export const TYPES = ["text", "binary"];'
    )
    snapshot = analyze(language, [("project/server", code), ("project/constants", constants)])
    assert snapshot.source is not None and not snapshot.source.skipped


def test_object_methods_are_not_misclassified_as_constant_operations() -> None:
    snapshot = analyze(
        "ts",
        [
            ("project/server", handler("ts", 'import {ops} from "./operations";', "ops.run")),
            (
                "project/operations",
                "export const ops = { run(value) { exec(`git show ${value}`); } };",
            ),
        ],
    )
    assert summarize(snapshot)["source"].status == "partial"


@pytest.mark.parametrize("language", ["py", "ts"])
def test_namespace_tool_registration_uses_defining_module(language: str) -> None:
    code = (
        "from . import operations as ops\nserver.add_tool(ops.run)\n"
        if language == "py"
        else 'import * as ops from "./operations"; server.tool("lookup", {}, ops.run);'
    )
    snapshot = analyze(
        language, [("project/server", code), ("project/operations", helper(language, safe=False))]
    )
    assert snapshot.source is not None
    assert any(h.kind == "shell_injection" for h in snapshot.source.hits)
    assert not snapshot.source.skipped


def test_python_star_import_does_not_claim_builtin_calls() -> None:
    snapshot = analyze(
        "py",
        [
            (
                "project/server",
                "from .operations import *\n@server.tool()\ndef lookup(value):\n"
                "    print(value)\n    run(value)\n",
            ),
            ("project/operations", helper("py", safe=False)),
        ],
    )
    assert snapshot.source is not None
    assert any(h.kind == "shell_injection" for h in snapshot.source.hits)
    assert not snapshot.source.skipped
