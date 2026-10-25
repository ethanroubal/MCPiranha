"""A check must protect the particular value at the particular file operation."""

from pathlib import Path

import pytest

from mcpiranha.source import taint_javascript as js
from mcpiranha.source import taint_python as py

PY_PATH = "p = (ROOT / arg).resolve()\n"
PY_CHECK = 'if not p.is_relative_to(ROOT):\n    raise ValueError("outside")\n'
PY_READ = "return p.read_text()"
JS_PATH = "const base = path.resolve(ROOT); let p = path.resolve(ROOT, arg); "
JS_CHECK = 'if (!p.startsWith(base + path.sep)) throw new Error("outside"); '
JS_READ = "return fs.readFileSync(p);"


def python(body: str) -> bool:
    text = "@server.tool()\ndef handler(arg, other):\n" + "".join(
        "    " + line + "\n" for line in body.splitlines()
    )
    return any(h.kind == "path_traversal" for h in py.analyze("fixture.py", text))


def javascript(body: str) -> bool:
    text = 'server.tool("t", {}, ({arg, other}) => { ' + body + " });"
    return any(h.kind == "path_traversal" for h in js.analyze("fixture.js", text.encode()))


@pytest.mark.parametrize(
    "label", ["safe", "invalid", "relative_to", "realpath", "guard", "allowed"]
)
def test_python_unrelated_words_cannot_suppress_a_finding(label: str) -> None:
    assert python(f"note = {label!r}\n" + PY_PATH + PY_READ)


@pytest.mark.parametrize(
    "body",
    [
        PY_PATH + "p.is_relative_to(ROOT)\n" + PY_READ,
        PY_PATH + PY_READ + "\n" + PY_CHECK,
        PY_PATH + 'if not p.is_relative_to(ROOT):\n    print("outside")\n' + PY_READ,
        PY_PATH
        + "q = (ROOT / other).resolve()\nif not q.is_relative_to(ROOT): raise ValueError\n"
        + PY_READ,
        PY_PATH + "if not p.is_relative_to(OTHER_ROOT): raise ValueError\n" + PY_READ,
        PY_PATH + PY_CHECK + "p = (ROOT / other).resolve()\n" + PY_READ,
        PY_PATH + 'ROOT = Path("/")\n' + PY_CHECK + PY_READ,
        PY_PATH + "if enabled:\n    " + PY_CHECK.replace("\n", "\n    ").rstrip() + "\n" + PY_READ,
        PY_PATH + "assert p.is_relative_to(ROOT)\n" + PY_READ,
        PY_PATH + "try:\n    p.relative_to(ROOT)\nexcept ValueError:\n    pass\n" + PY_READ,
        "p = ROOT / arg\nif not p.is_relative_to(ROOT): raise ValueError\n" + PY_READ,
        PY_PATH + "if not str(p).startswith(str(ROOT)): raise ValueError\n" + PY_READ,
        'if "/" in other or other.startswith("."): raise ValueError\n' + PY_PATH + PY_READ,
        "p = os.path.join(ROOT, arg)\narg = other\n"
        'if "/" in arg or "\\\\" in arg or arg.startswith("."): raise ValueError\n'
        "return open(p).read()",
        PY_PATH + "if not p.is_relative_to(ROOT) and enabled: raise ValueError\n" + PY_READ,
        PY_PATH + "def unrelated():\n    p.relative_to(ROOT)\n" + PY_READ,
        PY_PATH + "safe_path(p)\n" + PY_READ,
    ],
)
def test_python_ineffective_guards_remain_findings(body: str) -> None:
    assert python(body)


@pytest.mark.parametrize(
    "body",
    [
        PY_PATH + PY_CHECK + PY_READ,
        PY_PATH + 'if not p.is_relative_to(ROOT): return "outside"\n' + PY_READ,
        PY_PATH + "if p.is_relative_to(ROOT):\n    " + PY_READ,
        PY_PATH + "if p.is_relative_to(ROOT):\n    pass\nelse:\n    raise ValueError\n" + PY_READ,
        PY_PATH + "p.relative_to(ROOT)\n" + PY_READ,
        PY_PATH + "q = p\nif not q.is_relative_to(ROOT): raise ValueError\n" + PY_READ,
        PY_PATH + "if not p.is_relative_to(ROOT) or disabled: raise ValueError\n" + PY_READ,
        'if "/" in arg or "\\\\" in arg or arg.startswith("."): return "invalid"\n'
        "return open(os.path.join(ROOT, arg)).read()",
        "p = os.path.join(ROOT, arg)\n"
        'if "/" in arg or "\\\\" in arg or ".." in arg: raise ValueError\n'
        "return open(p).read()",
    ],
)
def test_python_effective_guards_are_benign(body: str) -> None:
    assert not python(body)


@pytest.mark.parametrize(
    "noise",
    [
        'const note = "startsWith"; ',
        "// if (!p.startsWith(base + path.sep)) throw 1;\n",
        "function validatePath() {} ",
        'const note = "safePath("; ',
        'other.startsWith("safe"); ',
    ],
)
def test_javascript_unrelated_text_cannot_suppress_a_finding(noise: str) -> None:
    assert javascript(JS_PATH + noise + JS_READ)


@pytest.mark.parametrize(
    "body",
    [
        JS_PATH + "p.startsWith(base + path.sep); " + JS_READ,
        JS_PATH + 'if (!p.startsWith(base + path.sep)) console.log("outside"); ' + JS_READ,
        JS_PATH + "if (!p.startsWith(base)) throw 1; " + JS_READ,
        JS_PATH + "const q = path.resolve(ROOT, other); "
        "if (!q.startsWith(base + path.sep)) throw 1; " + JS_READ,
        JS_PATH + "const elsewhere = path.resolve(OTHER_ROOT); "
        "if (!p.startsWith(elsewhere + path.sep)) throw 1; " + JS_READ,
        JS_PATH + JS_CHECK + "p = path.resolve(ROOT, other); " + JS_READ,
        'let ROOT = "/srv"; const base = path.resolve(ROOT); ROOT = "/"; '
        "let p = path.resolve(ROOT, arg); " + JS_CHECK + JS_READ,
        JS_PATH + "if (enabled) { " + JS_CHECK + "} " + JS_READ,
        JS_PATH + "if (!p.startsWith(base + path.sep) && enabled) throw 1; " + JS_READ,
        JS_PATH + JS_READ + " " + JS_CHECK,
        JS_PATH + 'if (arg.includes("/")) console.log("outside"); ' + JS_READ,
        JS_PATH + "function unused() { " + JS_CHECK + " } " + JS_READ,
        JS_PATH + "validatePath(p); " + JS_READ,
        "let name = arg; const p = path.join(ROOT, name); name = other; "
        'if (name.includes("/") || name.startsWith(".")) throw 1; ' + JS_READ,
    ],
)
def test_javascript_ineffective_guards_remain_findings(body: str) -> None:
    assert javascript(body)


@pytest.mark.parametrize(
    "body",
    [
        JS_PATH + JS_CHECK + JS_READ,
        JS_PATH + 'if (!p.startsWith(base + path.sep)) return "outside"; ' + JS_READ,
        JS_PATH + "if (p.startsWith(base + path.sep)) { " + JS_READ + " }",
        JS_PATH + "if (p.startsWith(base + path.sep)) {} else { throw 1; } " + JS_READ,
        JS_PATH + "const q = p; if (!q.startsWith(base + path.sep)) throw 1; " + JS_READ,
        JS_PATH + "if (!p.startsWith(base + path.sep) || disabled) throw 1; " + JS_READ,
        'if (arg.includes("/") || arg.includes("\\\\") || arg.startsWith(".")) return "invalid"; '
        "return fs.readFileSync(path.join(ROOT, arg));",
    ],
)
def test_javascript_effective_guards_are_benign(body: str) -> None:
    assert not javascript(body)


@pytest.mark.parametrize("language", ["python", "javascript"])
@pytest.mark.parametrize("checked_argument", ["first", "both", "neither"])
def test_helper_protection_is_per_argument(language: str, checked_argument: str) -> None:
    if language == "python":
        first = PY_CHECK if checked_argument in ("first", "both") else ""
        second = (
            "if not q.is_relative_to(ROOT): raise ValueError\n"
            if checked_argument == "both"
            else ""
        )
        text = (
            "def helper(first, second):\n    open(first).read()\n    open(second).read()\n"
            "@server.tool()\ndef handler(arg, other):\n"
            + "".join(
                "    " + line + "\n"
                for line in (
                    PY_PATH + "q = (ROOT / other).resolve()\n" + first + second + "helper(p, q)"
                ).splitlines()
            )
        )
        hits = py.analyze("fixture.py", text)
    else:
        first = JS_CHECK if checked_argument in ("first", "both") else ""
        second = (
            "if (!q.startsWith(base + path.sep)) throw 1; " if checked_argument == "both" else ""
        )
        text = (
            "function helper(first, second) {\n"
            " fs.readFileSync(first);\n fs.readFileSync(second);\n}\n"
            'server.tool("t", {}, ({arg, other}) => { '
            + JS_PATH
            + "const q = path.resolve(ROOT, other); "
            + first
            + second
            + "helper(p, q); });"
        )
        hits = js.analyze("fixture.js", text.encode())
    paths = [h for h in hits if h.kind == "path_traversal"]
    assert len(paths) == {"both": 0, "first": 1, "neither": 2}[checked_argument]


@pytest.mark.parametrize("language", ["python", "javascript"])
def test_guard_budget_exhaustion_cannot_invent_protection(
    monkeypatch: pytest.MonkeyPatch, language: str
) -> None:
    module = "mcpiranha.source.path_guards_" + language
    monkeypatch.setattr(module + ".MAX_GUARD_NODES", 1)
    assert (
        python(PY_PATH + PY_CHECK + PY_READ)
        if language == "python"
        else javascript(JS_PATH + JS_CHECK + JS_READ)
    )


@pytest.mark.parametrize("language", ["python", "javascript"])
def test_checked_helper_alias_keeps_its_original_value(language: str) -> None:
    if language == "python":
        text = (
            "def helper(first):\n    alias = first\n    return open(alias).read()\n"
            "@server.tool()\ndef handler(arg):\n"
            + "".join(
                "    " + line + "\n"
                for line in (PY_PATH + PY_CHECK + "return helper(p)").splitlines()
            )
        )
        hits = py.analyze("fixture.py", text)
    else:
        text = (
            "function helper(first) { const alias = first; return fs.readFileSync(alias); }\n"
            'server.tool("t", {}, ({arg}) => { ' + JS_PATH + JS_CHECK + "return helper(p); });"
        )
        hits = js.analyze("fixture.js", text.encode())
    assert not any(h.kind == "path_traversal" for h in hits)


@pytest.mark.parametrize("language", ["python", "javascript"])
def test_reassigning_checked_helper_argument_removes_protection(language: str) -> None:
    if language == "python":
        text = (
            "def helper(first, other):\n    first = (ROOT / other).resolve()\n"
            "    return open(first).read()\n"
            "@server.tool()\ndef handler(arg, other):\n"
            + "".join(
                "    " + line + "\n"
                for line in (PY_PATH + PY_CHECK + "return helper(p, other)").splitlines()
            )
        )
        hits = py.analyze("fixture.py", text)
    else:
        text = (
            "function helper(first, other) { first = path.resolve(ROOT, other); "
            'return fs.readFileSync(first); }\nserver.tool("t", {}, ({arg, other}) => { '
            + JS_PATH
            + JS_CHECK
            + "return helper(p, other); });"
        )
        hits = js.analyze("fixture.js", text.encode())
    assert any(h.kind == "path_traversal" for h in hits)


def test_slash_only_component_rejection_is_not_a_portable_guard() -> None:
    # A Windows absolute path can replace the base without containing a forward slash.
    assert python(
        'if "/" in arg or arg.startswith("."): raise ValueError\n'
        "return open(os.path.join(ROOT, arg)).read()"
    )
    assert javascript(
        'if (arg.includes("/") || arg.startsWith(".")) throw 1; '
        "return fs.readFileSync(path.join(ROOT, arg));"
    )
    assert not python(
        'if "/" in arg or arg.startswith("."): raise ValueError\n'
        "return open(posixpath.join(ROOT, arg)).read()"
    )


@pytest.mark.parametrize("protected", [False, True])
def test_static_cli_reports_only_the_unprotected_path(tmp_path: Path, protected: bool) -> None:
    import json

    from typer.testing import CliRunner

    from mcpiranha.cli import app

    target = tmp_path / "server.py"
    body = PY_PATH + (PY_CHECK if protected else 'note = "safe"\n') + PY_READ
    target.write_text(
        "@server.tool()\ndef handler(arg):\n"
        + "".join("    " + line + "\n" for line in body.splitlines())
    )
    result = CliRunner().invoke(
        app, ["scan", str(target), "--offline", "--no-lock", "--fail-on", "medium", "-f", "json"]
    )
    assert result.exit_code == (0 if protected else 1), result.output
    report = json.loads(result.stdout)
    assert not report["errors"]
    hits = [f for f in report["findings"] if f["rule_id"] == "MCP-SRC-103"]
    assert len(hits) == int(not protected)
    if hits:
        assert Path(hits[0]["location"]["file"]).resolve() == target.resolve()
        assert hits[0]["evidence"][0]["text"] == "return p.read_text()"


@pytest.mark.parametrize(
    "body",
    [
        PY_PATH + "p.relative_to(ROOT, walk_up=True)\n" + PY_READ,
        PY_PATH + PY_CHECK + "with replacement() as p:\n    return p.read_text()",
        'if "/" in arg or "\\\\" in arg or arg.startswith(".", 2): raise ValueError\n'
        "return open(os.path.join(ROOT, arg)).read()",
    ],
)
def test_python_guard_options_and_rebinding_cannot_bypass_detection(body: str) -> None:
    assert python(body)


@pytest.mark.parametrize(
    "condition",
    [
        'arg.includes("/", 1) || arg.includes("\\\\") || arg.startsWith(".")',
        'arg.includes("/") || arg.includes("\\\\") || arg.startsWith(".", 2)',
    ],
)
def test_javascript_offset_checks_are_not_full_component_validation(condition: str) -> None:
    assert javascript(
        "if (" + condition + ") throw 1; return fs.readFileSync(path.resolve(ROOT, arg));"
    )
