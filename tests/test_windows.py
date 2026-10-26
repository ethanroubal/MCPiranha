"""Windows command/path contracts also exercised by the native Windows CI matrix."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from mcpiranha.acquire.sandbox import stderr_log
from mcpiranha.core.launch import argv_pointer, command_line, executable_name, package_ref
from mcpiranha.core.models import Launch, Origin, ServerSnapshot
from mcpiranha.source import local_entry


@pytest.mark.parametrize("command", [r"C:\Program Files\nodejs\NPX.CMD", "npx.cmd", "NPX.EXE"])
@pytest.mark.parametrize("flags", [[], ["/d", "/s"], ["/Q", "/V:OFF", "/D"]])
def test_windows_cmd_wrappers_preserve_package_and_pointer(command: str, flags: list[str]) -> None:
    launch = Launch(
        transport="stdio",
        command=r"C:\Windows\System32\cmd.exe",
        args=[*flags, "/c", command, "-y", "server@1.2.3"],
    )
    assert executable_name(command) == "npx"
    assert command_line(launch) == [command, "-y", "server@1.2.3"]
    ref = package_ref(launch)
    assert ref is not None and ref.name == "server" and ref.spec == "1.2.3"
    assert argv_pointer(launch, ref.argv_index) == f"/launch/args/{len(flags) + 3}"


def test_unknown_cmd_switch_is_not_silently_discarded() -> None:
    launch = Launch(transport="stdio", command="cmd.exe", args=["/unexpected", "/c", "npx", "pkg"])
    assert command_line(launch)[0] == "cmd.exe" and package_ref(launch) is None


@pytest.mark.parametrize("command", [r"C:\Program Files\Python\python.exe", "python.EXE"])
def test_windows_interpreter_name_allows_static_source_collection(
    tmp_path: Path, command: str
) -> None:
    script = tmp_path / "server with spaces.py"
    script.write_text("value = 1\n", encoding="utf-8")
    snapshot = ServerSnapshot(
        id="windows",
        name="windows",
        origin=Origin(kind="config", ref="test"),
        launch=Launch(transport="stdio", command=command, args=[str(script)]),
    )
    assert local_entry(snapshot) == script.resolve()


def test_stderr_stream_captures_child_output_and_cleans_up() -> None:
    with stderr_log() as stream:
        path = Path(stream.name)
        subprocess.run(
            [sys.executable, "-c", 'import sys; sys.stderr.buffer.write("trace 測試".encode())'],
            stderr=stream,
            check=True,
        )
        stream.flush()
        stream.seek(0)
        assert stream.read() == "trace 測試"
    assert stream.closed and not path.exists() and not path.parent.exists()


@pytest.mark.skipif(sys.platform != "win32", reason="Requires native Windows directory junctions")
def test_source_scan_does_not_follow_windows_junctions(tmp_path: Path) -> None:
    import json

    from typer.testing import CliRunner

    from mcpiranha.cli import app

    root, external = tmp_path / "project", tmp_path / "external"
    root.mkdir()
    external.mkdir()
    (root / "good.py").write_text("value = 1\n", encoding="utf-8")
    (external / "bad.py").write_text("def broken(:\n", encoding="utf-8")
    junction = root / "linked"
    subprocess.run(
        ["cmd.exe", "/d", "/c", "mklink", "/J", str(junction), str(external)],
        check=True,
        capture_output=True,
    )
    try:
        assert junction.is_junction()
        result = CliRunner().invoke(
            app,
            [
                "scan",
                "path:" + str(root),
                "--offline",
                "--no-lock",
                "--require-coverage",
                "source",
                "-f",
                "json",
            ],
        )
        assert result.exit_code == 0, result.output
        coverage = json.loads(result.stdout)["servers"][0]["coverage"]["source"]
        assert coverage["status"] == "completed" and coverage["count"] == 1
    finally:
        junction.rmdir()
    assert (external / "bad.py").exists()
