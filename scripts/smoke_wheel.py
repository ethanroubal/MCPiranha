"""Check a built wheel as an installed CLI, independent of the source checkout."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


def main() -> None:
    wheels = list(Path("dist").glob("*.whl"))
    if len(wheels) != 1:
        raise SystemExit("Expected exactly one wheel in dist/; build in a clean checkout.")
    prefix = [
        "uv",
        "run",
        "--isolated",
        "--no-project",
        "--python",
        sys.executable,
        "--with",
        str(wheels[0].resolve()),
    ]
    environment = {**os.environ, "MCPIRANHA_OFFLINE": "1", "PYTHONIOENCODING": "utf-8"}
    for variable in ("PYTHONPATH", "PYTHONHOME"):
        environment.pop(variable, None)
    with tempfile.TemporaryDirectory(prefix="mcpiranha-wheel-") as directory:
        root = Path(directory)
        project = root / "source with spaces 測試"
        project.mkdir()
        home, appdata = root / "home", root / "roaming override 測試"
        home.mkdir()
        environment.update(HOME=str(home), USERPROFILE=str(home), APPDATA=str(appdata))

        def run(
            arguments: list[str], expected: int = 0, *, python: bool = False, cwd: Path = root
        ) -> None:
            result = subprocess.run(
                [*prefix, *(arguments if python else ["mcpiranha", *arguments])],
                cwd=cwd,
                env=environment,
                check=False,
                capture_output=True,
            )
            assert result.returncode == expected, (
                arguments,
                result.returncode,
                result.stdout.decode("utf-8", errors="replace"),
                result.stderr.decode("utf-8", errors="replace"),
            )

        # Check the interpreter and package origin as well as the console entry point. The
        # subprocess cwd is outside the checkout, with no editable/project import fallback.
        run(
            [
                "python",
                "-I",
                "-c",
                "import importlib.metadata, mcpiranha, pathlib, sys, sysconfig; "
                f"assert sys.version_info[:2] == {sys.version_info[:2]!r}; "
                "assert 'site-packages' in pathlib.Path(mcpiranha.__file__).parts; "
                "assert mcpiranha.__version__ == importlib.metadata.version('mcpiranha'); "
                "entry = 'mcpiranha.exe' if sys.platform == 'win32' else 'mcpiranha'; "
                "assert (pathlib.Path(sysconfig.get_path('scripts')) / entry).is_file()",
            ],
            python=True,
        )
        for arguments in (["--version"], ["--help"], ["scan", "--help"]):
            run(arguments)
        source, report = project / "server.py", root / "report.json"
        options = ["--offline", "--no-lock", "--strict", "-f", "json", "-o", str(report)]
        for unsafe in (True, False):
            body = (
                'os.system("git show " + value)'
                if unsafe
                else 'subprocess.run(["git", "show", value])'
            )
            source.write_text(
                "import os, subprocess\n@server.tool()\ndef lookup(value):\n    " + body + "\n",
                encoding="utf-8",
            )
            run(
                ["scan", "path:" + str(project), *options, "--require-coverage", "source"],
                int(unsafe),
            )
            data = json.loads(report.read_text(encoding="utf-8"))
            assert not data["errors"] and not data["warnings"]
            assert data["servers"][0]["coverage"]["source"]["status"] == "completed"
            assert {finding["rule_id"] for finding in data["findings"]} == (
                {"MCP-SRC-101"} if unsafe else set()
            )
            if unsafe:
                sarif_report = root / "report.sarif"
                run(
                    [
                        "scan",
                        "path:" + str(project),
                        "--offline",
                        "--no-lock",
                        "-f",
                        "sarif",
                        "-o",
                        str(sarif_report),
                    ],
                    1,
                )
                log = json.loads(sarif_report.read_text(encoding="utf-8"))
                uri = log["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
                    "artifactLocation"
                ]["uri"]
                assert " " not in uri and "%20" in uri and "%E6%B8%AC%E8%A9%A6" in uri

        config = project / ".mcp.json"
        config.write_text(
            "// Project configuration with BOM, comments and Unicode paths.\n"
            + json.dumps(
                {
                    "mcpServers": {
                        "project-selected": {"command": sys.executable, "args": [str(source)]},
                        "project-ignored": {"url": "http://insecure.invalid/mcp"},
                    }
                },
                ensure_ascii=False,
            ),
            encoding="utf-8-sig",
        )
        if sys.platform == "win32":
            support = appdata
            # A distinct APPDATA override must win over the home-directory fallback.
            decoy = home / "AppData" / "Roaming" / "Claude" / "claude_desktop_config.json"
            decoy.parent.mkdir(parents=True)
            decoy.write_text("{invalid JSON", encoding="utf-8")
        elif sys.platform == "darwin":
            support = home / "Library" / "Application Support"
        else:
            support = home / ".config"
        user_config = support / "Claude" / "claude_desktop_config.json"
        user_config.parent.mkdir(parents=True)
        user_config.write_text(
            json.dumps({"mcpServers": {"user-selected": {"url": "https://example.invalid/mcp"}}}),
            encoding="utf-8",
        )
        for target in ([str(config)], []):
            run(
                [
                    "scan",
                    *target,
                    *options,
                    "--server",
                    "project-selected",
                    "--require-coverage",
                    "source",
                ],
                cwd=project,
            )
            data = json.loads(report.read_text(encoding="utf-8"))
            assert not data["errors"] and not data["warnings"] and not data["findings"]
            [server] = data["servers"]
            assert server["id"] == "claude-code:project:project-selected"
            assert server["coverage"]["source"]["status"] == "completed"
            assert Path(server["origin"]["config_path"]).resolve() == config.resolve()
        run(
            ["scan", *options, "--client", "claude-desktop", "--require-coverage", "configuration"],
            cwd=project,
        )
        data = json.loads(report.read_text(encoding="utf-8"))
        assert not data["errors"] and not data["warnings"] and not data["findings"]
        [server] = data["servers"]
        assert server["id"] == "claude-desktop:user:user-selected"
        assert Path(server["origin"]["config_path"]).resolve() == user_config.resolve()
        assert server["coverage"]["configuration"]["status"] == "completed"
        run(["scan", *options, "--server", "missing-server"], 2, cwd=project)
    print("Installed-wheel CLI, detection, JSON/SARIF, config discovery and selection passed.")


if __name__ == "__main__":
    main()
