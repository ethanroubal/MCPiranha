"""Check a built wheel as an installed CLI, independent of the source checkout."""

from __future__ import annotations

import json
import os
import subprocess
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
        "--with",
        str(wheels[0].resolve()),
        "mcpiranha",
    ]
    environment = {**os.environ, "MCPIRANHA_OFFLINE": "1", "PYTHONIOENCODING": "utf-8"}
    for arguments in (["--version"], ["--help"], ["scan", "--help"]):
        subprocess.run([*prefix, *arguments], env=environment, check=True, capture_output=True)
    with tempfile.TemporaryDirectory(prefix="mcpiranha-wheel-") as directory:
        project = Path(directory) / "source with spaces 測試"
        project.mkdir()
        source = project / "server.py"
        report = Path(directory) / "report.json"
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
            result = subprocess.run(
                [
                    *prefix,
                    "scan",
                    "path:" + str(project),
                    "--offline",
                    "--no-lock",
                    "--strict",
                    "--require-coverage",
                    "source",
                    "-f",
                    "json",
                    "-o",
                    str(report),
                ],
                env=environment,
                check=False,
                capture_output=True,
            )
            if result.returncode != int(unsafe):
                raise SystemExit(f"Wheel scan returned {result.returncode}; expected {int(unsafe)}")
            data = json.loads(report.read_text(encoding="utf-8"))
            assert not data["errors"] and not data["warnings"]
            assert data["servers"][0]["coverage"]["source"]["status"] == "completed"
            assert {finding["rule_id"] for finding in data["findings"]} == (
                {"MCP-SRC-101"} if unsafe else set()
            )
    print("Installed-wheel help, Unicode/space paths, unsafe/safe scans and exit codes passed.")


if __name__ == "__main__":
    main()
