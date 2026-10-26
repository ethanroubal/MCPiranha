"""--connect against real MCP servers (fixtures/servers), run on the host since they're ours."""

from __future__ import annotations

import json
import socket
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import anyio
import pytest
from pydantic import SecretStr
from typer.testing import CliRunner

from mcpiranha.acquire import ConnectOptions, connect_all, connect_one
from mcpiranha.acquire.oauth import OAuthError, check_authorization_url
from mcpiranha.cli import EXIT_FINDINGS, EXIT_OK, app
from mcpiranha.core.models import Launch, Origin, ServerSnapshot

SERVERS = Path(__file__).parent.parent / "fixtures" / "servers"
HOST = ConnectOptions(sandbox="none", timeout=30, observe_seconds=0.2)
runner = CliRunner()
FAKE_TOKEN = "ghp_" + "P0r1q2s3" * 5


def _snapshot(script: str, env: dict[str, str] | None = None) -> ServerSnapshot:
    return ServerSnapshot(
        id=f"test:{script}",
        name=script,
        origin=Origin(kind="config", client="test", ref=script),
        launch=Launch(
            transport="stdio",
            command=sys.executable,
            args=[str(SERVERS / script)],
            env={k: SecretStr(v) for k, v in (env or {}).items()},
        ),
        tools_listed=False,
    )


def _project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, servers: dict[str, Any]) -> Path:
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("USERPROFILE", str(tmp_path / "home"))
    monkeypatch.chdir(tmp_path)
    (tmp_path / "home").mkdir()
    config = tmp_path / ".mcp.json"
    config.write_text(json.dumps({"mcpServers": servers}), encoding="utf-8")
    return config


def _entry(script: str, **extra: Any) -> dict[str, Any]:
    return {"command": sys.executable, "args": [str(SERVERS / script)], **extra}


def _scan_json(*args: str) -> tuple[int, dict[str, Any]]:
    result = runner.invoke(app, ["scan", *args, "--connect", "--sandbox", "none", "-f", "json"])
    return result.exit_code, json.loads(result.stdout)


def test_poisoned_server_end_to_end(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _project(tmp_path, monkeypatch, {"calculator": _entry("poisoned.py")})
    code, report = _scan_json(".")
    assert code == EXIT_FINDINGS
    rules = {f["rule_id"] for f in report["findings"]}
    assert {"MCP-TP-003", "MCP-TP-004", "MCP-TP-005", "MCP-TP-009"} <= rules
    assert report["warnings"] == []


def test_listing_covers_prompts_resources_and_server_info() -> None:
    listed = anyio.run(connect_one, _snapshot("poisoned.py"), HOST)
    assert listed.tools_listed
    assert [t.name for t in listed.tools] == ["add"]
    assert [p.name for p in listed.prompts] == ["explain"]
    assert [r.uri for r in listed.resources] == ["calc://history"]
    assert listed.server_info is not None and listed.server_info.name == "poisoned-calculator"


def test_rug_pull_during_session_is_detected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch
                                             ) -> None:  # fmt: skip
    _project(tmp_path, monkeypatch, {"weather": _entry("rug_pull.py")})
    code, report = _scan_json(".")
    [finding] = [f for f in report["findings"] if f["rule_id"] == "MCP-RP-002"]
    assert finding["severity"] == "high"
    assert "get_weather" in finding["rationale"]
    assert code == EXIT_FINDINGS


def _probe_description(env: dict[str, str], *, real: bool, environ: dict[str, str]) -> str:
    options = ConnectOptions(sandbox="none", real_credentials=real, timeout=30, observe_seconds=0)
    listed = anyio.run(connect_one, _snapshot("env_probe.py", env), options, None, environ)
    return listed.tools[0].description or ""


def test_servers_get_dummy_env_by_default() -> None:
    description = _probe_description({"PROBE_TOKEN": FAKE_TOKEN}, real=False, environ={})
    assert description == "probe token=mcpiranha-dummy-value"


def test_real_credentials_expand_placeholders() -> None:
    env = {"PROBE_TOKEN": "${MY_TOKEN}"}
    assert _probe_description(env, real=True, environ={"MY_TOKEN": "from-env"}) == (
        "probe token=from-env"
    )
    # unresolvable placeholders fall back to the dummy instead of passing "${...}" through
    assert _probe_description(env, real=True, environ={}).endswith("mcpiranha-dummy-value")


def test_a_failing_server_is_a_warning_not_an_error() -> None:
    script = f"import sys; sys.stderr.write('boom {FAKE_TOKEN}'); sys.exit(3)"
    crash = ServerSnapshot(
        id="test:crash",
        name="crash",
        origin=Origin(kind="config", ref="crash"),
        launch=Launch(transport="stdio", command=sys.executable, args=["-c", script]),
        tools_listed=False,
    )
    results, warnings = anyio.run(connect_all, [crash, _snapshot("poisoned.py")], HOST)
    assert [s.tools_listed for s in results] == [False, True]
    [warning] = warnings
    assert "crash" in warning and "boom" in warning
    assert FAKE_TOKEN not in warning  # server stderr is masked


def test_lock_and_verify_with_connect(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = _project(tmp_path, monkeypatch, {"probe": _entry("env_probe.py", env={
        "PROBE_TOKEN": "${PROBE_SOURCE}"})})  # fmt: skip
    monkeypatch.setenv("PROBE_SOURCE", "v1")
    flags = ["--connect", "--sandbox", "none", "--real-credentials"]
    assert runner.invoke(app, ["lock", ".", *flags]).exit_code == EXIT_OK
    lock = json.loads((tmp_path / "mcp-lock.json").read_text(encoding="utf-8"))
    assert (
        lock["servers"]["claude-code:project:probe"]["tools"]["noop"]["definition"]["description"]
        == "probe token=v1"
    )
    assert "v1" not in json.dumps(lock["servers"]["claude-code:project:probe"]["launch"])

    assert runner.invoke(app, ["verify", ".", *flags]).exit_code == EXIT_OK
    monkeypatch.setenv("PROBE_SOURCE", "v2")  # the server now serves a different description
    changed = runner.invoke(app, ["verify", ".", *flags])
    assert changed.exit_code == EXIT_FINDINGS
    assert "probe token=v2" in changed.output
    assert config.is_file()


# --- remote ---------------------------------------------------------------------------------------


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def http_server() -> Iterator[str]:
    port = _free_port()
    proc = subprocess.Popen(
        [sys.executable, str(SERVERS / "http_open.py"), str(port)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            with socket.socket() as s:
                if s.connect_ex(("127.0.0.1", port)) == 0:
                    break
            time.sleep(0.1)
        else:
            pytest.fail("fixture HTTP server did not start")
        yield f"http://127.0.0.1:{port}/mcp"
    finally:
        proc.terminate()
        proc.wait(timeout=10)


def test_remote_server_without_auth(http_server: str) -> None:
    code, report = _scan_json(http_server)
    [finding] = [f for f in report["findings"] if f["rule_id"] == "MCP-CF-003"]
    assert finding["severity"] == "medium"  # delete_record changes state
    assert "delete_record" in finding["rationale"]
    assert "MCP-CF-002" not in {f["rule_id"] for f in report["findings"]}  # loopback http is fine
    assert code == EXIT_OK  # medium is below the default --fail-on high


def test_only_executable_or_remote_targets_need_connect() -> None:
    assert runner.invoke(app, ["scan", "npm:some-package", "--offline", "--no-lock"]).exit_code == 0
    assert runner.invoke(app, ["scan", "docker:some-image"]).exit_code == 2


def test_parallel_connections_keep_order() -> None:
    from mcpiranha.core.models import ClientSettings

    snapshots = [_snapshot("poisoned.py"), _snapshot("env_probe.py"), _snapshot("rug_pull.py")]
    disabled = _snapshot("poisoned.py").model_copy(
        update={"id": "test:off", "client_settings": ClientSettings(disabled=True)}
    )
    options = ConnectOptions(sandbox="none", timeout=30, observe_seconds=0.2, jobs=3)
    started = time.monotonic()
    results, warnings = anyio.run(connect_all, [*snapshots, disabled], options)
    elapsed = time.monotonic() - started
    assert warnings == []
    assert [s.name for s in results] == [
        "poisoned.py",
        "env_probe.py",
        "rug_pull.py",
        "poisoned.py",
    ]
    assert [s.tools_listed for s in results] == [True, True, True, False]  # disabled: skipped
    assert elapsed < 20


@pytest.fixture
def oauth_server() -> Iterator[str]:
    port = _free_port()
    proc = subprocess.Popen([sys.executable, str(SERVERS / "http_oauth.py"), str(port)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)  # fmt: skip
    try:
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            with socket.socket() as s:
                if s.connect_ex(("127.0.0.1", port)) == 0:
                    break
            time.sleep(0.1)
        else:
            pytest.fail("fixture OAuth server did not start")
        yield f"http://127.0.0.1:{port}/mcp"
    finally:
        proc.terminate()
        proc.wait(timeout=10)


def test_auth_required_server_gets_a_useful_hint(oauth_server: str) -> None:
    result = runner.invoke(app, ["scan", oauth_server, "--connect", "-f", "json"])
    [warning] = json.loads(result.stdout)["warnings"]
    assert "requires authentication" in warning and "--oauth" in warning


def test_header_sends_a_token_to_a_single_url(oauth_server: str) -> None:
    args = ["scan", oauth_server, "--connect", "-f", "json",
            "-H", "Authorization: Bearer static-test-token"]  # fmt: skip
    report = json.loads(runner.invoke(app, args).stdout)
    assert report["warnings"] == []
    assert "MCP-CF-003" not in {f["rule_id"] for f in report["findings"]}  # credentials were sent


def test_header_is_refused_for_anything_but_one_url(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _project(tmp_path, monkeypatch, {"a": _entry("poisoned.py")})
    result = runner.invoke(app, ["scan", ".", "--connect", "-H", "Authorization: Bearer x"])
    assert result.exit_code == 2
    assert "single server URL" in result.output


def test_oauth_sign_in(oauth_server: str) -> None:
    import urllib.request

    opened: list[str] = []

    def sign_in(url: str) -> None:  # stands in for the browser: the test server approves at once
        opened.append(url)
        urllib.request.urlopen(url).read()

    options = ConnectOptions(timeout=30, observe_seconds=0, oauth_open=sign_in)
    from mcpiranha.targets import package_target

    listed = anyio.run(connect_one, package_target(oauth_server), options)
    assert [t.name for t in listed.tools] == ["get_record"]
    assert opened and "code_challenge=" in opened[0]  # PKCE
    assert not [o for o in listed.observations if o.kind == "auth_not_required"]


@pytest.mark.parametrize(
    "url",
    [
        "file:///Applications/Calculator.app",
        "calc:",
        "javascript:alert(1)",
        "http://a.example/$(touch /tmp/x)\nx",
        "https:///no-host",
    ],
)
def test_authorization_url_from_server_metadata_is_checked(url: str) -> None:
    # CVE-2025-6514 (mcp-remote): the authorization_endpoint was opened as given
    with pytest.raises(OAuthError):
        check_authorization_url(url)
    check_authorization_url("https://auth.example.com/authorize?client_id=x&state=y")
