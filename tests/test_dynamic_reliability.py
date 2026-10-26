"""Adversarial and benign controls for the behavioral scanner, including external tracing."""

from __future__ import annotations

import functools
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import anyio
import pytest

from mcpiranha import acquire
from mcpiranha.acquire import ConnectOptions, connect_all
from mcpiranha.acquire import sandbox as sb
from mcpiranha.acquire.listing import EnumerationError
from mcpiranha.core.models import (
    DynamicObservation,
    Launch,
    Origin,
    ProbeRun,
    ServerSnapshot,
    ToolDef,
)
from mcpiranha.core.pipeline import scan
from mcpiranha.dynamic.invoke import cases
from mcpiranha.dynamic.trace import correlate, destination, observations
from mcpiranha.rules import load_rules

ROOT = Path(__file__).resolve().parent.parent


def target() -> ServerSnapshot:
    return ServerSnapshot(
        id="reliability",
        name="reliability",
        origin=Origin(kind="docker", ref="test"),
        tools_listed=False,
        launch=Launch(transport="stdio", command="docker", args=["run", "fixture"]),
    )


def test_crash_preserves_collected_evidence(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fail(*args: Any, **kwargs: Any) -> Any:
        raise EnumerationError("intentional crash")

    async def collected() -> list[DynamicObservation]:
        return [
            DynamicObservation(
                kind="file_open",
                phase="startup",
                detail='open("/tmp/mcpiranha-home/.ssh/id_rsa", O_RDONLY) = 3',
            )
        ]

    cleaned: list[bool] = []

    async def cleanup() -> None:
        cleaned.append(True)

    async def prepare(*args: Any, **kwargs: Any) -> sb.Prepared:
        return sb.Prepared(lambda: None, "fixture", cleanup=cleanup, collect=collected)  # type: ignore[arg-type]

    async def instrument(*args: Any, **kwargs: Any) -> None:
        pass

    from mcpiranha.dynamic import runtime

    monkeypatch.setattr(runtime, "instrument", instrument)
    monkeypatch.setattr(acquire, "prepare", prepare)
    monkeypatch.setattr(acquire, "enumerate_server", fail)
    snapshots, warnings = anyio.run(connect_all, [target()], ConnectOptions(dynamic=True))
    assert not snapshots[0].tools_listed and warnings and cleaned == [True]
    result = scan(snapshots, load_rules(plugins=False))
    assert any(f.rule_id == "MCP-DY-003" and f.severity == "critical" for f in result.findings)
    assert snapshots[0].model_validate_json(snapshots[0].model_dump_json()).observations


def test_trace_paths_split_records_and_interference() -> None:
    trace = "\n".join(
        [
            '1 1800000000.001 chdir("/tmp/mcpiranha-home") = 0',
            '1 1800000000.002 openat(AT_FDCWD, ".ssh/id_rsa", O_RDONLY <unfinished ...>',
            '2 1800000000.003 openat(4</tmp/mcpiranha-home/.aws>, "credentials", O_RDONLY) = 5',
            "1 1800000000.004 <... openat resumed>) = 3</tmp/mcpiranha-home/.ssh/id_rsa>",
            "1 1800000000.005 kill(99, SIGKILL) = -1 EPERM (Operation not permitted)",
        ]
    )
    events = observations(trace, [], protected_pids={"99"})
    assert {e.path for e in events if e.kind == "file_open"} == {
        "/tmp/mcpiranha-home/.ssh/id_rsa",
        "/tmp/mcpiranha-home/.aws/credentials",
    }
    result = scan([target().model_copy(update={"observations": events})], load_rules(plugins=False))
    assert {"MCP-DY-003", "MCP-DY-007"} <= {f.rule_id for f in result.findings}
    assert len([f for f in result.findings if f.rule_id == "MCP-DY-003"]) == 2


def test_trace_forks_cwd_ipv6_and_incomplete_records() -> None:
    trace = "\n".join(
        [
            '1 1800000000.001 chdir("/tmp/mcpiranha-home") = 0',
            "1 1800000000.002 clone(child_stack=NULL, flags=SIGCHLD) = 2",
            '2 1800000000.003 openat(AT_FDCWD, ".env", O_RDONLY) = 3',
            "2 1800000000.004 connect(3, {sa_family=AF_INET6, sin6_port=htons(80), "
            'inet_pton(AF_INET6, "::1", &sin6_addr)}, 28) = -1',
            '2 1800000000.005 openat(AT_FDCWD, "lost", O_RDONLY <unfinished ...>',
        ]
    )
    events = observations(trace, [])
    assert events[0].path == "/tmp/mcpiranha-home/.env"
    assert events[1].destination == "[::1]:80"
    assert events[-1].kind == "probe_error"


def test_nested_fuzz_and_correlated_canaries() -> None:
    schema = {
        "type": "object",
        "required": ["documents"],
        "properties": {
            "documents": {"type": "array", "minItems": 1, "items": {"$ref": "#/$defs/document"}}
        },
        "$defs": {
            "document": {
                "type": "object",
                "required": ["value"],
                "properties": {"value": {"type": "string"}},
            }
        },
    }
    generated = cases(ToolDef(name="probe", input_schema=schema), None, True)
    assert len(generated) == 4 and generated[1].argument_path == "/documents/0/value"
    assert generated[0].arguments["documents"][0]["value"] == "mcpiranha-test"
    now = datetime.now(UTC)
    runs = [
        ProbeRun(
            id="probe:2",
            tool="probe",
            variant="path_traversal",
            argument_path="/documents/0/value",
            started_at=now,
            finished_at=now + timedelta(seconds=1),
            status="completed",
        )
    ]
    events = correlate(
        [
            DynamicObservation(
                kind="file_open",
                phase="invocation",
                at=now,
                detail='open("/tmp/mcpiranha-canary", O_RDONLY) = 3',
                path="/tmp/mcpiranha-canary",
                success=True,
            ),
            DynamicObservation(
                kind="file_open", phase="listing", at=now + timedelta(seconds=2), detail="later"
            ),
        ],
        runs,
    )
    assert events[0].probe_id == "probe:2" and events[1].probe_id is None
    snapshot = target().model_copy(update={"observations": events, "probes": runs})
    result = scan([snapshot], load_rules(plugins=False))
    finding = next(f for f in result.findings if f.rule_id == "MCP-DY-006")
    assert finding.location.tool == "probe" and "probe:2" in finding.rationale
    restored = ServerSnapshot.model_validate_json(snapshot.model_dump_json())
    assert restored.probes == runs


def test_network_expected_activity_does_not_hide_unknown_destinations() -> None:
    events = [
        DynamicObservation(
            kind="net_connect",
            phase="startup",
            detail="expected",
            destination="expected.invalid:443",
            expected=True,
        ),
        DynamicObservation(
            kind="net_connect", phase="startup", detail="unexpected", destination="192.0.2.1:80"
        ),
        DynamicObservation(
            kind="net_connect",
            phase="startup",
            detail="proxy hop",
            destination="172.22.0.2:8080",
            infrastructure=True,
        ),
    ]
    result = scan([target().model_copy(update={"observations": events})], load_rules(plugins=False))
    assert {f.severity for f in result.findings if f.rule_id == "MCP-DY-004"} == {"info", "high"}
    assert not any("proxy hop" in e.text for f in result.findings for e in f.evidence)
    assert destination("EXAMPLE.COM.:443") == "example.com:443"
    assert destination("[::1]:443") == "[::1]:443"
    for invalid in (
        "*.example:443",
        "https://example.com",
        "user@example.com:443",
        "a:0",
        "a:65536",
    ):
        with pytest.raises(ValueError):
            destination(invalid)


@pytest.fixture(scope="module")
def adversarial_image(tmp_path_factory: pytest.TempPathFactory) -> str:
    if os.environ.get("MCPIRANHA_DOCKER_TESTS") != "1":
        pytest.skip("needs Docker and network")
    path = tmp_path_factory.mktemp("dynamic-adversarial")
    (path / "server.py").write_text((ROOT / "fixtures/servers/dynamic_adversarial.py").read_text())
    (path / "Dockerfile").write_text(
        'FROM python:3.12-slim\nCOPY server.py /server.py\nENTRYPOINT ["python", "/server.py"]\n'
    )
    image = "mcpiranha-adversarial-fixture:test"
    anyio.run(functools.partial(sb.docker, "build", "-q", "-t", image, str(path), timeout=300))
    return image


@pytest.mark.parametrize(
    "mode",
    [
        "crash",
        "relative",
        "tamper",
        "direct",
        "dns",
        "delayed",
        "benign",
        "expected",
        "sinks",
        "inherited",
        "mapped",
        "hardlink",
        "renamed",
        "rejected",
    ],
)
def test_real_adversarial_docker(
    adversarial_image: str, mode: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = sb._docker  # pyright: ignore[reportPrivateUsage]
    calls: list[tuple[str, ...]] = []

    async def docker(*args: str, timeout: float) -> str:
        calls.append(args)
        if args == ("pull", adversarial_image):
            return ""
        return await original(*args, timeout=timeout)

    monkeypatch.setattr(sb, "_docker", docker)
    snapshot = target().model_copy(
        update={
            "launch": Launch(
                transport="stdio", command="docker", args=["run", "-i", adversarial_image, mode]
            )
        }
    )
    found, warnings = anyio.run(
        connect_all,
        [snapshot],
        ConnectOptions(
            dynamic=True,
            timeout=45,
            observe_seconds=0.6 if mode == "delayed" else 0,
            invoke=("probe",)
            if mode in ("sinks", "inherited", "mapped", "hardlink", "renamed", "rejected")
            else (),
            fuzz=mode in ("sinks", "rejected"),
            expected_destinations=("expected.invalid:80",),
        ),
    )
    listed = found[0]
    result = scan(found, load_rules(plugins=False))
    rules = {f.rule_id for f in result.findings}
    if mode in ("crash", "relative", "tamper", "delayed"):
        assert "MCP-DY-003" in rules, listed.observations
    if mode == "crash":
        assert warnings and not listed.tools_listed
    elif mode == "rejected":
        assert warnings and listed.tools_listed and len(listed.probes) == 1
        assert listed.probes[0].result_error and listed.probes[0].schema_valid
    else:
        assert not warnings, warnings
    if mode in ("inherited", "mapped", "hardlink", "renamed"):
        accesses = [
            e
            for e in listed.observations
            if e.kind == "file_access" and e.probe_id == "probe:1" and e.honeytoken
        ]
        assert accesses, listed.observations
        assert "MCP-DY-003" in rules
        if mode == "mapped":
            assert any(e.syscall == "mmap" for e in accesses)
        else:
            assert any(e.byte_count and e.byte_count > 0 for e in accesses)
        assert not any(
            "MCPIRANHA_HONEYTOKEN_SYNTHETIC_ONLY" in e.detail for e in listed.observations
        )
    if mode == "tamper":
        assert "MCP-DY-007" in rules
        assert all(e.success is False for e in listed.observations if e.kind == "trace_tamper")
    if mode in ("direct", "dns"):
        assert "MCP-DY-004" in rules
    if mode == "benign":
        assert not [f for f in result.findings if f.detector == "dynamic"]
    if mode == "expected":
        dynamic = [f for f in result.findings if f.detector == "dynamic"]
        assert dynamic and all(f.severity == "info" for f in dynamic)
        assert any("denied" in e.detail for e in listed.observations)
    if mode == "sinks":
        assert len(listed.probes) == 4
        correlated = [e for e in listed.observations if e.probe_id]
        assert any(
            e.path == "/tmp/mcpiranha-canary" and e.probe_id == "probe:2" for e in correlated
        )
        assert any(
            e.kind == "process_spawn" and e.probe_id == "probe:3" and "MCPIRANHA_FUZZ" in e.detail
            for e in correlated
        )
        assert any(e.destination == "192.0.2.1:80" and e.probe_id == "probe:4" for e in correlated)
        assert "MCP-DY-006" in rules
        assert all(c.probe_id for c in listed.content if c.kind == "tool")
    for call in calls:
        if call[:2] == ("volume", "create"):
            assert ("volume", "rm", "-f", call[2]) in calls
        if call[:2] == ("network", "create"):
            assert ("network", "rm", call[-1]) in calls
    for call in calls:
        if call[:2] == ("run", "-d") and "--pid" in call:
            assert "SYS_PTRACE" in call and "--network" in call


def test_trace_cannot_be_hidden_by_syscall_text_in_filenames() -> None:
    events = observations(
        '1 1800000000.001 openat(AT_FDCWD, "O_WRONLY) = <unfinished ...>", O_RDONLY) '
        "= 3</tmp/mcpiranha-home/.ssh/id_rsa>",
        [],
    )
    assert len(events) == 1 and events[0].readable and events[0].success
    result = scan([target().model_copy(update={"observations": events})], load_rules(plugins=False))
    assert any(f.rule_id == "MCP-DY-003" for f in result.findings)


def test_dns_queries_are_not_all_treated_as_internal_transport() -> None:
    query = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    query += b"\x06canary\x07example\x07invalid\x00\x00\x01\x00\x01"
    packet = '"' + "".join(f"\\{byte:03o}" for byte in query) + '"'
    trace = "\n".join(
        [
            "1 1800000000.001 connect(3, {sa_family=AF_INET, sin_port=htons(53), "
            'sin_addr=inet_addr("127.0.0.11")}, 16) = 0',
            f"1 1800000000.002 sendto(3, {packet}, 40, 0, NULL, 0) = 40",
        ]
    )
    events = observations(trace, [])
    assert events[0].infrastructure
    assert events[1].destination == "canary.example.invalid:53" and not events[1].infrastructure
    result = scan([target().model_copy(update={"observations": events})], load_rules(plugins=False))
    assert any(f.rule_id == "MCP-DY-004" and f.severity == "high" for f in result.findings)


def test_probe_windows_use_transport_clock_and_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    import sys

    from mcpiranha.acquire.listing import enumerate_server

    async def run(clock_fails: bool) -> Any:
        with sb.stderr_log() as errlog:
            prepared = await sb.prepare(
                Launch(
                    transport="stdio",
                    command=sys.executable,
                    args=[str(ROOT / "fixtures/servers/dynamic_probe.py")],
                ),
                sandbox="none",
                real_credentials=False,
                errlog=errlog,
                environ={},
            )
            clock = datetime.now(UTC) + timedelta(seconds=90)

            async def changed(probe: ProbeRun, started: bool) -> None:
                if started:
                    probe.started_at = clock
                else:
                    if clock_fails:
                        raise RuntimeError("clock unavailable")
                    probe.finished_at = clock + timedelta(seconds=1)

            try:
                return await enumerate_server(
                    prepared.connect(), invoke=("echo",), observe_seconds=0, probe_changed=changed
                )
            finally:
                await prepared.cleanup()

    found = anyio.run(run, False)
    assert found.probes[0].finished_at - found.probes[0].started_at == timedelta(seconds=1)
    assert found.probes[0].started_at > datetime.now(UTC) + timedelta(seconds=80)
    failed = anyio.run(run, True)
    assert failed.probes[0].finished_at is None
    assert any(e.kind == "probe_error" for e in failed.observations)
    events = correlate(
        [
            DynamicObservation(
                kind="file_open", phase="invocation", detail="later", at=failed.probes[0].started_at
            )
        ],
        failed.probes,
    )
    assert events[0].probe_id is None
