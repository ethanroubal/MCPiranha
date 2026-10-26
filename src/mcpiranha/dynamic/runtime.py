"""Run trusted tracing in a separate container; the target never mounts its trace volume."""

from __future__ import annotations

import contextlib
import json
import tempfile
import time
import uuid
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import anyio

from mcpiranha.acquire import sandbox as sb
from mcpiranha.core.hashing import hash_json
from mcpiranha.core.launch import docker_run
from mcpiranha.core.models import DynamicObservation, Launch, ProbeRun
from mcpiranha.dynamic.trace import Phase, destination, observations

MAX_TRACE = 8 * 1024 * 1024


async def instrument(
    prepared: sb.Prepared, *, allow_network: bool, expected_destinations: tuple[str, ...] = ()
) -> None:
    expected_destinations = tuple(destination(v) for v in expected_destinations)
    command = prepared.command
    if not command or command[0] != "docker":
        raise sb.SandboxError("--dynamic requires a Docker sandbox")
    parsed = docker_run(Launch(transport="stdio", command="docker", args=command[1:]))
    if parsed is None:
        raise sb.SandboxError("cannot identify the sandbox image")
    image_index = parsed.argv_index
    image = command[image_index]
    config: dict[str, Any] = json.loads(
        await sb.docker("image", "inspect", "--format", "{{json .Config}}", image, timeout=30)
    )
    entry = list(config.get("Entrypoint") or [])
    run_options = command[1:image_index]
    if "--entrypoint" in run_options:
        index = run_options.index("--entrypoint")
        entry = [run_options[index + 1]]
        del run_options[index : index + 2]
    argv = command[image_index + 1 :] or list(config.get("Cmd") or [])
    if not entry and not argv:
        raise sb.SandboxError("image has no executable")
    cwd = str(config.get("WorkingDir") or "/")
    if "--workdir" in run_options:
        cwd = run_options[run_options.index("--workdir") + 1]
    tag = uuid.uuid4().hex[:12]
    network, proxy, volume, tools = (
        f"mcpiranha-{part}-{tag}" for part in ("net", "proxy", "trace", "tools")
    )
    sources = {
        name: Path(__file__).with_name(name).read_text(encoding="utf-8")
        for name in ("proxy.py", "collector.py", "launcher.c")
    }
    helper = "mcpiranha-instrument:" + hash_json([sources, 2])[:16]
    boundaries: list[tuple[float, Phase]] = []
    resources: list[tuple[str, ...]] = []
    tracers: list[tuple[str, str]] = []
    protected_pids: dict[str, set[str]] = {}
    original_cleanup = prepared.cleanup

    async def cleanup() -> None:
        with anyio.CancelScope(shield=True):
            await original_cleanup()
            for args in reversed(resources):
                with contextlib.suppress(sb.SandboxError):
                    await sb.docker(*args, timeout=30)

    prepared.cleanup = cleanup

    def phase_changed(phase: str) -> None:
        if phase in ("startup", "listing", "invocation"):
            boundaries.append((time.time(), phase))

    prepared.phase_changed = phase_changed
    with tempfile.TemporaryDirectory(prefix="mcpiranha-build-") as directory:
        path = Path(directory)
        for name, source in sources.items():
            (path / name).write_text(source, encoding="utf-8")
        (path / "Dockerfile").write_text(
            "FROM python:3.12-slim-bookworm\n"
            "RUN apt-get update && apt-get install -y --no-install-recommends strace gcc libc6-dev "
            "&& rm -rf /var/lib/apt/lists/*\n"
            "COPY launcher.c /launcher.c\n"
            "RUN mkdir /opt/mcpiranha && gcc -static -O2 -Wall -Werror /launcher.c "
            "-o /opt/mcpiranha/launcher\n"
            "COPY collector.py /collector.py\nCOPY proxy.py /proxy.py\nUSER 1000:1000\n"
            'ENTRYPOINT ["python", "-u", "/proxy.py"]\n',
            encoding="utf-8",
        )
        await sb.docker("build", "-q", "-t", helper, directory, timeout=sb.FETCH_TIMEOUT)
    for name in (tools, volume):
        resources.append(("volume", "rm", "-f", name))
        await sb.docker("volume", "create", name, timeout=30)
    await sb.docker(
        "run",
        "--rm",
        "--network",
        "none",
        "--cap-drop",
        "ALL",
        "--user",
        "0",
        "-v",
        f"{tools}:/tools",
        "--entrypoint",
        "sh",
        helper,
        "-c",
        "cp -R /opt/mcpiranha/. /tools/",
        timeout=30,
    )
    resources.append(("network", "rm", network))
    await sb.docker("network", "create", "--internal", network, timeout=30)
    resources.append(("rm", "-f", proxy))
    await sb.docker(
        "run",
        "-d",
        "--name",
        proxy,
        "--network",
        "bridge",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        "64",
        "--memory",
        "128m",
        "--cpus",
        "0.5",
        "--log-opt",
        "max-size=2m",
        "--log-opt",
        "max-file=2",
        "-e",
        f"ALLOW_NETWORK={int(allow_network)}",
        helper,
        timeout=30,
    )
    await sb.docker("network", "connect", "--alias", "mcpiranha-egress", network, proxy, timeout=30)
    proxy_ip = (
        await sb.docker(
            "inspect",
            "--format",
            '{{(index .NetworkSettings.Networks "' + network + '").IPAddress}}',
            proxy,
            timeout=30,
        )
    ).strip()
    proxy_destination = f"{proxy_ip}:8080" if proxy_ip else None
    run_options.remove("--rm")
    if "--network" in run_options:
        index = run_options.index("--network")
        del run_options[index : index + 2]
    command[:] = [
        "docker",
        *run_options,
        "--network",
        network,
        "--user",
        "1000:1000",
        "-v",
        f"{tools}:/mcpiranha:ro",
        "-e",
        "HTTP_PROXY=http://mcpiranha-egress:8080",
        "-e",
        "HTTPS_PROXY=http://mcpiranha-egress:8080",
        "-e",
        "http_proxy=http://mcpiranha-egress:8080",
        "-e",
        "https_proxy=http://mcpiranha-egress:8080",
        "-e",
        "NO_PROXY=",
        "-e",
        "no_proxy=",
        "--entrypoint",
        "/mcpiranha/launcher",
        image,
        *entry,
        *argv,
    ]
    connect = prepared.connect

    @asynccontextmanager
    async def traced_connect() -> AsyncGenerator[Any, None]:
        phase_changed("startup")
        transport = connect()  # allocates a unique target container name
        async with transport as streams:
            target = prepared.containers[-1]
            with anyio.fail_after(15):
                while True:
                    try:
                        running = await sb.docker(
                            "inspect", "--format", "{{.State.Running}}", target, timeout=3
                        )
                        if running.strip() == "true":
                            break
                    except sb.SandboxError:
                        pass
                    await anyio.sleep(0.05)
            name, tracefile = f"mcpiranha-tracer-{tag}-{len(tracers)}", f"events.{len(tracers)}"
            resources.append(("rm", "-f", name))
            tracers.append((name, tracefile))
            await sb.docker(
                "run",
                "-d",
                "--name",
                name,
                "--network",
                "none",
                "--read-only",
                "--user",
                "0:0",
                "--cap-drop",
                "ALL",
                "--cap-add",
                "SYS_PTRACE",
                "--security-opt",
                "no-new-privileges",
                "--pid",
                f"container:{target}",
                "--pids-limit",
                "64",
                "--memory",
                "128m",
                "--cpus",
                "0.5",
                "--ulimit",
                f"fsize={MAX_TRACE}:{MAX_TRACE}",
                "-v",
                f"{volume}:/trace",
                "--entrypoint",
                "python",
                helper,
                "-u",
                "/collector.py",
                f"/trace/{tracefile}",
                timeout=30,
            )
            with anyio.fail_after(15):
                while True:
                    logs = await sb.docker("logs", name, timeout=3)
                    if '"ready": true' in logs:
                        ready = next(
                            json.loads(line)
                            for line in logs.splitlines()
                            if '"ready": true' in line
                        )
                        protected_pids[tracefile] = {
                            str(ready[k]) for k in ("collector_pid", "tracer_pid")
                        }
                        break
                    if '"error":' in logs:
                        raise sb.SandboxError(f"tracing failed: {logs[:300]}")
                    await anyio.sleep(0.05)
            await sb.docker("kill", "--signal", "USR1", target, timeout=10)
            yield streams

    async def probe_changed(probe: ProbeRun, started: bool) -> None:
        # Trace timestamps and call boundaries must use the same VM clock. Host clocks can
        # differ enough to attribute fast calls to the wrong probe on Docker Desktop.
        clock = await sb.docker(
            "exec", tracers[-1][0], "python", "-c", "import time; print(time.time())", timeout=5
        )
        at = datetime.fromtimestamp(float(clock.strip()), UTC)
        if started:
            probe.started_at = at
        else:
            probe.finished_at = at

    prepared.probe_changed = probe_changed
    prepared.connect = traced_connect
    prepared.label += ", isolated tracer, honeytokens, logging egress proxy"

    async def collect() -> list[DynamicObservation]:
        result: list[DynamicObservation] = []
        with anyio.CancelScope(shield=True):
            await prepared.stop()
            for name, tracefile in tracers:
                try:
                    await sb.docker("wait", name, timeout=10)
                    trace = await sb.docker(
                        "run",
                        "--rm",
                        "--network",
                        "none",
                        "--read-only",
                        "--cap-drop",
                        "ALL",
                        "--user",
                        "0",
                        "-v",
                        f"{volume}:/trace:ro",
                        "--entrypoint",
                        "head",
                        helper,
                        "-c",
                        str(MAX_TRACE),
                        f"/trace/{tracefile}",
                        timeout=30,
                    )
                    parsed_events = observations(
                        trace,
                        boundaries,
                        cwd=cwd,
                        expected_destinations=expected_destinations,
                        proxy_destination=proxy_destination,
                        protected_pids=protected_pids.get(tracefile, set()),
                    )
                    result.extend(parsed_events)
                    if not parsed_events or len(trace.encode()) >= MAX_TRACE:
                        result.append(
                            DynamicObservation(
                                kind="probe_error",
                                phase="listing",
                                detail="syscall trace absent or truncated",
                            )
                        )
                except Exception as exc:
                    result.append(
                        DynamicObservation(
                            kind="probe_error",
                            phase="listing",
                            detail=f"trace collection failed: {type(exc).__name__}: {exc}",
                        )
                    )
            try:
                logs = await sb.docker("logs", proxy, timeout=30)
                for line in logs.splitlines():
                    event = json.loads(line)
                    phase: Phase = "startup"
                    for at, label in boundaries:
                        if at <= event["time"]:
                            phase = label
                    target = destination(event["target"])
                    result.append(
                        DynamicObservation(
                            kind="net_connect",
                            phase=phase,
                            at=datetime.fromtimestamp(event["time"], UTC),
                            destination=target,
                            expected=target in expected_destinations,
                            detail=f"egress proxy: {target} "
                            f"({'allowed' if event['allowed'] else 'denied'})",
                        )
                    )
            except Exception as exc:
                result.append(
                    DynamicObservation(
                        kind="probe_error",
                        phase="listing",
                        detail=f"proxy collection failed: {type(exc).__name__}: {exc}",
                    )
                )
            if not tracers:
                result.append(
                    DynamicObservation(
                        kind="probe_error", phase="startup", detail="no tracer was started"
                    )
                )
        return result

    prepared.collect = collect
