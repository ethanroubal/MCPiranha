"""`--connect`: start (or reach) each server and fill its snapshot with what it really serves."""

from __future__ import annotations

import os
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

import anyio

from mcpiranha.acquire.listing import (
    Enumeration,
    EnumerationError,
    Handshake,
    enumerate_server,
    observe_classic,
)
from mcpiranha.acquire.oauth import OAuthError, OpenUrl
from mcpiranha.acquire.sandbox import Prepared, Sandbox, SandboxError, prepare, stderr_log
from mcpiranha.core.coverage import record
from mcpiranha.core.models import CoverageCheck, DynamicObservation, ServerSnapshot
from mcpiranha.core.secrets import mask_secrets

ProgressFn = Callable[[ServerSnapshot, str], None]
_STDERR_TAIL = 300


@dataclass(frozen=True, slots=True)
class ConnectOptions:
    dynamic: bool = False
    invoke: tuple[str, ...] = ()
    invoke_args: dict[str, Any] | None = None
    fuzz: bool = False
    expected_destinations: tuple[str, ...] = ()
    sandbox: Sandbox = "docker"
    real_credentials: bool = False
    timeout: float = 60.0
    observe_seconds: float = 1.0
    jobs: int = 4  # servers connected to at the same time
    extra_headers: Mapping[str, str] | None = None  # --header, for a single URL target
    oauth_open: OpenUrl | None = None  # --oauth: opens the sign-in URL (a browser, normally)
    allow_network: bool = False  # sandboxed servers may use the network while running
    allow_install_scripts: bool = False  # npm install scripts and PyPI source builds may run


def _auth_hint(snapshot: ServerSnapshot, options: ConnectOptions, message: str,
               statuses: Sequence[int]) -> str:  # fmt: skip
    denied = {401, 403} & set(statuses)
    if not denied and not any(s in message for s in ("401", "403", "Unauthorized", "Forbidden")):
        return ""
    if snapshot.launch and snapshot.launch.headers and not options.real_credentials:
        return " It requires authentication: rerun with --real-credentials to send its headers."
    if options.oauth_open is None:
        return (
            " It requires authentication: rerun with --oauth to sign in, or pass a token with "
            "--header."
        )
    return " It requires authentication, and signing in didn't succeed."


async def _enumerate_with_fallback(prepared: Prepared, options: ConnectOptions) -> Enumeration:
    """Try the SDK's default handshake, then the classic one in a fresh connection: some older
    servers crash on the 2026 `server/discover` probe instead of rejecting it."""
    invoked = False

    def phase_changed(phase: str) -> None:
        nonlocal invoked
        invoked = invoked or phase == "invocation"
        prepared.phase_changed(phase)

    async def attempt(handshake: Handshake) -> Enumeration:
        return await enumerate_server(
            prepared.connect(),
            timeout=options.timeout,
            observe_seconds=options.observe_seconds,
            handshake=handshake,
            invoke=options.invoke,
            invoke_args=options.invoke_args,
            fuzz=options.fuzz,
            phase_changed=phase_changed,
            probe_changed=prepared.probe_changed,
        )

    try:
        return await attempt("auto")
    except EnumerationError as first:
        if invoked or {401, 403} & set(prepared.http_statuses):
            raise  # never replay side effects after invocation began
        try:
            return await attempt("legacy")
        except EnumerationError as second:
            raise EnumerationError(
                f"{second} (also failed with the 2026 handshake: {first})"
            ) from second


CLASSIC_UNTIL = "2026-07-28"  # the first protocol version without mid-request server requests


async def _observe_classic(prepared: Prepared, options: ConnectOptions, found: Enumeration) -> None:
    """A second, classic-protocol session to see what the server sends clients that allow it
    (sampling, elicitation, roots, logs). Best effort: a server that won't speak it is fine."""
    try:
        extra = await observe_classic(prepared.connect(), timeout=options.timeout)
    except Exception:  # the main listing already succeeded
        return
    seen = {(c.kind, c.ref, c.text) for c in found.content}
    found.content += [c for c in extra.content if (c.kind, c.ref, c.text) not in seen]
    found.observations += extra.observations


async def connect_one(
    snapshot: ServerSnapshot,
    options: ConnectOptions,
    progress: ProgressFn | None = None,
    environ: Mapping[str, str] | None = None,
) -> ServerSnapshot:
    """The snapshot with tools, prompts, resources and observations filled in."""
    if options.fuzz and not options.invoke:
        raise SandboxError("--fuzz requires named --invoke tools")
    if options.dynamic and (
        options.sandbox != "docker" or (snapshot.launch and snapshot.launch.transport != "stdio")
    ):
        raise SandboxError("--dynamic requires a Docker-sandboxed stdio server")
    if snapshot.launch is None:
        raise SandboxError("no launch configuration")
    with stderr_log() as errlog:
        prepared = await prepare(
            snapshot.launch,
            sandbox=options.sandbox,
            real_credentials=options.real_credentials,
            errlog=errlog,
            environ=os.environ if environ is None else environ,
            extra_headers=options.extra_headers,
            oauth_open=options.oauth_open,
            allow_network=options.allow_network,
            allow_install_scripts=options.allow_install_scripts,
        )
        if options.dynamic:
            from mcpiranha.dynamic.runtime import instrument

            try:
                await instrument(
                    prepared,
                    allow_network=options.allow_network,
                    expected_destinations=options.expected_destinations,
                )
            except BaseException:
                await prepared.cleanup()
                raise
        if progress:
            progress(snapshot, f"connecting ({prepared.label})")
        failed = False
        try:
            found = await _enumerate_with_fallback(prepared, options)
            if found.protocol_version >= CLASSIC_UNTIL and (found.prompts or found.resources):
                await _observe_classic(prepared, options, found)
        except EnumerationError as exc:
            errlog.flush()
            errlog.seek(0)
            tail = mask_secrets(errlog.read()[-_STDERR_TAIL:].strip())
            message = str(exc) + _auth_hint(snapshot, options, str(exc), prepared.http_statuses)
            if not options.dynamic:
                raise EnumerationError(
                    message + (f" Server stderr: {tail}" if tail else "")
                ) from exc
            failed = True
            found = Enumeration(
                observations=[
                    DynamicObservation(
                        kind="probe_error",
                        phase="startup",
                        detail=mask_secrets(message + (f" Server stderr: {tail}" if tail else "")),
                    )
                ]
            )
        finally:
            try:
                runtime = await prepared.collect()
            finally:
                await prepared.cleanup()

    observations = [*snapshot.observations, *found.observations, *runtime]
    from mcpiranha.dynamic.trace import correlate

    observations = correlate(observations, found.probes)
    if prepared.remote and not prepared.sent_credentials and not failed:
        observations.append(
            DynamicObservation(
                kind="auth_not_required",
                phase="listing",
                detail=f"listed {len(found.tools)} tool(s) without sending any credentials",
            )
        )
    listed = snapshot.model_copy(
        update={
            "server_info": found.server_info,
            "tools": found.tools,
            "earlier_tools": found.earlier_tools,
            "prompts": found.prompts,
            "resources": found.resources,
            "observations": observations,
            "content": found.content,
            "tools_listed": not failed,
            "probes": found.probes,
            "package": prepared.resolved or snapshot.package,
        }
    )

    listed = record(
        listed,
        "tools",
        CoverageCheck(
            status="failed" if failed else "completed",
            reason="Server initialization/listing failed; metadata is unknown."
            if failed
            else "Tool listing completed.",
            count=None if failed else len(found.tools),
        ),
    )
    if options.dynamic:
        errors = [
            o.detail
            for o in [*found.observations, *runtime]
            if o.kind == "probe_error" and o.phase != "invocation"
        ]
        listed = record(
            listed,
            "dynamic",
            CoverageCheck(
                status="partial" if errors or failed else "completed",
                reason=mask_secrets("; ".join(errors))
                if errors
                else "Bounded syscall/egress tracing completed; unexercised paths remain unknown.",
            ),
        )
    if options.invoke:
        errors = [o.detail for o in found.observations if o.kind == "probe_error"]
        completed = sum(p.status == "completed" for p in found.probes)
        listed = record(
            listed,
            "invocation",
            CoverageCheck(
                status="partial"
                if errors or failed or completed != len(found.probes)
                else "completed",
                reason=mask_secrets("; ".join(errors))
                if errors
                else f"{completed}/{len(found.probes)} calls completed. "
                "Completion does not mean the tool accepted the input.",
                count=completed,
            ),
        )
    return listed


async def connect_all(
    snapshots: Sequence[ServerSnapshot],
    options: ConnectOptions,
    progress: ProgressFn | None = None,
) -> tuple[list[ServerSnapshot], list[str]]:
    """Connect to every server that hasn't been listed yet, `options.jobs` at a time. Results
    keep the input order. A server that fails keeps its config-only snapshot and produces a
    warning; it doesn't stop the scan. Servers disabled in their client config are skipped."""
    results: list[ServerSnapshot] = list(snapshots)
    warnings: dict[int, str] = {}
    limiter = anyio.CapacityLimiter(max(1, options.jobs))

    async def one(i: int, snapshot: ServerSnapshot) -> None:
        async with limiter:
            try:
                listed = await connect_one(snapshot, options, progress)
            except Exception as exc:  # any failure is this server's problem, not the scan's
                known = isinstance(exc, (SandboxError, EnumerationError, OAuthError))
                warnings[i] = f"could not list {snapshot.name!r}: " + (
                    str(exc) if known else f"{type(exc).__name__}: {exc}"
                )
                results[i] = record(
                    snapshot,
                    "tools",
                    CoverageCheck(status="failed", reason=mask_secrets(warnings[i])),
                )
                if options.dynamic:
                    results[i] = record(
                        results[i],
                        "dynamic",
                        CoverageCheck(
                            status="failed", reason="Could not establish a traced server session."
                        ),
                    )
                if options.invoke:
                    results[i] = record(
                        results[i],
                        "invocation",
                        CoverageCheck(
                            status="skipped",
                            reason="Server connection failed before invocation.",
                            count=0,
                        ),
                    )
                if progress:
                    progress(snapshot, "failed")
                return
        if progress:
            progress(snapshot, f"listed {len(listed.tools)} tool(s), {len(listed.prompts)} "
                     f"prompt(s), {len(listed.resources)} resource(s)")  # fmt: skip
        incomplete = [o.detail for o in listed.observations if o.kind == "probe_error"]
        if incomplete:
            warnings[i] = mask_secrets(
                f"incomplete behavioral scan of {snapshot.name!r}: " + "; ".join(incomplete)
            )
        results[i] = listed

    async with anyio.create_task_group() as group:
        for i, snapshot in enumerate(snapshots):
            if snapshot.tools_listed or snapshot.launch is None:
                continue
            if snapshot.client_settings and snapshot.client_settings.disabled:
                for stage in ("tools", "dynamic", "invocation"):
                    results[i] = record(
                        results[i],
                        stage,
                        CoverageCheck(
                            status="skipped", reason="Server disabled in client configuration."
                        ),
                    )
                if progress:
                    progress(snapshot, "skipped: disabled in its client config")
                continue
            group.start_soon(one, i, snapshot)
    return results, [warnings[i] for i in sorted(warnings)]
