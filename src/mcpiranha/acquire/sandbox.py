"""Start a server so it can be enumerated, without trusting it.

Docker sandbox (the default), in two phases:

1. Fetch: download the package into a throwaway volume, with network access but without running
   it. npm installs use --ignore-scripts and PyPI installs accept wheels only, so no package
   code runs during installation either.
2. Run: start the server from that volume, read-only, with no network, no capabilities, no
   privilege escalation, a non-root user, resource limits, and fake values for its env vars.

Docker-image servers are pulled, then run with the same restrictions instead of the flags from
their config. Servers that run local files (`node ./server.js`) can't be sandboxed this way;
`--sandbox none` runs them, and everything else, directly on this machine.

Remote servers aren't started at all; they're only connected to.
"""

from __future__ import annotations

import contextlib
import json
import os
import posixpath
import re
import tempfile
import uuid
from collections.abc import Awaitable, Callable, Generator, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, TextIO, cast

import anyio
import httpx2
from mcp.client import Transport
from mcp.client.sse import sse_client
from mcp.client.stdio import StdioServerParameters, get_default_environment, stdio_client
from mcp.client.streamable_http import streamable_http_client

from mcpiranha.acquire.oauth import LoopbackCallback, OpenUrl, oauth_provider
from mcpiranha.core.launch import PackageRef, command_line, docker_run, package_ref
from mcpiranha.core.models import DynamicObservation, Launch, PackageMeta, ProbeRun

Sandbox = Literal["docker", "none"]

DUMMY_VALUE = "mcpiranha-dummy-value"
NODE_IMAGE = os.environ.get("MCPIRANHA_NODE_IMAGE", "node:22-bookworm-slim")
UV_IMAGE = os.environ.get("MCPIRANHA_UV_IMAGE", "ghcr.io/astral-sh/uv:python3.12-bookworm-slim")
FETCH_TIMEOUT = 300.0
PULL_TIMEOUT = 600.0
# Package caches shared by every fetch container, so repeat scans don't re-download. Only npm
# and uv write to them (no package code runs during a fetch). Remove with `docker volume rm`.
NPM_CACHE_VOLUME = "mcpiranha-npm-cache"
UV_CACHE_VOLUME = "mcpiranha-uv-cache"

# Applied to every sandboxed server container.
UV_IMAGE_NEWER = os.environ.get(
    "MCPIRANHA_UV_IMAGE_NEWER", "ghcr.io/astral-sh/uv:python3.13-bookworm-slim"
)  # for packages whose requires-python excludes UV_IMAGE's Python

# Applied to every sandboxed server container.
RUN_RESTRICTIONS = (
    "--rm", "-i",
    "--cap-drop", "ALL",
    "--security-opt", "no-new-privileges",
    "--pids-limit", "256", "--memory", "1g", "--cpus", "1",
    "--tmpfs", "/tmp:rw,exec,size=256m",
    "-e", "HOME=/tmp", "-e", "TMPDIR=/tmp",
)  # fmt: skip
NO_NETWORK = ("--network", "none")  # dropped only with --allow-network
# npm/PyPI servers run entirely from the read-only package volume, so the root can be read-only
# too; /tmp is the working directory for servers that write next to themselves. Docker-image
# servers keep a writable root (discarded by --rm): many write inside their own app directory.
PACKAGE_FS = ("--read-only", "--workdir", "/tmp")
FETCH_RESTRICTIONS = ("--rm", "--cap-drop", "ALL", "--security-opt", "no-new-privileges")
NON_ROOT = ("--user", "1000:1000")

# Runs in the fetch container: install (without scripts unless allowed), then print the
# package's bin path and version.
_NPM_FETCH = (
    "npm install --prefix /work $MCPIRANHA_IGNORE_SCRIPTS --no-audit --no-fund --loglevel=error "
    '"$1" >&2 && node -e "$MCPIRANHA_BIN_JS" "$2" "$3"'
)
_NPM_BIN_JS = (
    "const [name, want] = process.argv.slice(1);"
    "const pkg = require(`/work/node_modules/${name}/package.json`);"
    "let bin = pkg.bin;"
    "if (bin && typeof bin === 'object') "
    "bin = bin[want] || bin[name.split('/').pop()] || Object.values(bin)[0];"
    "process.stdout.write(`MCPIRANHA_BIN=${bin || pkg.main || 'index.js'}\\n`);"
    "process.stdout.write(`MCPIRANHA_VERSION=${pkg.version}\\n`);"
)
# Arguments: requirement, distribution name, then any `uvx --with` requirements.
_PYPI_FETCH = (
    'req="$1"; name="$2"; shift 2; rm -rf /work/venv && uv venv -q /work/venv && '
    'uv pip install -q --python /work/venv/bin/python $MCPIRANHA_BINARY_ONLY "$req" "$@" && '
    '/work/venv/bin/python -c "$MCPIRANHA_VERSION_PY" "$name"'
)
_PYPI_VERSION_PY = (
    "import sys, importlib.metadata as m; d = m.distribution(sys.argv[1]); "
    "print('MCPIRANHA_VERSION=' + d.version); "
    "print('MCPIRANHA_SCRIPTS=' + ','.join(sorted("
    "e.name for e in d.entry_points if e.group == 'console_scripts')))"
)
# ${VAR} / ${env:VAR} (most clients), {env:VAR} (opencode), $VAR; anything else in ${...} is
# client-only (VS Code ${input:...}, Continue ${{ secrets.X }}) and can't be resolved here.
_PLACEHOLDER = re.compile(
    r"\$\{(?:env:)?([A-Za-z_]\w*)\}|\{env:([A-Za-z_]\w*)\}|\$([A-Za-z_]\w*)|\$\{[^}]*\}"
)
_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


@contextlib.contextmanager
def stderr_log() -> Generator[TextIO, None, None]:
    """An actual text stream on every OS, closed before its temporary directory is removed."""
    with (
        tempfile.TemporaryDirectory(prefix="mcpiranha-stderr-") as directory,
        (Path(directory) / "stderr.log").open("w+", encoding="utf-8", errors="replace") as stream,
    ):
        yield stream


class SandboxError(Exception):
    pass


async def _no_cleanup() -> None:
    return None


async def _no_observations() -> list[DynamicObservation]:
    return []


async def _no_probe(probe: ProbeRun, started: bool) -> None:
    return None


@dataclass
class Prepared:
    connect: Callable[[], Transport]  # a fresh transport per attempt (handshake fallback)
    label: str  # how the server is being run, for progress output
    cleanup: Callable[[], Awaitable[None]] = _no_cleanup
    collect: Callable[[], Awaitable[list[DynamicObservation]]] = _no_observations
    stop: Callable[[], Awaitable[None]] = _no_cleanup
    phase_changed: Callable[[str], None] = lambda phase: None
    remote: bool = False
    sent_credentials: bool = False
    command: list[str] | None = None  # the full command line, for stdio servers
    resolved: PackageMeta | None = None  # the package version / image digest actually run
    # HTTP statuses a remote server answered with (the SDK reports 401s as a generic error).
    http_statuses: list[int] = field(default_factory=list[int])
    containers: list[str] = field(default_factory=list[str])
    probe_changed: Callable[[ProbeRun, bool], Awaitable[None]] = _no_probe


# --- credentials ----------------------------------------------------------------------------------


def expand(value: str, environ: Mapping[str, str]) -> str | None:
    """Resolve ${VAR}, ${env:VAR} and $VAR the way clients do. None if any can't be resolved
    (including client-only forms like VS Code's ${input:...})."""
    missing = False

    def sub(m: re.Match[str]) -> str:
        nonlocal missing
        name = next((g for g in m.groups() if g), None)
        if name is None or name not in environ:
            missing = True
            return ""
        return environ[name]

    expanded = _PLACEHOLDER.sub(sub, value)
    return None if missing else expanded


def server_env(launch: Launch, *, real_credentials: bool, environ: Mapping[str, str]
               ) -> dict[str, str]:  # fmt: skip
    """The env the server is started with: fake values unless real credentials were asked for."""
    if not real_credentials:
        return dict.fromkeys(launch.env, DUMMY_VALUE)
    out: dict[str, str] = {}
    for key, secret in launch.env.items():
        value = expand(secret.get_secret_value(), environ)
        out[key] = DUMMY_VALUE if value is None else value
    return out


def remote_headers(launch: Launch, *, real_credentials: bool, environ: Mapping[str, str]
                   ) -> dict[str, str]:  # fmt: skip
    if not real_credentials:
        return {}
    headers: dict[str, str] = {}
    for key, secret in launch.headers.items():
        value = expand(secret.get_secret_value(), environ)
        if value is not None:
            headers[key] = value
    return headers


# --- docker ---------------------------------------------------------------------------------------


async def _docker(*args: str, timeout: float) -> str:
    try:
        with anyio.fail_after(timeout):
            done = await anyio.run_process(["docker", *args], check=False)
    except FileNotFoundError as exc:
        raise SandboxError("docker is not installed (or use --sandbox none)") from exc
    except TimeoutError as exc:
        raise SandboxError(f"docker {args[0]} took longer than {timeout:.0f}s") from exc
    if done.returncode != 0:
        detail = done.stderr.decode(errors="replace").strip()[-400:]
        raise SandboxError(f"docker {args[0]} failed: {detail}")
    return done.stdout.decode(errors="replace")


async def docker_available() -> None:
    try:
        await _docker("version", "--format", "{{.Server.Version}}", timeout=20)
    except SandboxError as exc:
        raise SandboxError(
            "the Docker sandbox needs a running Docker daemon (start Docker Desktop), or pass "
            f"--sandbox none to run servers directly on this machine. ({exc})"
        ) from exc


def _env_flags(env: Mapping[str, str]) -> list[str]:
    return [flag for key, value in env.items() for flag in ("-e", f"{key}={value}")]


def npm_bin_path(name: str, bin_relative: str) -> str:
    """Absolute bin path inside the volume; refuses paths that escape the package directory."""
    root = posixpath.join("/work/node_modules", name)
    path = posixpath.normpath(posixpath.join(root, bin_relative))
    if not path.startswith(root + "/"):
        raise SandboxError(f"package {name} declares a bin outside itself: {bin_relative!r}")
    return path


def pypi_requirement(ref: PackageRef) -> str:
    name = ref.name + ref.extras
    if ref.spec is None:
        return name
    return name + ("==" + ref.spec[1:] if ref.spec.startswith("@") else ref.spec)


def _marker(output: str, prefix: str) -> str | None:
    values = [ln[len(prefix) :].strip() for ln in output.splitlines() if ln.startswith(prefix)]
    return values[-1] if values and values[-1] else None


def _repo_digest(inspect_json: str, name: str) -> str | None:
    """The sha256 digest for `name` from `docker image inspect` RepoDigests output."""
    try:
        data: Any = json.loads(inspect_json or "null")
    except ValueError:
        return None
    digests = cast(list[Any], data) if isinstance(data, list) else []
    for item in digests:
        repo, _, digest = str(item).partition("@")
        if digest and (repo == name or repo.endswith("/" + name)):
            return digest
    return None


def pick_script(wanted: str, scripts: list[str]) -> str:
    """The console script to run: the requested one, else the package's only one, else its only
    MCP-named one. (`uvx pkg` asks for an executable named like the package; some packages name
    theirs differently.)"""
    if not scripts or wanted in scripts:
        return wanted
    if len(scripts) == 1:
        return scripts[0]
    mcp = [s for s in scripts if "mcp" in s.lower()]
    if len(mcp) == 1:
        return mcp[0]
    raise SandboxError(f"{wanted!r} isn't one of the package's executables: {', '.join(scripts)}")


def _python_too_old(error: SandboxError) -> bool:
    # uv wraps long messages, so the words can be split across lines
    return bool(re.search(r"does\s+not\s+satisfy\s+Python|requires-python", str(error), re.I))


async def _prepare_docker(
    launch: Launch,
    env: dict[str, str],
    errlog: TextIO,
    *,
    allow_network: bool = False,
    allow_install_scripts: bool = False,
) -> Prepared:
    ref = package_ref(launch)
    if ref is None:
        argv = " ".join(command_line(launch))
        raise SandboxError(
            f"can't sandbox `{argv}`: it doesn't launch a registry package or image. Use "
            "--sandbox none to run it directly on this machine."
        )
    await docker_available()
    argv = command_line(launch)
    server_args = argv[ref.rest_index :]
    tag = uuid.uuid4().hex[:12]
    container, volume = f"mcpiranha-run-{tag}", f"mcpiranha-pkg-{tag}"

    attempts: list[str] = []  # container names used, one per connection attempt

    async def cleanup() -> None:
        with anyio.CancelScope(shield=True):
            removals = [("rm", "-f", name) for name in attempts] + [("volume", "rm", "-f", volume)]
            for args in removals:
                with contextlib.suppress(SandboxError):
                    await _docker(*args, timeout=30)

    network = [] if allow_network else list(NO_NETWORK)
    run = ["run", *RUN_RESTRICTIONS, *network, "--name", container, *_env_flags(env)]
    where = "network allowed" if allow_network else "no network"
    try:
        if ref.registry == "docker":
            image = argv[ref.argv_index]
            platform: list[str] = []
            try:
                await _docker("pull", image, timeout=PULL_TIMEOUT)
            except SandboxError as exc:
                if "no matching manifest" not in str(exc):
                    raise
                # No build for this machine's architecture: run the amd64 one under emulation.
                platform = ["--platform", "linux/amd64"]
                await _docker("pull", *platform, image, timeout=PULL_TIMEOUT)
            digests = await _docker("image", "inspect", "--format", "{{json .RepoDigests}}",
                                    image, timeout=30)  # fmt: skip
            resolved = PackageMeta(registry="docker", name=ref.name,
                                   version=_repo_digest(digests, ref.name))  # fmt: skip
            config_run = docker_run(launch)
            forwarded = {
                (value or "").split("=", 1)[0]
                for flag, value in (config_run.options if config_run else [])
                if flag in ("-e", "--env") and value
            }
            run = [*run, *platform, *_env_flags(dict.fromkeys(forwarded - env.keys(), DUMMY_VALUE))]
            command = [*run, image, *server_args]
            label = f"docker sandbox (image {ref.display}, {where})"
        else:
            await _docker("volume", "create", volume, timeout=30)
            fetch = ["run", *FETCH_RESTRICTIONS, "-v", f"{volume}:/work", "--entrypoint", "sh"]
            mount = [*PACKAGE_FS, "-v", f"{volume}:/work:ro", *NON_ROOT]
            if ref.registry == "npm":
                spec = f"{ref.name}@{ref.spec}" if ref.spec else ref.name
                scripts = "" if allow_install_scripts else "--ignore-scripts"
                npm_args = ["-v", f"{NPM_CACHE_VOLUME}:/cache", "-e", "npm_config_cache=/cache/npm",
                            "-e", f"MCPIRANHA_IGNORE_SCRIPTS={scripts}",
                            "-e", f"MCPIRANHA_BIN_JS={_NPM_BIN_JS}", NODE_IMAGE, "-c"]  # fmt: skip
                script_args = [_NPM_FETCH, "sh", spec, ref.name, ref.entry or ""]
                output = await _docker(*fetch, *npm_args, *script_args, timeout=FETCH_TIMEOUT)
                found = _marker(output, "MCPIRANHA_BIN=")
                if not found:
                    raise SandboxError(f"installed {spec} but couldn't find its executable")
                entry = npm_bin_path(ref.name, found)
                resolved = PackageMeta(registry="npm", name=ref.name,
                                       version=_marker(output, "MCPIRANHA_VERSION="))  # fmt: skip
                command = [*run, *mount, "--entrypoint", "node", NODE_IMAGE, entry, *server_args]
            else:
                binary_only = "" if allow_install_scripts else "--only-binary :all:"
                uv_env = ["-v", f"{UV_CACHE_VOLUME}:/cache", "-e", "UV_CACHE_DIR=/cache/uv",
                          "-e", "UV_LINK_MODE=copy", "-e", f"MCPIRANHA_BINARY_ONLY={binary_only}",
                          "-e", f"MCPIRANHA_VERSION_PY={_PYPI_VERSION_PY}"]  # fmt: skip
                install = [_PYPI_FETCH, "sh", pypi_requirement(ref), ref.name,
                           *ref.with_requirements]  # fmt: skip
                python_image = UV_IMAGE
                try:
                    output = await _docker(*fetch, *uv_env, python_image, "-c", *install,
                                           timeout=FETCH_TIMEOUT)  # fmt: skip
                except SandboxError as exc:
                    if not _python_too_old(exc):
                        raise
                    python_image = UV_IMAGE_NEWER
                    output = await _docker(*fetch, *uv_env, python_image, "-c", *install,
                                           timeout=FETCH_TIMEOUT)  # fmt: skip
                resolved = PackageMeta(registry="pypi", name=ref.name,
                                       version=_marker(output, "MCPIRANHA_VERSION="))  # fmt: skip
                scripts_found = (_marker(output, "MCPIRANHA_SCRIPTS=") or "").split(",")
                entry_name = pick_script(ref.entry or ref.name, [s for s in scripts_found if s])
                if not _SAFE_NAME.match(entry_name):
                    raise SandboxError(f"unexpected executable name {entry_name!r}")
                entry = f"/work/venv/bin/{entry_name}"
                command = [*run, *mount, "--entrypoint", entry, python_image, *server_args]
            label = f"docker sandbox ({ref.registry} {ref.display}, {where})"
    except BaseException:
        await cleanup()
        raise

    async def stop() -> None:
        with anyio.CancelScope(shield=True):
            for name in attempts:
                with contextlib.suppress(SandboxError):
                    await _docker("stop", "--time", "1", name, timeout=10)

    command.insert(0, "docker")

    def connect() -> Transport:
        name = f"{container}-{len(attempts)}"
        attempts.append(name)
        args = [name if arg == container else arg for arg in command[1:]]
        params = StdioServerParameters(command="docker", args=args, env=get_default_environment())
        return stdio_client(params, errlog=errlog)

    return Prepared(
        connect, label, cleanup, stop=stop, command=command, resolved=resolved, containers=attempts
    )


# --- entry point ----------------------------------------------------------------------------------


async def prepare(
    launch: Launch,
    *,
    sandbox: Sandbox,
    real_credentials: bool,
    errlog: TextIO,
    environ: Mapping[str, str] | None = None,
    extra_headers: Mapping[str, str] | None = None,
    oauth_open: OpenUrl | None = None,
    allow_network: bool = False,
    allow_install_scripts: bool = False,
) -> Prepared:
    """`extra_headers`: sent to a remote server as given (--header). `oauth_open`: sign in with
    OAuth, calling it with the authorization URL (--oauth)."""
    environ = os.environ if environ is None else environ
    if launch.transport != "stdio":
        if not launch.url:
            raise SandboxError("remote server has no url")
        headers = remote_headers(launch, real_credentials=real_credentials, environ=environ)
        headers.update(extra_headers or {})
        callback = LoopbackCallback() if oauth_open else None
        auth = oauth_provider(launch.url, callback, oauth_open) if callback and oauth_open else None
        sent = bool(headers) or auth is not None
        label = "remote, " + ("signing in with OAuth" if auth else
                              "credentials sent" if headers else "no credentials sent")  # fmt: skip

        async def cleanup() -> None:
            if callback:
                callback.close()

        if launch.transport == "sse":
            url = launch.url
            return Prepared(lambda: sse_client(url, headers=headers, auth=auth), label, cleanup,
                            remote=True, sent_credentials=sent)  # fmt: skip
        statuses: list[int] = []

        async def record(response: httpx2.Response) -> None:
            statuses.append(response.status_code)

        # MCP's default HTTP timeouts: 30s, and 300s reads for long-lived streams.
        http = httpx2.AsyncClient(headers=headers, auth=auth, event_hooks={"response": [record]},
                                  timeout=httpx2.Timeout(30.0, read=300.0))  # fmt: skip

        async def close_http() -> None:
            await http.aclose()
            await cleanup()

        url = launch.url
        return Prepared(lambda: streamable_http_client(url, http_client=http), label, close_http,
                        remote=True, sent_credentials=sent, http_statuses=statuses)  # fmt: skip

    if not launch.command:
        raise SandboxError("stdio server has no command")
    env = server_env(launch, real_credentials=real_credentials, environ=environ)
    if sandbox == "docker":
        return await _prepare_docker(launch, env, errlog, allow_network=allow_network,
                                     allow_install_scripts=allow_install_scripts)  # fmt: skip
    params = StdioServerParameters(
        command=launch.command, args=launch.args, env={**get_default_environment(), **env}
    )
    return Prepared(lambda: stdio_client(params, errlog=errlog), "on this machine, no sandbox",
                    command=[launch.command, *launch.args])  # fmt: skip


async def docker(*args: str, timeout: float) -> str:
    """Run a bounded Docker CLI operation for sandbox instrumentation."""
    return await _docker(*args, timeout=timeout)
