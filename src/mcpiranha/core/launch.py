"""Understand how a stdio server is launched: which package runner, which package, which version.

Clients launch most servers through a package runner (`npx -y pkg`, `uvx pkg`, `docker run image`),
so the launch command is where the supply-chain facts live.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import PurePath, PureWindowsPath
from typing import Literal

from mcpiranha.core.models import Launch

Registry = Literal["npm", "pypi", "docker"]

_EXACT_SEMVER = re.compile(r"^v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
_PEP440_EXACT = re.compile(r"^\d+(?:\.\d+)*(?:(?:a|b|rc)\d+)?(?:\.post\d+)?(?:\.dev\d+)?$")
_PY_SPEC = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)(?P<extras>\[[^\]]*\])?\s*(?P<spec>.*)$"
)
_NOT_A_REGISTRY_PACKAGE = ("./", "../", "/", "~", "file:", "git+", "git:", "github:", "http:",
                           "https:", "npm:")  # fmt: skip

_NPM_VALUE_FLAGS = frozenset({"-p", "--package", "-c", "--call", "--registry", "--cache"})
_UV_VALUE_FLAGS = frozenset({"--from", "--spec", "--with", "-w", "--python", "-p", "--index",
                             "--index-url", "--extra-index-url", "--constraint", "-c",
                             "--with-requirements",
                             "--with-editable", "--directory", "--cache-dir"})  # fmt: skip
# `docker run` options that take a value when not written as --opt=value.
_DOCKER_VALUE_FLAGS = frozenset({
    "-e", "--env", "--env-file", "-v", "--volume", "--mount", "--name", "-p", "--publish",
    "--network", "--net", "-u", "--user", "-w", "--workdir", "--entrypoint", "-l", "--label",
    "--cap-add", "--cap-drop", "--pid", "--ipc", "--uts", "--userns", "--platform", "-m",
    "--memory", "--cpus", "--add-host", "--device", "--security-opt", "--tmpfs", "--ulimit",
    "-h", "--hostname", "--runtime", "--restart", "--log-driver", "--log-opt", "--dns",
    "--pids-limit", "--group-add", "--cgroupns", "--pull", "--stop-signal", "--shm-size", "--gpus",
})  # fmt: skip


def executable_name(command: str) -> str:
    """Runner name independent of host path syntax and Windows executable suffixes."""
    name = PureWindowsPath(command).name if "\\" in command else PurePath(command).name
    return re.sub(r"\.(cmd|exe|bat|ps1)$", "", name, flags=re.IGNORECASE).lower()


def command_line(launch: Launch) -> list[str]:
    """The effective command line, with Windows `cmd /c` wrappers removed."""
    argv = [launch.command or "", *launch.args]
    flags = {"/d", "/s", "/q", "/a", "/u", "/e:on", "/e:off", "/f:on", "/f:off", "/v:on", "/v:off"}
    while len(argv) > 2 and executable_name(argv[0]) == "cmd":
        index = 1
        while index < len(argv) and argv[index].lower() in flags:
            index += 1
        if index + 1 >= len(argv) or argv[index].lower() not in ("/c", "/k"):
            break
        argv = argv[index + 1 :]
    return argv


def argv_pointer(launch: Launch, argv_index: int) -> str:
    """JSON pointer (into the snapshot) for `command_line(launch)[argv_index]`."""
    i = argv_index + 1 + len(launch.args) - len(command_line(launch))
    return "/launch/command" if i == 0 else f"/launch/args/{i - 1}"


@dataclass(frozen=True, slots=True)
class PackageRef:
    registry: Registry
    name: str
    spec: str | None  # version, range, tag or digest exactly as written; None = not specified
    runner: str  # "npx", "uvx", "docker", ...
    argv_index: int  # position of the package argument in command_line(launch)
    entry: str | None = None  # executable to run when named explicitly (uvx cmd, npx -p pkg cmd)
    rest_index: int = 0  # position in command_line(launch) where the server's own args start
    with_requirements: tuple[str, ...] = ()  # uvx --with: extra requirements installed alongside
    extras: str = ""  # PyPI extras as written, e.g. "[mcp-docker]"

    @property
    def pinned(self) -> bool:
        """Immutable reference: exact version (npm/PyPI) or image digest (docker)."""
        if self.spec is None:
            return False
        if self.registry == "npm":
            return bool(_EXACT_SEMVER.match(self.spec))
        if self.registry == "pypi":
            version = self.spec.removeprefix("==").removeprefix("@").strip()
            return self.spec.startswith(("==", "@")) and bool(_PEP440_EXACT.match(version))
        return self.spec.startswith("sha256:")

    @property
    def display(self) -> str:
        if self.spec is None:
            return self.name
        sep = {"npm": "@", "pypi": "", "docker": "@" if self.spec.startswith("sha256:") else ":"}
        return f"{self.name}{sep[self.registry]}{self.spec}"


@dataclass(frozen=True, slots=True)
class DockerRun:
    image: str
    options: list[tuple[str, str | None]] = field(default_factory=list[tuple[str, str | None]])
    argv_index: int = 0


def package_ref(launch: Launch | None) -> PackageRef | None:
    if launch is None or launch.transport != "stdio" or not launch.command:
        return None
    argv = command_line(launch)
    runner, rest = executable_name(argv[0]), argv[1:]

    if runner == "npx":
        return _npm(rest, runner, 1)
    if runner in ("npm", "pnpm", "yarn", "bun") and rest and rest[0] in ("exec", "x", "dlx"):
        return _npm(rest[1:], f"{runner} {rest[0]}", 2)
    if runner == "bunx":
        return _npm(rest, runner, 1)
    if runner == "uvx":
        return _pypi(rest, runner, 1, from_flag="--from")
    if runner == "uv" and rest[:2] == ["tool", "run"]:
        return _pypi(rest[2:], "uv tool run", 3, from_flag="--from")
    if runner == "pipx" and rest[:1] == ["run"]:
        return _pypi(rest[1:], "pipx run", 2, from_flag="--spec")
    if (run := docker_run(launch)) is not None:
        return _docker_ref(run.image, runner, run.argv_index)
    return None


def docker_run(launch: Launch | None) -> DockerRun | None:
    if launch is None or not launch.command:
        return None
    argv = command_line(launch)
    if executable_name(argv[0]) not in ("docker", "podman") or argv[1:2] != ["run"]:
        return None
    options: list[tuple[str, str | None]] = []
    i = 2
    while i < len(argv):
        arg = argv[i]
        if arg == "--":
            i += 1
            break
        if not arg.startswith("-"):
            break
        if "=" in arg and arg.startswith("--"):
            flag, value = arg.split("=", 1)
            options.append((flag, value))
        elif arg in _DOCKER_VALUE_FLAGS and i + 1 < len(argv):
            options.append((arg, argv[i + 1]))
            i += 1
        else:
            options.append((arg, None))
        i += 1
    if i >= len(argv):
        return None
    return DockerRun(image=argv[i], options=options, argv_index=i)


def _first_positional(args: list[str], value_flags: frozenset[str]) -> tuple[int, str] | None:
    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "--":
            return (i + 1, args[i + 1]) if i + 1 < len(args) else None
        if arg.startswith("-"):
            i += 2 if arg in value_flags and "=" not in arg else 1
            continue
        return i, arg
    return None


def _flag_value(args: list[str], flag: str) -> tuple[int, str] | None:
    for i, arg in enumerate(args):
        if arg == flag and i + 1 < len(args):
            return i + 1, args[i + 1]
        if arg.startswith(f"{flag}="):
            return i, arg.split("=", 1)[1]
    return None


def _npm(args: list[str], runner: str, offset: int) -> PackageRef | None:
    flagged = _flag_value(args, "--package") or _flag_value(args, "-p")
    positional = _first_positional(args, _NPM_VALUE_FLAGS)
    if flagged is not None:  # npx -p pkg cmd args: the positional is the command to run
        (idx, spec), entry = flagged, positional[1] if positional else None
        rest = positional[0] + 1 if positional else len(args)
    elif positional is not None:
        (idx, spec), entry, rest = positional, None, positional[0] + 1
    else:
        return None
    if spec.startswith(_NOT_A_REGISTRY_PACKAGE):
        return None
    at = spec.find("@", 1)  # skip the leading @ of a scoped name
    name, version = (spec[:at], spec[at + 1 :] or None) if at > 0 else (spec, None)
    return PackageRef("npm", name, version, runner, idx + offset, entry, rest + offset)


def _pypi(args: list[str], runner: str, offset: int, *, from_flag: str) -> PackageRef | None:
    positional = _first_positional(args, _UV_VALUE_FLAGS)  # the command, maybe with a version
    found = _flag_value(args, from_flag) or positional
    if found is None or positional is None:
        return None
    idx, raw = found
    if raw.startswith(_NOT_A_REGISTRY_PACKAGE):
        return None
    m = _PY_SPEC.match(raw)
    command = _PY_SPEC.match(positional[1])
    if not m or not command:
        return None
    spec = m.group("spec").strip() or None
    extras = tuple(
        value for i, arg in enumerate(args[: positional[0]])
        for value in ([args[i + 1]] if arg in ("--with", "-w") and i + 1 < len(args)
                      else [arg.split("=", 1)[1]] if arg.startswith("--with=") else [])
    )  # fmt: skip
    return PackageRef("pypi", m.group("name"), spec, runner, idx + offset,
                      command.group("name"), positional[0] + 1 + offset, extras,
                      m.group("extras") or "")  # fmt: skip


def _docker_ref(image: str, runner: str, argv_index: int) -> PackageRef:
    name, _, digest = image.partition("@")
    tag = None
    if (colon := name.rfind(":")) > name.rfind("/"):
        name, tag = name[:colon], name[colon + 1 :]
    return PackageRef(
        "docker", name, digest or tag or None, runner, argv_index, None, argv_index + 1
    )
