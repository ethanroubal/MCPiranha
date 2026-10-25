"""Source analysis: read the code a server runs, without running it.

Sources:
- a local script the config launches (`python server.py`, `node build/index.js`): that file, or
  its whole project when the directory has a pyproject.toml / package.json / .git;
- the npm tarball or PyPI wheel (sdist if there's no wheel) of the release the registry lookup
  resolved: downloaded, checked against the registry's hash, and read in memory. Nothing is
  extracted to disk or installed. Archives are cached in ~/.cache/mcpiranha/archives.

Python is parsed with `ast`, JavaScript/TypeScript with tree-sitter. What they find is stored on
the snapshot (`SourceTree.hits`), so saved snapshots can be rescanned offline; the MCP-SRC rules
judge it.
"""

from __future__ import annotations

import io
import os
import re
import tarfile
import zipfile
from collections.abc import Iterator, Sequence
from pathlib import Path, PurePosixPath

import anyio
import anyio.to_thread
import httpx2

from mcpiranha import __version__
from mcpiranha.core.coverage import record, summarize
from mcpiranha.core.launch import command_line
from mcpiranha.core.models import (
    CoverageCheck,
    PackageMeta,
    ServerSnapshot,
    SourceHit,
    SourceHitKind,
    SourceTree,
)
from mcpiranha.source import javascript, patterns, python, taint_javascript, taint_python
from mcpiranha.supply.archives import ArchiveError
from mcpiranha.supply.archives import download as _download
from mcpiranha.supply.archives import verify as verify  # re-exported for callers

PY = (".py",)
JS = (".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".tsx", ".jsx")
MAX_FILE = 5 * 1024 * 1024
MAX_TOTAL = 80 * 1024 * 1024
MAX_UNPACKED = 1024 * 1024 * 1024  # stop reading an archive (bombs: tiny download, huge content)
MAX_HITS = 100
MAX_HITS_WITH_DEPS = 300
DEPENDENCY_JOBS = 8
MAX_DEPENDENCY_BYTES = 300 * 1024 * 1024  # per server
# `curl ... | sh` in an install script: the download runs at install time
_DOWNLOAD_AND_RUN = re.compile(
    r"\b(curl|wget)\b[^|;&\n]*\|\s*(sudo\s+)?(sh|bash|zsh|python3?|node)\b"
    r"|\b(iwr|irm|invoke-webrequest)\b.{0,80}\|\s*iex\b",
    re.IGNORECASE,
)
_PROJECT_MARKERS = ("pyproject.toml", "setup.py", "package.json", ".git")
_SKIP_DIRS = frozenset({"node_modules", ".venv", "venv", ".git", "__pycache__", ".tox", "dist-info",
                        "test", "tests", "__tests__", "spec", "examples"})  # fmt: skip
_RUNNERS = frozenset({"python", "python3", "node", "bun", "deno", "tsx", "ts-node", "uv"})


SourceError = ArchiveError  # what a failed download raises


class SourceLimit(Exception):
    """A source input budget was reached; keep the evidence already collected."""


def _skip(path: str) -> bool:
    parts = PurePosixPath(path).parts
    return any(p in _SKIP_DIRS for p in parts[:-1]) or path.endswith((".d.ts", ".map"))


def analyze_files(files: Iterator[tuple[str, bytes]], root: str, *,
                  taint: bool = True) -> SourceTree:  # fmt: skip
    """`taint`: also follow tool arguments (off for dependencies: they have no tool handlers)."""
    hits: list[SourceHit] = []
    seen: set[tuple[str, str]] = set()
    count, languages, skipped = 0, set[str](), list[str]()
    py_files: list[tuple[str, str]] = []
    js_files: list[tuple[str, bytes]] = []

    def keep(found: list[SourceHit]) -> None:
        for h in found:
            key = (h.kind, h.detail)  # one hit per distinct thing (bundles repeat code)
            if key not in seen:
                seen.add(key)
                if len(hits) < MAX_HITS:
                    hits.append(h)
                elif (reason := f"Source finding limit ({MAX_HITS}) reached") not in skipped:
                    skipped.append(reason)

    try:
        for path, data in files:
            if len(data) > MAX_FILE:
                skipped.append(f"{path}: larger than {MAX_FILE // 2**20} MB")
                continue
            count += 1
            if path.endswith(PY):
                languages.add("py")
                text = data.decode("utf-8", "replace")
                before = len(skipped)
                keep(python.analyze(path, text, skipped=skipped))
                if len(skipped) == before:
                    py_files.append((path, text))
                else:
                    count -= 1
            else:
                languages.add("ts" if path.endswith((".ts", ".mts", ".cts", ".tsx")) else "js")
                js_files.append((path, data))
                keep(javascript.analyze(path, data, skipped=skipped))
    except SourceLimit as exc:
        skipped.append(str(exc))
    if taint:  # taint crosses files: a handler in index.js, the exec in tools/run.js
        keep(taint_python.analyze_package(py_files, skipped=skipped))
        keep(taint_javascript.analyze_package(js_files, skipped=skipped))
    language = "py" if languages == {"py"} else "ts" if "ts" in languages else (
        "js" if languages else "other")  # fmt: skip
    return SourceTree(root=root, language=language, files=count, skipped=skipped, hits=hits)


# --- local scripts --------------------------------------------------------------------------------


def local_entry(snapshot: ServerSnapshot) -> Path | None:
    """The script a stdio config runs with an interpreter, if it's a file on this machine."""
    launch = snapshot.launch
    if launch is None or launch.transport != "stdio" or not launch.command:
        return None
    argv = command_line(launch)
    if Path(argv[0]).name.split(".")[0] not in _RUNNERS:
        return None
    # Relative paths: clients start servers in the project (the config's folder) or the cwd.
    bases = [Path(snapshot.origin.config_path).parent] if snapshot.origin.config_path else []
    for arg in argv[1:]:
        if arg.endswith(PY + JS):
            path = Path(arg).expanduser()
            for candidate in (
                [path] if path.is_absolute() else [b / path for b in [*bases, Path.cwd()]]
            ):
                if candidate.is_file():
                    return candidate.resolve()
    return None


def _local_files(entry: Path) -> Iterator[tuple[str, bytes]]:
    project = next((d for d in [entry.parent, entry.parent.parent]
                    if any((d / m).exists() for m in _PROJECT_MARKERS)), None)  # fmt: skip
    if project is None or project == Path.home():
        yield entry.name, _read_file(entry)
        return
    yield from _directory_files(project)


def _read_file(path: Path) -> bytes:
    with path.open("rb") as stream:
        return stream.read(MAX_FILE + 1)  # oversized files are reported, never loaded wholesale


def _directory_files(project: Path) -> Iterator[tuple[str, bytes]]:
    total = 0
    for base, directories, names in os.walk(project, followlinks=False):
        directories[:] = sorted(
            d for d in directories if d not in _SKIP_DIRS and not (Path(base) / d).is_symlink()
        )
        for name in sorted(names):
            path = Path(base) / name
            rel = path.relative_to(project).as_posix()
            if (
                path.suffix in PY + JS
                and not path.is_symlink()
                and path.is_file()
                and not _skip(rel)
            ):
                data = _read_file(path)
                total += len(data)
                if total > MAX_TOTAL:
                    raise SourceLimit("Source byte limit reached; remaining files not analyzed.")
                yield rel, data


# --- package archives -----------------------------------------------------------------------------


def archive_files(data: bytes, name: str) -> Iterator[tuple[str, bytes]]:
    """Source files in a .tgz / .tar.gz / .whl / .zip, read in memory (never extracted)."""
    total = 0
    if name.endswith((".whl", ".zip")):
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            if sum(i.file_size for i in archive.infolist()) > MAX_UNPACKED:
                yield "(archive)", b"x" * (MAX_FILE + 1)  # reported as skipped
                return
            for info in archive.infolist():
                if info.filename.endswith(PY + JS) and not _skip(info.filename):
                    if info.file_size > MAX_FILE:
                        yield info.filename, b"x" * (MAX_FILE + 1)  # reported as skipped
                        continue
                    total += info.file_size
                    if total > MAX_TOTAL:
                        raise SourceLimit(
                            "Source byte limit reached; remaining files not analyzed."
                        )
                    yield info.filename, archive.read(info)
        return
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
        unpacked = 0
        for member in archive:
            unpacked += member.size
            if unpacked > MAX_UNPACKED:
                raise SourceLimit(
                    "Archive unpacked byte limit reached; remaining files not analyzed."
                )
            if not member.isfile() or not member.name.endswith(PY + JS):
                continue
            path = member.name.split("/", 1)[-1]  # "package/..." (npm), "name-1.0/..." (sdist)
            if _skip(path):
                continue
            if member.size > MAX_FILE:
                yield path, b"x" * (MAX_FILE + 1)
                continue
            total += member.size
            if total > MAX_TOTAL:
                raise SourceLimit("Source byte limit reached; remaining files not analyzed.")
            extracted = archive.extractfile(member)
            if extracted is not None:
                yield path, extracted.read()


# --- collection -----------------------------------------------------------------------------------


async def collect(
    snapshots: Sequence[ServerSnapshot], *, download: bool = True, jobs: int = 4
) -> tuple[list[ServerSnapshot], list[str]]:
    """Snapshots with `source` filled in where code could be read, plus warnings."""
    out = list(snapshots)
    warnings: list[str] = []
    limiter = anyio.CapacityLimiter(jobs)
    headers = {"User-Agent": f"mcpiranha/{__version__}"}

    async with httpx2.AsyncClient(timeout=60, headers=headers, follow_redirects=True) as client:

        async def one(i: int, snapshot: ServerSnapshot) -> None:
            package = snapshot.package
            try:
                async with limiter:
                    if snapshot.origin.kind == "path" and snapshot.launch is None:
                        root = Path(snapshot.origin.ref)
                        if not root.exists() and snapshot.source is not None:
                            return  # portable saved evidence does not require the original checkout
                        files = (
                            _directory_files(root)
                            if root.is_dir()
                            else iter([(root.name, _read_file(root))])
                        )
                        tree = await anyio.to_thread.run_sync(
                            lambda: analyze_files(
                                files, str(root if root.is_dir() else root.parent)
                            )
                        )
                    elif (entry := local_entry(snapshot)) is not None:
                        tree = await anyio.to_thread.run_sync(
                            lambda: analyze_files(_local_files(entry), str(entry.parent))
                        )
                        tree = tree.model_copy(update={"entrypoints": [entry.name]})
                    elif download and package and package.archive_url and package.archive_hash:
                        data = await _download(client, package.archive_url, package.archive_hash)
                        sep = "==" if package.registry == "pypi" else "@"
                        root = f"{package.registry}:{package.name}{sep}{package.version}"
                        name = package.archive_url.rsplit("/", 1)[-1]
                        tree = await anyio.to_thread.run_sync(
                            lambda: analyze_files(archive_files(data, name), root)
                        )
                    else:
                        if snapshot.source is None:
                            out[i] = record(
                                snapshot,
                                "source",
                                CoverageCheck(
                                    status="skipped",
                                    reason=(
                                        "Offline; no local or saved source evidence."
                                        if not download
                                        else "No supported local source or verified archive."
                                    ),
                                ),
                            )
                        return
            except (SourceError, httpx2.HTTPError, OSError, tarfile.TarError,
                    zipfile.BadZipFile) as exc:  # fmt: skip
                warnings.append(f"{snapshot.name}: source not analyzed: {exc}")
                out[i] = record(
                    snapshot,
                    "source",
                    CoverageCheck(status="failed", reason=f"Source analysis failed: {exc}"),
                )
                return
            if package is not None:
                tree = await _with_dependencies(tree, package, client, download=download)
            collected = snapshot.model_copy(update={"source": tree})
            # Refresh this stage, rather than retaining a previous snapshot's status.
            check = summarize(collected.model_copy(update={"coverage": {}}))["source"]
            out[i] = record(collected, "source", check)

        async with anyio.create_task_group() as group:
            for i, snapshot in enumerate(snapshots):
                group.start_soon(one, i, snapshot)
    for snapshot in out:
        check = summarize(snapshot)["source"]
        if snapshot.source is not None and check.status == "partial":
            warnings.append(f"{snapshot.name}: source analysis incomplete: {check.reason}")
    return out, warnings


ALWAYS_KINDS: frozenset[str] = frozenset({"reverse_shell", "miner", "destructive"})
# Bytes any ALWAYS_KINDS hit needs: other files of an unsuspicious dependency aren't parsed
# (a server's tree is often thousands of files).
_ALWAYS_MARKERS = re.compile(rb"stratum\+|xmrig|cryptonight|coinhive|donate-level|/dev/tcp|dup2|"
                             rb"rm -[a-z]*r|rmtree|rmSync|rmdirSync|removeSync|emptyDir|mkfs|"
                             rb"vssadmin|del /|format [a-z]:|Net\.Sockets|socat|mkfifo|nc -e|"
                             rb"ncat|\bdd if=", re.IGNORECASE)  # fmt: skip
_SCRIPT_FILE = re.compile(
    r"\b(?:node|python3?|sh|bash|tsx|bun)\s+(?:\./)?([\w./-]+\.(?:c?js|mjs|ts|py|sh))"
)
RECENT_DAYS = 30


def install_files(package: PackageMeta) -> set[str]:
    """Files that run when the package is installed: what its install scripts start (`node
    setup.js`), and setup.py for a PyPI release without a wheel."""
    files: set[str] = set()
    for script in package.install_scripts:
        files.update(m.group(1) for m in _SCRIPT_FILE.finditer(script))
        if script.startswith("setup.py"):
            files.add("setup.py")
    return files


def suspicious(package: PackageMeta) -> bool:
    """Signs a dependency's release may be hijacked or malicious, so all its code counts."""
    if any(v.id.startswith("MAL-") for v in package.vulnerabilities or []):
        return True
    now = package.checked_at
    if now is None:
        return False
    if package.created_at and (now - package.created_at).days < RECENT_DAYS:
        return True  # a new package (typosquats, slopsquats)
    recent = package.published_at is not None and (now - package.published_at).days < RECENT_DAYS
    prev = package.previous
    return recent and (
        (prev is not None and not prev.install_scripts and bool(package.install_scripts))
        or (prev is not None and bool(prev.provenance) and package.provenance is False)
        or (bool(package.publisher) and bool(package.earlier_publishers)
            and package.publisher not in package.earlier_publishers
            and not (package.publisher or "").startswith("trusted publishing"))
    )  # fmt: skip


def script_hits(package: PackageMeta, prefix: str) -> list[SourceHit]:
    """Install-script command lines run as soon as the package is installed: judge each one as
    an executed command (reverse shells, wipes, cron installs, downloads piped to a shell)."""
    hits: list[SourceHit] = []
    for script in package.install_scripts:
        command = script.split(": ", 1)[-1]
        found: list[tuple[SourceHitKind, str]] = list(patterns.string_hits(command))
        if m := _DOWNLOAD_AND_RUN.search(command):
            found.append(("dynamic_code", f"install script runs downloaded code: {m.group(0)}"))
        for kind, detail in found:
            where = f"{prefix}package.json"
            hits.append(SourceHit(kind=kind, file=where, line=1, code=script[:200],
                                  detail=f"install script: {detail}"))  # fmt: skip
    return hits


async def _with_dependencies(
    tree: SourceTree, package: PackageMeta, client: httpx2.AsyncClient, *, download: bool
) -> SourceTree:
    """Add what each dependency's code and install scripts do (behavior only, not taint): their
    hits keep the dependency's name in the path, `name@version/file`."""
    hits = [*tree.hits, *script_hits(package, "")]
    skipped = list(tree.skipped)
    deps = [d for d in package.dependencies or [] if d.version]
    limiter = anyio.CapacityLimiter(DEPENDENCY_JOBS)
    files = tree.files
    total = 0

    async def one(dep: PackageMeta) -> None:
        nonlocal files, total
        prefix = f"{dep.name}@{dep.version}/"
        found = script_hits(dep, prefix)
        installs = install_files(dep)
        suspect = suspicious(dep)
        if not (suspect or dep.install_scripts):
            # Nothing of it runs at install and the release looks normal: its code is a library
            # the server calls, judged by OSV and the hijack signals, not read line by line
            # (a server's tree is often hundreds of packages and thousands of files).
            hits.extend(found)
            return
        if download and dep.archive_url and dep.archive_hash and total < MAX_DEPENDENCY_BYTES:
            try:
                async with limiter:
                    data = await _download(client, dep.archive_url, dep.archive_hash)
                    total += len(data)
                    name = dep.archive_url.rsplit("/", 1)[-1]
                    wanted = (
                        f for f in archive_files(data, name)
                        if suspect or f[0] in installs or _ALWAYS_MARKERS.search(f[1])
                    )  # fmt: skip
                    sub = await anyio.to_thread.run_sync(
                        lambda: analyze_files(wanted, dep.name, taint=False)
                    )
                files += sub.files
                skipped.extend(f"{prefix}{reason}" for reason in sub.skipped)
                # Library code is full of features that look like malice out of context (shell
                # completion writing ~/.bashrc, dup2 in output capture): a dependency's code
                # counts when it runs at install, when the release looks hijacked, or when the
                # behavior is unambiguous (calibration: 22 of 84 servers before this).
                found += [h.model_copy(update={"file": prefix + h.file}) for h in sub.hits
                          if suspect or h.file in installs or h.kind in ALWAYS_KINDS]  # fmt: skip
            except (SourceError, httpx2.HTTPError, OSError, tarfile.TarError,
                    zipfile.BadZipFile) as exc:  # fmt: skip
                skipped.append(f"{prefix}: not analyzed: {exc}")
        hits.extend(found)

    async with anyio.create_task_group() as group:
        for dep in deps:
            group.start_soon(one, dep)
    if total >= MAX_DEPENDENCY_BYTES:
        skipped.append(
            f"dependencies: stopped downloading after {MAX_DEPENDENCY_BYTES // 2**20} MB"
        )
    distinct = list({(h.kind, h.file, h.detail): h for h in hits}.values())
    if len(distinct) > MAX_HITS_WITH_DEPS:
        skipped.append(f"Dependency source finding limit ({MAX_HITS_WITH_DEPS}) reached")
    unique = distinct[:MAX_HITS_WITH_DEPS]
    if len(unique) == len(tree.hits) and files == tree.files and skipped == tree.skipped:
        return tree
    return tree.model_copy(update={"hits": unique, "files": files, "skipped": skipped})
