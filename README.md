# MCPiranha

[![PyPI](https://img.shields.io/pypi/v/mcpiranha)](https://pypi.org/project/mcpiranha/)
[![CI](https://github.com/ethanroubal/MCPiranha/actions/workflows/ci.yml/badge.svg)](https://github.com/ethanroubal/MCPiranha/actions/workflows/ci.yml)
[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue)](https://github.com/ethanroubal/MCPiranha/blob/main/pyproject.toml)

Find security risks in **Model Context Protocol (MCP) servers** before giving them access to
your files, credentials or other tools. MCPiranha scans client configurations, Python and
JavaScript/TypeScript source, published packages, and live server metadata.

**Static scans do not start servers or run package code.** Live inspection and tool invocation
are explicit opt-ins. Reports show both findings and what the scanner could actually inspect.

See the [changelog](https://github.com/ethanroubal/MCPiranha/blob/main/CHANGELOG.md) for release history, upgrade notes and unreleased changes.

[Quick start](#quick-start) · [Common tasks](#common-tasks) · [Reading results](#reading-results) ·
[Limits](#limits) · [Full usage guide](https://github.com/ethanroubal/MCPiranha/blob/main/docs/USAGE.md)

## Quick start

Requires **Python 3.12+**. Docker is needed for sandboxed local server connections, not static scans.

```bash
# Run without installing, using uv
uvx mcpiranha scan .mcp.json

# Or install the command
pipx install mcpiranha
mcpiranha scan .mcp.json
```

Use `mcpiranha --help` to list commands, or `mcpiranha scan --help` for scan options
and short descriptions. Every command supports `--help`.

Without a target, `mcpiranha scan` discovers supported client configurations on your machine
and in the current project. [Supported clients and config paths](https://github.com/ethanroubal/MCPiranha/blob/main/docs/CLIENTS.md) include
Claude Desktop/Code, Cursor, VS Code, Codex CLI and others on macOS, Linux and Windows.

Registry/advisory lookups use the network by default and send package names and versions to
registries and OSV. Add **`--offline`** for local or saved evidence only.

## Common tasks

| Task | Command |
|---|---|
| Scan a client configuration | `mcpiranha scan .mcp.json` |
| Scan a source directory explicitly | `mcpiranha scan path:./server-source --offline` |
| Inspect an npm release without installing it | `mcpiranha scan npm:@scope/server@1.2.3` |
| Inspect a PyPI release without installing it | `mcpiranha scan pypi:some-server==1.2.3` |
| Select one server from a config | `mcpiranha scan .mcp.json --server search` |
| Inspect live tools, prompts and resources | `mcpiranha scan .mcp.json --server search --connect` |
| Inspect risky combinations of servers | `mcpiranha flows .mcp.json` |
| Export GitHub code-scanning results | `mcpiranha scan .mcp.json -f sarif -o scan.sarif` |

`--server` selects an exact name or ID and can be repeated. Add `--client cursor` to narrow
client discovery. Unmatched selectors fail before acquisition. Cross-server checks use only
the selected servers; scan the whole configuration to assess their interactions.

### What it checks

| Area | Examples |
|---|---|
| Model-facing content | Prompt injection, hidden instructions, encoded payloads, secret-export links |
| Source behavior | Shell/SQL injection, path traversal, SSRF, secret harvesting, persistence |
| Client configuration | Embedded secrets, insecure endpoints, excessive approval settings |
| Supply chain | Known vulnerabilities/malware, dependency risks, publisher/provenance changes |
| Cross-server interactions | Untrusted content combined with private-data access or code execution |
| Opt-in runtime behavior | Synthetic credential access, process activity and unexpected network destinations |

See the [rule catalog](https://github.com/ethanroubal/MCPiranha/blob/main/docs/RULES.md) for individual checks and severity guidance.

## Reading results

A finding includes severity, confidence, evidence, location and remediation. **Severity is
potential impact; confidence is certainty in the analysis.** A high-severity static finding
can have medium confidence and still need review.

Coverage is reported per server for configuration, tools, source, package/dependency checks,
dynamic tracing and invocation. Read it alongside the findings:

| Coverage status | Meaning |
|---|---|
| `completed` | Evidence was collected within the supported analysis model; not proof of safety |
| `partial` | Some evidence or analysis was omitted; the report explains why |
| `skipped` | That stage did not run, such as tool listing during a static scan |
| `failed` / `unknown` | The stage failed or its completeness cannot be established |

Helper flows follow local import aliases, namespaces and common re-exports using a cached work
queue. Unresolved local bindings or exhausted analysis/finding budgets mark source coverage
**partial**, retaining findings and snapshot limitations. Completion does not establish that
arbitrary dynamic calls, custom classes or validators were understood.
`basename()` alone does not establish containment; use a checked path or filename allowlist.

### Use in CI

```bash
mcpiranha scan path:./server-source --offline --strict \
  --require-coverage source --fail-on high -f json -o scan.json
```

| Exit code | Meaning |
|---|---|
| `0` | No unsuppressed finding at or above the threshold; requested checks passed |
| `1` | Findings meet the configured failure threshold |
| `2` | Scan/input failure, a strict-mode warning, or an unmet coverage requirement |

`--strict` fails on scan warnings, including partial source analysis. Repeat
`--require-coverage` to require additional stages. Requirements apply to every selected server;
a static scan cannot satisfy tool-listing coverage. Saved evidence can satisfy a coverage
requirement but does not imply a fresh connection or lookup.

Reviewed exceptions belong in [`.mcpiranha.yaml`](https://github.com/ethanroubal/MCPiranha/blob/main/docs/USAGE.md#policy-file), with a reason and
optional expiration. Suppressed findings remain visible in JSON and SARIF.

## Live inspection and change detection

```bash
# Start/list the selected server; no tool invocation
mcpiranha scan .mcp.json --server search --connect --save-snapshots ./captures

# Pin launch settings and tool definitions, then detect subsequent changes
mcpiranha lock .mcp.json --connect
mcpiranha verify .mcp.json --connect
```

Local package servers run in a Docker sandbox by default, with dummy credentials, a read-only
filesystem and runtime networking disabled. Remote URLs require `--connect`; OAuth is available
with `--oauth`. Tool calls require explicit `--invoke NAME` and can have side effects.

For synthetic-credential tracing, bounded fuzzing, remote authentication and sandbox options,
see the [usage guide](https://github.com/ethanroubal/MCPiranha/blob/main/docs/USAGE.md#behavioral-scanning-phase-04).

## Limits

Detection is bounded and heuristic. A clean report does not prove that a server is safe.
Novel paraphrases, unresolved/dynamic calls, arbitrary heap objects, custom validators,
filesystem races and dormant runtime triggers remain gaps. Registry dependency resolution may
differ from an installed environment; Docker image source is not analyzed.

The [labeled evaluation](https://github.com/ethanroubal/MCPiranha/blob/main/evaluation/README.md) records attacks, benign controls, misses, false
alarms and implementation fingerprints. Its examples were used during development; passing
that set is not an independent estimate of real-world accuracy. Tests also cover two existing
vulnerable/fixed release pairs. Broader independent validation remains necessary.

## Development and documentation

```bash
uv sync --all-extras
uv run pytest -q
uv run ruff check .
uv run pyright
```

- [Advanced usage and runtime scanning](https://github.com/ethanroubal/MCPiranha/blob/main/docs/USAGE.md)
- [Testing and optional Docker/registry checks](https://github.com/ethanroubal/MCPiranha/blob/main/docs/TESTING.md)
- [Detection-quality evaluation](https://github.com/ethanroubal/MCPiranha/blob/main/evaluation/README.md)
- [Rules](https://github.com/ethanroubal/MCPiranha/blob/main/docs/RULES.md) · [Client support](https://github.com/ethanroubal/MCPiranha/blob/main/docs/CLIENTS.md) · [Architecture](https://github.com/ethanroubal/MCPiranha/blob/main/docs/ARCHITECTURE.md)
- [Changelog](https://github.com/ethanroubal/MCPiranha/blob/main/CHANGELOG.md) · [Adding rules](https://github.com/ethanroubal/MCPiranha/blob/main/docs/USAGE.md#adding-a-rule)

The optional local classifier is experimental. The LLM layer, runtime guard proxy and MCP
server mode are planned; see [classifier details](https://github.com/ethanroubal/MCPiranha/blob/main/docs/USAGE.md#experimental-classifier).
