# MCPiranha — MCP security scanner

[![PyPI](https://img.shields.io/pypi/v/mcpiranha)](https://pypi.org/project/mcpiranha/)
[![CI](https://github.com/ethanroubal/MCPiranha/actions/workflows/ci.yml/badge.svg)](https://github.com/ethanroubal/MCPiranha/actions/workflows/ci.yml)
[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue)](https://github.com/ethanroubal/MCPiranha/blob/main/pyproject.toml)
[![Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)](https://github.com/ethanroubal/MCPiranha/blob/main/LICENSE)

An open-source security scanner for **Model Context Protocol (MCP)** servers. Find prompt
injection, tool poisoning, unsafe configurations, vulnerable packages and risky source code.

## Installation

Requires **Python 3.12+**. Works on Windows, macOS and Linux.

```bash
pipx install mcpiranha
```

Or run without installing: `uvx mcpiranha scan`.

## Usage

```bash
# Discover and scan your configured MCP servers
mcpiranha scan

# Scan a configuration file
mcpiranha scan .mcp.json

# Scan one server from a configuration
mcpiranha scan .mcp.json --server search

# Scan local source without registry lookups
mcpiranha scan path:./my-server --offline

# Scan a published npm package without running it
mcpiranha scan npm:@scope/server@1.2.3

# Save a JSON report (use -f sarif for GitHub code scanning)
mcpiranha scan .mcp.json -f json -o report.json

# Show all scan options and descriptions
mcpiranha scan --help
```

Scans do not start servers by default. Add `--connect` to inspect a live server.
Sandboxed local connections require Docker; on Windows, use Docker Desktop with Linux containers.

## Reading Results

Each finding shows its **severity**, **confidence**, **location**, **evidence** and a **suggested fix**.
Severity describes potential impact; confidence describes certainty in the finding.

Check coverage alongside findings: `completed` means the supported analysis completed,
`partial` means some analysis was omitted, `skipped` means the check did not run, and
`failed` / `unknown` means coverage could not be established.

| Exit code | Meaning |
|---|---|
| `0` | No findings meet the failure threshold; requested checks passed |
| `1` | Findings meet the failure threshold (high severity by default) |
| `2` | Scan error, unmet coverage requirement or a warning with `--strict` |

Use `--fail-on medium` to fail on medium-severity findings too.

[Full usage guide](https://github.com/ethanroubal/MCPiranha/blob/main/docs/USAGE.md) ·
[Rules](https://github.com/ethanroubal/MCPiranha/blob/main/docs/RULES.md) ·
[Supported clients](https://github.com/ethanroubal/MCPiranha/blob/main/docs/CLIENTS.md) ·
[Report an issue](https://github.com/ethanroubal/MCPiranha/issues/new/choose)
