# Introducing MCPiranha

Ready-to-edit copy for a launch post or a project listing. These are drafts; nothing has been
posted to another community. Use a community's own submission rules before sharing.

## Short description

MCPiranha is an open-source MCP security scanner for Model Context Protocol servers. Check
prompt injection, tool poisoning, unsafe configurations, vulnerable packages and risky source
code before connecting servers to your AI assistant.

## Launch post

**MCPiranha: an open-source MCP security scanner with offline checks**

I built MCPiranha to inspect MCP servers before giving them access to files, credentials or
other tools. It scans client configs, Python/JavaScript/TypeScript source and published packages,
with explicit opt-ins for live inspection. Reports include evidence, remediation and coverage.

Try a static scan of your configured servers:

```bash
uvx mcpiranha scan --offline --no-lock
```

It supports Windows, macOS and Linux, with configuration discovery for Claude Desktop/Code,
Cursor, VS Code, Codex CLI and others. JSON/SARIF reports fit CI workflows. A clean report is
not proof of safety; the repository documents detection limits and evaluation results.

I'm looking for feedback from MCP server authors and users: false positives, missed attacks,
installation problems, or anything that makes results hard to act on. Please share sanitized
examples through the issue form.

[Repository and demo](https://github.com/ethanroubal/MCPiranha) ·
[Install](https://pypi.org/project/mcpiranha/) ·
[Feedback](https://github.com/ethanroubal/MCPiranha/issues/new/choose)

## Directory listing draft

[Awesome MCP DevTools](https://github.com/punkpeye/awesome-mcp-devtools#testing-tools) has a
Testing Tools section that includes scanners. Review its contribution guidelines before proposing:

- [ethanroubal/MCPiranha](https://github.com/ethanroubal/MCPiranha) 🐍 — MCP security scanner for
  prompt injection, tool poisoning, unsafe configurations and risky source code. Offline static
  checks, explicit live inspection, and JSON/SARIF reports on Windows, macOS and Linux.

## First user feedback

Aim for five independently maintained MCP servers. Ask each willing maintainer to scan one
server, review one finding and report whether the evidence and remediation were useful.
Track completed scans, actionable findings, false alarms and installation failures. Collect
only volunteered, sanitized feedback; GitHub stars alone do not measure successful use.
