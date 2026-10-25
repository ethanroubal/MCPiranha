# Rule catalog

Ids are permanent: never renumber or reuse one. Status: ✅ implemented, ⬜ planned.
Sections refer to docs/ARCHITECTURE.md §5. Tool-metadata rules were tuned against the 100
most-downloaded registry servers; see calibration/README.md.

## MCP-TP — Tool poisoning (§5.1)
| Id | Title | Status |
|---|---|---|
| MCP-TP-001 | Invisible or smuggled Unicode characters | ✅ |
| MCP-TP-002 | Terminal escape sequences | ✅ |
| MCP-TP-003 | Directive markup (`<IMPORTANT>`, `<system>`, fake role markers) | ✅ |
| MCP-TP-004 | Instructions steering the model against the user | ✅ |
| MCP-TP-005 | Instructions involving credentials or sensitive files | ✅ |
| MCP-TP-006 | Encoded payloads (base64 / hex) | ✅ |
| MCP-TP-007 | Exfiltration via rendered links or images | ✅ |
| MCP-TP-008 | Padding that pushes suspicious text out of view | ✅ |
| MCP-TP-009 | Exfiltration-shaped parameters | ✅ |
| MCP-TP-010 | Sentence classified as a prompt injection (`--classifier`, experimental) | ✅ |

## MCP-XS — Cross-server (§5.2)
| Id | Title | Status |
|---|---|---|
| MCP-XS-001 | Description references another server's tools | ✅ |
| MCP-XS-002 | Tool name collision or confusable look-alike | ✅ |
| MCP-XS-003 | Server name typosquat | ✅ |

## MCP-RP — Rug pulls & integrity (§5.3)
| Id | Title | Status |
|---|---|---|
| MCP-RP-001 | Tool definition changed since lock | ✅ |
| MCP-RP-002 | Tools changed during a session (`--connect`) | ✅ |
| MCP-RP-003 | Floating (unpinned) package version | ✅ |

## MCP-CF — Configuration & transport (§5.4)
| Id | Title | Status |
|---|---|---|
| MCP-CF-001 | Plaintext secret in client config | ✅ |
| MCP-CF-002 | Remote server over plain HTTP | ✅ |
| MCP-CF-003 | Remote server without authentication (`--connect`) | ✅ |
| MCP-CF-004 | Dangerous launcher (`curl \| sh`, `--privileged`, host mounts) | ✅ |
| MCP-CF-005 | Over-broad filesystem scope | ✅ |
| MCP-CF-006 | Tool calls approved without confirmation (client auto-approve settings) | ✅ |

## MCP-TF — Toxic flows across servers (§5.7)
| Id | Title | Status |
|---|---|---|
| MCP-TF-001 | Untrusted input, private data and an outbound channel in one agent | ✅ |
| MCP-TF-002 | Untrusted input and code execution or destructive tools in one agent | ✅ |

## MCP-SC — Supply chain (§5.6)
Judged on registry and OSV data gathered before the scan (`mcpiranha.supply`); off with `--offline`.

| Id | Title | Status |
|---|---|---|
| MCP-SC-001 | Known vulnerability (OSV) or known malicious package (OSV `MAL-`) | ✅ |
| MCP-SC-002 | Package runs code at install time (npm lifecycle scripts, sdist-only PyPI release); high when just added | ✅ |
| MCP-SC-003 | Release lost its build provenance, or was built from another owner's repository | ✅ |
| MCP-SC-004 | Very new package (under 30 days) | ✅ |
| MCP-SC-005 | Release published by an npm account that never published the package before | ✅ |
| MCP-SC-006 | Deprecated or yanked release, or a package name missing from the registry | ✅ |
| MCP-SC-007 | Known malicious (critical) or vulnerable dependency | ✅ |
| MCP-SC-008 | Dependency runs code at install time (high when a recent release just added it) | ✅ |
| MCP-SC-009 | Suspicious dependency: not on the registry, from git/URL, or a recent release with a new publisher or lost provenance | ✅ |

## MCP-SRC — Source code (§5.5)
Judged on what `mcpiranha.source` finds in a local script or the package's release archive.

| Id | Title | Status |
|---|---|---|
| MCP-SRC-001 | Code adds a fixed Bcc/Cc recipient | ✅ |
| MCP-SRC-002 | Code collects secrets from the environment (serializes it, or reads TOKEN/KEY values) | ✅ |
| MCP-SRC-003 | Code names credential files and has a way to send data out | ✅ |
| MCP-SRC-004 | Code runs decoded, downloaded or obfuscated code (`eval(atob(...))`, `exec(b64decode(...))`, javascript-obfuscator, PyArmor) | ✅ |
| MCP-SRC-005 | Code contains a request-catcher, tunnel or Discord webhook address | ✅ |
| MCP-SRC-006 | Code opens a reverse shell (executed `/dev/tcp`, `nc -e`, a shell wired to a socket) | ✅ |
| MCP-SRC-007 | Code mines cryptocurrency (mining pools, xmrig) | ✅ |
| MCP-SRC-008 | Code installs itself to run later (writes shell profiles, LaunchAgents, systemd, cron, git hooks) | ✅ |
| MCP-SRC-009 | Code writes MCP client configs (low; high when it also sets auto-approve) | ✅ |
| MCP-SRC-010 | Code wipes the home directory or the disk | ✅ |
| MCP-SRC-101 | Tool argument injected into a shell command | ✅ |
| MCP-SRC-102 | Tool argument injected into a SQL query | ✅ |
| MCP-SRC-103 | Tool argument escapes its base directory (joined without a containment check) | ✅ |
| MCP-SRC-104 | Tool argument chooses the host of a server request (SSRF) | ✅ |

SRC-1xx are taint rules: input spliced into a command, query or URL host, or joined to a base
directory, counts; input used whole (a shell tool's `command`) is a capability, not a finding.
SRC-103 and SRC-104 classify these unguarded boundary flows as **high severity**, with
**medium confidence** in the bounded static analysis. Severity expresses potential impact;
it does not assert observed exploitation or raise the analyzer's certainty. Recognized guards,
literal allowlists, safe argument positions and whole-input capabilities remain excluded.

## MCP-DY — Server behavior during a session
Observed while listing (`--connect`): mcpiranha advertises sampling, elicitation and roots like a
real client, declines each request, and records it. It also reads prompt bodies, static resource
contents and log notifications, which the MCP-TP rules then check like descriptions.

| Id | Title | Status |
|---|---|---|
| MCP-DY-001 | Server used the client's model (sampling) or asked for its roots, unprompted | ✅ |
| MCP-DY-002 | Server asked the user for input (elicitation), unprompted; high when it asks for secrets | ✅ |

Runtime egress and file access checks are available with Phase 4 (below). Tool output uses
the existing MCP-TP rules after explicit invocation.

Every rule is mapped to the threats it covers, and to the tests that prove it, in
[zoo/threats.yaml](../zoo/threats.yaml).

### Dynamic behavior (opt-in)

| ID | Check | Default severity |
|---|---|---|
| MCP-DY-003 | Successful read-capable open, positive read, or readable mapping of a synthetic credential file, including observed aliases | critical during startup/listing; high during invocation |
| MCP-DY-004 | Network attempts from syscall traces or the logging proxy | high during startup/listing; medium during invocation; info for explicit expected destinations |
| MCP-DY-005 | Successful execution of a shell | medium |
| MCP-DY-006 | Fuzz-window access to a traversal, shell or network canary | medium; review intended permissions |
| MCP-DY-007 | Attempt to signal or trace a protected collector process | high |

These findings use `detector: dynamic`. Network attempts do not prove exfiltration, and a
credential open or readable mapping does not prove its bytes were consumed. Positive reads
record byte counts without buffer contents. Observed aliases and descriptor lifetimes are
tracked; the strongest evidence per phase/probe is reported. Trace events include phase and raw
syscall evidence. Saved snapshots preserve observations for offline rescans.
