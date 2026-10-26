# Usage guide

Start with the [README](../README.md) for installation, common commands and interpreting results.
This guide covers advanced scanning, policy, sandbox behavior and development. Historical
calibration figures describe tuning runs, not deployment accuracy; see the
[detection evaluation](../evaluation/README.md) for current measurements and limitations.

## Toxic flows

Servers that are harmless alone can be dangerous together. mcpiranha labels every tool (reads
untrusted content, reads private data, sends data out, runs code, destroys data) from its name,
its parameters and a table of well-known servers, then looks across all servers one client
loads. **MCP-TF-001** reports the "lethal trifecta", e.g. `github.get_issue -> filesystem.read_file
-> slack.post_message`: one poisoned issue can make the agent read your files and post them.
**MCP-TF-002** reports untrusted content next to code execution or destructive tools. Flows across
servers are high severity (critical if the last step is auto-approved); flows inside a single
server, which are usually by design, are lower. Well-known servers count even without
`--connect`.

## Supply chain

`scan` looks every npm and PyPI package a config runs up on the registry and on
[osv.dev](https://osv.dev): the release `npx`/`uvx` would install (or, with `--connect`, the one
that was installed), its publisher, install scripts, provenance and the release before it.
**MCP-SC-001** reports known vulnerabilities and known malware (e.g. `mcp-remote@0.1.15`,
CVE-2025-6514; `postmark-mcp@1.0.16`, taken down and listed as MAL-2025-47604).
**SC-002** install scripts (high when the release just added one), **SC-003** a release that lost
its build provenance or moved to another owner's repository, **SC-004** a package under 30 days
old, **SC-005** a release by an npm account that never published the package before, **SC-006**
deprecated or yanked releases and names missing from the registry (which anyone could register).
This sends package names and versions to those services; `--offline` (or
`MCPIRANHA_OFFLINE=1`) turns it off. `MCPIRANHA_NPM_REGISTRY` / `MCPIRANHA_PYPI_INDEX` point
at a mirror. Docker images aren't looked up yet.

**Dependencies** get the same treatment (`--no-deps` turns it off): the tree npx/uvx would
install is resolved from registry metadata (npm ranges and aliases; PyPI Requires-Dist with
markers evaluated for the sandbox's Python), up to 400 packages, and every dependency is checked
against OSV. **SC-007** reports known malicious (critical) or vulnerable dependencies, **SC-008**
dependencies that run code at install (low; high when a release from the last 30 days just added
it), **SC-009** suspicious ones: a name the registry doesn't have, a git or URL dependency, or a
recent release with a new publisher or without the provenance its predecessor had. Install
scripts' command lines are judged as executed commands, and the code of dependencies that run at
install or look hijacked is read with the MCP-SRC rules (paths show `name@version/file`). Each
finding names the chain that pulls the dependency in (`server > lib > leaf`).

## Source analysis

mcpiranha also reads the code a server runs, without running it: a local script the config
launches (`python server.py`, `node build/index.js`), or, online, the npm tarball or PyPI wheel
of the resolved release, checked against the registry's hash and read in memory (nothing is
extracted or installed). Python is parsed with `ast`, JavaScript/TypeScript (bundles and
minified output included) with tree-sitter. The MCP-SRC rules look for malice behind honest
metadata: **SRC-001** a fixed address added as Bcc/Cc (how postmark-mcp copied every email),
**SRC-002** collecting secrets from the environment, **SRC-003** credential paths in code that
also has a way out, **SRC-004** running decoded, downloaded or obfuscated code, **SRC-005** a
hardcoded request catcher, tunnel or Discord webhook, **SRC-006** reverse shells, **SRC-007**
miners, **SRC-008** persistence (writing shell profiles, LaunchAgents, cron), **SRC-009** writing
MCP client configs, **SRC-010** wipers. Command strings only count when executed and config paths
only when written, since deny-lists and installers are full of both.

**Exploitable tool handlers** (taint analysis): tool arguments are followed from the handler
(`server.tool(...)`, `registerTool`, `@mcp.tool()`, low-level `call_tool` handlers) through
assignments, simple object/dictionary fields and aliases, common array/iterable callbacks, and
helper arguments/returns across the package's files using cached contexts and a bounded work
queue. Module-level local imports bind to files and symbols, including aliases, namespaces,
Python package entrypoints, ESM re-exports/default exports, and common CommonJS/TypeScript
`require` bindings. Imported callbacks and tool registrations use their defining module.
Unrelated same-named functions are not treated as imported helpers. **SRC-101** command injection,
**SRC-102** SQL injection, **SRC-103** path traversal, **SRC-104** SSRF. Only input spliced into
code the developer wrote counts: ``execSync(`git log ${branch}`)`` is reported, a shell tool
running the `command` it's given is a capability (the toxic-flow rules cover that), not a bug.
It flags the vulnerable releases of two servers with published command-injection CVEs, and
stays quiet on their fixes.

Path guards are matched to the value being used and must execute before the file operation.
Recognized patterns include resolved Python paths checked with `is_relative_to`/`relative_to`,
normalized JavaScript paths checked against a normalized base plus `path.sep`, and filename
component rejection (both separators and dot traversal for portable paths). A label, comment,
ignored boolean check, weak string prefix or check on another path does not suppress a finding.
Protection passed to helpers is specific to the checked argument. Custom validators and more
complex control flow can still require manual review; this does not prove filesystem safety
against symlink races or arbitrary side effects.

Unguarded paths joined to an intended base and input inserted into a request's host are high
severity risks (SRC-103/SRC-104), with medium static-analysis confidence. They now affect the
normal `--fail-on high` gate; recognized safe cases and whole-input capabilities remain excluded.

Sanitizers are evaluated for the sink: shell quoting does not make a path, SQL fragment or
hostname safe. `basename()` is a transformation, not a containment guarantee: it can return
`.` or `..`, and a joined suffix can then reach outside the intended base. Its input remains
tainted in Python and JavaScript/TypeScript, including helper-return flows. Use a recognized
check on the resolved candidate or a small safe literal filename allowlist before use. Quoting inside existing shell quotes is not accepted as protection. Small
literal allowlists can suppress findings only when they reject unsafe values before use and
the checked binding remains unchanged. Helper calls use a cached, context-sensitive work queue
instead of a fixed two-call cutoff. Per-language/package limits are 4,096 helper contexts,
4,096 return summaries, 1,000,000 analysis node visits, 24 nested return summaries, 32 assignment
propagation passes and 65,536 inferred literal characters. Guard inference retains its
2,000-node limit. Expression inference stops beyond 40 nested evaluations and literal/URL
alias inference after eight bindings. Source findings are capped at 100 per package and 300 with dependencies.

Import/re-export resolution is capped at 64 steps. Missing or ambiguous local bindings,
unresolved local exports, re-export cycles and handler-local reassignment/shadowing of imported
callables also mark analysis partial. Recognized methods on literal exported constants do not
create unresolved-function warnings. External libraries without supplied source are outside
this local resolver; their ordinary calls are not reported as missing project modules.

Resolution is static, not a language runtime. Function-scoped imports, dynamic imports/requires,
custom import hooks, TypeScript path mappings, conditional exports, arbitrary object/class
methods and complex rebinding remain limitations. Python wildcard imports do not model custom
`__all__` behavior. Same-file lexical scope and runtime module search paths can require review.

Exhausted limits retain findings and mark source coverage partial, with a warning that fails
`--strict`. Snapshots preserve these reasons. Arbitrary object methods, dynamic dispatch and
custom validators remain limitations even when coverage is completed. Detection-quality
measurements and their limits are documented in [the evaluation report](../evaluation/README.md).

## Server behavior during a session

With `--connect`, mcpiranha also reads prompt bodies and static resource contents and keeps log
notifications, so poisoning there is caught like poisoning in descriptions. It advertises
sampling, elicitation and roots like a real client (over the classic protocol too, where servers
can send such requests mid-call), declines every request, and reports a server that uses your
model, maps your workspace (**DY-001**) or asks you for input, worst when it's a password or token
(**DY-002**), while it was only being listed.

## Experimental classifier

`--classifier` adds a local prompt-injection model (protectai/deberta-v3-base-prompt-injection-v2,
Apache-2.0, ~740 MB, downloaded once and verified against pinned hashes). It catches some reworded
attacks the phrase rules miss, but it was trained on chat prompts and flags ordinary usage
guidance in tool descriptions too, so its findings are low severity and meant as a review
queue. Measurements: [calibration/README.md](https://github.com/ethanroubal/MCPiranha/blob/main/calibration/README.md).

## Policy file

`.mcpiranha.yaml` in the current directory (or `--policy PATH`) sets defaults and suppresses
findings you've reviewed. Suppressed findings stay in JSON and SARIF output, marked with their
reason.

```yaml
fail_on: high
strict: true            # exit 2 on scan warnings, including partial source analysis
suppress:
  - rule_id: MCP-CF-001
    server: internal-db
    reason: Secret is injected by vault at runtime   # required
    expires: 2027-01-01                               # optional
  - rule_id: "MCP-TP-*"   # globs work for rule_id, server and tool
    server: docs-search
    reason: Reviewed 2026-10; descriptions quote attack examples on purpose
```

## Static inspection without execution

`scan npm:<package>` and `scan pypi:<package>` resolve registry metadata, check advisories and
inspect hash-verified release archives without installing the package, running install scripts
or starting the server. Network access is used for metadata and archives; `--offline` disables
those lookups. Tool metadata remains unknown until an explicit `--connect` scan. Docker images
and remote URLs still require `--connect`.

A `.py`, `.js` or `.ts` file (including supported variants) is read as source. A directory with
no discovered MCP configuration is scanned as source; directories with configurations retain
client discovery behavior. Use `path:<directory>` to explicitly inspect source in either case.
Source traversal excludes dependency/test directories and does not follow child symlinks.
Source-only paths have no launch configuration and reject `--connect`. Python parse failures
and JavaScript/TypeScript recovery errors produce partial source coverage, preserving findings
from files or syntax trees that could still be analyzed.

## Server selection and scan coverage

Use `--server` to select an exact server name or stable ID before any connection, package
lookup or source acquisition. Repeat it to select several servers. `--client` narrows the
selection to exact client identifiers such as `cursor` or `claude-desktop`:

```bash
mcpiranha scan --client cursor --server filesystem --connect
mcpiranha scan .mcp.json --server search --connect --dynamic --invoke search
mcpiranha scan .mcp.json --server search --server files --offline
```

Names shared by multiple clients select all matches; combine with `--client` or use the ID
shown in terminal reports, JSON reports or `inspect` to disambiguate. Every selector must
match, or the command exits 2 before acquisition. Repeated values are combined with OR;
client and server selectors are combined with AND. Selection also works with `lock`,
`verify`, `inspect` and `flows`. A selected `lock` writes only the selected servers; selected
`verify` ignores removals outside that scope. Cross-server rules see only the selected servers,
so scan the whole client configuration when checking interactions between servers.

Each report includes per-server coverage for configuration, tool metadata, source, package
and vulnerability lookups, dependencies, dynamic tracing, and explicit tool invocation.
Statuses are `completed`, `partial`, `skipped`, `failed`, or `unknown`, with reasons and
file/tool/dependency/call counts where applicable. A completed stage means evidence was
collected within that stage's limits; it does not establish that the server is safe. An empty
tool list is distinguished from tools that could not be listed. Tracing and invocation have
separate statuses because either can run without the other.

Saved snapshots retain coverage; reloaded records are labelled as saved evidence, not fresh
observations. Older snapshots remain readable and their coverage is inferred conservatively.
JSON reports now use `schema_version: 2` with coverage under each server. SARIF stores it in
`runs[].properties.coverage` and includes scan warnings in invocation notifications. Coverage
does not change severity thresholds. Partial source analysis emits a warning, so `--strict`
also fails when analysis is incomplete.
Use `--require-coverage source` (repeatable) or policy `require_coverage: [source, package]`
to exit 2 when required stages are partial, skipped, failed or unknown. Requirements apply to
every selected server and cannot be suppressed as findings; no targets also fails a requirement.
CLI requirements add to policy requirements. Saved completed evidence can satisfy a requirement;
it does not imply a fresh connection or lookup.

## What `--connect` does

It initializes the server, lists tools, prompts and resources, and fetches supported prompt
bodies and static resource contents. Tool calls require explicit `--invoke` names. Tools are
listed twice to catch servers that change them mid-session.

- **stdio servers** run in a Docker sandbox by default. The package is downloaded with network
  access but without running any of its code (`npm install --ignore-scripts`, wheels only for
  PyPI), then the server runs with no network, a read-only filesystem, no capabilities, a
  non-root user and resource limits. Servers that run local files can't be sandboxed this way;
  `--sandbox none` runs servers directly on this machine, as your MCP client would.
- **Env vars** get dummy values unless you pass `--real-credentials` (which also expands
  `${VAR}` references). Most servers list their tools without valid credentials.
- **Remote servers** are reached without credentials unless you pass `--real-credentials`
  (the config's headers), `--header` (for a single URL target only, so a token can't reach
  another server) or `--oauth` (signs in through your browser; tokens stay in memory for that
  run). A server that answers without credentials is reported (MCP-CF-003).
- **Servers run in parallel**, four at a time (`--jobs`). npm and uv downloads are cached in the
  Docker volumes `mcpiranha-npm-cache` and `mcpiranha-uv-cache`; remove them with
  `docker volume rm` to start fresh.
- **Locking** with `--connect` also pins the package version or image digest that actually ran,
  so `verify` catches an unpinned `npx -y pkg` quietly moving to a new release.
- **Opt-ins** for servers that won't start otherwise: `--allow-network` (network while running)
  and `--allow-install-scripts` (npm install scripts and PyPI source builds during download).
  Both are off by default.
- **`--save-snapshots DIR`** keeps what each server served, so it can be rescanned offline.
- **Disabled servers** (disabled in their client config) aren't started.
- **Older servers** that crash on the 2026 `server/discover` probe are retried in a fresh
  process with the classic `initialize` handshake.
- **Versions can differ from your machine's**: npm picks the newest release whose `engines`
  match the sandbox's Node 22 (`MCPIRANHA_NODE_IMAGE` overrides the image), so an unpinned package
  may resolve differently than on a machine with a newer Node.

## Calibration

The tool-metadata rules are tuned against the 100 most-downloaded servers in the official MCP
registry: zero false positives on the 59 the sandbox could list, with the attack fixtures still
detected. Method, scripts and results: [calibration/README.md](https://github.com/ethanroubal/MCPiranha/blob/main/calibration/README.md).

The supply-chain rules were run on the same 85 npm/PyPI servers, pinned and unpinned: no false
publisher or provenance alarms, one package with 159 advisories, two yanked or deprecated
releases, and one registry config that runs a PyPI name nobody owns. The source rules read
19,000 files across their releases with no findings.

Attacks are tested against [the zoo](https://github.com/ethanroubal/MCPiranha/blob/main/zoo/README.md): 48 safe-by-construction
malicious and vulnerable servers, configs and packages, including reconstructions of public
incidents and hijacked or backdoored releases (and dependencies) served from local registries.
They're organized by a [threat catalog](https://github.com/ethanroubal/MCPiranha/blob/main/zoo/threats.yaml) of 63 ways an MCP server can act
maliciously, which a test keeps in sync with the rules: 55 are detected, 6 partly, and 2 are
tracked gaps (repository diffs and conditional runtime triggers). Runtime egress and file
access have partial coverage through opt-in behavioral scanning.

## Development

```bash
uv sync --all-extras
uv run mcpiranha scan fixtures/metadata/unicode-tag-smuggling/snapshots.json
uv run mcpiranha scan fixtures/configs/claude_desktop_config.json
uv run mcpiranha inspect fixtures/metadata/unicode-tag-smuggling/snapshots.json
uv run pytest                     # MCPIRANHA_DOCKER_TESTS=1 also runs a real Docker sandbox
uv run ruff check . && uv run ruff format --check . && uv run pyright
```

The [adversarial testing guide](https://github.com/ethanroubal/MCPiranha/blob/main/docs/TESTING.md) explains the attack/disguise matrix, benign
controls, live replay tests, runtime evidence checks and the limits of what they prove.

## Adding a rule

1. Reserve an id in `docs/RULES.md`.
2. Add a module under `src/mcpiranha/rules/builtin/` with a `Rule` subclass decorated with
   `@register` (see `invisible_unicode.py`). Iterate text with `iter_text_fields` so nested schema
   text is covered.
3. List the id in `expected.json` for each fixture case it should fire on, and add a benign
   look-alike case. `tests/test_fixtures.py` then checks it everywhere.
4. Build any invisible or look-alike characters with `chr()`; `tests/test_source_hygiene.py`
   fails on raw ones in the source.

Third-party rule packs can register through the `mcpiranha.rules` entry-point group.

## Behavioral scanning (phase 04)

```bash
# Observe startup/listing: seed synthetic credentials, trace syscalls, log/deny egress.
uv run mcpiranha scan npm:@acme/server@1.2.3 --connect --dynamic --strict

# Explicitly call one named tool. Annotations never authorize invocation.
uv run mcpiranha scan npm:@acme/server@1.2.3 --connect --dynamic \
  --invoke lookup --invoke-args '{"query":"mcpiranha-test"}' --save-snapshots ./captures

# Add traversal, shell-marker and reserved-address SSRF inputs (maximum 24 calls/server).
uv run mcpiranha scan npm:@acme/server@1.2.3 --connect --dynamic \
  --invoke lookup --invoke-args '{"query":"mcpiranha-test"}' --fuzz
```

`--dynamic` requires a Linux Docker runtime with compatible architecture and support for
sharing a container's PID namespace and attaching strace. It builds a cached trusted helper
image (network needed for the first build). A static launcher seeds the synthetic HOME and
waits until a separate collector attaches, then starts the server. The server runs as UID 1000
without capabilities and mounts only read-only package/launcher volumes. Only the trusted
collector receives `SYS_PTRACE`; its private trace volume is never mounted in the server.
Untrusted server images are never used as build bases or run during helper setup.

The server joins an internal network; a separate HTTP/HTTPS proxy logs destinations and denies
requests. With `--allow-network`, that proxy forwards HTTP/HTTPS, including CONNECT for TLS.
Clients ignoring proxy environment variables cannot directly reach the Internet. The proxy
records destinations, never headers or bodies; it does not decrypt TLS.

The synthetic HOME contains fake SSH, AWS, dotenv and browser-cookie files. Successful opens
for reading during startup/listing produce critical findings. The sensor also follows positive
reads through observed duplicated/inherited descriptors, readable file mappings, and observed
hard-link and rename aliases (including renamed directories). Descriptor close/reuse and
close-on-exec state are tracked. Read buffers are not decoded: evidence contains addresses
and byte counts. A readable mapping is reported as a mapping, not proof its pages were read.
Reports prefer the strongest evidence for a credential within each phase/probe window.
Syscall tracing handles absolute and relative paths, directory file descriptors, forked
working directories, split syscall records, DNS queries and process execution. Attempts to signal or trace the protected collector
produce MCP-DY-007 findings. Evidence is retained even when initialization crashes, while the
scan remains incomplete (`--strict` exits 2). Trace limits, unsupported runtimes, unobserved
syscalls and conditional triggers remain coverage limits; a clean scan is not proof of safety.
The default scan remains static.

`--invoke NAME` is repeatable and requires exactly one server target. It can cause side effects
even if a server labels its tool read-only. Bounded required objects, arrays and local schema
references can be generated; unsupported constraints require `--invoke-args` as a JSON object.
Generated and explicit baseline arguments are checked against JSON Schema Draft 7, 2019-09
or 2020-12 before any tool call. Validation runs offline in a separate worker with a two-second wall limit, bounded
input/depth/size, and Linux CPU/memory limits. External references are never fetched; costly
or unsupported schemas fail the probe visibly. Format annotations are not asserted. A server
rejecting a valid baseline makes the scan incomplete and stops further probes for that tool;
the response is retained. `--fuzz` deliberately permits mutations outside schema constraints,
mutates nested string values, and makes at most 24 calls per server.
A separate nonsensitive traversal canary lives at `/tmp/mcpiranha-canary`. Each call has a probe
ID, variant, argument path, status and time window. Saved snapshots link outputs and behavioral
observations to those probe IDs. MCP-DY-006 flags canary access during a matching fuzz window;
this temporal association does not establish causality or unauthorized behavior. Tool text and
structured results also pass through the existing poisoning detectors. Failed or truncated
probes produce warnings; the scanner never replays a call after invocation begins.

Declare expected destinations explicitly to distinguish normal traffic from unknown endpoints:

```bash
uv run mcpiranha scan npm:@acme/server@1.2.3 --connect --dynamic \
  --expected-destination api.example.com:443 --observe-seconds 5 --strict
```

`--expected-destination` is repeatable and matches an exact normalized host:port across the scan.
It keeps matching network activity as informational findings; it does **not** permit egress,
verify a destination's safety, suppress unknown destinations, or lower credential-access findings.
DNS queries use host:53 entries. Only the proxy hop and its internal hostname lookup are treated
as infrastructure; other DNS queries remain visible. `--observe-seconds` accepts 0–30 seconds
within the server timeout. Delayed observations outside a call window remain unassigned rather
than being attributed to a completed probe. Explicit invocation also works over remote
transports and the existing `--sandbox none` mode, without local syscall tracing.

Run the safe Docker regression with:

```bash
MCPIRANHA_DOCKER_TESTS=1 uv run pytest -q tests/test_dynamic*.py
```
