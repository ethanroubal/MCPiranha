# Changelog

## Unreleased

- Replace the two-call source-flow cutoff with cached, context-sensitive helper scheduling
  across Python and JavaScript/TypeScript files. Follow deeper sink and return chains while
  keeping safe argument and guard contexts separate.
- Report exhausted analysis/finding budgets as partial source coverage, preserve findings and
  replay reasons, and fail strict scans on incomplete source analysis.
- Shorten the README around common tasks, coverage and CI; move advanced usage into a guide.

- Classify unguarded handler-to-filesystem and handler-to-URL-host flows as high-impact risk,
  retaining medium static-analysis confidence and the existing capability/safety exclusions.
- Escalate nearby authority/authorization overrides paired with harmful actions, explicit
  deception, and failure/success contradictions about the same execution. Keep isolated,
  unrelated, negated, quoted and retry/new-execution cases below high.
- Recognize bound credential exports, including explicit content/pronoun references and a
  small set of French transfer verbs. A credential mention near an unrelated outward message
  no longer suffices for a high credential finding.
- Add 99 severity/control/CLI regressions and preserve earlier evaluation stages separately
  from the high-threshold reports; the unchanged corpus now catches 32/32 attacks at high.

- Follow simple object/dictionary fields and aliases, iterable callbacks and helper return
  values through injection analysis. Retain assignment alternatives so later safe values
  cannot erase an earlier unsafe SQL/URL use; isolate uncalled nested function scopes.
- Apply sanitizers per sink and shell quote context. Recognize only dominating, unchanged
  small literal allowlists; ignored checks and arbitrary validator names are not safety proofs.
- Detect additional authorization bypass, deceptive reporting, answer contamination and
  credential-in-URL instructions, plus CSS resource URLs. Reduce medium-severity noise from
  explicitly rejected attack quotations, public identifiers and numeric image cache versions.
- Preserve the 64-case evaluation baseline and record candidate results separately. Add
  generalization/benign-control regressions and opt-in vulnerable/fixed release tests.

- Replace function-wide path-containment keywords with value-specific, preceding guard
  recognition in Python and JavaScript/TypeScript. Reject ignored/late/wrong-path checks,
  weak prefixes, changed bindings and portable component guards missing a separator.
- Carry caller protection only to the particular checked helper argument; retain aliases
  and remove protection after reassignment. Bound guard inference to 2,000 syntax nodes.
- Add 78 path-guard adversarial and benign cases, including static CLI finding/evidence checks.

## 0.3.0 — 2026-10-24

- Inspect npm/PyPI metadata and verified source archives without `--connect`, installation,
  install scripts or execution. Add direct source-file/directory targets and `path:` overrides.
- Record Python parse failures and JavaScript/TypeScript recovery errors as partial coverage;
  prune excluded source directories and do not follow child symlinks.
- Add repeatable `--require-coverage` and policy `require_coverage` requirements. Incomplete
  required evidence fails with exit 2 and remains visible in JSON/SARIF even with suppressions.


- Add 501 adversarial/control tests covering text surfaces and disguises, runtime read
  semantics, descriptor reuse, probe attribution, and live poisoned-listing/offline replay.
- Detect payloads in nested schema examples/defaults/const/enum values and retained tools'
  output schemas; the new matrix exposed 40 previously missed variants.

- Add exact, repeatable `--server` and `--client` selection before acquisition across scan,
  lock, verify, inspect and flows. Reject unmatched selectors and scope lock verification.
- Report per-server evidence coverage, counts and skipped/incomplete reasons in terminal,
  JSON (schema version 2), and SARIF; preserve saved coverage and surface SARIF warnings.
- Record source byte-limit truncation as partial analysis instead of silently stopping.

- Isolate validator imports from the scanned directory and PYTHONPATH; explicitly support
  JSON Schema Draft 7, 2019-09 and 2020-12 without remote reference retrieval.

- Track observed hard-link/rename aliases, duplicated/inherited descriptors, positive reads
  and readable mappings of synthetic credentials. Keep read buffers out of traces and prefer
  the strongest credential/canary evidence per phase or probe.
- Validate baseline inputs offline in a bounded JSON Schema worker before invocation;
  retain rejected baseline responses and stop further probes for that tool with a warning.

- Preserve behavioral evidence when initialization crashes; keep strict scans incomplete.
- Isolate tracing in a separate collector container behind a static launch gate, resolve
  relative/directory-FD paths and split syscall records, and detect collector interference.
- Correlate nested fuzz probes with output and behavioral canaries (MCP-DY-006/007); record
  probe windows and status in snapshots. Add exact expected-destination classification,
  visible external DNS queries, bounded observation delays, and adversarial Docker controls.

- Add opt-in Docker behavioral scans: synthetic credential honeytokens, syscall tracing,
  and a logging HTTP/HTTPS egress proxy with default denial.
- Add named tool invocation, bounded deterministic fuzz inputs, and tool-output injection
  scanning. Incomplete probes are visible in strict scans; invocation is never retried.
- Add MCP-DY-003 through MCP-DY-005 and regression coverage for behavioral evidence.


## 0.2.0 — 2026-10-23

`scan` now looks past what a server shows the model: the package it runs, the code inside it,
everything it installs, and what it does during a session. Lookups go to npm, PyPI and osv.dev;
`--offline` turns them off, `--no-deps` skips dependency trees.

### Supply chain (MCP-SC-001..009)
- Resolves the release npx/uvx would run and checks it against OSV: known vulnerabilities and
  malware, even for packages the registry took down (postmark-mcp).
- Install scripts, lost build provenance, brand-new packages, releases by a new npm account,
  deprecated or yanked releases, and package names nobody owns.
- Dependency trees: every dependency checked against OSV, for install scripts, and for hijack
  signals on recent releases; each finding names the chain that pulls it in.

### Source analysis (MCP-SRC)
- Reads local server scripts, and the npm tarball or PyPI wheel of the release (hash-checked,
  read in memory, never installed). Python via `ast`, JavaScript/TypeScript via tree-sitter.
- Hidden behavior (SRC-001..010): fixed Bcc/Cc recipients, environment harvesting, credential
  theft, decoded/downloaded/obfuscated code, request catchers, reverse shells, miners,
  persistence, MCP client config writes, wipers.
- Exploitable tool handlers (SRC-101..104): taint from tool arguments to shell commands, SQL,
  file paths and URL hosts, across a package's files. Flags the vulnerable releases for
  CVE-2025-53355 and CVE-2025-52573 and not their fixes.
- The code of dependencies that run at install or look hijacked is read too.

### Session checks (with `--connect`)
- Reads prompt bodies, static resource contents and log notifications, and checks them like
  descriptions.
- Records sampling, roots and elicitation requests a server sends while only being listed
  (MCP-DY-001/002), also over the classic protocol where servers can send them mid-request.
- Scans earlier versions of tools that change mid-session (rug pulls).
- Opens only http(s) OAuth authorization URLs (CVE-2025-6514).

### Testing
- `mcpiranha bench` scores the scanner against the zoo: 48 safe-by-construction malicious and
  vulnerable servers, configs and packages, some served from local npm/PyPI registries.
- `zoo/threats.yaml` catalogs 63 ways an MCP server can act maliciously (54 detected, 4 partly,
  5 tracked gaps); a test keeps it in sync with the rules.
- Calibrated on the 100 most-downloaded registry servers: see `calibration/README.md`.

### Other
- Cross-server toxic-flow labels tightened on real server combinations.
- New dependencies: tree-sitter (JavaScript/TypeScript grammars), packaging.

## 0.1.0 — 2026-10-22

First release: client config discovery (16 clients), config and tool-metadata rules,
sandboxed `--connect`, lockfiles, policies, toxic flows, an experimental local classifier, and
TTY/JSON/SARIF output.
