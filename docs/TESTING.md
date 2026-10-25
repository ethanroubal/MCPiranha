# Adversarial regression tests

The test suite checks specific detection guarantees and benign controls. A passing suite
does not prove detection of every malicious server, paraphrase, program behavior or trigger.

Run the new adversarial batches without Docker or registry access:

```bash
uv run pytest -q tests/test_adversarial_matrix.py tests/test_runtime_matrix.py
```

`test_adversarial_matrix.py` places the same credential-stealing instruction on 32 surfaces:
tool/server metadata, prompt arguments, resources, input/output schemas, earlier tool
definitions and six kinds of session content. Eight disguises cover ordinary and uppercase
text, fullwidth characters, zero-width insertion, Unicode tags, variation-selector encoding,
base64 and hex. The 256 attack cases assert expected detectors, exact JSON pointers and
verbatim evidence spans. Another 128 cases put legitimate usage instructions, credential-path
mentions, hashes and emoji on the same surfaces to check false positives.

Two live stdio tests use `fixtures/servers/structured_poison.py`, an inert metadata fixture
and its clean twin. The poisoned fixture removes its payload after the first listing. Tests
check detection in the retained definition and in a saved snapshot rescanned offline; the
fixture never reads credentials or sends network traffic.

`test_runtime_matrix.py` adds 115 deterministic checks for five credential-read syscalls,
all four synthetic credential paths, decimal/hexadecimal successful reads, EOF and failed
reads, ordinary files, descriptor replacement, probe-window boundaries, incomplete probe
windows and expected versus unexpected network activity. These are trace-parser and rule
tests; they complement the existing live Docker tests and do not replace them.

Run the full suite including live Docker tracing:

```bash
MCPIRANHA_DOCKER_TESTS=1 uv run pytest -q
```

Registry-backed zoo tests additionally require `MCPIRANHA_ZOO_REGISTRIES=1` and the local
registries described in `zoo/README.md`. Classifier integration requires
`MCPIRANHA_ML_TESTS=1`, the optional ML dependencies and the downloaded model.

When adding attacks, specify the expected rule independently of scanner output, add a benign
twin, and check evidence/location as well as detection. If the scanner misses a supported
case, retain the failing regression while fixing it. For an unsupported behavior, record the
limitation in `zoo/threats.yaml`; do not weaken the expected result to make the test pass.

Remaining evaluation priorities include independent paraphrases, source flows through
callbacks/objects beyond current taint limits, and payloads gated on time, identity or call
counts. Bounded scans cannot guarantee activation of arbitrary conditional behavior.

## Path-containment regression checks

`uv run pytest -q tests/test_path_guards.py tests/test_taint.py` checks ineffective guards
(labels/comments, ignored results, late checks, unrelated paths/roots, reassignment and weak
prefixes, `relative_to(walk_up=True)` and partial-string offset checks) against recognized guards that reject unsafe values before the sink. It also checks
that a helper's unchecked second argument remains reportable, aliases retain their value, and
inference-budget exhaustion cannot invent a safety proof. Portable filename guards must reject
both slash forms and dot traversal; forward-slash-only rejection is accepted only for explicit
Python `posixpath.join` operations.

The earlier JavaScript benign example using `p.startsWith(ROOT)` was insecure against sibling
prefixes. Its benign replacement uses a normalized base plus `path.sep`; the old form remains
in the adversarial cases. These are developer-authored regressions, not an independent blinded
benchmark or a general safety guarantee. Custom validators, object/callback flows and filesystem
races remain limitations.

### Static package smoke pilot

The published 0.3.0 wheel and the guard-fix candidate were compared on these pinned packages
using static scans with `--no-deps --no-lock`; no server was started or tool invoked:

| Package | Version | Source files | Path findings, baseline / candidate |
|---|---|---:|---:|
| `npm:@modelcontextprotocol/server-filesystem` | `2.0.0` | 7 | 0 / 0 |
| `npm:@modelcontextprotocol/server-everything` | `2.0.0` | 48 | 0 / 0 |
| `pypi:mcp-server-time` | `2026.10.19` | 3 | 0 / 0 |

Source collection completed without errors for both versions. Other rule findings were not
suppressed. This small compatibility check is not an independent user pilot, a labeled
malware benchmark, or an estimate of detection accuracy; deeper evaluation still needs
independently reviewed malicious and benign examples.

## Detection-quality evaluation

The repository now has a separate [labeled challenge experiment](../evaluation/README.md)
with 64 cases across eight threat families, frozen first-run reports at medium/high thresholds,
and per-case regression checks. It measures false alarms as well as missed attacks, and records
analysis failures separately. Run `uv run pytest -q tests/test_detection_quality.py` or
`uv run python -m evaluation.quality --output /tmp/quality.json` from the repository root.

The first candidate measurement caught 13/32 attacks and flagged 7/32 benign cases at medium
severity. These are developer-authored challenge results, not deployment accuracy estimates.
They expose source-flow and semantic-instruction gaps that passing zoo regressions conceal.
The labels and detectors were not adjusted to improve these scores. See the experiment README
for scoring policy, assumptions, case-level reports and a path toward independent evaluation.

`MCPIRANHA_QUALITY_REGISTRIES=1 uv run pytest -q tests/test_detection_quality_registry.py`
checks two existing published-CVE release pairs against their fixes. It downloads hash-verified
archives without installing or executing them and rejects incomplete source collection.
Both vulnerable releases were flagged and both fixed releases were clean in the initial run.

### Detection fixes and generalization checks

`tests/test_quality_improvements.py` adds 99 developer-authored checks outside the original
corpus: field and alias flows, helper return values, Python/JavaScript callbacks, clean neighboring
fields, fixed returns, inactive nested functions, fake and context-inappropriate sanitizers,
quoting inside shell quotes, ineffective allowlists, later assignments, computed writes/spreads,
negated instructions, defensive-quote bypasses, and CSS/cache-query rendering behavior.

The unchanged 64-case corpus now catches 32/32 attacks with 0/32 benign medium alerts, versus
13/32 and 7/32 initially. At high severity it catches 16/32, versus 7/32 initially, with no benign
high alerts. Candidate reports are separate from the original baseline, and per-case regression
checks protect the improvements. These are development-set results after tuning, not independent
accuracy estimates. The two CVE pairs still pass; the same three pinned package scans retain
identical rule/severity finding counts, with completed source coverage for all 58 files.

### High-severity classification

`uv run pytest -q tests/test_high_severity.py` runs 99 additional severity/control checks,
including four inert static CLI cases that verify `--fail-on high` exits 1 for unsafe flows
and 0 for their safe counterparts. Text checks cover four surfaces and fullwidth normalization,
local impact corroboration, unrelated/retry outcomes, explicit credential exports, pronouns,
negation, quotes, public identifiers, different content sources and distance bounds.

The frozen corpus now catches 32/32 attacks at **both** medium and high thresholds, with no
benign medium/high alerts. The 16 additional high alerts were already detected at medium;
this stage corrects risk classification rather than claiming 16 new detections. Reports are
stored as `evaluation/high-threshold-{medium,high}.json`; the original baseline and preceding
candidate reports remain intact, and regression tests compare against all three stages.
Source severity expresses high potential impact while confidence remains medium. See the
[evaluation report](../evaluation/README.md) for the escalation policy and its limitations.


### Deeper helper flows and analysis limits

`uv run pytest -q tests/test_deep_helpers.py` runs 57 checks covering Python and
JavaScript/TypeScript sink chains of 3, 8 and 80 helpers, return chains of 3, 8 and 16 helpers,
and their safe counterparts. It also checks cross-file calls, recursive sink graphs,
context/return-summary reuse, separation of guarded or sanitized arguments, and concurrent
JavaScript package scans with isolated parser instances.

Forced context, summary, node, assignment, literal, expression/alias depth and finding limits must retain available
findings and mark source coverage partial. A 30-helper return chain checks the actual return
depth bound. Unresolved recursive return summaries must also report partial coverage while
retaining other findings. Saved evidence retains the limitation, and CLI checks require exit 2 under
`--strict` or `--require-coverage source`. These developer-authored regressions address the
previous two-helper miss; they do not measure independent deployment accuracy.


The unchanged corpus is also recorded in `evaluation/helper-flow-{medium,high}.json`, with
32/32 attacks detected, no benign alerts and no incomplete cases at either threshold. Both
vulnerable/fixed release pairs pass. The three pinned package scans keep the same findings;
filesystem now reports an unresolved recursive return summary as partial coverage, while
everything and time remain completed. This is a correction to completeness reporting, not a
new vulnerability finding.
