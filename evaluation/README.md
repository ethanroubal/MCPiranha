# Detection-quality challenge set

This experiment asks whether the scanner catches varied unsafe behavior and avoids flagging
benign near-neighbors. It is separate from the zoo's expected-rule regressions. Payloads are
inert text or parsed source: the offline evaluator starts no servers, executes no payloads,
and makes no registry requests. It adds no runtime dependency or product command.

## Run it

From the repository root:

```bash
uv run python -m evaluation.quality --output /tmp/quality-medium.json
uv run python -m evaluation.quality --threshold high --output /tmp/quality-high.json
uv run python -m evaluation.quality --output /tmp/quality-medium.json \
  --baseline evaluation/baseline-medium.json
uv run pytest -q tests/test_detection_quality.py
```

A measurement-only run exits zero even when attacks are missed. Exit 2 means incomplete or
failed analysis; baseline comparison exits 1 if it finds a regression (including incomplete
analysis). Baseline comparison requires identical corpus bytes and severity threshold. It
checks individual cases: an improved overall score cannot hide a newly missed attack or a
new benign false alarm. Ordinary pytest checks both medium and high baselines. Known misses
remain visible in the reports; passing these regression checks does **not** mean 100% recall.

Real-package integration checks are opt-in:

```bash
MCPIRANHA_QUALITY_REGISTRIES=1 uv run pytest -q tests/test_detection_quality_registry.py
```

These reuse the two CVE release pairs in `calibration/cve_recall.py`, downloading the pinned
npm archives and verifying their registry hashes without installation or execution. They
require completed source collection, a matching injection finding in the vulnerable release,
and no injection findings in the fixed release. Registry failures fail the test rather than
counting as clean negatives. Both pairs passed on 2026-10-24:

| Existing advisory case | Vulnerable release flagged | Fixed release clean |
|---|---|---|
| CVE-2025-53355, `mcp-server-kubernetes` | 2.4.9 | 2.5.0 |
| CVE-2025-52573, `ios-simulator-mcp` | 1.3.2 | 1.3.3 |

These two already-known examples provide a small real-artifact check, not an independent
estimate across published vulnerabilities. Advisory identity is inherited from that existing
calibration script; this experiment does not independently adjudicate the advisories.

## Frozen first measurement

`cases.json` contains 64 developer-authored scenarios, with four attacks and four benign
examples per family. Labels, payloads, relevant rule IDs and rationales were written before
the first scoring run. The scanner's implementation had already been examined by the author;
this is **not** an independently blinded benchmark. No detector changes were made in response
to these measurements. The candidate includes the existing uncommitted path-guard fixes.

| Alert threshold | Attacks caught | Attacks missed | Benign cases flagged | Precision on this set |
|---|---:|---:|---:|---:|
| Medium or above | 13 / 32 (40.6%) | 19 | 7 / 32 (21.9%) | 65.0% |
| High or above | 7 / 32 (21.9%) | 25 | 2 / 32 (6.3%) | 77.8% |

All 64 inputs completed analysis at both thresholds. Counting any rule finding instead of
requiring a relevant-family finding gives the same totals in this first run. At medium:

| Family | Attacks caught / 4 | Benign flagged / 4 |
|---|---:|---:|
| Authority override | 2 | 1 |
| Credential exfiltration | 3 | 1 |
| Deceptive reporting / answer contamination | 1 | 0 |
| Render-triggered exfiltration | 3 | 1 |
| Shell injection | 1 | 1 |
| SQL injection | 1 | 1 |
| Path traversal | 1 | 1 |
| SSRF | 1 | 1 |

The full per-case outcomes, exact corpus/scanner-source/evaluator SHA-256 fingerprints,
loaded rule IDs, version, Git revision and dirty-working-tree marker are stored in
`baseline-medium.json` and `baseline-high.json`. Version alone cannot identify this candidate:
the scanner still declares 0.3.0, but these measurements use local source changes.

## What this exposes

* Source flows through objects, callbacks and helper return values are missed in these cases.
* Applying `shlex.quote` to a path or hostname can incorrectly suppress traversal/SSRF
  findings. Shell quoting does not establish safety for those sinks.
* Exact value allowlists are safe in the labeled source examples but still produce alarms.
* Semantic authority spoofing, falsified success reports and covert answer contamination can
  evade phrase matching. The cloud-verification URL instruction is also missed.
* Defensive quotations, a public support address and a versioned public image generate noise.
  The image finding is an intentional conservative signal; calling it a false alarm here
  measures the burden of treating medium findings as attack classifications, not a claim
  that the detector violated its documented behavior.
* The CSS example assumes a client substitutes a secret and loads CSS. It measures coverage
  of that hypothetical rendering channel, not exploitability in every MCP client. The other
  rendering examples likewise assume substitution/loading. No browser or model is exercised.

## Scoring and limits

One case contributes one classification regardless of finding count. A true positive requires
at least one of its declared relevant rules at or above the threshold. All built-in rules run;
plugins and the optional classifier are excluded. `any_alert_metrics` separately counts any
qualifying rule, so unrelated warnings cannot silently inflate family recall and unrelated
benign alerts remain visible. Reports also group results by family and input surface.

Exceptions, rule errors, parse failures and skipped source become inconclusive, never true
negatives. Reports show completion rate, metrics on completed cases, and a recall lower bound
that treats inconclusive attacks as undetected. Undefined metrics are JSON null. The harness
has tests for these policies, threshold changes, wrong-family detections and baseline errors.

This is an intentionally difficult, small, nonrandom set. Its 50% attack prevalence is artificial;
precision will differ in production. Four attacks per family cannot establish reliable family
rankings. Family and surface are not fully crossed, so differences do not isolate causal effects.
Source snippets assume the surrounding MCP server, imports/globals and ordinary filesystem
state; they test static information flow rather than running end-to-end exploits. Benign path
cases assume no hostile symlinks. The set does not measure acquisition coverage across clients,
supply-chain detection, cross-server interactions, dormant triggers, runtime tracing or an LLM's
actual susceptibility. Passing existing regressions or these CVE pairs cannot establish that
all attacks will be caught.

Use these cases as a development set after this first measurement. Keep labels and operating
thresholds fixed while fixing misses, and add paired regressions for changes. Do not rewrite
the baseline merely to bless a regression. Changing the corpus requires a reviewed new baseline
and loses direct score comparability. For a credible deployment estimate, obtain independently
reviewed held-out examples and representative benign server snapshots, separate by project
and attack scenario from tuning data, and score them without further tuning. This harness makes
those labels and failures auditable; it does not replace that independent evaluation.

## Candidate after detection fixes

The original corpus, labels, relevant rule IDs, thresholds and first-run baselines remain
unchanged. `candidate-medium.json` and `candidate-high.json` record the updated implementation:

| Threshold | Original attacks caught | Candidate attacks caught | Original / candidate benign alerts |
|---|---:|---:|---:|
| Medium or above | 13 / 32 | 32 / 32 | 7 / 0 |
| High or above | 7 / 32 | 16 / 32 | 2 / 0 |

These are development-set improvements, not held-out accuracy. High severity still misses
16 attacks in this set; the changes preserve the existing severity policy rather than raising
all findings to improve that score. All cases completed analysis. Tests now protect both the
original baseline and the candidate's case-level gains.

The implementation changes information flow and guard recognition, rather than matching case
IDs or filenames: fields/aliases, callback argument binding, bounded helper return summaries,
assignment alternatives, context-specific sanitizers and preceding literal allowlists. Shell
quoting inside existing shell quotes is rejected as a safety proof. Computed field writes and
object spreads conservatively taint possibly overwritten fields. Uncalled nested functions do
not leak their local state into their enclosing handler.

`tests/test_quality_improvements.py` adds 99 further source/text regressions with different
names, sinks and layouts, plus benign controls and bypass checks. These examples were also
used during implementation and are **not** a held-out set. The new instruction checks recognize
specific relationships involving authority, authorization, deceptive reporting and answer
contamination; they remain bounded heuristics, not a general semantic understanding of intent.
Defensive-quotation handling applies to the rejected quote's span, not the entire document;
negated directives and narrowly public identifiers do not exempt neighboring attacks.

The two vulnerable/fixed registry pairs still pass. Static scans of the same three pinned
packages in `docs/TESTING.md` completed for all 58 files without errors or warnings. Their
rule/severity finding counts were unchanged: filesystem and time had no findings; everything
retained its existing high-severity environment-collection finding. This small compatibility
pilot does not establish a deployment false-positive rate.

Remaining source limits include the two-call helper bound, four assignment-propagation passes,
a 2,048-query return-summary budget per file, limited callback APIs, heuristic name/module
resolution, arbitrary class instances and dynamic dispatch. Field aliases are conservative
rather than a full heap analysis; nested object precision, branch joins and mutation ordering
can still produce noise or misses. Recognized sanitizer idioms assume their ordinary library
meaning; rebinding and custom implementations need review. The literal quote tracker is not a
complete shell interpreter. Custom validators, filesystem races, redirects/DNS changes and
client-specific rendering behavior remain outside these proofs. An independent, project-separated
holdout is still needed before making deployment accuracy claims.

## High-threshold follow-up

`high-threshold-medium.json` and `high-threshold-high.json` record the next candidate without
rewriting either earlier stage or the corpus. At **both thresholds**, all 32 attack cases now
produce a relevant finding, with 0/32 benign cases flagged and no incomplete analyses. This
is a development-set result after tuning. The change from 16/32 to 32/32 at high includes
severity-policy corrections, not 16 newly discovered attacks: these cases already alerted at
medium in the preceding candidate.

The risk decisions are explicit:

* SRC-103/SRC-104 use high severity for input flowing from a registered handler into a based
  file operation or a URL host without a recognized safeguard. Static-analysis confidence
  remains medium, and safe cases and whole-input capabilities retain their exclusions.
* TP-004 can escalate an authority/authorization override paired with a nearby high-impact
  action, an explicit instruction to falsify a result, an override of the user's refusal, or
  a failure assertion paired with a success directive about the same execution. Findings
  include the corroborating spans and the reason for escalation. The global phrase score
  thresholds are unchanged. Weak signals and unrelated or explicitly new/retry executions
  do not gain high severity from these predicates.
* TP-005 can escalate a credential reference bound to a local export directive and concrete
  destination. Bindings include explicit file references, contents/assignments and a limited
  set of pronouns following a read instruction. The supported French transfer verbs are
  enumerated, not general multilingual understanding. An unrelated public identifier, another
  document's contents, a filename-only message, negated export, rejected quote or distant
  reference is insufficient. Generic outward-message steering alone no longer promotes an
  unrelated credential reference to high severity.

`tests/test_high_severity.py` adds 99 developer-authored checks across four text surfaces,
plain/fullwidth text, positive/negative pairs, source confidence and the CLI's actual high
exit-code gate. These are additional development regressions, not a held-out benchmark. The
three pinned package smoke scans still have identical finding counts/severities and no errors
or warnings. Both CVE/fixed release pairs remain covered by the integration suite.

Risk classification remains heuristic. Source findings do not prove exploitability, and text
correlation does not provide general natural-language reasoning or prove that a client will
obey an instruction. Independent examples and representative deployment data are still needed.


## Deeper helper-flow follow-up

`helper-flow-medium.json` and `helper-flow-high.json` preserve another measurement against
the identical 64-case corpus: 32/32 attacks detected, 0/32 benign alerts, and no incomplete
analyses at either threshold. The earlier stages remain unchanged. This corpus did not expose
the two-call helper cutoff; the new deep-chain regressions exercise that gap directly.

`tests/test_deep_helpers.py` adds 57 developer-authored checks. Python and JavaScript/TypeScript
sink chains through 3, 8 and 80 helpers now alert, while sanitized counterparts stay quiet.
Return chains through 3, 8 and 16 helpers also work. Cross-file calls, recursive sink graphs,
context-sensitive caching and parallel parser use are covered. Cache keys keep guard and
argument-sanitization contexts separate rather than reusing a safety conclusion indiscriminately.

A work queue replaces the fixed helper-call depth. Return inference remains bounded; context,
summary, node, assignment, expression/alias depth, literal, guard and finding limits now mark
source coverage partial and retain available findings. Unresolved recursive return summaries
also report partial coverage. These reasons survive snapshot replay and fail `--strict` or
a source coverage requirement. See [the usage guide](../docs/USAGE.md#source-analysis) for limits.

Both existing vulnerable/fixed registry pairs still pass. Repeating the same three pinned
package scans preserves all rule/severity finding counts across 58 files. Everything and time
have completed source coverage; filesystem now reports partial coverage because its recursive
`buildTree` return summary cannot be resolved. The prior completed status hid that limitation.
No package code was installed or executed. This small pilot and the developer-authored tests
are compatibility/regression evidence, not an independent deployment accuracy estimate.

Remaining gaps include heuristic module/name resolution, limited callback APIs, arbitrary
class/heap behavior, dynamic dispatch, custom validators, branch/mutation precision and runtime
conditions. The earlier four-pass/two-call bounds describe the preceding implementation, not
the current one. Independent project-separated validation remains the next quality priority.


## Local import-resolution follow-up

`import-flow-medium.json` and `import-flow-high.json` preserve the identical corpus and earlier
reports: 32/32 attacks detected, 0/32 benign alerts and no incomplete cases at either threshold.
This development corpus did not test imported aliases or colliding module function names.

Read-only probes before implementation found that direct imports alerted, while aliased
Python/JavaScript imports and JavaScript namespace calls missed the same shell-injection flow.
A Python safe/unsafe same-name pair changed detection when its source-file order was reversed.
Those misses reported no analysis limitation. A module/symbol binding graph now replaces the
package-wide first-name match. Namespace helper returns are evaluated before generic object
method propagation. Imported callbacks and registrations use their defining analyzer, and
local sanitizer lookalikes do not suppress findings.

`tests/test_import_resolution.py` adds 113 developer-authored regressions with safe twins,
file-order permutations, re-export/require variants, coverage and CLI checks. Resolution is
bounded; local missing/ambiguous/cyclic/reassigned call bindings report partial coverage.
No package code is imported or executed. These checks demonstrate the specific correction;
they are not an independent estimate of detection performance.

The same two vulnerable/fixed registry pairs remain passing. Static smoke scans of filesystem
2.0.0, everything 2.0.0 and time 2026.10.19 retain the previous findings across 58 files:
filesystem and time have no findings; everything retains one high SRC-002 finding. Filesystem
retains its documented recursive-return partial coverage; everything and time are completed.

Dynamic loading, custom resolvers, complex scope/rebinding, arbitrary classes and runtime
search-path differences remain outside this binding model. See [usage limits](../docs/USAGE.md#source-analysis).
The next quality priority is independent project-separated validation, with labels reviewed
without tuning detectors to those cases.


## Basename-safety follow-up

`basename-safety-medium.json` and `basename-safety-high.json` keep the identical corpus,
labels and earlier reports. At both thresholds the current scanner records **32 TP, 2 FP,
0 FN, 30 TN**, with no incomplete cases: all 32 attacks alert, while two of the 32
benign-labeled cases now alert. Precision on this set is 94.1%, versus 100% in the preceding
stage. This remains a development-set measurement, not deployment accuracy.

The removed exemption treated basename extraction as sufficient path sanitization. Basename
preserves `..`; joining a fixed filename afterward or using a directory operation can escape
the intended base. Input now remains tainted through aliases and helper returns. JavaScript
also preserves basename arguments in other domains instead of taking the untainted `path`
receiver as its result. Real containment checks and safe literal filename allowlists remain
recognized, including through resolved/nested joined paths.

The existing `py-path-basename` and `js-path-basename` cases are read-only examples without
that fixed suffix, and remain labeled benign. Removing the blanket exemption conservatively
alerts on them; it does not prove those specific reads exploitable. Their labels and earlier
zero-alert results were not rewritten. The comparator reports exactly four signal changes
(two cases, each for detected/any-alert), and regression tests explicitly review only those
changes. The current-stage baseline still admits no new regression. These alerts make the
precision cost visible rather than hiding it behind a relabeled challenge set.

`tests/test_basename_safety.py` adds 74 developer-authored regressions, including safe twins,
guard bypasses, cross-domain flows, high-threshold CLI checks and real inert filesystem
examples. The first 46 checks reproduced 26 failures before the fix. The three pinned package
smoke scans retain the same finding counts and coverage statuses, and both vulnerable/fixed
registry pairs still pass. Independent reviewed validation remains outstanding.
