"""Offline labeled challenge evaluation: python -m evaluation.quality --output report.json.

A successful run means measurement completed, not that every attack was caught.
The payloads are parsed as data/source; no server or payload is executed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from collections.abc import Sequence
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, model_validator

from mcpiranha import __version__
from mcpiranha.core.models import ServerSnapshot, Severity
from mcpiranha.core.pipeline import scan
from mcpiranha.rules import load_rules
from mcpiranha.rules.base import Rule
from mcpiranha.source import analyze_files

CORPUS = Path(__file__).with_name("cases.json")


class Case(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    id: str
    family: str
    label: Literal["attack", "benign"]
    surface: Literal["description", "instructions", "resource", "tool", "python", "typescript"]
    payload: str
    rules: list[str]
    rationale: str


class Corpus(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal[1]
    provenance: str
    cases: list[Case]

    @model_validator(mode="after")
    def validate_cases(self) -> Corpus:
        ids = [c.id for c in self.cases]
        if not ids or len(ids) != len(set(ids)):
            raise ValueError("Corpus needs nonempty, unique case IDs")
        known = {r.id for r in load_rules(plugins=False)}
        for case in self.cases:
            if not case.rules or set(case.rules) - known:
                raise ValueError(f"{case.id}: unknown or empty relevant rule list")
            if not all((case.id, case.family, case.payload, case.rationale)):
                raise ValueError("Case fields must not be empty")
        return self


class Outcome(BaseModel):
    id: str
    family: str
    surface: str
    label: Literal["attack", "benign"]
    # None means analysis failed/incomplete; never quietly score that as a clean negative.
    detected: bool | None
    any_alert: bool | None
    alerts: list[str] = []
    errors: list[str] = []


def evaluate(case: Case, rules: Sequence[Rule], threshold: Severity) -> Outcome:
    data: dict[str, Any] = {
        "id": case.id,
        "name": case.id,
        "origin": {"kind": "snapshot", "ref": f"quality:{case.id}"},
    }
    errors: list[str] = []
    try:
        if case.surface in {"python", "typescript"}:
            suffix = "py" if case.surface == "python" else "ts"
            source = analyze_files(iter([(f"server.{suffix}", case.payload.encode())]), "quality")
            errors.extend(source.skipped)
            if source.files != 1:
                errors.append("Source analysis did not cover exactly one file")
            data.update(source=source, tools_listed=False)
        elif case.surface == "description":
            data["tools"] = [{"name": "lookup", "description": case.payload}]
        elif case.surface == "instructions":
            data["server_info"] = {"name": "quality", "instructions": case.payload}
        else:
            data["content"] = [{"kind": case.surface, "ref": "quality", "text": case.payload}]
        result = scan([ServerSnapshot.model_validate(data)], rules)
        errors.extend(result.errors)
        alerts = sorted({f.rule_id for f in result.findings if f.severity.rank >= threshold.rank})
    except (
        Exception
    ) as exc:  # preserve failures as inconclusive, including acquisition/parser errors
        errors.append(f"{type(exc).__name__}: {exc}")
        alerts = []
    return Outcome(
        id=case.id,
        family=case.family,
        surface=case.surface,
        label=case.label,
        detected=None if errors else bool(set(alerts) & set(case.rules)),
        any_alert=None if errors else bool(alerts),
        alerts=alerts,
        errors=errors,
    )


def metrics(outcomes: Sequence[Outcome], *, any_alert: bool = False) -> dict[str, Any]:
    counts = dict(tp=0, fp=0, fn=0, tn=0, inconclusive=0)
    for outcome in outcomes:
        predicted = outcome.any_alert if any_alert else outcome.detected
        if predicted is None:
            counts["inconclusive"] += 1
        else:
            counts[
                ("t" if predicted == (outcome.label == "attack") else "f")
                + ("p" if predicted else "n")
            ] += 1
    tp, fp, fn, tn = (counts[k] for k in ("tp", "fp", "fn", "tn"))
    attacks = sum(o.label == "attack" for o in outcomes)
    return {
        **counts,
        "cases": len(outcomes),
        "attacks": attacks,
        "precision": tp / (tp + fp) if tp + fp else None,
        "recall_completed": tp / (tp + fn) if tp + fn else None,
        "recall_lower_bound": tp / attacks if attacks else None,
        "false_positive_rate_completed": fp / (fp + tn) if fp + tn else None,
        "completion_rate": (len(outcomes) - counts["inconclusive"]) / len(outcomes)
        if outcomes
        else None,
    }


def regressions(baseline: dict[str, Any], current: dict[str, Any]) -> list[str]:
    """Compare case-level behavior, so gains cannot conceal newly introduced misses/noise."""
    if any(baseline.get(k) != current.get(k) for k in ("corpus_sha256", "threshold")):
        raise ValueError("Baseline must use the identical corpus and severity threshold")
    previous_outcomes = [Outcome.model_validate(o) for o in baseline["outcomes"]]
    current_outcomes = [Outcome.model_validate(o) for o in current["outcomes"]]
    old = {o.id: o.model_dump() for o in previous_outcomes}
    if set(old) != {o.id for o in current_outcomes}:
        raise ValueError("Baseline case IDs differ")
    changes: list[str] = []
    for outcome in current["outcomes"]:
        previous = old[outcome["id"]]
        if outcome["detected"] is None:
            changes.append(f"{outcome['id']}: inconclusive")
        elif outcome["label"] == "attack" and previous["detected"] is True:
            if outcome["detected"] is not True:
                changes.append(f"{outcome['id']}: new miss")
        elif outcome["label"] == "benign":
            for signal in ("detected", "any_alert"):
                if previous[signal] is False and outcome[signal] is True:
                    changes.append(f"{outcome['id']}: new false alarm ({signal})")
    return changes


def run(corpus_path: Path = CORPUS, threshold: Severity = Severity.MEDIUM) -> dict[str, Any]:
    raw = corpus_path.read_bytes()
    corpus = Corpus.model_validate_json(raw)
    rules = load_rules(plugins=False)
    outcomes = [evaluate(case, rules, threshold) for case in corpus.cases]
    try:
        revision = subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=CORPUS.parent,
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
        dirty = bool(
            subprocess.check_output(
                ["git", "status", "--porcelain"],
                cwd=CORPUS.parent,
                text=True,
            ).strip()
        )
    except (OSError, subprocess.CalledProcessError):
        revision, dirty = "unknown", True
    # Include the exact loaded implementation, including working-tree changes, in provenance.
    from mcpiranha import __file__ as package_file

    digest = hashlib.sha256()
    root = Path(str(package_file)).parent
    for file in sorted(root.rglob("*.py")):
        digest.update(file.relative_to(root).as_posix().encode() + b"\0" + file.read_bytes())
    return {
        "schema_version": 1,
        "scanner_version": __version__,
        "revision": revision,
        "working_tree_dirty": dirty,
        "scanner_source_sha256": digest.hexdigest(),
        "corpus_sha256": hashlib.sha256(raw).hexdigest(),
        "provenance": corpus.provenance,
        "evaluator_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "threshold": threshold.value,
        "rules": sorted(r.id for r in rules),
        "metrics": metrics(outcomes),
        "any_alert_metrics": metrics(outcomes, any_alert=True),
        "by_family": {
            family: metrics([o for o in outcomes if o.family == family])
            for family in sorted({o.family for o in outcomes})
        },
        "by_surface": {
            surface: metrics([o for o in outcomes if o.surface == surface])
            for surface in sorted({o.surface for o in outcomes})
        },
        "outcomes": [o.model_dump() for o in outcomes],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=CORPUS)
    parser.add_argument("--threshold", choices=[s.value for s in Severity], default="medium")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--baseline", type=Path)
    args = parser.parse_args()
    if args.baseline and args.output.resolve() == args.baseline.resolve():
        parser.error("Output must not overwrite the comparison baseline")
    baseline = json.loads(args.baseline.read_text()) if args.baseline else None
    report = run(args.corpus, Severity(args.threshold))
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"overall": report["metrics"], "families": report["by_family"]}, indent=2))
    if baseline is not None:
        changes = regressions(baseline, report)
        if changes:
            print("Regressions:\n" + "\n".join(changes))
            raise SystemExit(1)
    if any(o["errors"] for o in report["outcomes"]):
        raise SystemExit(2)


if __name__ == "__main__":
    main()
