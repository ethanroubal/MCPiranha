"""SARIF 2.1.0 output, for GitHub code scanning and other CI tools.

Each finding points at the config file (or snapshot) it came from; the server/tool/JSON pointer
goes in a logical location, since SARIF has no notion of an MCP tool.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Sequence
from pathlib import Path, PureWindowsPath
from typing import Any
from urllib.parse import quote

from mcpiranha import REPO_URL, RULES_URL, __version__
from mcpiranha.core.models import Finding, ScanResult, Severity
from mcpiranha.core.text import reveal
from mcpiranha.rules.base import Rule

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}
# GitHub sorts and labels code-scanning alerts by this 0-10 score.
_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.INFO: "0.0",
}


def artifact_uri(path: str, base: Path) -> str:
    p = Path(path).expanduser()
    foreign = PureWindowsPath(path)
    if sys.platform != "win32" and foreign.is_absolute():
        return foreign.as_uri()
    if not p.is_absolute() and not p.root and not p.drive:
        return quote(p.as_posix(), safe="/")
    try:
        return quote(p.resolve().relative_to(base.resolve()).as_posix(), safe="/")
    except ValueError:
        return p.resolve().as_uri()


def _description(rule: Rule) -> str:
    """First paragraph of the rule module's docstring, minus the "MCP-XX-000: " prefix."""
    doc = sys.modules[type(rule).__module__].__doc__ or rule.title
    first = " ".join(doc.strip().split("\n\n", 1)[0].split())
    return first.split(": ", 1)[1] if first.startswith(f"{rule.id}: ") else first


def _rule_descriptor(rule: Rule) -> dict[str, Any]:
    descriptor: dict[str, Any] = {
        "id": rule.id,
        "name": "".join(w.capitalize() for w in rule.title.split()),
        "shortDescription": {"text": rule.title},
        "fullDescription": {"text": _description(rule)},
        "help": {"text": rule.remediation},
        "defaultConfiguration": {"level": _LEVEL[rule.default_severity]},
        "properties": {
            "tags": ["security", "mcp", rule.category.value],
            "security-severity": _SECURITY_SEVERITY[rule.default_severity],
        },
    }
    descriptor["helpUri"] = rule.references[0] if rule.references else RULES_URL
    return descriptor


def _result(finding: Finding, files: dict[str, str], names: dict[str, str], base: Path
            ) -> dict[str, Any]:  # fmt: skip
    loc = finding.location
    parts = [names.get(loc.server_id, loc.server_id), loc.tool or loc.prompt or loc.resource]
    logical = "/".join(reveal(part) for part in parts if part)
    if loc.json_pointer:
        logical += f"#{loc.json_pointer}"
    location: dict[str, Any] = {
        "logicalLocations": [{"fullyQualifiedName": logical, "kind": "member"}],
    }
    if source := (loc.file or files.get(loc.server_id)):
        physical: dict[str, Any] = {"artifactLocation": {"uri": artifact_uri(source, base)}}
        if loc.line:
            physical["region"] = {"startLine": loc.line}
        location["physicalLocation"] = physical
    return {
        "ruleId": finding.rule_id,
        "level": _LEVEL[finding.severity],
        "message": {"text": reveal(finding.rationale)},
        "locations": [location],
        "partialFingerprints": {"mcpiranhaFindingId/v1": finding.id},
        "properties": {
            "severity": finding.severity.value,
            "confidence": finding.confidence.value,
            "detector": finding.detector.value,
            "security-severity": _SECURITY_SEVERITY[finding.severity],
        },
    }


def render(result: ScanResult, rules: Sequence[Rule], base: Path | None = None) -> str:
    """`base`: directory that artifact paths are made relative to (the repository root in CI)."""
    base = base or Path.cwd()
    files = {s.id: s.origin.config_path for s in result.servers if s.origin.config_path}
    names = {s.id: s.name for s in result.servers}
    used = {f.rule_id for f in result.findings} | {s.finding.rule_id for s in result.suppressed}
    results = [_result(f, files, names, base) for f in result.findings]
    for item in result.suppressed:  # kept in the log, marked as accepted, so they can be audited
        suppressed = _result(item.finding, files, names, base)
        suppressed["suppressions"] = [
            {"kind": "external", "status": "accepted", "justification": item.reason}
        ]
        results.append(suppressed)
    log = {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "mcpiranha",
                        "version": __version__,
                        "informationUri": REPO_URL,
                        "rules": [_rule_descriptor(r) for r in rules if r.id in used],
                    }
                },
                "results": results,
                "properties": {
                    "coverage": [
                        {
                            "serverId": s.id,
                            "serverName": s.name,
                            "stages": {k: v.model_dump(mode="json") for k, v in s.coverage.items()},
                        }
                        for s in result.servers
                    ],
                },
                "invocations": [
                    {
                        "executionSuccessful": not result.errors,
                        "toolExecutionNotifications": [
                            {"level": level, "message": {"text": reveal(message)}}
                            for level, messages in (
                                ("error", result.errors),
                                ("warning", result.warnings),
                            )
                            for message in messages
                        ],
                    }
                ],
            }
        ],
    }
    return json.dumps(log, indent=2, ensure_ascii=False) + "\n"
