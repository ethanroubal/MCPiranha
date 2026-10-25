"""MCP-TP-005: getting the model to read or send credentials and other sensitive files.

A calculator or weather tool has no reason to tell the model to read `~/.ssh/id_rsa`, `.env` or the
client's MCP config. But mentioning them is common in legitimate tools: calibration found popular
servers that search for `.env` files, warn against committing secrets, or store keys in the
keychain. So a reference alone isn't reported. It is when it's hidden, when the same text steers
the model (see MCP-TP-004), or when the same sentence asks to read, send or upload it.
"""

from __future__ import annotations

import re

from mcpiranha.core.matching import MatchView, carries_hidden_text
from mcpiranha.core.models import Category, Evidence, Finding, Severity
from mcpiranha.core.text import CONTENT_KINDS, iter_text_fields
from mcpiranha.rules.base import Rule, RuleContext
from mcpiranha.rules.builtin.instruction_phrases import (
    instruction_matches,
    rejected_instruction,
    steers_model,
)
from mcpiranha.rules.registry import register

_I = re.IGNORECASE
_B = r"(?<![\w.-])"  # start boundary that still allows a leading "~/", "/" or quote

# (pattern, label)
_SENSITIVE: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\.ssh\b|\bid_(rsa|dsa|ecdsa|ed25519)\b|\bauthorized_keys\b|\bknown_hosts\b", _I),
     "SSH keys"),
    (re.compile(r"\.aws/(credentials|config)\b|\.azure/|\.config/gcloud\b|"
                r"application_default_credentials\.json", _I), "cloud credentials"),
    (re.compile(_B + r"\.env(\.[a-z]+)?\b|\bdotenv\s+(file|document)\b", _I), "dotenv file"),
    (re.compile(r"\.(npmrc|pypirc|netrc|git-credentials)\b|\.docker/config\.json|\.kube/config\b|"
                r"\.gnupg\b", _I), "tool credentials"),
    (re.compile(r"\bmcp\.json\b|claude_desktop_config\.json|\.claude\.json|\.cursor/|"
                r"mcp_config\.json", _I), "MCP client config"),
    (re.compile(r"/etc/(passwd|shadow|sudoers)\b", _I), "system account files"),
    (re.compile(r"\b(Login Data|Cookies\.sqlite|key[34]\.db|logins\.json)\b|"
                r"\bkeychain\b|\bwallet\.dat\b|\bseed\s+phrase\b", _I),
     "browser or wallet secrets"),
    (re.compile(r"\b(private|secret)[ _-]?keys?\b", _I), "private keys"),
    # described in words rather than as paths
    (re.compile(r"\bssh\s+(config(uration)?|keys?|private\s+keys?|identity)\b|"
                r"\b(aws|gcp|azure|cloud)\s+credentials\b|\bbrowser\s+(cookies|passwords)\b|"
                r"\bsaved\s+passwords\b", _I), "credentials described in words"),
)  # fmt: skip


_ACTS_ON = re.compile(
    r"\b(read|cat|open|load|send|pass|include|upload|post|forward|share|copy|append|attach|paste|"
    r"exfiltrate|leak|provide)\b",
    re.IGNORECASE,
)
_SENTENCE_END = re.compile(r"[.!?](?=\s)|\n")


def sensitive_hits(view: MatchView) -> list[tuple[str, Evidence]]:
    return [(label, ev) for pattern, label in _SENSITIVE for _, ev in view.finditer(pattern)]


def sentence_around(text: str, start: int, end: int) -> str:
    before = [m.end() for m in _SENTENCE_END.finditer(text, 0, start)]
    after = _SENTENCE_END.search(text, end)
    return text[(before[-1] if before else 0) : (after.start() if after else len(text))]


def acted_on(text: str, evidence: Evidence) -> bool:
    """Does the sentence around this reference ask to read, send or upload something?"""
    if evidence.start is None or evidence.end is None:
        return False
    return bool(
        _ACTS_ON.search(MatchView.of(sentence_around(text, evidence.start, evidence.end)).text)
    )


_EXPORT = re.compile(
    r"\b(send|upload|forward|transmit|exfiltrate|email|copy|post|attach|paste|"
    r"transmets|transmettez|envoie|envoyez)\b[^\n]{0,280}?"
    r"(https?://[^\s<>\"]+|[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,})",
    _I,
)
_EXPORTED_CONTENT = re.compile(
    r"\b(its|their|the|this\s+file's|that\s+file's)\s+(contents?|credentials?|secrets?|tokens?)\b|"
    r"\b(every|all)\s+(the\s+)?(assignments?|credentials?|secrets?|tokens?)\b|"
    r"\b(son|leur)\s+contenu\b",
    _I,
)
_OTHER_CONTENT_SOURCE = re.compile(r"\bcontents?\s+(of|from)\b", _I)
_READ_SOURCE = re.compile(r"\b(read|cat|open|load|lis|lisez|ouvre|ouvrez)\b", _I)
_EXPORT_PRONOUN = re.compile(r"\b(it|them)\s+(to|at|into)\b", _I)
_REFERENCE_ONLY = re.compile(r"^\w+\s+(the\s+)?(file\s+)?(path|location|name|filename)\b", _I)
_CONTENT_WORD = re.compile(r"\b(contents?|credentials?|secrets?|tokens?|assignments?)\b", _I)


def credential_exports(view: MatchView, hits: list[tuple[str, Evidence]]) -> list[Evidence]:
    """Credential reference + local content-export directive + concrete destination.

    Recognizes English and a small explicit set of French transfer verbs. This is not a
    language-independent semantic classifier. A nearby public identifier is insufficient.
    """
    exports: list[Evidence] = []
    for match, evidence in view.finditer(_EXPORT):
        if rejected_instruction(view, evidence) or re.match(
            r"(transmets|transmettez|envoie|envoyez)\s+pas\b",
            match.group(),
            _I,
        ):
            continue
        if _REFERENCE_ONLY.search(match.group()) and not _CONTENT_WORD.search(match.group()):
            continue
        for _, sensitive in hits:
            if evidence.start is None or evidence.end is None or sensitive.start is None:
                continue
            inside = evidence.start <= sensitive.start < evidence.end
            preceding = sensitive.end is not None and 0 <= evidence.start - sensitive.end <= 180
            gap = view.source[sensitive.end : evidence.start] if preceding else ""
            read_prefix = view.source[max(0, sensitive.start - 60) : sensitive.start]
            pronoun = _EXPORT_PRONOUN.search(match.group()) and _READ_SOURCE.search(read_prefix)
            bound_content = (
                preceding
                and len(list(_SENTENCE_END.finditer(gap))) <= 1
                and (_EXPORTED_CONTENT.search(match.group()) or pronoun)
                and not _OTHER_CONTENT_SOURCE.search(match.group())
            )
            if inside or bound_content:
                exports.append(evidence)
                break
    return exports


def is_suspicious(text: str) -> bool:
    """Shared bar for text that other rules found tucked away (in an HTML comment, after padding):
    hidden characters, model steering (MCP-TP-004), or acting on a sensitive file."""
    view = MatchView.of(text)
    if carries_hidden_text(text) or steers_model(instruction_matches(view)):
        return True
    return any(acted_on(text, ev) for _, ev in sensitive_hits(view))


@register
class SensitivePaths(Rule):
    id = "MCP-TP-005"
    title = "Instructions involving credentials or sensitive files"
    category = Category.TOOL_POISONING
    default_severity = Severity.HIGH
    applies_to = frozenset({"tool", "prompt", "resource"})
    remediation = (
        "Check why this tool's metadata asks the model to handle sensitive files. Unless the tool "
        "genuinely manages them (and you expected that), it is likely trying to get the model to "
        "read and leak them."
    )

    def run(self, ctx: RuleContext) -> list[Finding]:
        findings: list[Finding] = []
        for tf in iter_text_fields(ctx.snapshot):
            if tf.kind in ("name", "uri", "property-name"):
                continue
            view = MatchView.of(tf.text)
            hits = sensitive_hits(view)
            if not hits:
                continue
            hidden = any(carries_hidden_text(ev.text) for _, ev in hits)
            # An unrelated outward message is not proof that the referenced credential
            # is exported. Require an explicit binding for transfer-only instructions.
            matches = [
                m
                for m in instruction_matches(view)
                if m.label != "sends data to an outside address"
            ]
            steering = steers_model(matches)
            exports = credential_exports(view, hits)
            # Fetched content (agent guides, docs) tells the agent how to handle files all the
            # time; there, require hidden/steering text or an explicitly bound export.
            acted = (
                []
                if tf.kind in CONTENT_KINDS
                else [(lb, ev) for lb, ev in hits if acted_on(tf.text, ev)]
            )
            if not (hidden or steering or acted or exports):
                continue  # a mention, not an instruction
            labels = ", ".join(sorted({lb for lb, _ in hits}))
            if hidden:
                rationale, severity = f"Hidden text references {labels}.", Severity.CRITICAL
            elif exports:
                rationale = (
                    f"The {tf.kind} links {labels} to a content-export directive and destination."
                )
                severity = Severity.HIGH
            elif steering:
                rationale = f"The {tf.kind} references {labels} and steers the model."
                severity = Severity.HIGH
            else:
                rationale = f"The {tf.kind} asks to act on {labels}."
                severity = Severity.MEDIUM
            findings.append(
                self.finding(
                    location=tf.location,
                    evidence=[ev for _, ev in (acted or hits)] + exports,
                    rationale=rationale,
                    severity=severity,
                )
            )
        return findings
