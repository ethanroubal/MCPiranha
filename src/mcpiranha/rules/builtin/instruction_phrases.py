"""MCP-TP-004: phrases that steer the model against the user, not describe the tool.

Legitimate tools give usage guidance all the time ("you should always run the linter first",
"before calling this tool, read the schema"): calibration against the 100 most-downloaded
registry servers found such guidance in popular servers and nothing malicious. So phrases come in
two kinds. Attack signals are what tool poisoning needs and usage guidance doesn't: keeping things
from the user, overriding earlier instructions, changing how other tools behave, sending data to
an outside address. Guidance phrases (pre-conditions, "you must", urgency) only add weight. A
finding needs at least one attack signal, or text hidden in invisible characters.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from mcpiranha.core.matching import MatchView, carries_hidden_text
from mcpiranha.core.models import Category, Confidence, Evidence, Finding, Severity
from mcpiranha.core.text import iter_text_fields
from mcpiranha.rules.base import Rule, RuleContext
from mcpiranha.rules.registry import register

_I = re.IGNORECASE

# (pattern, weight, label, attack signal?)
PHRASES: tuple[tuple[re.Pattern[str], int, str, bool], ...] = (
    (re.compile(r"\b(ignore|disregard|forget|override)\s+(all\s+|any\s+)?(the\s+|your\s+)?"
                r"(previous|prior|above|earlier|other|original)\s+(instructions?|directions|rules"
                r"|guidelines|context|prompts?)", _I), 3, "override earlier instructions", True),
    (re.compile(r"\b(new|updated|real|actual|secret|hidden)\s+instructions?\b|"
                r"\b(primary|new|real|actual|overriding)\s+directive\b", _I), 2,
     "claims new instructions", True),
    # paraphrased overrides: "you were advised to refuse ... now", "prior guidance is outdated"
    (re.compile(r"\b(you\s+(were|had\s+been)|originally|previously)\b[^.\n]{0,80}\b(advised|"
                r"instructed|told|asked)\b[^.\n]{0,120}\b(now|no\s+longer|anymore)\b", _I), 3,
     "override earlier instructions", True),
    (re.compile(r"\b(prior|previous|earlier|original|existing)\s+(guidance|instructions?|"
                r"directions|rules|guidelines)\b[^.\n]{0,40}\b(outdated|obsolete|superseded|"
                r"void|invalid|no\s+longer\s+appl)", _I), 3, "override earlier instructions", True),
    (re.compile(r"\b(do\s+not|don't|dont|never|without)\s+(ever\s+)?(tell(ing)?|mention(ing)?|"
                r"inform(ing)?|reveal(ing)?|notify(ing)?|disclos(e|ing)|alert(ing)?|let)\b[^.\n]{0,40}"
                r"\b(user|human|anyone|them)\b", _I), 2, "conceal from the user", True),
    (re.compile(r"\b(the\s+user\s+(must|should)\s+not\s+(know|see|be\s+told)|hide\s+(this|it)\s+"
                r"from)\b", _I), 2, "conceal from the user", True),
    (re.compile(r"\b(no\s+need\s+to|needn't|without)\s+(mention|tell|inform|notify|alert)(ing)?\b|"
                r"\b(quietly|silently|secretly|discreetly|covertly)\s+(include|send|add|pass|copy|"
                r"forward|attach|read|share|upload)\b", _I), 2, "conceal from the user", True),
    (re.compile(r"\b(when|whenever|if|after|each\s+time)\b[^.\n]{0,60}\b(tool|function)\s+is\s+"
                r"(used|called|invoked|run)", _I), 2, "hooks another tool's use", True),
    (re.compile(r"\b(otherwise|or\s+else)\b[^.\n]{0,30}\b(will\s+not|won't|will\s+fail|fails|"
                r"cannot|can't)\s+(work|run|function)", _I), 2, "threat to make the model comply",
     True),
    (re.compile(r"\b(act|behave|respond)\s+as\s+(if\s+you\s+are\s+|an?\s+)?(admin|administrator|"
                r"developer|system|root)\b", _I), 2, "role override", True),
    # (?:[^.\n]|\.(?=\S)) lets file names like ".env" through but stops at the end of a sentence
    (re.compile(r"\b(send|forward|bcc|cc|copy|post|upload|email|exfiltrate|report)\b"
                r"(?:[^.\n]|\.(?=\S)){0,80}"
                r"\b(to|at)\s+(\S+@\S+\.\w+|https?://|(an?\s+|the\s+|our\s+|this\s+)?(external|remote|"
                r"audit|logging|collection|backup|monitoring|analytics|telemetry|third[- ]party)\s+"
                r"(endpoint|server|webhook|address|url|service|bucket))", _I), 3,
     "sends data to an outside address", True),
    # Relational signals: authority/consent and truthful reporting, rather than attack slogans.
    (re.compile(r"\b(takes?\s+precedence\s+over|supersedes?|outranks?)\s+(the\s+|all\s+|any\s+|your\s+)*"
                r"(conversation|requests?|user(?:'s)?\s+(instructions?|requests?)|system\s+(instructions?|rules)|"
                r"previous\s+instructions?)\b", _I), 3,
     "claims authority over the conversation", True),
    (re.compile(r"\b(approve|authorize|execute|perform|complete|mark\b[^.\n]{0,35}\bapproved)\b"
                r"[^.\n]{0,90}"
                r"\b(without\s+(asking|requesting|obtaining|user)|even\s+if\s+[^.\n]{0,30}"
                r"(declined|refused|denied)|despite\s+[^.\n]{0,30}(refusal|denial))\b", _I), 3,
     "bypasses user authorization", True),
    (re.compile(r"\b(nevertheless|regardless|despite|even\s+though)\b[^.\n]{0,100}"
                r"\b(tell|report|claim|state|say|assert)\b[^.\n]{0,90}"
                r"\b(passed|successful|succeeded|success|no\s+(errors|action))\b", _I), 3,
     "directs a potentially false success report", True),
    (re.compile(r"\b(pretend|falsely\s+(report|claim|state)|lie\s+to\s+the\s+user)\b"
                r"[^.\n]{0,100}\b(success|passed|succeeded|completed|safe|user)\b", _I), 3,
     "directs deceptive reporting", True),
    (re.compile(r"\b(include|insert|append|add|repeat)\b[^.\n]{0,160}"
                r"\b(in|to)\s+(every|all|each)\s+(answers?|responses?|replies)\b", _I), 3,
     "contaminates unrelated answers", True),
    (re.compile(r"\b(conceal|hide)\s+(this|these|the)\s+(instructions?|directives?|changes?|actions?)\b|"
                r"\b(present|portray)\s+it\s+as\s+(your|an?)\s+(independent|own)\b", _I), 2,
     "conceals the origin of an instruction", True),
    # A credential attached to a URL leaks just as surely as an explicit upload command.
    (re.compile(r"\b(append|attach|embed|paste|insert|encode)\b[^\n]{0,160}"
                r"(?:credentials?|private[ _-]?key|access[ _-]?token|\.ssh/|\.aws/|\.env\b)"
                r"[^\n]{0,180}https?://", _I), 3, "embeds credentials in an outbound URL", True),
    # usage guidance: common in legitimate tools, so it only adds weight
    (re.compile(r"\bbefore\s+(using|calling|invoking|running|you\s+(use|call))\s+(this|the|any)\s+"
                r"(tool|function)", _I), 2, "pre-condition on tool use", False),
    (re.compile(r"\byou\s+(must|should|need\s+to|have\s+to)\s+(always\s+|first\s+)*(call|use|"
                r"invoke|read|send|include|pass|set|add|run|execute|forward)\b", _I), 2,
     "commands the model", False),
    (re.compile(r"\balways\s+(call|use|invoke|set|add|include|send|pass|bcc|cc|forward|run|"
                r"execute|copy)\b", _I), 2, "commands the model", False),
    (re.compile(r"\b(this\s+is|it\s+is)\s+(very\s+|extremely\s+)?(important|required|mandatory|"
                r"critical|essential)\b", _I), 1, "urgency", False),
    (re.compile(r"\binclude\s+(the\s+|its\s+|their\s+)?(full\s+)?(output|contents?|results?|"
                r"response)\s+(of|from|in)\b", _I), 1, "asks to relay data", False),
    (re.compile(r"\bsystem\s+prompt\b", _I), 1, "mentions the system prompt", False),
    # "read ~/.ssh/id_rsa", "include the contents of ./config": with concealment, an attack
    (re.compile(r"\b(read|cat|open|load|include|attach|append)\s+(the\s+)?(contents?\s+of\s+)?"
                r"(~|\.{1,2}/|/)[\w./-]+", _I), 1, "asks to read a file", False),
)  # fmt: skip

THRESHOLD = 3
HIGH_SCORE = 5


@dataclass(frozen=True, slots=True)
class PhraseMatch:
    label: str
    evidence: Evidence
    weight: int
    attack: bool


_QUOTES = re.compile(r'["“]([^"”\n]{1,400})["”]')
_QUOTE_CONTEXT = re.compile(r"\b(attacker|attack|malicious|untrusted|example|quoted)\b", _I)
_REJECT_QUOTE = re.compile(
    r"\b(treat|regard|consider)\s+(it|this|that|these|such)\b[^.\n]{0,35}"
    r"\b(untrusted|data)\b|"
    r"\b(do\s+not|never|don't)\s+(follow|obey|execute|adopt)\s+"
    r"(it|this|that|these|such|the\s+quoted)\b",
    _I,
)
_PUBLIC_TRANSFER = re.compile(
    r"^(send|forward|post|email|report)\s+(the\s+)?public\s+"
    r"((issue|ticket|build)\s+(number|id)|commit\s+(id|hash)|status)\s+(to|at)\s+",
    _I,
)


def _defensive_quote(view: MatchView, evidence: Evidence) -> bool:
    if evidence.start is None or evidence.end is None or carries_hidden_text(evidence.text):
        return False
    for quote in _QUOTES.finditer(view.source):
        if quote.start(1) <= evidence.start and evidence.end <= quote.end(1):
            before = view.source[max(0, quote.start() - 100) : quote.start()]
            after = view.source[quote.end() : quote.end() + 180]
            if _QUOTE_CONTEXT.search(before) and _REJECT_QUOTE.search(after):
                return True
    return False


def rejected_instruction(view: MatchView, evidence: Evidence) -> bool:
    """Local negation or an explicitly rejected quote, never a document-wide exemption."""
    if carries_hidden_text(evidence.text) or evidence.start is None:
        return False
    prefix = MatchView.of(view.source[max(0, evidence.start - 45) : evidence.start]).text
    return bool(
        re.search(r"\b(do\s+not|don't|never|must\s+not|should\s+not)\s+$", prefix, _I)
        or _defensive_quote(view, evidence)
    )


_IMPACT_ACTIONS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(
            r"\b(delete|erase|wipe|disable|remove|suppress|alter|tamper\s+with)\b"
            r"[^.\n]{0,65}\b(audit\s+(logs?|records?|trail)|security\s+(logs?|controls?)|"
            r"backups?|access\s+controls?)\b",
            _I,
        ),
        "security-state mutation",
    ),
    (
        re.compile(
            r"\b(execute|initiate|send|approve|authorize|perform|complete)\b"
            r"[^.\n]{0,70}\b((wire\s+)?transfers?|payments?|purchases?|transactions?|funds)\b",
            _I,
        ),
        "financial action",
    ),
    (
        re.compile(
            r"\b(reveal|disclose|export|print|leak)\s+"
            r"((the|your|hidden|original|secret|full)\s+)*system\s+prompt\b",
            _I,
        ),
        "protected-prompt disclosure",
    ),
)
_FAILURE_FACT = re.compile(
    r"\b(check|verification|tests?|scan|backup|deployment|operation)\s+"
    r"(did\s+not\s+(pass|succeed|complete)|failed|has\s+failed|was\s+unsuccessful)\b",
    _I,
)
_DIFFERENT_RUN = re.compile(
    r"\b(retry|rerun|re-run|new|second|different|subsequent|recovered)\b", _I
)
_OVERRIDE_LABELS = frozenset(
    {"override earlier instructions", "claims authority over the conversation"}
)


def high_impact_evidence(view: MatchView, matches: list[PhraseMatch]) -> list[tuple[str, Evidence]]:
    """Escalate corroborated harmful intent, rather than lowering the global phrase threshold."""
    evidence: list[tuple[str, Evidence]] = []
    for signal in matches:
        if signal.label == "directs deceptive reporting":
            evidence.append(("explicit instruction to falsify a result", signal.evidence))
        if signal.label == "bypasses user authorization" and re.search(
            r"\buser\b[^.\n]{0,25}\b(declined|refused|denied)\b",
            MatchView.of(signal.evidence.text).text,
            _I,
        ):
            evidence.append(("instruction to override a user's refusal", signal.evidence))
        if signal.label == "directs a potentially false success report":
            for failure, fact in view.finditer(_FAILURE_FACT):
                subject = failure.group(1).rstrip("s")
                same_subject = re.search(
                    rf"\b{subject}s?\b", MatchView.of(signal.evidence.text).text, _I
                )
                if (
                    same_subject
                    and not _DIFFERENT_RUN.search(MatchView.of(signal.evidence.text).text)
                    and not rejected_instruction(view, fact)
                    and _near(fact, signal.evidence)
                ):
                    evidence.append(
                        ("failure assertion paired with a success-report directive", fact)
                    )
        if signal.label in _OVERRIDE_LABELS or signal.label == "bypasses user authorization":
            for pattern, impact in _IMPACT_ACTIONS:
                for _, action in view.finditer(pattern):
                    if not rejected_instruction(view, action) and _near(action, signal.evidence):
                        evidence.append(
                            (f"authority/authorization bypass paired with {impact}", action)
                        )
    return evidence


def _near(first: Evidence, second: Evidence) -> bool:
    return (
        first.start is not None
        and second.start is not None
        and abs(first.start - second.start) <= 320
    )


def instruction_matches(view: MatchView) -> list[PhraseMatch]:
    matches: list[PhraseMatch] = []
    for pattern, weight, label, attack in PHRASES:
        for match, evidence in view.finditer(pattern):
            if rejected_instruction(view, evidence):
                continue
            if label == "sends data to an outside address" and _PUBLIC_TRANSFER.match(
                match.group()
            ):
                continue
            matches.append(PhraseMatch(label, evidence, weight, attack))
    return matches


def steers_model(matches: list[PhraseMatch]) -> bool:
    """Enough weight, and at least one attack signal or hidden text: the bar for a finding."""
    hidden = any(carries_hidden_text(m.evidence.text) for m in matches)
    return sum(m.weight for m in matches) >= THRESHOLD and (
        hidden or any(m.attack for m in matches)
    )


@register
class InstructionPhrases(Rule):
    id = "MCP-TP-004"
    title = "Instructions aimed at the model"
    category = Category.TOOL_POISONING
    default_severity = Severity.MEDIUM
    applies_to = frozenset({"tool", "prompt", "resource"})
    remediation = (
        "Tool metadata should only describe what the tool does. Review the quoted text: if the "
        "server's author didn't put it there on purpose, treat the server as compromised."
    )
    references = ("https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks",)

    def run(self, ctx: RuleContext) -> list[Finding]:
        findings: list[Finding] = []
        for tf in iter_text_fields(ctx.snapshot):
            if tf.kind in ("name", "uri", "property-name"):
                continue
            view = MatchView.of(tf.text)
            matches = instruction_matches(view)
            if not steers_model(matches):
                continue
            score = sum(m.weight for m in matches)
            hidden = any(carries_hidden_text(m.evidence.text) for m in matches)
            attack_score = sum(m.weight for m in matches if m.attack)
            impacts = high_impact_evidence(view, matches)
            high = attack_score >= HIGH_SCORE or hidden or bool(impacts)
            signals = sorted({m.label for m in matches if m.attack})
            rationale = f"Instructions steering the model (score {score})"
            rationale += f": {', '.join(signals)}." if signals else "."
            if impacts:
                rationale += " High impact: " + "; ".join(sorted({why for why, _ in impacts})) + "."
            if hidden:
                rationale += " Some of them are hidden in invisible characters."
            findings.append(
                self.finding(
                    location=tf.location,
                    evidence=[m.evidence for m in matches] + [ev for _, ev in impacts],
                    rationale=rationale,
                    severity=Severity.HIGH if high else Severity.MEDIUM,
                    confidence=Confidence.HIGH
                    if attack_score >= HIGH_SCORE or hidden
                    else Confidence.MEDIUM,
                )
            )
        return findings
