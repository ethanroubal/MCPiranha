"""MCP-SRC: what the server's code does that its tools don't say.

Judged on what `mcpiranha.source` found in the code the server runs (a local script, or the npm /
PyPI release, read without running it). These look for malicious behavior hidden behind honest
metadata, the case no metadata rule can see:

- SRC-001: a fixed email address added as Bcc/Cc (postmark-mcp copied every email it sent).
- SRC-002: collecting the environment's secrets (serializing it, or picking TOKEN/KEY variables).
- SRC-003: literal paths to credential stores (~/.ssh, ~/.aws/credentials, browser logins), in
  code that also has a way out (SRC-001, -002 or -005). Alone they're common and benign: SSH
  tunnels read ~/.ssh/id_rsa, security tools list these paths to block them.
- SRC-004: running decoded or downloaded code (eval(atob(...)), exec(b64decode(...))). Not
  `curl | sh` strings: calibration found them only in install instructions and deny-lists.
- SRC-005: a hardcoded request catcher, tunnel or Discord webhook as a destination.
- SRC-006: a reverse shell (bash -i >& /dev/tcp, nc -e, a shell wired to a socket).
- SRC-007: a cryptominer (mining pools, xmrig).
- SRC-008: persistence: writing shell profiles, LaunchAgents, systemd units, cron, git hooks.
- SRC-009: writing MCP client configs; high when the code also sets auto-approve (installers
  register servers, which is low).
- SRC-010: wiping the home directory or the disk.

Paths in SRC-008 and SRC-009 only count when the code writes them (reading ~/.zshrc or an MCP
config is common), and command strings (reverse shells, wipes, cron installs) only when they're
executed: the analyzers check the enclosing call, or a name such a call is given.

One finding per rule and server, citing up to five places.
"""

from __future__ import annotations

from mcpiranha.core.models import (
    Category,
    Confidence,
    Evidence,
    Finding,
    Location,
    Severity,
    SourceHit,
    SourceHitKind,
)
from mcpiranha.rules.base import Rule, RuleContext
from mcpiranha.rules.registry import register

SHOWN = 5


class _SourceRule(Rule):
    category = Category.SOURCE
    applies_to = frozenset({"source"})
    kinds: tuple[SourceHitKind, ...]
    what: str
    confidence = Confidence.MEDIUM

    def run(self, ctx: RuleContext) -> list[Finding]:
        tree = ctx.snapshot.source
        hits = [h for h in tree.hits if h.kind in self.kinds] if tree else []
        if not tree or not hits:
            return []
        places = "; ".join(f"{h.file}:{h.line} {h.detail}" for h in hits[:SHOWN])
        more = f" (and {len(hits) - SHOWN} more)" if len(hits) > SHOWN else ""
        first = hits[0]
        return [self.finding(
            location=Location(server_id=ctx.snapshot.id, file=_file(tree.root, first),
                              line=first.line),
            evidence=[Evidence(text=h.code) for h in hits[:SHOWN] if h.code],
            rationale=f"{self.what} in {tree.root}: {places}{more}.",
            confidence=self.confidence,
        )]  # fmt: skip


def _file(root: str, hit: SourceHit) -> str:
    return f"{root}/{hit.file}" if not hit.file.startswith("/") else hit.file


@register
class HiddenRecipient(_SourceRule):
    id = "MCP-SRC-001"
    title = "Code adds a fixed Bcc/Cc recipient"
    default_severity = Severity.HIGH
    kinds = ("hardcoded_recipient",)
    what = "The code sends copies of messages to a fixed address"
    confidence = Confidence.HIGH
    remediation = (
        "Nothing in a mail tool's description says copies go elsewhere. Unless the server's "
        "purpose explains it, treat every message sent through it as leaked, and remove it."
    )
    references = ("https://www.koi.ai/blog/postmark-mcp-npm-malicious-backdoor-email-theft",)


@register
class EnvHarvest(_SourceRule):
    id = "MCP-SRC-002"
    title = "Code collects secrets from the environment"
    default_severity = Severity.HIGH
    kinds = ("env_harvest",)
    what = "The code collects environment variables wholesale or by secret-looking names"
    remediation = (
        "A server needs the variables its config sets, by name. Collecting all of them, or "
        "every TOKEN / KEY, is how credential stealers start; rotate what it could see."
    )


@register
class CredentialPaths(_SourceRule):
    id = "MCP-SRC-003"
    title = "Code names credential files and has a way to send data out"
    default_severity = Severity.HIGH
    kinds = ("sensitive_file",)
    what = "The code names credential stores, and also sends data to a fixed destination"
    remediation = (
        "Credential paths next to a hardcoded destination is the shape of a stealer. Don't run "
        "it, and rotate the credentials if it already ran."
    )
    _OUT: tuple[SourceHitKind, ...] = ("exfil_host", "hardcoded_recipient", "env_harvest")

    def run(self, ctx: RuleContext) -> list[Finding]:
        tree = ctx.snapshot.source
        if tree is None or not any(h.kind in self._OUT for h in tree.hits):
            return []
        return super().run(ctx)


@register
class HiddenCode(_SourceRule):
    id = "MCP-SRC-004"
    title = "Code runs decoded, downloaded or obfuscated code"
    default_severity = Severity.HIGH
    kinds = ("dynamic_code", "obfuscated")
    what = "The code runs code it decodes or downloads, or is obfuscated"
    remediation = (
        "Code that only exists after decoding or downloading can't be reviewed, and can change "
        "without a release. Don't run the server until you know what it executes."
    )


@register
class ExfilEndpoint(_SourceRule):
    id = "MCP-SRC-005"
    title = "Code contains a request-catcher or webhook address"
    default_severity = Severity.HIGH
    kinds = ("exfil_host",)
    what = "The code has a hardcoded data-collection endpoint"
    remediation = (
        "Request catchers, tunnels and webhook URLs are where stolen data is sent; a server "
        "that posts to your own webhook takes its URL as configuration, not as a literal."
    )


@register
class RemoteAccess(_SourceRule):
    id = "MCP-SRC-006"
    title = "Code opens a reverse shell"
    default_severity = Severity.CRITICAL
    kinds = ("reverse_shell",)
    what = "The code connects a shell to the network"
    confidence = Confidence.HIGH
    remediation = (
        "A reverse shell hands your machine to whoever is listening. Don't run the server; if "
        "it ran, treat the machine as compromised."
    )


@register
class CryptoMiner(_SourceRule):
    id = "MCP-SRC-007"
    title = "Code mines cryptocurrency"
    default_severity = Severity.HIGH
    kinds = ("miner",)
    what = "The code refers to mining pools or miners"
    remediation = "No MCP server needs a mining pool. Remove it and check for running miners."


@register
class Persistence(_SourceRule):
    id = "MCP-SRC-008"
    title = "Code installs itself to run later"
    default_severity = Severity.MEDIUM
    kinds = ("persistence",)
    what = "The code writes files that run code later (shell profiles, autostart, cron, hooks)"
    remediation = (
        "Writing ~/.bashrc, LaunchAgents, cron or git hooks keeps code running after the server "
        "is removed. Check those files if it ran, and remove what it added."
    )


@register
class ClientConfigTampering(_SourceRule):
    id = "MCP-SRC-009"
    title = "Code writes MCP client configs"
    default_severity = Severity.HIGH
    kinds = ("client_config",)
    what = "The code writes MCP client configuration"
    remediation = (
        "Installers write client configs to register a server; a server that does it can add "
        "servers or turn on auto-approve without you seeing it. Review your client configs "
        "(`mcpiranha scan`), especially auto-approve settings."
    )

    def run(self, ctx: RuleContext) -> list[Finding]:
        findings = super().run(ctx)
        tree = ctx.snapshot.source
        hits = tree.hits if tree is not None else []
        approve = any(h.kind == "client_config" and "auto-approve" in h.detail for h in hits)
        severity = Severity.HIGH if approve else Severity.LOW
        return [f.model_copy(update={"severity": severity}) for f in findings]


@register
class Wiper(_SourceRule):
    id = "MCP-SRC-010"
    title = "Code wipes the home directory or the disk"
    default_severity = Severity.CRITICAL
    kinds = ("destructive",)
    what = "The code deletes the home directory, the filesystem root or disks"
    confidence = Confidence.HIGH
    remediation = "Don't run it. Check your backups if it already ran."


# --- MCP-SRC-1xx: exploitable tool handlers (taint, source/taint_*.py) ---------------------------
# Not malice: bugs that let whoever controls the model's input (a poisoned page, issue or email)
# turn a tool call into an attack. Only input spliced into code the developer wrote counts; a
# tool that runs whatever command or SQL it's given is a capability (MCP-TF), not injection.


@register
class CommandInjection(_SourceRule):
    id = "MCP-SRC-101"
    title = "Tool argument injected into a shell command"
    default_severity = Severity.HIGH
    kinds = ("shell_injection",)
    what = "A tool argument reaches a shell command string"
    remediation = (
        "Pass arguments as a list without a shell (subprocess.run([...]), execFile), or quote "
        "each complete shell word (shlex.quote), without wrapping it in additional quotes. "
        "Shell quoting does not protect SQL, file paths or URL hosts."
    )
    references = ("https://cwe.mitre.org/data/definitions/78.html",)


@register
class SqlInjection(_SourceRule):
    id = "MCP-SRC-102"
    title = "Tool argument injected into a SQL query"
    default_severity = Severity.HIGH
    kinds = ("sql_injection",)
    what = "A tool argument is built into a SQL string"
    remediation = "Use parameterized queries (placeholders plus a parameters argument)."
    references = ("https://cwe.mitre.org/data/definitions/89.html",)


@register
class PathTraversal(_SourceRule):
    id = "MCP-SRC-103"
    title = "Tool argument escapes its base directory"
    # A handler argument crossing a filesystem/network boundary is high-impact even
    # when static-analysis confidence remains medium. Whole-input capabilities are excluded.
    default_severity = Severity.HIGH
    kinds = ("path_traversal",)
    what = "A tool argument reaches a based path without a recognized effective containment guard"
    remediation = (
        "Resolve the candidate and base, then reject paths outside that base before use. "
        "Use Path.is_relative_to or a normalized JavaScript base plus path.sep; raw string "
        "prefixes are insufficient. Account for symlinks and filesystem races."
    )
    references = ("https://cwe.mitre.org/data/definitions/22.html",)


@register
class ServerSideRequestForgery(_SourceRule):
    id = "MCP-SRC-104"
    title = "Tool argument chooses the host of a server request"
    # A handler argument crossing a filesystem/network boundary is high-impact even
    # when static-analysis confidence remains medium. Whole-input capabilities are excluded.
    default_severity = Severity.HIGH
    kinds = ("ssrf",)
    what = "A tool argument sets the host of a URL the server requests"
    remediation = (
        "Allow-list hosts, and refuse private and link-local addresses (169.254.169.254, "
        "localhost) before requesting; remote servers can otherwise be pointed at internal ones."
    )
    references = ("https://cwe.mitre.org/data/definitions/918.html",)
