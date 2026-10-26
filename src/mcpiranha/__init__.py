"""mcpiranha: security scanner for Model Context Protocol servers."""

from importlib.metadata import PackageNotFoundError, version

REPO_URL = "https://github.com/ethanroubal/MCPiranha"
RULES_URL = f"{REPO_URL}/blob/main/docs/RULES.md"

try:
    __version__ = version("mcpiranha")
except PackageNotFoundError:  # running from a source checkout without installing
    __version__ = "0.0.0+unknown"
