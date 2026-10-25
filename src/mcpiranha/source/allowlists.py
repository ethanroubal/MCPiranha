"""Small literal allowlists safe for a specific injection context, not arbitrary validators."""

import re


def safe_literals(values: list[str], domain: str) -> bool:
    if not values or len(values) > 64:
        return False
    if domain == "path":
        return all(v and v not in {".", ".."} and not any(c in v for c in "/\\:\0") for v in values)
    patterns = {
        "shell": r"[A-Za-z0-9_./:@+-]+",
        "sql": r"[A-Za-z0-9_]+",
        "url": r"[A-Za-z0-9][A-Za-z0-9.-]*(?::[0-9]+)?",
    }
    return domain in patterns and all(re.fullmatch(patterns[domain], v) for v in values)
