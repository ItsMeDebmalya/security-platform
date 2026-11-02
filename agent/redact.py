"""The agent's own redactor. Python 3.6 floor, stdlib only.

agent/ cannot import core/, so the token families are duplicated deliberately.
tests/agent/test_redact.py asserts this set is a superset of core/redaction.py's.

NOT YET IMPLEMENTED, and owed to the spec 6.3 collection task: the value-level base64
deny-list (bare base64 runs over a length threshold, as core's heuristics do). A later
task must not assume that coverage exists; test_redact.py pins the difference.
"""

import re
from typing import Any, Dict, Tuple

REDACTED = "[redacted]"
BLOCK_MARKER = "[redacted:private_key]"

SECRET_PATTERNS = (
    ("aws_access_key_id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("bearer_token", re.compile(r"\bBearer\s+[A-Za-z0-9._\-]{16,}")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
)

_LABEL = r"(?:[A-Za-z0-9_]|[ \t]){0,40}?PRIVATE[ \t_-]?KEY(?:[ \t]+BLOCK)?"
_BEGIN = re.compile(r"-{4,5}[ \t]*BEGIN[ \t]+" + _LABEL + r"[ \t]*-{4,5}", re.IGNORECASE)
_END = re.compile(r"-{4,5}[ \t]*END[ \t]+" + _LABEL + r"[ \t]*-{4,5}", re.IGNORECASE)


def _cut_private_keys(text: str, counts: Dict[str, int]) -> str:
    out = []
    pos = 0
    for begin in _BEGIN.finditer(text):
        if begin.start() < pos:
            continue
        out.append(text[pos : begin.start()])
        out.append(BLOCK_MARKER)
        counts["private_key"] = counts.get("private_key", 0) + 1
        end = _END.search(text, begin.end())
        if end is None:  # no safe partial boundary: cut to the end
            return "".join(out)
        pos = end.end()
    out.append(text[pos:])
    return "".join(out)


def redact_text(text: Any) -> Tuple[Any, Dict[str, int]]:
    if not text:
        return text, {}
    counts = {}  # type: Dict[str, int]
    text = _cut_private_keys(text, counts)
    for name, pattern in SECRET_PATTERNS:
        text, n = pattern.subn("%s:%s" % (REDACTED, name), text)
        if n:
            counts[name] = counts.get(name, 0) + n
    return text, counts


def redact_tree(value: Any, counts: Dict[str, int]) -> Any:
    """Redact every string (keys and values) in a JSON-shaped tree, tallying by family."""
    if isinstance(value, str):
        new, found = redact_text(value)
        for name, n in found.items():
            counts[name] = counts.get(name, 0) + n
        return new
    if isinstance(value, dict):
        return {redact_tree(k, counts): redact_tree(v, counts) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_tree(v, counts) for v in value]
    return value


def redact_data(value: Any) -> Any:
    return redact_tree(value, {})
