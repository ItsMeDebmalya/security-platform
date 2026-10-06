"""Information-disclosure signals: version strings, error/debug pages, secrets.

Error signatures are confirmed against real recordings in the corpus lab
(Django, Python traceback) or real public responses during live verification;
the rest are unit-tested only until then (ledger D-W items).
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Literal

from scanners.web.headers import get

VERSION_HEADERS = ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version")
_VERSION = re.compile(r"\d+(?:\.\d+)+")

SECRET_KINDS = frozenset(
    {"aws_access_key_id", "github_token", "slack_token", "private_key", "bearer_token"}
)
"""core.evidence's redaction kinds that are real credentials. google_api_key is
excluded on purpose: browser API keys are public by design."""


def version_disclosures(headers: Mapping[str, str], generator: str | None) -> list[tuple[str, str]]:
    found = [
        (name, value)
        for name in VERSION_HEADERS
        if (value := get(headers, name)) and _VERSION.search(value)
    ]
    if generator and _VERSION.search(generator):
        found.append(("meta generator", generator))
    return found


@dataclass(frozen=True)
class ErrorSignature:
    name: str
    kind: Literal["debug", "error"]
    pattern: re.Pattern[str]
    source: str


SIGNATURES: tuple[ErrorSignature, ...] = (
    ErrorSignature(
        "Django debug page",
        "debug",
        re.compile(r"You.re seeing this error because you have <code>DEBUG = True</code>"),
        "https://docs.djangoproject.com/en/5.2/ref/settings/#debug",
    ),
    ErrorSignature(
        "Python traceback",
        "error",
        re.compile(r"Traceback \(most recent call last\):"),
        "https://docs.python.org/3/library/traceback.html",
    ),
    ErrorSignature(
        "Java stack trace",
        "error",
        re.compile(
            r"\bat (?:java|javax|org\.springframework|org\.apache)\.[\w.$]+"
            r"\(\w+\.java:\d+\)"
        ),
        (
            "https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/lang/"
            "StackTraceElement.html"
        ),
    ),
    ErrorSignature(
        "PHP error",
        "error",
        re.compile(
            r"<b>(?:Fatal error|Warning|Parse error)</b>:.+? in <b>[^<]+</b> "
            r"on line <b>\d+</b>"
        ),
        "https://www.php.net/manual/en/errorfunc.configuration.php#ini.display-errors",
    ),
    ErrorSignature(
        "ASP.NET error page",
        "error",
        re.compile(r"Server Error in '[^']*' Application\."),
        (
            "https://learn.microsoft.com/en-us/aspnet/web-forms/overview/"
            "older-versions-getting-started/deploying-web-site-projects/"
            "displaying-a-custom-error-page-cs"
        ),
    ),
)


def error_signature(body: str) -> ErrorSignature | None:
    if not body:
        return None
    matches = [s for s in SIGNATURES if s.pattern.search(body)]
    if not matches:
        return None
    debug = [s for s in matches if s.kind == "debug"]
    return debug[0] if debug else matches[0]


def excerpt(body: str, sig: ErrorSignature, width: int = 80) -> str:
    match = sig.pattern.search(body)
    if match is None:
        return ""
    return body[max(0, match.start() - width) : match.end() + width]


def secret_kinds(redactions: Iterable[str]) -> list[str]:
    return sorted(set(redactions) & SECRET_KINDS)
