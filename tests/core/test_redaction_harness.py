"""D21 step (c): Tool 4a's 153-case leak harness, run against core directly.

The cases are the ones `web`'s scanner-side redactor was proven against in
Tool 4a's three leak-fix rounds (`atk.py`: 44, `atk2.py`: 100, `atk3.py`: 9):
private keys in every encoding a page can carry them, placed to straddle a
truncation cut at small caps and at the default 256 KB cap. Here no scanner
code runs. Each case goes through every storage point core owns:

1. a live capture (`capture_http_pair`), capped;
2. a recorded fixture on disk, and the replay of it;
3. **a legacy fixture**: what core wrote before ADR-028 (BEGIN line replaced,
   key body kept, then truncated), replayed through the current core;
4. a finding whose description is built with core's cap;
5. a scan error carrying the body.

Pass condition: no key line, no 24-character tail of one, and no END line in
anything stored. Zero leaks.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from core.evidence import DEFAULT_BODY_CAP, capture_http_pair
from core.http import RawHttpResponse, RecordingHttpBackend, ReplayHttpBackend, _fixture_name
from core.models import Finding, ScanError
from core.redaction import SECRET_PATTERNS, cap_text
from tests.core.test_redaction import key_lines, pem
from tests.core.test_redaction_storage import _finding_kwargs, _req, _resp

L = key_lines()
L2 = key_lines(seed=7)
LPHP = [line.replace("/", "\\/") for line in L]
H = DEFAULT_BODY_CAP // 2
Y = "y" * DEFAULT_BODY_CAP
END = "-----END RSA PRIVATE KEY-----"


def _cases() -> list[tuple[str, str, int | None, list[str]]]:
    cases: list[tuple[str, str, int | None, list[str]]] = []

    def check(name, body, cap=None, ls=L):
        cases.append((name, body, cap, ls))

    # --- atk.py (44) --------------------------------------------------------
    check("plain", f"<pre>{pem(L)}</pre>")
    check("crlf", f"<pre>{pem(L, sep=chr(13) + chr(10))}</pre>")
    check("json \\n", json.dumps({"k": pem(L) + "\n"}))
    check("php json \\/ terminated", json.dumps({"k": pem(L) + "\n"}).replace("/", "\\/"), ls=LPHP)
    check(
        "php json \\/ unterminated",
        json.dumps({"k": pem(L, end=False)}).replace("/", "\\/"),
        ls=LPHP,
    )
    check("br unterminated", "<pre>" + pem(L, sep="<br>\n", end=False) + "</pre><p>x</p>")
    check("br terminated", "<pre>" + pem(L, sep="<br>") + "</pre>")
    check("attr &#10; unterminated", '<input value="' + pem(L, sep="&#10;", end=False) + '">')
    check("76col", f"<pre>{pem(key_lines(30, 76), end=False)}</pre>", ls=key_lines(30, 76))
    check(
        "80col unterminated",
        f"<pre>{pem(key_lines(30, 80), end=False)}</pre>",
        ls=key_lines(30, 80),
    )
    for cap in (400, 700, 1000, 1500):
        for pre in (900, 1000, 1100, 1300):
            check(f"straddle cap={cap} pre={pre}", "x" * pre + "\n" + pem(L) + "\n" + "y" * 40, cap)
    for cap in (400, 1000):
        body = json.dumps({"pad": "x" * 900, "k": pem(L) + "\n", "z": "y" * 40}).replace("/", "\\/")
        check(f"php straddle cap={cap}", body, cap, LPHP)
    for cap in (400, 1000):
        check(
            f"br straddle cap={cap}",
            "x" * 900 + "<pre>" + pem(L, sep="<br>\n") + "</pre>" + "y" * 40,
            cap,
        )
    for cap in (400, 1000):
        check(
            f"crlf straddle cap={cap}",
            "x" * 900 + "\r\n" + pem(L, sep="\r\n") + "\r\n" + "y" * 40,
            cap,
        )
    for width in (64, 70, 76, 80, 58):
        lw = key_lines(30, width)
        check(
            f"bare unterminated w={width}",
            "x" * 900 + "\n" + pem(lw, end=False) + "\n<p>t</p>",
            1200,
            lw,
        )
    traceback_tail = '\nTraceback (most recent call last):\n  File "/app/s.py", line 9\n</pre>'
    trace = "<pre>" + pem(L, sep="<br>", end=False) + traceback_tail
    check("error excerpt br unterminated", trace)
    for pad in (H - 1000, H - 500, H - 200):
        check(
            f"default br terminated pad={pad}",
            "x" * pad + "<pre>" + pem(L, sep="<br>\n") + "</pre>" + Y,
        )
        body = json.dumps({"pad": "x" * pad, "k": pem(L) + "\n", "z": Y}).replace("/", "\\/")
        check(f"default php terminated pad={pad}", body, ls=LPHP)

    # --- atk2.py (100) --------------------------------------------------------
    def straddle(name, keytext, ls):
        n = len(keytext)
        for frac in (0.2, 0.5, 0.8):
            check(f"{name} head {frac}", "x" * (H - int(n * frac)) + keytext + Y, ls=ls)
            check(
                f"{name} tail {frac}", "x" * (H + 5000) + keytext + "y" * (H - int(n * frac)), ls=ls
            )

    seps = ["\n", "<br>", "\r\n", "&#10;", "\\n"]
    mixed = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        + "".join(line + seps[i % 5] for i, line in enumerate(L))
        + END
    )
    straddle("mixed seps", "<pre>" + mixed + "</pre>", L)
    brattr = (
        '-----BEGIN RSA PRIVATE KEY-----<BR class="x">'
        + '<BR class="x">'.join(L)
        + '<BR class="x">'
        + END
    )
    straddle("BR attrs", brattr, L)
    check("BR attrs unterminated live", "x" + brattr.split("-----END")[0] + "<p>t</p>")
    straddle("&#x0A;", '<input value="' + pem(L, sep="&#x0A;") + '">', L)
    straddle("&#X0D;&#X0A;", '<input value="' + pem(L, sep="&#X0D;&#X0A;") + '">', L)
    straddle("textarea", "<textarea>" + pem(L) + "</textarea>", L)
    straddle("json \\/", json.dumps({"k": pem(L) + "\n"}).replace("/", "\\/"), LPHP)
    straddle("json /", json.dumps({"k": pem(L) + "\n"}), L)
    cm = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        + "\n".join(L[:15])
        + "\n<!-- c -->\n"
        + "\n".join(L[15:])
        + "\n"
        + END
    )
    straddle("html comment split", "<pre>" + cm + "</pre>", L)
    cm2 = (
        "-----BEGIN RSA PRIVATE KEY-----\n" + "\n".join(line + "<!---->" for line in L) + "\n" + END
    )
    straddle("comment each line", "<pre>" + cm2 + "</pre>", L)
    two = "<pre>" + pem(L) + "</pre><p>between</p><pre>" + pem(L2) + "</pre>"
    check("two keys live", two, ls=L + L2)
    straddle("two keys straddle", two, L + L2)
    sp = "-----BEGIN RSA PRIVATE KEY----- " + " ".join(L) + " " + END
    straddle("space-separated", "<p>KEY=" + sp + "</p>", L)
    straddle("space-separated nl-after-text", "<p>KEY=\n" + sp + "</p>", L)
    tabs = "-----BEGIN RSA PRIVATE KEY-----\n" + "\n".join("\t\t" + line for line in L) + "\n" + END
    straddle("indent tabs", "<pre>" + tabs + "</pre>", L)
    prefixed = (
        "-----BEGIN RSA PRIVATE KEY-----\n" + "\n".join("key: " + line for line in L) + "\n" + END
    )
    straddle("prefixed lines", prefixed, L)
    td = (
        "-----BEGIN RSA PRIVATE KEY-----" + "".join(f"<tr><td>{line}</td></tr>" for line in L) + END
    )
    straddle("table cells", td, L)
    straddle("unterminated br", "<pre>" + pem(L, sep="<br>", end=False) + "</pre><p>t</p>", L)
    trace = (
        "<pre>"
        + pem(L, sep="<br>", end=False)
        + '\nTraceback (most recent call last):\n  File "/app/s.py", line 9\n</pre>'
    )
    check("excerpt unterminated", trace)
    check(
        "excerpt after sig", "<p>Traceback (most recent call last):\n" + pem(L, sep="<br>") + "</p>"
    )

    # --- atk3.py (9) ----------------------------------------------------------
    def tail(name, keytext, ls, fracs=(0.2, 0.5, 0.8)):
        for frac in fracs:
            check(
                f"{name} {frac}",
                "x" * (H + 5000) + keytext + "y" * (H - int(len(keytext) * frac)),
                ls=ls,
            )

    tail("json \\/ space", json.dumps({"k": pem(L, sep=" ")}).replace("/", "\\/"), LPHP)
    tail(
        "404 excerpt",
        pem(L, sep=" ")
        + '\n<pre>Traceback (most recent call last):\n  File "/app/s.py", line 9\n</pre>',
        L,
    )
    check(
        "head full key + gap key",
        pem(L2, sep=" ") + "x" * (H + 5000) + sp + "y" * (H - len(sp) // 2),
        ls=L + L2,
    )
    return cases


ROBOTS_BODY = "User-agent: *\n" + "".join(f"Disallow: /{line}\n" for line in L)
"""atk3.py's last two cases: key lines used as robots.txt paths, at caps 400 and 1000.

They are **not counted as leaks**, and that is stated rather than hidden. A
base64 string after `Disallow: /` has no PEM structure and matches no token
pattern, so no redactor can call it key material without also redacting every
hash-like path in every URL. These two cases "leak" through `web` on the code
that predates ADR-028 as well (30/30 lines live; 5/30 and 13/30 on replay,
re-measured 2026-10-09), so Tool 4a's "0 leaks" held for its 151 PEM cases,
not all 153. What the robots cases guarded in Tool 4a was the description cap
splitting a secret (leak-fix round 1);
`test_a_secret_in_a_robots_path_is_never_stored` covers that with a real secret.
"""


CASES = _cases()


def test_the_harness_has_every_tool_4a_case():
    assert len(CASES) + 2 == 153  # the two robots cases are below, with the reason


# --- what core wrote before ADR-028, to build legacy fixtures -----------------

_OLD_BEGIN = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")


def _old_core_capture(body: str, cap: int) -> str:
    """Core's capture before ADR-028: the BEGIN line became a marker, the body was
    kept, then the text was cut (head and tail, with a note)."""
    body = _OLD_BEGIN.sub("[redacted]:private_key", body)
    for name, pattern in SECRET_PATTERNS:
        body = pattern.sub(f"[redacted]:{name}", body)
    if len(body) <= cap:
        return body
    head, tail = cap // 2, cap - cap // 2
    return f"{body[:head]}\n... [{len(body) - cap} bytes truncated] ...\n{body[-tail:]}"


def _leaks(stored: str, lines: list[str]) -> list[str]:
    found = [line for line in lines if line in stored or line[-24:] in stored]
    if "END RSA PRIVATE KEY" in stored:
        found.append("END line")
    return found


class _Site:
    def __init__(self, body: str) -> None:
        self.body = body

    def send(self, method, url, *, body_cap, **kwargs):
        return RawHttpResponse(status_code=200, headers={}, text=self.body, url=url, elapsed_ms=1)


@pytest.mark.parametrize(("name", "body", "cap", "lines"), CASES, ids=[c[0] for c in CASES])
def test_no_storage_point_in_core_keeps_a_key(name, body, cap, lines, tmp_path: Path):
    cap = cap or DEFAULT_BODY_CAP
    stored: dict[str, str] = {}

    # 1. live capture
    stored["capture"] = capture_http_pair(
        label="l",
        control_request=_req(),
        control_response=_resp(),
        test_request=_req(),
        test_response=_resp(body=body),
        cap=cap,
    ).model_dump_json()

    # 2. recorded fixture, and its replay
    rec = tmp_path / "rec"
    RecordingHttpBackend(rec, inner=_Site(body)).send("GET", "https://x.test/", body_cap=cap)
    stored["fixture"] = "".join(p.read_text() for p in rec.rglob("*.json"))
    stored["replay"] = ReplayHttpBackend(rec).send("GET", "https://x.test/", body_cap=cap).text

    # 3. a legacy fixture written by core before ADR-028, replayed now
    legacy = tmp_path / "legacy"
    legacy.mkdir()
    payload = {
        "status": 200,
        "headers": {},
        "body": _old_core_capture(body, cap),
        "body_truncated": len(body) > cap,
        "elapsed_ms": 1,
        "redactions": ["private_key"],
        "url": "https://x.test/",
    }
    (legacy / _fixture_name("GET", "https://x.test/")).write_text(json.dumps(payload))
    stored["legacy replay"] = (
        ReplayHttpBackend(legacy).send("GET", "https://x.test/", body_cap=cap).text
    )

    # 4. a finding description built with core's cap, 5. a scan error
    excerpt, _ = cap_text(body, 2000)
    stored["finding"] = Finding.create(
        **_finding_kwargs(description=f"excerpt: {excerpt}")
    ).model_dump_json()
    stored["error"] = ScanError(stage="fetch", message=body[:5000]).message

    leaks = {where: _leaks(text, lines) for where, text in stored.items()}
    assert {where: found for where, found in leaks.items() if found} == {}, name


@pytest.mark.parametrize("cap", [400, 1000])
def test_the_robots_cases_store_their_paths_and_say_so(cap):
    """Kept visible: these strings are not secrets, so they are stored."""
    text, _ = cap_text(ROBOTS_BODY, cap)

    assert L[0] in text  # the first path survives the head of the cut, by design


@pytest.mark.parametrize("cap", [400, 1000])
@pytest.mark.parametrize(
    "secret", ["AKIAIOSFODNN7EXAMPLE", "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"]
)
def test_a_secret_in_a_robots_path_is_never_stored(cap, secret):
    """What Tool 4a's robots case guarded: a cut must never split a secret."""
    runs = {secret[i : i + 8] for i in range(len(secret) - 7)}
    for offset in range(0, 400, 7):
        body = (
            "User-agent: *\nDisallow: /"
            + "a" * offset
            + "/"
            + secret
            + "\n"
            + "Disallow: /z\n" * 50
        )
        stored, _ = cap_text(body, cap)
        assert not any(run in stored for run in runs), offset
