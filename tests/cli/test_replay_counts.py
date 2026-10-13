"""What a run counted, and under what conditions (D64).

A recorded lab scan replayed through `scan run --replay` reported 4 requests
against 6 live. Both numbers are honest: the two missing ones are the D60
address pin's A and AAAA lookups, which a replay never performs because
`ReplayHttpBackend.connects` is False, so `HttpClient` skips `pin()`
altogether - no socket is opened, so no address is needed. The recording is
complete; it holds all six interactions.

The defect was that one published figure silently meant two different things
depending on run mode. The repair is to say which is which: a recorded run
writes down what it counted, broken down by protocol, and a replay that
finds that manifest reports both totals and names the difference. With no
manifest - an older recording - a replay says what it did and invents no
live number.
"""

from __future__ import annotations

import json

from cli.replay_counts import (
    MANIFEST,
    Counts,
    LiveManifest,
    counting_http_backend,
    counting_resolver,
    counting_tls_backend,
    divergence_note,
    read_manifest,
    write_manifest,
)

# --- the counters ------------------------------------------------------------


class _Backend:
    connects = True

    def __init__(self) -> None:
        self.sent: list[tuple[str, str]] = []
        self.refusals = 0

    def send(self, method: str, url: str, *, body_cap: int, **kwargs: object) -> str:
        self.sent.append((method, url))
        return "response"

    def record_refusal(self, method: str, url: str, exc: object) -> None:
        self.refusals += 1


def test_the_http_counter_counts_sends_and_passes_everything_else_through() -> None:
    inner = _Backend()
    counts = Counts()
    wrapped = counting_http_backend(inner, counts)

    assert wrapped.send("GET", "http://x/", body_cap=10) == "response"
    assert wrapped.send("GET", "http://x/robots.txt", body_cap=10) == "response"
    assert counts.http == 2
    # The wrapper must not hide what `HttpClient` looks for on a backend: a
    # backend that opens sockets still says so (fail closed), and a refusal
    # still reaches the recording so its replay refuses too (D60).
    assert wrapped.connects is True
    wrapped.record_refusal("GET", "http://x/", ValueError("refused"))
    assert inner.refusals == 1
    # A refusal opens no socket and costs no request, so it is not counted.
    assert counts.http == 2


def test_a_replay_backend_keeps_saying_it_opens_no_socket_through_the_wrapper() -> None:
    class _Replay:
        connects = False

        def send(self, method: str, url: str, *, body_cap: int, **kwargs: object) -> str:
            return "fixture"

    wrapped = counting_http_backend(_Replay(), Counts())
    assert wrapped.connects is False


def test_a_backend_that_says_nothing_about_connecting_is_still_treated_as_connecting() -> None:
    class _Silent:
        def send(self, method: str, url: str, *, body_cap: int, **kwargs: object) -> str:
            return "x"

    assert counting_http_backend(_Silent(), Counts()).connects is True


def test_the_dns_counter_counts_resolver_calls() -> None:
    class _Resolver:
        def resolve(self, name: str, rrtype: str, resolver: str | None = None) -> str:
            return f"{name}/{rrtype}"

    counts = Counts()
    wrapped = counting_resolver(_Resolver(), counts)
    assert wrapped.resolve("localhost", "A", "1.1.1.1") == "localhost/A"
    assert wrapped.resolve("localhost", "AAAA") == "localhost/AAAA"
    assert counts.dns == 2
    assert counts.http == 0


def test_the_tls_counter_counts_handshakes_but_never_a_policy_refusal() -> None:
    """`TlsClient` does not charge a request for a handshake the address policy
    stopped (review of D60, round 2), live or replayed. The counter must agree
    with the meter, so it does not charge for one either."""
    import datetime as dt

    from core.tls import RawHandshake

    reached = RawHandshake(reachable=True, observed_at=dt.datetime.now(dt.UTC))
    refused = RawHandshake(
        reachable=False,
        observed_at=dt.datetime.now(dt.UTC),
        error="address_refused:127.0.0.1 is not a global address",
    )

    class _Tls:
        connects = False

        def __init__(self) -> None:
            self.answers = [reached, refused]

        def handshake(self, host: str, port: int, servername: str | None, **kw: object):
            return self.answers.pop(0)

    counts = Counts()
    wrapped = counting_tls_backend(_Tls(), counts)
    assert wrapped.handshake("h", 443, "h") is reached
    assert wrapped.handshake("h", 443, "h") is refused
    assert counts.tls == 1


# --- the manifest ------------------------------------------------------------


def test_the_manifest_records_the_breakdown_and_not_only_the_total(tmp_path) -> None:
    """`requests` conflates DNS lookups with HTTP sends (D65), so a manifest
    holding one total would preserve that ambiguity in a new place."""
    write_manifest(tmp_path, counts=Counts(http=4, dns=2, tls=0), requests_counted=6)
    stored = json.loads((tmp_path / MANIFEST).read_text())
    assert stored["live"] == {
        "http_sends": 4,
        "dns_queries": 2,
        "tls_handshakes": 0,
        "requests_counted": 6,
    }

    read = read_manifest(tmp_path)
    assert read is not None
    assert read.counts == Counts(http=4, dns=2, tls=0)
    assert read.requests_counted == 6


def test_no_manifest_reads_as_nothing_known(tmp_path) -> None:
    assert read_manifest(tmp_path) is None


def test_a_manifest_we_cannot_read_is_nothing_known_rather_than_an_error(tmp_path) -> None:
    """An older or hand-edited recording must not stop a replay. It means we do
    not know the live count, which is exactly what `None` says."""
    (tmp_path / MANIFEST).write_text("{not json")
    assert read_manifest(tmp_path) is None
    (tmp_path / MANIFEST).write_text('{"version": 99, "live": {}}')
    assert read_manifest(tmp_path) is None


# --- the reported line -------------------------------------------------------


def _note(live: Counts, live_total: int, replay: Counts, replay_total: int) -> str | None:
    return divergence_note(
        replay_total=replay_total,
        replay_counts=replay,
        manifest=LiveManifest(counts=live, requests_counted=live_total),
    )


def test_the_note_names_the_difference_the_scan_actually_showed() -> None:
    note = _note(Counts(http=4, dns=2), 6, Counts(http=4), 4)
    assert note == (
        "4 request(s) replayed (6 live: 2 more DNS queries - "
        "the address pin a replay does not need)"
    )


def test_counts_that_agree_say_so_rather_than_going_quiet() -> None:
    note = _note(Counts(http=4, dns=2), 6, Counts(http=4, dns=2), 6)
    assert note == "6 request(s) replayed (6 live: the same count)"


def test_a_difference_the_breakdown_does_not_explain_is_said_to_be_unattributed() -> None:
    """testssl.sh charges a fixed connection budget, not a counted call, so a
    total can move without any protocol counter moving. Saying so is the point
    of this change; quietly attributing it to DNS would not be."""
    note = _note(Counts(http=1, dns=1), 12, Counts(http=1, dns=1), 2)
    assert note is not None
    assert "10 more not attributed to a counted protocol" in note


def test_several_protocols_differing_are_all_named() -> None:
    note = _note(Counts(http=4, dns=2, tls=3), 9, Counts(http=4), 4)
    assert note is not None
    assert "2 more DNS queries" in note
    assert "3 more TLS handshakes" in note


def test_a_replay_that_counted_more_than_the_live_run_is_reported_too() -> None:
    """Not expected, and precisely why it must not be silent."""
    note = _note(Counts(http=4), 4, Counts(http=5), 5)
    assert note is not None
    assert "1 fewer HTTP sends live" in note


def test_without_a_manifest_the_line_says_what_the_replay_did_and_claims_nothing_else() -> None:
    note = divergence_note(replay_total=4, replay_counts=Counts(http=4), manifest=None)
    assert note == "4 request(s) replayed (no live count recorded with these fixtures)"


# --- end to end: the case the ledger recorded --------------------------------


def test_a_recorded_lab_scan_replayed_reports_both_counts_and_names_the_difference(
    tmp_path, capsys
) -> None:
    """The ledgered observation itself: 4 requests on replay against 6 live.

    Recorded through the lab entry point, replayed through `scan run --replay`,
    against a loopback stand-in.
    """
    import http.server
    import threading

    from typer.testing import CliRunner

    from cli.main import app
    from corpus.lab import scan as lab

    class _Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            body = b"<html><body>lab</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args: object) -> None:
            return None

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    port = server.server_address[1]
    recording = tmp_path / "fixtures"
    try:
        code = lab.main(
            [
                "web",
                "--target",
                f"http://localhost:{port}/",
                "--target-type",
                "url",
                "--record",
                str(recording),
            ]
        )
    finally:
        server.shutdown()
        server.server_close()
    assert code == 0
    live_line = [ln for ln in capsys.readouterr().out.splitlines() if "request(s)" in ln]
    assert live_line[0].endswith("6 request(s)")

    manifest = read_manifest(recording)
    assert manifest is not None
    assert manifest.requests_counted == 6
    assert manifest.counts == Counts(http=4, dns=2, tls=0)

    result = CliRunner().invoke(
        app,
        [
            "run",
            "web",
            "--target",
            f"http://localhost:{port}/",
            "--target-type",
            "url",
            "--replay",
            str(recording),
        ],
    )
    assert result.exit_code == 0, result.output
    assert (
        "4 request(s) replayed (6 live: 2 more DNS queries - "
        "the address pin a replay does not need)"
    ) in result.output
