"""Independent review of D21 (2026-10-09): one blocker and eight should-fixes.

Written before the fixes; each test failed on the branch as first reviewed.
"""

from __future__ import annotations

import json
import sqlite3

import pytest

from core.models import Finding, HttpPairEvidence, ScanError
from core.redaction import redact_text
from tests.core.test_redaction import AWS, GHP, LINES, key_lines, leaked, pem
from tests.core.test_redaction_storage import NOW, _finding_kwargs, _pair


def _clean(dumped: str) -> bool:
    return AWS not in dumped and GHP not in dumped and leaked(dumped) == []


# --- BLOCKER: the one way in -----------------------------------------------


def test_assigning_a_secret_to_a_finding_field_redacts_it():
    finding = Finding.create(**_finding_kwargs())
    finding.description = f"now {GHP}"

    assert _clean(finding.model_dump_json())


def test_an_evidence_instance_mutated_after_construction_is_redacted_in_the_finding():
    evidence = _pair()
    evidence.test.response.headers["Server"] = f"x {AWS}"
    evidence.test.response.body = pem(LINES)

    finding = Finding.create(**_finding_kwargs(evidence=[evidence]))

    assert _clean(finding.model_dump_json())


def test_evidence_model_construct_is_blocked():
    with pytest.raises(TypeError):
        HttpPairEvidence.model_construct(**_pair().model_dump())


def test_the_deprecated_copy_redacts_too():
    finding = Finding.create(**_finding_kwargs())

    copied = finding.copy(update={"description": f"x {GHP}"})

    assert _clean(copied.model_dump_json())


def test_scan_error_construct_is_blocked_and_assignment_redacts():
    with pytest.raises(TypeError):
        ScanError.model_construct(stage="s", message=AWS)
    error = ScanError(stage="s", message="ok")
    error.message = f"got {AWS}"

    assert AWS not in error.message


# --- should-fix 1: heuristic cuts are not a verdict ----------------------------


@pytest.mark.parametrize(
    "body",
    [
        "<pre>" + "\n".join(key_lines(10, width=76)) + "</pre>",  # MIME-wrapped base64 blob
        "\n".join("a" * 40 + f"{i:024x}" for i in range(5)),  # hex digests on lines
        '<script>var b = "' + "\\n".join(key_lines(6)) + '";</script>',
    ],
    ids=["mime", "digests", "js-string"],
)
def test_a_heuristic_cut_is_not_reported_as_a_private_key(body):
    _, counts = redact_text(body)

    assert "private_key" not in counts
    assert counts.get("possible_key_material", 0) >= 1


def test_a_real_block_is_still_reported_as_a_private_key():
    assert redact_text(pem(LINES))[1] == {"private_key": 1}


# --- should-fix 3: hostile public BEGINs stay linear ----------------------------


def test_many_public_begins_with_a_base64_run_stay_linear():
    import time

    hostile = "-----BEGIN CERTIFICATE-----\n" * 20000 + "\n".join(LINES)
    started = time.perf_counter()
    redact_text(hostile)

    assert time.perf_counter() - started < 1.0


# --- should-fix 4: instance_key -------------------------------------------------


def test_a_secret_in_the_instance_key_is_redacted_and_the_id_follows_it():
    finding = Finding.create(**_finding_kwargs(instance_key=f"k-{AWS}"))

    assert AWS not in (finding.instance_key or "")
    assert finding.id == Finding.create(**_finding_kwargs(instance_key=finding.instance_key)).id


# --- should-fix 5: the store is cleaned at rest ------------------------------------


def _insert_legacy_row(path, secret_location: str) -> dict:
    """Write a row as a pre-ADR-028 store would have: raw location, its raw id."""
    from core.ids import finding_id
    from core.store import FindingStore

    raw = Finding.create(**_finding_kwargs()).model_dump(mode="json")
    raw["location"] = secret_location
    raw["id"] = finding_id(
        scanner=raw["scanner"],
        check_id=raw["check_id"],
        target_value=raw["target"]["value"],
        location=secret_location,
        instance_key=None,
    )
    with FindingStore(path):
        pass
    db = sqlite3.connect(path)
    try:
        db.execute(
            "INSERT INTO findings VALUES (?,?,?,?,?,?,?,?)",
            (
                raw["id"],
                raw["org_id"],
                raw["scanner"],
                raw["check_id"],
                "x.test",
                secret_location,
                "open",
                json.dumps(raw),
            ),
        )
        db.commit()
    finally:
        db.close()
    return raw


def test_a_legacy_row_with_a_secret_location_is_rewritten_at_rest(tmp_path):
    from core.store import FindingStore

    path = tmp_path / "s.db"
    raw = _insert_legacy_row(path, f"/hook/{GHP}")

    with FindingStore(path) as store:
        found = store.list_findings(raw["org_id"])
    on_disk = path.read_bytes().decode("latin-1")

    assert len(found) == 1 and GHP not in found[0].location
    assert GHP not in on_disk


@pytest.mark.parametrize("read", ["list", "get"])
def test_a_legacy_row_does_not_overwrite_the_newer_row_it_redacts_onto(tmp_path, read):
    """Re-review N1: the row already under the redacted id keeps its status and history."""
    from core.store import FindingStore

    path = tmp_path / "s.db"
    secret_location = f"/hook/{GHP}"
    fresh = Finding.create(**_finding_kwargs(location=secret_location))
    with FindingStore(path) as store:
        store.ingest([fresh])
        newer = store.transition(
            fresh.id, fresh.org_id, to="accepted_risk", at=NOW, by="operator:t", scan_id="s2"
        )
    raw = _insert_legacy_row(path, secret_location)
    assert raw["id"] != fresh.id

    with FindingStore(path) as store:
        if read == "list":
            found = store.list_findings(fresh.org_id)
        else:
            found = [store.get(raw["id"], fresh.org_id)]
        rows = store._conn.execute("SELECT id FROM findings").fetchall()

    assert [(f.id, f.status) for f in found] == [(fresh.id, "accepted_risk")]
    assert found[0].status_history == newer.status_history
    assert rows == [(fresh.id,)]
    assert GHP not in path.read_bytes().decode("latin-1")


def _mark_unswept(path) -> None:
    db = sqlite3.connect(path)
    try:
        db.execute("PRAGMA user_version = 0")
        db.commit()
    finally:
        db.close()


def test_opening_a_legacy_store_cleans_it_before_any_write(tmp_path):
    """Re-review follow-up: an ingest before any read must not leave the secret on disk,
    nor reopen the legacy finding's status."""
    from core.store import FindingStore

    path = tmp_path / "s.db"
    secret_location = f"/hook/{GHP}"
    raw = _insert_legacy_row(path, secret_location)
    db = sqlite3.connect(path)
    try:
        raw["status"] = "accepted_risk"
        db.execute(
            "UPDATE findings SET status = ?, data = ? WHERE id = ?",
            ("accepted_risk", json.dumps(raw), raw["id"]),
        )
        db.commit()
    finally:
        db.close()
    _mark_unswept(path)  # as a store written before ADR-028 would be

    with FindingStore(path) as store:
        store.ingest([Finding.create(**_finding_kwargs(location=secret_location))])
        on_disk = path.read_bytes().decode("latin-1")
        found = store.list_findings(raw["org_id"])

    assert GHP not in on_disk
    assert [f.status for f in found] == ["accepted_risk"]


def test_the_open_time_sweep_runs_once(tmp_path):
    from core.store import FindingStore

    path = tmp_path / "s.db"
    with FindingStore(path):
        pass
    raw = _insert_legacy_row(path, f"/hook/{GHP}")

    with FindingStore(path) as store:  # already marked swept: rows load lazily
        rows = store._conn.execute("SELECT id FROM findings").fetchall()

    assert rows == [(raw["id"],)]


# --- should-fix 6: the rest of what core stores ---------------------------------


def test_check_run_and_suppressed_locations_are_redacted():
    from core.models import CheckRun, Suppressed

    assert AWS not in CheckRun(check_id="c", location=f"/{AWS}", outcome="clear").location
    suppressed = Suppressed(check_id="c", location=f"/{AWS}", confidence=0.1, reason=f"r {AWS}")
    assert AWS not in suppressed.model_dump_json()


def test_a_finding_target_related_assets_and_taxonomy_are_redacted():
    finding = Finding.create(
        **_finding_kwargs(
            target={"type": "url", "value": f"https://x.test/?k={AWS}"},
            related_assets=[{"type": "url", "value": f"https://x.test/{GHP}", "relation": "r"}],
            taxonomy={"note": [AWS]},
        )
    )

    assert _clean(finding.model_dump_json())


def test_a_fixture_filename_carries_no_secret():
    from core.http import _fixture_name

    name = _fixture_name("GET", f"https://x.test/hooks/{GHP}/{AWS}")

    assert GHP.lower() not in name.lower() and AWS.lower() not in name.lower()


# --- should-fix 7 and 8: encodings and labels -------------------------------------

GAP_SEPARATORS = [
    "&#x0a;",
    "&#x0D;&#x0A;",
    "&#010;",
    "\\u000a",
    "%0A",
    "%0D%0A",
    "&NewLine;",
    "\\\\n",
]


@pytest.mark.parametrize("sep", GAP_SEPARATORS)
def test_an_orphan_end_in_any_encoding_takes_its_key_lines(sep):
    text = "<p>x</p>" + sep + sep.join(LINES) + sep + "-----END RSA PRIVATE KEY-----"

    assert leaked(redact_text(text)[0]) == []


@pytest.mark.parametrize("sep", [*GAP_SEPARATORS, " ", "\t"])
def test_a_bare_run_in_any_encoding_is_cut(sep):
    text = "intro" + sep + sep.join(LINES) + sep + "outro"

    assert leaked(redact_text(text)[0]) == []


@pytest.mark.parametrize("space", ["%20", "+"])
def test_a_url_encoded_block_is_cut(space):
    block = pem(LINES, sep="%0A").replace(" ", space)

    assert leaked(redact_text(block)[0]) == []


@pytest.mark.parametrize(
    "begin,end",
    [
        ("-----BEGIN rsa private key-----", "-----END rsa private key-----"),
        ("----- BEGIN RSA PRIVATE KEY -----", "----- END RSA PRIVATE KEY -----"),
        ("---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----", "---- END SSH2 ENCRYPTED PRIVATE KEY ----"),
        ("-----BEGIN RSA PRIVATE-KEY-----", "-----END RSA PRIVATE-KEY-----"),
    ],
)
def test_non_standard_private_labels_are_cut_even_without_heuristics(begin, end):
    block = begin + "\n" + "\n".join(LINES) + "\n" + end

    assert leaked(redact_text(block, heuristics=False)[0]) == []


def test_a_file_excerpt_with_a_bare_key_run_is_redacted():
    from core.models import Evidence

    raw = {
        "kind": "file_excerpt",
        "label": "l",
        "captured_at": "2026-10-09T00:00:00Z",
        "data": {"path": "/.env", "text": "\n".join(LINES)},
    }
    try:
        evidence = Evidence.model_validate(raw)
    except Exception:
        from core.redaction import redact_evidence

        assert leaked(json.dumps(redact_evidence(raw))) == []
        return
    assert leaked(evidence.model_dump_json()) == []


# --- nit: an unterminated public BEGIN does not shield later private runs ----------


def test_an_unterminated_public_begin_does_not_protect_a_later_key_run():
    text = "-----BEGIN PUBLIC KEY-----\nMIIBIj\n<p>prose</p>\n" + "\n".join(LINES)

    assert leaked(redact_text(text)[0]) == []
