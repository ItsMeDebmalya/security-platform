"""ADR-037: the evidence-contract migration (host-agent design section 12, D75, D65).

Tests first. Additive only: every artefact valid before this migration stays valid, and the
three host-observation kinds each carry a receipt_ref tying them to the receipt line that
produced them.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError
from referencing import Registry, Resource

from core.cost import CostMeter
from core.models import Evidence, ScanResult, Telemetry
from tests.core.test_redaction import AWS

CONTRACTS = Path(__file__).resolve().parents[2] / "contracts"
_SCHEMAS = {p.name: json.loads(p.read_text()) for p in CONTRACTS.glob("*.schema.json")}
_REGISTRY = Registry()
for _s in _SCHEMAS.values():
    _REGISTRY = _REGISTRY.with_resource(_s["$id"], Resource.from_contents(_s))
EVIDENCE = Draft202012Validator(_SCHEMAS["evidence.schema.json"], registry=_REGISTRY)
SCANRESULT = Draft202012Validator(_SCHEMAS["scanresult.schema.json"], registry=_REGISTRY)

HOST_REF = "sha256:" + "ab12cd34ef56ab78"
WHEN = "2026-10-13T09:14:22Z"


def command_output() -> dict[str, Any]:
    return {
        "kind": "command_output",
        "label": "dpkg-query openssl",
        "captured_at": WHEN,
        "control_rationale": (
            "the allowlist entry declares exit 0 and one line per package; this is the test"
        ),
        "data": {
            "argv": ["/usr/bin/dpkg-query", "-W", "-f=${Package}\t${Version}\n"],
            "exit_status": 0,
            "output": "openssl\t3.0.2-0ubuntu1.10\n",
            "output_selection": {
                "method": "lines_matching",
                "detail": "package name == 'openssl'",
                "captured_bytes": 41233,
                "truncated": False,
            },
            "receipt_ref": {"reason_id": "packages.debian", "command_index": 3},
            "collected_at": WHEN,
            "host_ref": HOST_REF,
        },
    }


def file_excerpt() -> dict[str, Any]:
    return {
        "kind": "file_excerpt",
        "label": "sshd_config",
        "captured_at": WHEN,
        "control_rationale": "the allowlist entry names PermitRootLogin as the only key read",
        "data": {
            "path": "/etc/ssh/sshd_config",
            "keys": {"PermitRootLogin": "yes"},
            "excerpt": "PermitRootLogin yes",
            "line_numbers": [34],
            "stat": {"mode": "0644", "owner_uid": 0, "size_bytes": 3321},
            "receipt_ref": {"reason_id": "ssh.config", "file_index": 1},
            "collected_at": WHEN,
            "host_ref": HOST_REF,
        },
    }


def access_matrix() -> dict[str, Any]:
    return {
        "kind": "access_matrix",
        "label": "who can delete app.log",
        "captured_at": WHEN,
        "control_rationale": "rights derived from mode, group and the parent directory's write bit",
        "data": {
            "subject_kind": "file",
            "path": "/var/log/app.log",
            "stat": {"mode": "0644", "owner_uid": 0, "owner_group_gid": 4},
            "parent_stat": {"mode": "0775", "owner_uid": 0, "owner_group_gid": 4},
            "acl": None,
            "principals": [
                {
                    "principal": "group:adm",
                    "members_observed": 7,
                    "read": True,
                    "write": False,
                    "delete": True,
                    "basis": "parent_directory_write",
                }
            ],
            "derivation": "mode+group+acl",
            "receipt_ref": {"reason_id": "logs.perms", "file_index": 2},
            "collected_at": WHEN,
            "host_ref": HOST_REF,
        },
    }


NEW_KINDS = {
    "command_output": command_output,
    "file_excerpt": file_excerpt,
    "access_matrix": access_matrix,
}


def schema_errors(item: dict[str, Any]) -> list[str]:
    return [e.message for e in EVIDENCE.iter_errors(item)]


def model_ok(item: dict[str, Any]) -> bool:
    try:
        Evidence.model_validate(item)
    except ValidationError:
        return False
    return True


# --- one conformance case per new kind --------------------------------------------


@pytest.mark.parametrize("kind", sorted(NEW_KINDS))
def test_each_new_kind_conforms_to_schema_and_model(kind):
    item = NEW_KINDS[kind]()

    assert schema_errors(item) == []
    parsed = Evidence.model_validate(item)
    assert parsed.kind == kind
    emitted = json.loads(parsed.model_dump_json(exclude_none=False, by_alias=True))
    assert schema_errors(emitted) == []
    assert emitted["data"]["receipt_ref"] == item["data"]["receipt_ref"]
    assert emitted["data"]["host_ref"] == HOST_REF


@pytest.mark.parametrize("kind", sorted(NEW_KINDS))
def test_each_new_kind_carries_a_control(kind):
    assert Evidence.model_validate(NEW_KINDS[kind]()).has_control() is True


@pytest.mark.parametrize("kind", sorted(NEW_KINDS))
def test_each_new_kind_needs_its_control_rationale(kind):
    item = NEW_KINDS[kind]()
    del item["control_rationale"]

    assert schema_errors(item) != []
    assert not model_ok(item)


# --- every kind rejects evidence with no receipt_ref -------------------------------


@pytest.mark.parametrize("kind", sorted(NEW_KINDS))
def test_each_new_kind_rejects_evidence_with_no_receipt_ref(kind):
    item = NEW_KINDS[kind]()
    del item["data"]["receipt_ref"]

    assert schema_errors(item) != []
    assert not model_ok(item)


@pytest.mark.parametrize("kind", sorted(NEW_KINDS))
def test_each_new_kind_rejects_an_empty_receipt_ref(kind):
    item = NEW_KINDS[kind]()
    item["data"]["receipt_ref"] = {}

    assert schema_errors(item) != []
    assert not model_ok(item)


@pytest.mark.parametrize("kind", sorted(NEW_KINDS))
def test_each_new_kind_rejects_a_missing_or_malformed_host_ref(kind):
    missing = NEW_KINDS[kind]()
    del missing["data"]["host_ref"]
    short = NEW_KINDS[kind]()
    short["data"]["host_ref"] = "sha256:abc"
    hostname = NEW_KINDS[kind]()
    hostname["data"]["host_ref"] = "web-01.internal"

    for bad in (missing, short, hostname):
        assert schema_errors(bad) != []
        assert not model_ok(bad)


def test_a_host_shaped_file_excerpt_without_receipt_ref_is_not_the_legacy_shape():
    """Dropping receipt_ref must not demote an excerpt to the legacy, unreceipted shape."""
    item = file_excerpt()
    del item["data"]["receipt_ref"]
    del item["data"]["host_ref"]

    assert schema_errors(item) != []
    assert not model_ok(item)


# --- the specified shapes ---------------------------------------------------------


def test_command_output_keeps_a_non_zero_exit_status_as_evidence():
    item = command_output()
    item["data"]["exit_status"] = 2
    item["data"]["output"] = ""

    assert schema_errors(item) == []
    assert Evidence.model_validate(item).data.exit_status == 2


def test_command_output_argv_is_a_non_empty_list_of_strings_never_a_shell_string():
    for bad in ("dpkg-query -W", [], ["ok", 3]):
        item = command_output()
        item["data"]["argv"] = bad
        assert schema_errors(item) != []
        assert not model_ok(item)


def test_command_output_says_how_the_output_was_reduced():
    item = command_output()
    del item["data"]["output_selection"]
    assert schema_errors(item) != []
    assert not model_ok(item)

    item = command_output()
    item["data"]["output_selection"]["method"] = "grep"
    assert schema_errors(item) != []
    assert not model_ok(item)


def test_command_output_receipt_ref_names_a_command_index():
    item = command_output()
    item["data"]["receipt_ref"] = {"reason_id": "packages.debian"}
    assert schema_errors(item) != []
    assert not model_ok(item)


def test_command_output_output_is_redacted_at_the_value_level():
    item = command_output()
    item["data"]["output"] = f"token={AWS}\n"

    assert AWS not in Evidence.model_validate(item).model_dump_json()


def test_file_excerpt_text_is_redacted():
    item = file_excerpt()
    item["data"]["excerpt"] = f"AccessKey {AWS}"

    assert AWS not in Evidence.model_validate(item).model_dump_json()


def test_a_new_kind_refuses_fields_the_shape_does_not_name():
    for kind in NEW_KINDS:
        item = NEW_KINDS[kind]()
        item["data"]["whole_file"] = "everything"
        assert schema_errors(item) != []
        assert not model_ok(item)


def test_access_matrix_null_acl_means_not_observed_and_is_allowed():
    item = access_matrix()
    item["data"]["acl"] = None
    assert schema_errors(item) == []
    assert Evidence.model_validate(item).data.acl is None


def test_access_matrix_states_members_observed_not_members():
    item = access_matrix()
    item["data"]["principals"][0]["members"] = 7
    assert schema_errors(item) != []
    assert not model_ok(item)

    item = access_matrix()
    del item["data"]["principals"][0]["members_observed"]
    assert schema_errors(item) != []
    assert not model_ok(item)


def test_access_matrix_every_right_has_a_basis_and_the_matrix_a_derivation():
    item = access_matrix()
    del item["data"]["principals"][0]["basis"]
    assert schema_errors(item) != []
    assert not model_ok(item)

    item = access_matrix()
    del item["data"]["derivation"]
    assert schema_errors(item) != []
    assert not model_ok(item)


def test_access_matrix_subject_kind_is_file_or_directory():
    item = access_matrix()
    item["data"]["subject_kind"] = "socket"
    assert schema_errors(item) != []
    assert not model_ok(item)


# --- additive: nothing valid today became invalid ----------------------------------


LEGACY_FILE_EXCERPTS = [
    {  # core/correlation.py
        "kind": "file_excerpt",
        "label": "composition rule r1",
        "captured_at": WHEN,
        "control_rationale": "a correlation makes no new observation",
        "data": {"rule_id": "r1", "rule_why": "w", "premise_finding_ids": [], "premises": []},
    },
    {  # scanners/tls
        "kind": "file_excerpt",
        "label": "testssl.sh vulnerability probe",
        "captured_at": WHEN,
        "control_rationale": "the control is testssl.sh's own sibling verdicts",
        "data": {"addresses_tested": ["192.0.2.1"], "per_address": {"192.0.2.1": "HIGH"}},
    },
    {  # a bare reserved file_excerpt
        "kind": "file_excerpt",
        "label": "bare",
        "captured_at": WHEN,
        "control_rationale": "r",
        "data": {},
    },
]


@pytest.mark.parametrize("item", LEGACY_FILE_EXCERPTS)
def test_the_file_excerpts_shipped_scanners_emit_today_stay_valid(item):
    assert schema_errors(item) == []
    parsed = Evidence.model_validate(item)
    assert parsed.has_control() is False
    assert json.loads(parsed.model_dump_json())["data"] == item["data"]


def test_screenshot_stays_reserved():
    item = {
        "kind": "screenshot",
        "label": "s",
        "captured_at": WHEN,
        "control_rationale": "r",
        "data": {"anything": 1},
    }
    assert schema_errors(item) == []
    assert Evidence.model_validate(item).has_control() is False


def test_the_kind_enum_only_grew():
    kinds = _SCHEMAS["evidence.schema.json"]["properties"]["kind"]["enum"]

    assert {
        "http_pair",
        "oob_callback",
        "timing",
        "dns_answer",
        "tls_handshake",
        "screenshot",
        "file_excerpt",
    } <= set(kinds)
    assert {"command_output", "access_matrix"} <= set(kinds)


def test_every_existing_schema_example_is_still_valid():
    for name in ("evidence.schema.json", "finding.schema.json", "scanresult.schema.json"):
        validator = Draft202012Validator(_SCHEMAS[name], registry=_REGISTRY)
        for example in _SCHEMAS[name]["examples"]:
            validator.validate(copy.deepcopy(example))


# --- D65: Telemetry.counts beside an unchanged requests ----------------------------


def _result(telemetry: dict[str, Any]) -> dict[str, Any]:
    return {
        "scanner": "example",
        "scanner_version": "1.0.0",
        "target": {"type": "domain", "value": "example.com"},
        "mode": "light",
        "findings": [],
        "errors": [],
        "telemetry": telemetry,
        "outcome": "succeeded",
    }


COUNTS = {"http_sends": 3, "dns_queries": 2, "tls_handshakes": 1, "testssl_budget": 0, "other": 0}


def test_requests_equals_what_it_equalled_before():
    old = _result({"checks_run": [], "requests": 4, "wall_ms": 10, "ai_tokens": 0})

    assert list(SCANRESULT.iter_errors(old)) == []
    result = ScanResult.model_validate(old)
    assert result.telemetry.requests == 4
    assert result.telemetry.counts is None
    assert Telemetry().requests == 0


def test_the_cost_meter_still_reports_its_running_total_as_requests():
    meter = CostMeter()
    meter.record_request(3)
    meter.record_request()

    assert meter.snapshot().requests == 4


def test_counts_sit_beside_requests_without_changing_it():
    telemetry = {"checks_run": [], "requests": 6, "counts": COUNTS}
    new = _result(telemetry)

    assert list(SCANRESULT.iter_errors(new)) == []
    result = ScanResult.model_validate(new)
    assert result.telemetry.requests == 6
    assert result.telemetry.counts is not None
    assert result.telemetry.counts.dns_queries == 2
    emitted = json.loads(result.model_dump_json(by_alias=True))
    assert list(SCANRESULT.iter_errors(emitted)) == []
    assert emitted["telemetry"]["requests"] == 6
    assert emitted["telemetry"]["counts"] == COUNTS


def test_counts_name_exactly_the_five_d65_fields_and_none_is_negative():
    missing = dict(COUNTS)
    del missing["other"]
    extra = {**COUNTS, "requests": 1}
    negative = {**COUNTS, "other": -1}

    for bad in (missing, extra, negative):
        assert list(SCANRESULT.iter_errors(_result({"checks_run": [], "counts": bad}))) != []
        with pytest.raises(ValidationError):
            Telemetry.model_validate({"counts": bad})


def test_requests_must_equal_the_sum_of_counts_when_counts_is_set():
    with pytest.raises(ValidationError):
        Telemetry.model_validate({"requests": 7, "counts": COUNTS})
    assert Telemetry.model_validate({"requests": 6, "counts": COUNTS}).counts is not None
