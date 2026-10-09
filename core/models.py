"""Typed objects for the Scanner Contract.

The JSON Schemas in `contracts/` are authoritative; these pydantic models
mirror them and `tests/contract/test_schema_model_drift.py` fails if the two
diverge. Codegen is deliberately not used - it obscures where the truth lives.

Two invariants are enforced here rather than left to scanner authors:

- `state` is derived by `core.state`. A `Finding` whose stored state does not
  match what the derivation produces is rejected, so a hand-set state is a
  loud failure rather than a quiet one.
- A check that ran must account for itself. `ScanResult` rejects a
  `checks_run` entry with neither a finding nor a suppression record, which is
  the contract-level half of "never silently drop a check".
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import date, datetime
from typing import Annotated, Any, ClassVar, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, field_validator, model_validator

from core.ids import TARGET_LEVEL, finding_id
from core.redaction import redact_data, redact_evidence, redact_text
from core.state import State, derive_state

Mode = Literal["light", "standard", "deep"]
Severity = Literal["critical", "high", "medium", "low", "info"]
Status = Literal["open", "closed", "accepted_risk", "false_positive"]
Outcome = Literal["succeeded", "partial", "errored", "killed"]
Derivation = Literal["detected", "derived"]
ValidationOutcome = Literal["passed", "failed", "unavailable", "not_applicable"]
NoVerdictReason = Literal[
    "timeout",
    "servfail",
    "waf_block",
    "blocked_prerequisite",
    "oob_unavailable",
    "ambiguous_response",
    "rate_limited",
]
SEMVER = r"^\d+\.\d+\.\d+$"


class Strict(BaseModel):
    # validate_assignment: an assignment after construction is validated, and so
    # redacted, like construction itself (ADR-028 clause 6; review of D21).
    model_config = ConfigDict(extra="forbid", populate_by_name=True, validate_assignment=True)

    @classmethod
    def model_construct(cls, *args: Any, **kwargs: Any) -> Self:
        raise TypeError(
            f"{cls.__name__}.model_construct skips validation, and so redaction (ADR-028)"
        )

    def model_copy(self, *, update: Mapping[str, Any] | None = None, deep: bool = False) -> Self:
        """A copy is a new object: validated, and so redacted, like any other."""
        data = self.model_dump()
        data.update(update or {})
        return type(self).model_validate(data)

    def copy(
        self, *, update: Mapping[str, Any] | None = None, deep: bool = False, **_: Any
    ) -> Self:
        """pydantic's deprecated v1 `copy`, routed through `model_copy`."""
        return self.model_copy(update=update, deep=deep)


# --- assets and cost --------------------------------------------------------


AssetType = Literal["domain", "url", "ip", "cidr", "repo", "cloud_account", "image", "email"]


class Asset(Strict):
    type: AssetType
    value: str = Field(min_length=1)


class RelatedAsset(Strict):
    type: str
    value: str
    relation: str


class Cost(Strict):
    requests: int = 0
    wall_ms: int = 0
    ai_tokens: int = 0


# --- evidence ---------------------------------------------------------------


class EvidenceBase(Strict):
    label: str = Field(min_length=1)
    captured_at: datetime
    redactions: list[str] = Field(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def _redact_before_storage(cls, data: Any) -> Any:
        """ADR-028: evidence is redacted however it is built, not only by the capture
        helpers. Public key material in DNS and TLS evidence is kept (clause 2)."""
        return redact_evidence(data) if isinstance(data, dict) else data

    def has_control(self) -> bool:
        """Whether this evidence carries a control alongside its test.

        'The server returned an error' is not evidence. Every kind answers
        this question in whatever form the kind allows.
        """
        raise NotImplementedError

    def payload_id_or_none(self) -> str | None:
        return None


class HttpRequest(Strict):
    method: str
    url: str
    headers: dict[str, str] = Field(default_factory=dict)
    body: str | None = None
    body_truncated: bool = False


class HttpResponse(Strict):
    status: int
    headers: dict[str, str] = Field(default_factory=dict)
    body: str | None = None
    body_truncated: bool = False
    elapsed_ms: int | None = None


class HttpExchange(Strict):
    request: HttpRequest
    response: HttpResponse


class HttpPairEvidence(EvidenceBase):
    kind: Literal["http_pair"]
    control: HttpExchange
    test: HttpExchange
    delta: dict[str, str] = Field(default_factory=dict)
    payload_id: str | None = None

    def has_control(self) -> bool:
        return True

    def payload_id_or_none(self) -> str | None:
        return self.payload_id


class OobHit(Strict):
    received_at: datetime
    protocol: Literal["dns", "http", "https", "smtp"]
    raw_request: str
    source_ip: str | None = None


class OobCallbackEvidence(EvidenceBase):
    """The control is the absence of a callback, observed elsewhere and later."""

    kind: Literal["oob_callback"]
    token: str
    emitted_in: str
    emitted_at: datetime
    window_s: int = Field(ge=1)
    hit: OobHit | None = None
    control_tokens_unhit: list[str] = Field(min_length=1)

    def has_control(self) -> bool:
        return bool(self.control_tokens_unhit)


class TimingEvidence(EvidenceBase):
    """A single before/after pair is not how timing is validated."""

    kind: Literal["timing"]
    baseline_samples_ms: list[float] = Field(min_length=5)
    test_samples_ms: list[float] = Field(min_length=5)
    n: int = Field(ge=10)
    delta_ms: float
    method: Literal["welch_t", "mann_whitney"]
    p_value: float = Field(ge=0, le=1)
    payload_id: str | None = None

    def has_control(self) -> bool:
        return len(self.baseline_samples_ms) >= 5

    def payload_id_or_none(self) -> str | None:
        return self.payload_id


class DnsQuery(Strict):
    name: str
    rrtype: str
    resolver: str | None = None


class DnsAnswerRecords(Strict):
    rcode: str
    records: list[str]
    ttl: int | None = None
    flags: list[str] = Field(default_factory=list)


class DnsExchange(Strict):
    query: DnsQuery
    answer: DnsAnswerRecords


class DnsAnswerEvidence(EvidenceBase):
    kind: Literal["dns_answer"]
    test: DnsExchange
    control: DnsExchange | None = None
    control_rationale: str = Field(min_length=1)
    analysis: dict[str, Any] | None = None
    """Our reading of the answer - a parse tree, a resolved include chain and
    its lookup count. Kept separate from the raw answer so a user can check
    our working rather than take the conclusion on trust."""

    def has_control(self) -> bool:
        return self.control is not None


class TlsHandshakeEvidence(EvidenceBase):
    """What a server presented, beside what a strict client made of it.

    `test` is the observation, taken with a deliberately permissive client so
    that an obsolete server can be observed at all. `control` is normally the
    verifying client's verdict; for protocol enumeration it is a second
    observation of the same server negotiating a current protocol.
    """

    kind: Literal["tls_handshake"]
    test: dict[str, Any]
    control: dict[str, Any] | None = None
    control_rationale: str = Field(min_length=1)
    observed_at: datetime

    def has_control(self) -> bool:
        return self.control is not None


class ReservedEvidence(EvidenceBase):
    """screenshot and file_excerpt.

    Their shapes are specified when the first scanner needs them. Until then
    they carry the base fields and a stated rationale for their control, so
    nobody ships one without answering the control question.
    """

    kind: Literal["screenshot", "file_excerpt"]
    control_rationale: str = Field(min_length=1)
    data: dict[str, Any] = Field(default_factory=dict)

    def has_control(self) -> bool:
        return False


EvidenceItem = Annotated[
    HttpPairEvidence
    | OobCallbackEvidence
    | TimingEvidence
    | DnsAnswerEvidence
    | TlsHandshakeEvidence
    | ReservedEvidence,
    Field(discriminator="kind"),
]


class Evidence:
    """Validator for the evidence union.

    Not a model itself - evidence is a discriminated union, and pydantic
    expresses that as an annotated type rather than a base class. This gives
    the union a single obvious entry point: `Evidence.model_validate(...)`.
    """

    adapter: ClassVar[TypeAdapter[EvidenceItem]] = TypeAdapter(EvidenceItem)

    def __init__(self) -> None:  # pragma: no cover
        raise TypeError("Evidence is a validator namespace; use Evidence.model_validate")

    @classmethod
    def model_validate(cls, value: object) -> EvidenceItem:
        return cls.adapter.validate_python(value)


# --- detection and validation ----------------------------------------------


class DetectionMethod(Strict):
    """One contributing signal, with everything the confidence engine needs.

    `independence_class` is what stops three variants of one technique
    masquerading as corroboration. `prior_justification` is required because
    docs/10-measurement.md makes a justified prior a shipping condition.
    """

    method: str = Field(min_length=1)
    likelihood_ratio: float = Field(gt=0)
    independence_class: str = Field(min_length=1)
    prior: float = Field(gt=0, lt=1)
    prior_justification: str = Field(min_length=1)


class Validation(Strict):
    attempted: bool
    outcome: ValidationOutcome
    method: str | None = None

    @model_validator(mode="after")
    def _passed_requires_an_attempt(self) -> Self:
        if self.outcome in {"passed", "failed"} and not self.attempted:
            raise ValueError("validation outcome 'passed'/'failed' requires attempted=True")
        return self


class StatusChange(Strict):
    to: Status
    at: datetime
    by: str
    from_: Status | None = Field(default=None, alias="from")
    scan_id: str | None = None


# --- the finding ------------------------------------------------------------


def _redacted_value(value: Any) -> Any:
    """`value` with secrets removed, keeping model instances as instances.

    Unchanged values are returned as they are. On assignment, pydantic does not
    re-validate the other fields, so anything handed back must already be the
    right type."""
    if isinstance(value, list):
        return [_redacted_value(v) for v in value]
    if isinstance(value, BaseModel):
        dumped = value.model_dump()
        clean = redact_data(dumped, heuristics=True)
        return value if clean == dumped else type(value).model_validate(clean)
    clean = redact_data(value, heuristics=True)
    return value if clean == value else clean


_FREE_TEXT_FIELDS = (
    "title",
    "description",
    "impact",
    "remediation",
    "materialises_reason",
    "location",
    "instance_key",
)


class Finding(Strict):
    id: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    org_id: str = Field(min_length=1)
    scanner: str = Field(min_length=1)
    scanner_version: str = Field(pattern=SEMVER)
    check_id: str = Field(min_length=1)
    renamed_from: list[str] = Field(default_factory=list)
    title: str = Field(min_length=1)

    target: Asset
    location: str = Field(min_length=1)
    instance_key: str | None = None

    severity: Severity
    confidence: float = Field(ge=0, le=1)
    confidence_provisional: bool = True
    state: State
    no_verdict_reason: NoVerdictReason | None = None

    detection_methods: list[DetectionMethod] = Field(min_length=1)
    validation: Validation
    evidence: list[EvidenceItem] = Field(min_length=1)
    related_assets: list[RelatedAsset] = Field(default_factory=list)

    status: Status = "open"
    status_history: list[StatusChange] = Field(default_factory=list)

    description: str = Field(min_length=1)
    impact: str = Field(min_length=1)
    remediation: str = Field(min_length=1)
    references: list[str] = Field(default_factory=list)
    taxonomy: dict[str, list[str]] = Field(default_factory=dict)

    first_seen: datetime
    first_seen_scan_id: str = Field(min_length=1)
    last_seen: datetime
    last_seen_scan_id: str = Field(min_length=1)
    cost: Cost = Field(default_factory=Cost)

    # --- v3.4 / ADR-018: a finding carries a date, and says where it came from
    materialises_at: date | None = None
    materialises_reason: str | None = Field(default=None, min_length=1)
    derivation: Derivation = "detected"
    derived_from: str | None = None

    @model_validator(mode="before")
    @classmethod
    def _redact_before_storage(cls, data: Any) -> Any:
        """ADR-028 clause 6: the one way into a Finding redacts its text.

        `_redact_text_field` below does the same for each field on assignment,
        where pydantic validates only the field assigned.

        This runs for `Finding.create`, direct construction, `model_validate`,
        `model_validate_json` and so for every finding loaded from the store, so
        stores written before ADR-028 are redacted on load. A location that held
        a secret is redacted, and the id, which hashes the location, follows it.
        """
        if not isinstance(data, dict):
            return data
        out = dict(data)
        for key in _FREE_TEXT_FIELDS:
            if isinstance(out.get(key), str):
                out[key] = redact_text(out[key])[0] or out[key]
        if isinstance(out.get("references"), list):
            out["references"] = [
                redact_text(r)[0] or r if isinstance(r, str) else r for r in out["references"]
            ]
        # Evidence objects are re-validated, so one mutated after it was built is
        # redacted here too (pydantic does not revalidate instances by default).
        if isinstance(out.get("evidence"), list):
            out["evidence"] = [
                type(e).model_validate(e.model_dump()) if isinstance(e, BaseModel) else e
                for e in out["evidence"]
            ]
        target = out.get("target")
        if isinstance(target, BaseModel):
            value = getattr(target, "value", None)
            if isinstance(value, str) and (clean := redact_text(value)[0] or value) != value:
                out["target"] = type(target).model_validate({**target.model_dump(), "value": clean})
        elif isinstance(target, dict) and isinstance(target.get("value"), str):
            out["target"] = {**target, "value": redact_text(target["value"])[0] or target["value"]}
        for key in ("related_assets", "taxonomy", "detection_methods"):
            if key in out:
                out[key] = _redacted_value(out[key])
        identity = ("location", "instance_key", "target")
        if any(out.get(k) is not data.get(k) for k in identity) and "id" in out:
            target = out["target"]
            out["id"] = finding_id(
                scanner=out["scanner"],
                check_id=out["check_id"],
                target_value=target["value"] if isinstance(target, dict) else target.value,
                location=out["location"],
                instance_key=out.get("instance_key"),
            )
        return out

    @field_validator(*_FREE_TEXT_FIELDS)
    @classmethod
    def _redact_text_field(cls, value: str | None) -> str | None:
        return redact_text(value)[0] if value else value

    @model_validator(mode="after")
    def _materialisation_reason_needs_a_date(self) -> Self:
        if self.materialises_at is not None and not self.materialises_reason:
            raise ValueError(
                "materialises_reason is required when materialises_at is set: "
                "a future date with no stated reason is not a claim we can stand behind"
            )
        if self.materialises_at is None and self.materialises_reason is not None:
            raise ValueError(
                "materialises_reason is meaningless without materialises_at: "
                "either set both or neither"
            )
        return self

    @model_validator(mode="after")
    def _derivation_and_premise_agree(self) -> Self:
        if self.derivation == "derived" and not self.derived_from:
            raise ValueError(
                "derived_from is required when derivation is 'derived': a derived finding "
                "must name the premise it was computed from, per ADR-018"
            )
        if self.derivation == "detected" and self.derived_from is not None:
            raise ValueError(
                "derived_from is forbidden when derivation is 'detected': it names the "
                "premise a derived finding was computed from, and a detected finding has none"
            )
        return self

    @model_validator(mode="after")
    def _state_and_id_are_derived_not_chosen(self) -> Self:
        decision = derive_state(
            severity=self.severity,
            confidence=self.confidence,
            validation=self.validation,
            detection_methods=self.detection_methods,
            no_verdict_reason=self.no_verdict_reason,
        )
        if decision.state is None:
            raise ValueError(
                "confidence below the reporting threshold: record this in "
                "telemetry.suppressed rather than as a finding"
            )
        if decision.state != self.state:
            raise ValueError(
                f"state is derived, not hand-set: expected {decision.state!r} "
                f"from core.state, got {self.state!r}"
            )
        if abs(decision.confidence - self.confidence) > 1e-9:
            raise ValueError(
                f"confidence must carry the cap core.state applies: expected "
                f"{decision.confidence}, got {self.confidence}"
            )

        expected_id = finding_id(
            scanner=self.scanner,
            check_id=self.check_id,
            target_value=self.target.value,
            location=self.location,
            instance_key=self.instance_key,
        )
        if self.id != expected_id:
            raise ValueError("id must be the deterministic id for this finding")
        return self

    @classmethod
    def create(cls, **kwargs: Any) -> Finding:
        """Build a finding the way a scanner does: state and id derived, not passed."""
        if "state" in kwargs or "id" in kwargs:
            raise TypeError("state and id are derived; do not pass them to Finding.create")

        validation = kwargs.get("validation") or {"attempted": False, "outcome": "not_applicable"}
        detection_methods = kwargs.get("detection_methods", [])
        decision = derive_state(
            severity=kwargs["severity"],
            confidence=kwargs["confidence"],
            validation=validation,
            detection_methods=detection_methods,
            no_verdict_reason=kwargs.get("no_verdict_reason"),
        )
        if decision.state is None:
            raise ValueError(
                "confidence below the reporting threshold: record this in "
                "telemetry.suppressed rather than as a finding"
            )

        target = kwargs["target"]
        target_value = target["value"] if isinstance(target, dict) else target.value
        kwargs["state"] = decision.state
        kwargs["confidence"] = decision.confidence
        kwargs["id"] = finding_id(
            scanner=kwargs["scanner"],
            check_id=kwargs["check_id"],
            target_value=target_value,
            location=kwargs.get("location", TARGET_LEVEL),
            instance_key=kwargs.get("instance_key"),
        )
        return cls.model_validate(kwargs)

    def matches_stored_check_id(self, stored: str) -> bool:
        """Whether a finding stored under `stored` is this same finding.

        Renames are a migration, not an edit: `renamed_from` is what keeps a
        finding's history across a `check_id` change.
        """
        return stored == self.check_id or stored in self.renamed_from

    def payload_ids(self) -> list[str]:
        seen: list[str] = []
        for item in self.evidence:
            payload_id = item.payload_id_or_none()
            if payload_id and payload_id not in seen:
                seen.append(payload_id)
        return seen


# --- results and runs -------------------------------------------------------


class ScanError(Strict):
    stage: str = Field(min_length=1)
    message: str = Field(min_length=1)
    fatal: bool = False
    check_id: str | None = None

    @field_validator("message")
    @classmethod
    def _redact_message(cls, value: str) -> str:
        """An error can carry a response snippet; it is stored and printed (ADR-028)."""
        return redact_text(value)[0] or value


class Suppressed(Strict):
    check_id: str
    location: str
    confidence: float = Field(ge=0, le=1)
    reason: str

    @field_validator("location", "reason")
    @classmethod
    def _redact(cls, value: str) -> str:
        return redact_text(value)[0] or value


CheckOutcome = Literal["reported", "clear", "inconclusive", "suppressed", "error"]


class CheckRun(Strict):
    """One check's execution and what it concluded.

    A check that ran and found nothing wrong is `clear` - reporting nothing is
    the correct outcome, and it is still accounted for here. That accounting is
    what makes a silently dropped check detectable, and it is the denominator
    of inconclusive_rate (docs/10-measurement.md).
    """

    check_id: str = Field(min_length=1)
    outcome: CheckOutcome
    location: str = TARGET_LEVEL

    @field_validator("location")
    @classmethod
    def _redact_location(cls, value: str) -> str:
        return redact_text(value)[0] or value


class Telemetry(Strict):
    checks_run: list[CheckRun] = Field(default_factory=list)
    suppressed: list[Suppressed] = Field(default_factory=list)
    requests: int = 0
    wall_ms: int = 0
    ai_tokens: int = 0


class ScanResult(Strict):
    scanner: str = Field(min_length=1)
    scanner_version: str = Field(pattern=SEMVER)
    target: Asset
    mode: Mode
    findings: list[Finding] = Field(default_factory=list)
    errors: list[ScanError] = Field(default_factory=list)
    telemetry: Telemetry = Field(default_factory=Telemetry)
    started_at: datetime | None = None
    finished_at: datetime | None = None
    killed: bool = False
    outcome: Outcome = "succeeded"

    @model_validator(mode="after")
    def _enforce_the_error_boundary(self) -> Self:
        fatal = any(e.fatal for e in self.errors)
        if fatal and self.findings:
            raise ValueError(
                "a scanner that could not execute produces zero findings; "
                "a check that ran without a verdict emits an inconclusive finding instead"
            )

        derived: Outcome
        if self.killed:
            derived = "killed"
        elif fatal:
            derived = "errored"
        elif self.errors:
            derived = "partial"
        else:
            derived = "succeeded"
        object.__setattr__(self, "outcome", derived)

        ran = {c.check_id for c in self.telemetry.checks_run}
        unknown = [f.check_id for f in self.findings if f.check_id not in ran]
        if unknown:
            raise ValueError(
                f"findings from checks absent from telemetry.checks_run: {unknown}. "
                "Every check that produced a finding must account for having run."
            )

        reported = {f.check_id for f in self.findings}
        promised = {
            c.check_id
            for c in self.telemetry.checks_run
            if c.outcome in {"reported", "inconclusive"}
        }
        missing = sorted(promised - reported)
        if missing:
            raise ValueError(
                f"checks claim an outcome they never delivered: {missing}. A check that "
                "reached no verdict emits an inconclusive finding rather than vanishing."
            )

        suppressed = {s.check_id for s in self.telemetry.suppressed}
        undocumented = sorted(
            {c.check_id for c in self.telemetry.checks_run if c.outcome == "suppressed"}
            - suppressed
        )
        if undocumented:
            raise ValueError(
                f"checks marked suppressed with no telemetry.suppressed entry: {undocumented}"
            )
        return self

    def inconclusive_rate(self) -> float:
        """inconclusive / (all checks that ran), per docs/10-measurement.md."""
        if not self.telemetry.checks_run:
            return 0.0
        inconclusive = sum(1 for c in self.telemetry.checks_run if c.outcome == "inconclusive")
        return inconclusive / len(self.telemetry.checks_run)


class ScannerRef(Strict):
    name: str
    version: str = Field(pattern=SEMVER)


class ScanRun(Strict):
    scan_id: str = Field(min_length=26)
    org_id: str = Field(min_length=1)
    target: Asset
    mode: Mode
    scanners: list[ScannerRef] = Field(min_length=1)
    started_at: datetime
    finished_at: datetime | None = None
    outcome: Outcome = "succeeded"
    authz_ref: str | None = None
    cost: Cost = Field(default_factory=Cost)

    @model_validator(mode="after")
    def _active_modes_need_authorisation(self) -> Self:
        if self.mode in {"standard", "deep"} and not self.authz_ref:
            raise ValueError(
                "standard and deep mode require an authz_ref "
                "(docs/09-ownership-verification.md); deny by default"
            )
        return self
