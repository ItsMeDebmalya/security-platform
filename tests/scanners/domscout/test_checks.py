from scanners.domscout.checks import (
    CHECKS,
    ENUMERATION_CHECK_IDS,
    SERVICE_HOSTS,
    requires_authorisation,
)


def test_every_check_is_passive() -> None:
    for check in CHECKS.values():
        assert check.passive is True


def test_requires_authorisation_is_false_in_every_mode() -> None:
    assert requires_authorisation("light") is False
    assert requires_authorisation("standard") is False


def test_enumeration_check_ids_are_a_subset_of_the_catalogue() -> None:
    assert {c.check_id for c in CHECKS.values()} >= ENUMERATION_CHECK_IDS


def test_every_check_has_a_justification() -> None:
    for check in CHECKS.values():
        assert check.justification.strip() != ""


def test_service_hosts() -> None:
    assert frozenset({"crt.sh", "rdap.org"}) == SERVICE_HOSTS
