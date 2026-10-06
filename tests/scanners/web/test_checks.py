from scanners.web.checks import (
    AUTOINDEX,
    CHECKS,
    ERROR_PAGE,
    HTML_DOCUMENT,
    HTTP_HEADER,
    VERSION_STRING,
    requires_authorisation,
)

EXPECTED = {
    "web-https-redirect-missing",
    "web-hsts-missing",
    "web-hsts-weak",
    "web-csp-missing",
    "web-csp-weak",
    "web-clickjacking-unprotected",
    "web-xcto-missing",
    "web-referrer-policy-unsafe",
    "web-referrer-policy-missing",
    "web-cors-wildcard",
    "web-mixed-content",
    "web-sri-missing",
    "web-version-disclosure",
    "web-error-disclosure",
    "web-debug-mode",
    "web-secret-in-response",
    "web-directory-listing",
    "web-technology",
    "web-robots-paths",
    "web-security-txt-missing",
    "web-component-eol",
}
CLASSES = {HTTP_HEADER, HTML_DOCUMENT, ERROR_PAGE, AUTOINDEX, VERSION_STRING}


def test_catalogue_is_exactly_the_spec():
    assert set(CHECKS) == EXPECTED


def test_every_check_is_declared_passive_and_justified():
    for check in CHECKS.values():
        assert check.passive is True
        assert check.justification and check.impact and check.remediation
        assert check.severity in {"critical", "high", "medium", "low", "info"}
        assert check.independence_class in CLASSES
        assert check.likelihood_ratio > 1


def test_severities_match_the_spec():
    sev = {c: CHECKS[c].severity for c in CHECKS}
    assert sev["web-debug-mode"] == "high" and sev["web-secret-in-response"] == "high"
    assert sev["web-mixed-content"] == "low"
    for info in (
        "web-technology",
        "web-robots-paths",
        "web-security-txt-missing",
        "web-referrer-policy-missing",
    ):
        assert sev[info] == "info"


def test_no_authorisation_needed_in_any_mode():
    for mode in ("light", "standard", "deep"):
        assert requires_authorisation(mode) is False
