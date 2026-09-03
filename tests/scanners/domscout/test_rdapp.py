from datetime import date

from scanners.domscout.rdapp import RegistrationInfo, expiry_verdict, parse_rdap

RDAP = (
    '{"events":[{"eventAction":"expiration","eventDate":"2026-10-01T00:00:00Z"},'
    '{"eventAction":"registration","eventDate":"2010-01-01T00:00:00Z"}],'
    '"status":["client transfer prohibited"],'
    '"entities":[{"roles":["registrar"],"vcardArray":["vcard",'
    '[["fn",{},"text","Acme Registrar"]]]}]}'
)


def test_parse_rdap_extracts_expiry_registrar_status() -> None:
    info = parse_rdap(RDAP)
    assert info.expiry == date(2026, 10, 1)
    assert info.registrar == "Acme Registrar"
    assert info.statuses == ["client transfer prohibited"]
    assert info.created == date(2010, 1, 1)


def test_expiry_verdict_thresholds() -> None:
    info = RegistrationInfo(expiry=date(2026, 9, 20), registrar=None, statuses=[], created=None)
    assert expiry_verdict(info, date(2026, 9, 3)) == "expiring"  # 17 days
    assert expiry_verdict(info, date(2026, 10, 1)) == "expired"
    future = RegistrationInfo(date(2027, 1, 1), None, [], None)
    assert expiry_verdict(future, date(2026, 9, 3)) == "ok"
    assert expiry_verdict(RegistrationInfo(None, None, [], None), date(2026, 9, 3)) == "unknown"


def test_sparse_rdap_does_not_raise() -> None:
    assert parse_rdap("{}") == RegistrationInfo(None, None, [], None)
