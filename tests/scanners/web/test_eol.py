from datetime import date

from scanners.web import eol


def test_branch_matches_on_components():
    assert eol.branch_matches("7.4.33", "7.4")
    assert not eol.branch_matches("7.40.1", "7.4")
    assert eol.branch_matches("7", "7") and not eol.branch_matches("7", "7.4")


def test_php_74_matches_and_supported_does_not():
    entries = eol.load()
    assert eol.match(entries, "PHP", "7.4.33").branch == "7.4"
    assert eol.match(entries, "PHP", "8.4.1") is None
    assert eol.match(entries, "Unknown", "1.0") is None


def test_longest_branch_wins():
    d = date(2020, 1, 1)
    entries = (
        eol.EolEntry("X", "1", d, "https://a", d),
        eol.EolEntry("X", "1.2", d, "https://b", d),
    )
    assert eol.match(entries, "X", "1.2.3").branch == "1.2"
