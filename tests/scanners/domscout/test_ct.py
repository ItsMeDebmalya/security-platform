from scanners.domscout.ct import is_within_apex, normalize_name, parse_crtsh


def test_normalize_lowercases_strips_dot_and_wildcard():
    assert normalize_name("API.Example.COM.", "example.com") == "api.example.com"
    assert normalize_name("*.api.example.com", "example.com") == "api.example.com"


def test_rejects_names_not_within_apex():
    assert normalize_name("example.com.evil.com", "example.com") is None
    assert normalize_name("notexample.com", "example.com") is None
    assert is_within_apex("a.b.example.com", "example.com") is True
    assert is_within_apex("example.com.evil.com", "example.com") is False


def test_idna_punycode():
    assert normalize_name("xn--e1afmkfd.example.com", "example.com") == "xn--e1afmkfd.example.com"
    assert normalize_name("пример.example.com", "example.com") == "xn--e1afmkfd.example.com"


def test_parse_crtsh_dedupes_splits_and_drops_apex():
    payload = (
        '[{"name_value": "a.example.com\\n*.a.example.com"}, '
        '{"name_value": "example.com"}, {"name_value": "b.example.com"}]'
    )
    assert parse_crtsh(payload, "example.com") == ["a.example.com", "b.example.com"]
