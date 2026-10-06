from scanners.web import disclosure as d

DJANGO = (
    "<p>You're seeing this error because you have <code>DEBUG = True</code> in your "
    "Django settings file.</p>"
)
TRACE = '<pre>Traceback (most recent call last):\n  File "/app/server.py", line 9</pre>'


def test_version_in_header():
    assert d.version_disclosures({"Server": "nginx/1.27.3"}, None) == [("server", "nginx/1.27.3")]


def test_product_without_version_is_not_disclosure():
    assert d.version_disclosures({"server": "nginx", "x-powered-by": "Express"}, None) == []


def test_generator_version():
    assert d.version_disclosures({}, "WordPress 6.4.2") == [("meta generator", "WordPress 6.4.2")]


def test_signatures():
    assert d.error_signature(DJANGO).kind == "debug"
    assert d.error_signature(TRACE).kind == "error"
    assert (
        d.error_signature(
            "at org.springframework.web.servlet.DispatcherServlet.doDispatch"
            "(DispatcherServlet.java:1089)"
        ).kind
        == "error"
    )
    assert (
        d.error_signature(
            "<b>Warning</b>:  Undefined variable $x in <b>/var/www/html/a.php</b> on line <b>2</b>"
        ).kind
        == "error"
    )
    assert d.error_signature("Server Error in '/' Application.").kind == "error"


def test_plain_404_has_no_signature():
    assert d.error_signature("<h1>404 Not Found</h1><hr><center>nginx</center>") is None
    assert d.error_signature("") is None


def test_debug_wins_over_error():
    assert d.error_signature(TRACE + DJANGO).kind == "debug"


def test_excerpt_is_bounded_and_contains_the_match():
    sig = d.error_signature("x" * 500 + TRACE + "y" * 500)
    text = d.excerpt("x" * 500 + TRACE + "y" * 500, sig)
    assert "Traceback (most recent call last):" in text and len(text) < 300


def test_secret_kinds_filter():
    assert d.secret_kinds(["set-cookie", "google_api_key", "aws_access_key_id"]) == [
        "aws_access_key_id"
    ]
