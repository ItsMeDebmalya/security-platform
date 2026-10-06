from scanners.web import html

BASE = "https://x.test/"


def test_scripts_resolved_absolute_with_integrity():
    facts = html.extract(
        '<script src="/a.js"></script>'
        '<script src="https://cdn.y.test/b.js" integrity="sha384-abc"></script>',
        BASE,
    )
    assert facts.scripts == (
        html.Script("https://x.test/a.js", None),
        html.Script("https://cdn.y.test/b.js", "sha384-abc"),
    )


def test_stylesheet_only_when_rel_is_stylesheet():
    facts = html.extract(
        '<link rel="stylesheet" href="/s.css"><link rel="icon" href="/f.ico">', BASE
    )
    assert facts.stylesheets == ("https://x.test/s.css",)
    assert "https://x.test/f.ico" in facts.asset_urls


def test_meta_csp_and_generator():
    facts = html.extract(
        '<meta http-equiv="Content-Security-Policy" content="default-src \'self\'">'
        '<meta name="generator" content="WordPress 6.4.2">',
        BASE,
    )
    assert facts.meta_csp == ("default-src 'self'",)
    assert facts.generator == "WordPress 6.4.2"


def test_nothing_when_absent():
    facts = html.extract("<p>hi</p>", BASE)
    assert facts.meta_csp == () and facts.generator is None and facts.scripts == ()


def test_directories_are_parents_of_same_origin_assets_only():
    facts = html.extract(
        '<script src="/static/js/app.js"></script><img src="/img/logo.png">'
        '<script src="https://cdn.y.test/lib/x.js"></script>'
        '<link rel="stylesheet" href="/top.css">',
        BASE,
    )
    assert html.same_origin_directories(facts, BASE) == ["/img/", "/static/js/"]


def test_directories_respect_the_limit():
    body = "".join(f'<img src="/d{i}/x.png">' for i in range(10))
    assert len(html.same_origin_directories(html.extract(body, BASE), BASE, limit=4)) == 4


def test_linked_files_grouped_by_directory():
    facts = html.extract(
        '<script src="/assets/app.js"></script><link rel="stylesheet" href="/assets/site.css">',
        BASE,
    )
    assert html.linked_files(facts, BASE) == {"/assets/": frozenset({"app.js", "site.css"})}


def test_same_origin_is_scheme_host_and_port():
    assert html.is_same_origin("https://x.test/a", BASE)
    assert not html.is_same_origin("http://x.test/a", BASE)
    assert not html.is_same_origin("https://www.x.test/a", BASE)
    assert not html.is_same_origin("https://x.test:8443/a", BASE)


def test_malformed_markup_never_raises():  # Review Focus 5
    facts = html.extract(
        "<html><head><script src=/a.js><meta name=generator content=X 1.2<body><img src", BASE
    )
    assert isinstance(facts, html.PageFacts)
    assert html.extract("", BASE).asset_urls == ()
