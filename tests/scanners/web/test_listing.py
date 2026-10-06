from scanners.web import listing

NGINX = (
    "<html>\r\n<head><title>Index of /assets/</title></head>\r\n<body>\r\n"
    '<h1>Index of /assets/</h1><hr><pre><a href="../">../</a>\r\n'
    '<a href="app.js">app.js</a>   01-Oct-2026 10:00   12\r\n'
    '<a href="site.css">site.css</a> 01-Oct-2026 10:00   34\r\n</pre><hr></body>\r\n</html>'
)
APACHE = (
    "<title>Index of /files</title><h1>Index of /files</h1><table>"
    '<tr><td><a href="/files/">Parent Directory</a></td></tr>'
    '<tr><td><a href="report.pdf">report.pdf</a></td></tr>'
    '<tr><td><a href="?C=N;O=D">Name</a></td></tr></table>'
)
APACHE_SUBDIR = (
    "<title>Index of /files/sub/</title><h1>Index of /files/sub/</h1><table>"
    '<tr><td><a href="/files/">Parent Directory</a></td></tr>'
    '<tr><td><a href="x.txt">x.txt</a></td></tr></table>'
)
PYTHON = (
    "<title>Directory listing for /d/</title><h1>Directory listing for /d/</h1>"
    '<ul><li><a href="a.txt">a.txt</a></li>'
    '<li><a href="sub/">sub/</a></li></ul>'
)
IIS = (
    '<pre><A HREF="/">[To Parent Directory]</A><br><br> 10/1/2026 10:00 AM 12 '
    '<A HREF="/assets/app.js">app.js</A><br></pre>'
)
IIS_SUBDIR = (
    '<pre><A HREF="/">[To Parent Directory]</A><br><br> 10/1/2026 10:00 AM 12 '
    '<A HREF="/assets/app.js">app.js</A><br></pre>'
)


def test_nginx():
    found = listing.detect(NGINX)
    assert found.kind == "index-of" and found.entries == frozenset({"app.js", "site.css"})


def test_apache():
    assert listing.detect(APACHE).entries == frozenset({"report.pdf"})


def test_python():
    found = listing.detect(PYTHON)
    assert found.kind == "python-http-server" and found.entries == frozenset({"a.txt", "sub"})


def test_iis():
    found = listing.detect(IIS)
    assert found.kind == "iis" and found.entries == frozenset({"app.js"})


def test_prose_is_not_a_listing():
    assert listing.detect("<title>Blog</title><p>The Index of /var is big</p>") is None
    assert listing.detect("") is None


def test_apache_subdir_filters_parent_link():
    """Parent link /files/ is not under /files/sub/ so it's dropped."""
    found = listing.detect(APACHE_SUBDIR)
    assert found.entries == frozenset({"x.txt"})


def test_iis_listing_filters_parent_link():
    """IIS parent link / and entry /assets/app.js both absolute; only app.js
    is under /assets/."""
    found = listing.detect(IIS_SUBDIR)
    assert found.kind == "iis" and found.entries == frozenset({"app.js"})


def test_index_of_title_needs_h1():
    """Title 'Index of /x' alone is not a listing (could be blog prose)."""
    assert (
        listing.detect("<title>Index of /etc/passwd explained</title><p>This is an article</p>")
        is None
    )


def test_directory_listing_title_needs_h1():
    """Title 'Directory listing for /x' alone is not a listing."""
    assert (
        listing.detect("<title>Directory listing for /x guide</title><p>This is an article</p>")
        is None
    )


def test_to_parent_directory_needs_pre():
    """[To Parent Directory] in a <p> tag is not IIS listing marker."""
    assert listing.detect("<p><a href='/'>[To Parent Directory]</a></p><p>Some content</p>") is None
