from scanners.web import listing

NGINX = (
    "<html>\r\n<head><title>Index of /assets/</title></head>\r\n<body>\r\n"
    '<h1>Index of /assets/</h1><hr><pre><a href="../">../</a>\r\n'
    '<a href="app.js">app.js</a>   01-Oct-2026 10:00   12\r\n'
    '<a href="site.css">site.css</a> 01-Oct-2026 10:00   34\r\n</pre><hr></body>\r\n</html>'
)
APACHE = (
    "<title>Index of /files</title><h1>Index of /files</h1><table>"
    '<tr><td><a href="/">Parent Directory</a></td></tr>'
    '<tr><td><a href="report.pdf">report.pdf</a></td></tr>'
    '<tr><td><a href="?C=N;O=D">Name</a></td></tr></table>'
)
PYTHON = (
    '<title>Directory listing for /d/</title><ul><li><a href="a.txt">a.txt</a></li>'
    '<li><a href="sub/">sub/</a></li></ul>'
)
IIS = (
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
