from scanners.web import fingerprint

FPS = fingerprint.load()


def found(**kw):
    args = {"headers": {}, "body": "", "asset_urls": (), "generator": None, **kw}
    return {d.name: d for d in fingerprint.detect(FPS, **args)}


def test_nginx_with_and_without_version():
    assert found(headers={"server": "nginx/1.27.3"})["nginx"].version == "1.27.3"
    assert found(headers={"server": "nginx"})["nginx"].version is None


def test_apache_coyote_is_not_apache_httpd():
    assert "Apache httpd" not in found(headers={"server": "Apache-Coyote/1.1"})


def test_php_wordpress_drupal_jquery():
    assert found(headers={"x-powered-by": "PHP/7.4.33"})["PHP"].version == "7.4.33"
    assert found(generator="WordPress 6.4.2")["WordPress"].version == "6.4.2"
    assert found(generator="Drupal 7 (https://www.drupal.org)")["Drupal"].version == "7"
    assert found(asset_urls=("https://x.test/js/jquery-3.7.1.min.js",))["jQuery"].version == "3.7.1"


def test_cdn_category():
    assert found(headers={"cf-ray": "8a1b2c3d4e5f-BOM"})["Cloudflare"].category == "cdn"


def test_nothing_on_a_plain_page():
    assert found(headers={"content-type": "text/html"}, body="<p>hi</p>") == {}


def test_every_entry_has_a_signal():
    for fp in FPS:
        assert fp.headers or fp.html or fp.asset or fp.generator, fp.name
