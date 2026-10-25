"""One theme file: all colours and fonts live in web/static/theme.css and everything else derives from them."""
import re
from pathlib import Path

from web.app import create_app
from tests.test_web_auth import make_config

ROOT = Path(__file__).resolve().parents[1]
CSS = (ROOT / "web" / "static" / "theme.css").read_text(encoding="utf-8")
MARK = "END OF THEME VARIABLES"


def test_every_page_loads_theme_css_after_bootstrap(tmp_path):
    app = create_app(make_config(tmp_path))
    html = app.test_client().get("/login").get_data(as_text=True)
    bootstrap = html.index("bootstrap.min.css")
    assert html.index("theme.css") > bootstrap  # later stylesheet wins


def test_theme_css_is_served_and_allowed_by_the_csp(tmp_path):
    app = create_app(make_config(tmp_path))
    response = app.test_client().get("/static/theme.css")
    assert response.status_code == 200 and response.mimetype == "text/css"
    assert "style-src 'self'" in response.headers["Content-Security-Policy"]


def test_every_ev_variable_that_is_used_is_defined():
    used = set(re.findall(r"var\((--ev-[a-z-]+)", CSS))
    defined = set(re.findall(r"(--ev-[a-z-]+)\s*:", CSS))
    assert used <= defined, sorted(used - defined)


def test_colours_are_written_once_in_the_variables_block_only():
    """Below the marker there must be no literal colours: restyling means editing the top block only."""
    below = CSS.split(MARK)[1]
    assert not re.findall(r"#[0-9a-fA-F]{3,8}\b", below)
    assert not re.findall(r"rgba?\(\s*\d", below)


def test_the_variables_block_defines_the_brief_roles():
    top = CSS.split(MARK)[0]
    for name in ("primary", "accent", "success", "warning", "danger", "info", "neutral"):
        assert re.search(rf"--ev-{name}-rgb:\s*\d+,\s*\d+,\s*\d+;", top)
    for name in ("--ev-font:", "--ev-font-size:", "--ev-container-max:", "--ev-radius:"):
        assert name in top


def test_templates_and_scripts_hard_code_no_colours_or_inline_styles():
    for path in list((ROOT / "web" / "templates").glob("*.html")) + list((ROOT / "web" / "static").glob("*.js")):
        text = path.read_text(encoding="utf-8")
        assert "style=" not in text, path.name  # also forbidden by the CSP
        assert not re.search(r"(?<![&\w\"'/=#-])#[0-9a-fA-F]{6}\b", text), path.name