"""theme-extras.css: dark-theme fixes and the polish layer must stay driven by the theme variables."""
import re
from pathlib import Path

from tests.test_web_auth import make_config
from web.app import create_app

STATIC = Path(__file__).resolve().parents[1] / "web" / "static"
THEME = (STATIC / "theme.css").read_text(encoding="utf-8")
EXTRAS = (STATIC / "theme-extras.css").read_text(encoding="utf-8")


def test_extras_load_after_the_theme_and_are_served(tmp_path):
    app = create_app(make_config(tmp_path))
    client = app.test_client()
    html = client.get("/login").get_data(as_text=True)
    assert html.index("theme-extras.css") > html.index("theme.css") > html.index("bootstrap.min.css")
    assert client.get("/static/theme-extras.css").status_code == 200


def test_extras_contain_no_literal_colours():
    assert not re.findall(r"#[0-9a-fA-F]{3,8}\b", EXTRAS)
    assert not re.findall(r"rgba?\(\s*\d", EXTRAS)


def test_every_ev_variable_used_in_the_extras_is_defined():
    used = set(re.findall(r"var\((--ev-[a-z-]+)", EXTRAS))
    defined = set(re.findall(r"(--ev-[a-z-]+)\s*:", THEME + EXTRAS))
    assert used <= defined, sorted(used - defined)


def test_braces_are_balanced():
    stripped = re.sub(r"/\*.*?\*/", "", EXTRAS, flags=re.S)
    assert stripped.count("{") == stripped.count("}")


def test_bg_white_boxes_follow_the_theme_surface():
    """Six pages use Bootstrap's bg-white; without this mapping they turn white in a dark theme."""
    assert re.search(r"--bs-white-rgb:\s*var\(--ev-surface-rgb\)", EXTRAS)
    assert re.search(r"--bs-emphasis-color-rgb:\s*var\(--ev-text-rgb\)", EXTRAS)


# ---------- dropdowns and date pickers ----------

TEMPLATES = Path(__file__).resolve().parents[1] / "web" / "templates"


def test_every_select_and_date_input_in_the_templates_gets_the_theme():
    """New dropdowns and calendars are themed automatically as long as they use the Bootstrap classes."""
    for path in TEMPLATES.glob("*.html"):
        text = path.read_text(encoding="utf-8")
        for tag in re.findall(r"<select\b[^>]*>", text):
            assert "form-select" in tag, f"{path.name}: {tag}"
        for tag in re.findall(r"<input\b[^>]*type=\"(?:date|datetime-local|time|month)\"[^>]*>", text):
            assert "form-control" in tag, f"{path.name}: {tag}"


def test_extras_style_dropdowns_lists_and_date_fields():
    assert re.search(r"select option, select optgroup\s*\{[^}]*--ev-surface-rgb", EXTRAS)
    assert "@supports (appearance: base-select)" in EXTRAS and "::picker(select)" in EXTRAS
    for needle in ('input[type="datetime-local"]', "::-webkit-calendar-picker-indicator", "::-webkit-datetime-edit-day-field:focus"):
        assert needle in EXTRAS
    assert re.search(r"accent-color:\s*var\(--ev-accent\)", EXTRAS)


def test_links_are_not_underlined_except_plain_text_links_inside_sentences():
    """Buttons, cards and menus must not get an underline on hover."""
    stripped = re.sub(r"/\*.*?\*/", "", EXTRAS, flags=re.S)
    assert re.search(r"a, a:hover, a:focus \{ text-decoration: none; \}", stripped)
    for selector in re.findall(r"([^{}]+)\{[^}]*text-decoration:\s*underline", stripped):
        assert "a:not([class])" in selector and ":hover" in selector and "p " in selector + " ", selector


def test_badges_have_a_fixed_size_that_headings_cannot_enlarge():
    assert re.search(r"--ev-badge-font-size:\s*[\d.]+rem;", EXTRAS)
    assert re.search(r"\.badge \{[^}]*font-size:\s*var\(--ev-badge-font-size\)", EXTRAS)