import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parent
REPO_ROOT = ROOT.parent

_renderer_spec = importlib.util.spec_from_file_location(
    "lwip_ce_tls_spec_renderer",
    ROOT / "render_tls_specifications.py",
)
if _renderer_spec is None or _renderer_spec.loader is None:
    raise RuntimeError("unable to load the TLS specification renderer")
_renderer = importlib.util.module_from_spec(_renderer_spec)
_renderer_spec.loader.exec_module(_renderer)
render_tls_specifications = _renderer.render

project = "lwIP-CE"
author = "Anthony Cagliano"
copyright = "2026, CagsCalcLabs"

extensions = [
    "breathe",
]

templates_path = ["_templates"]
exclude_patterns = [
    "_site_toc.rst",
    "_build",
    "_doxygen",
    "whitepaper/generated",
    "whitepaper/_minted-whitepaper",
]

html_theme = "sphinx_rtd_theme"
html_theme_options = {
    "collapse_navigation": False,
    "includehidden": True,
    "navigation_depth": 4,
    "titles_only": False,
}
html_static_path = ["_static"]
html_extra_path = [
    "tls-specifications.xml",
]
html_css_files = [
    "landing.css",
]

breathe_projects = {
    "lwip-ce": str(ROOT / "_doxygen" / "xml"),
}
breathe_default_project = "lwip-ce"
breathe_domain_by_extension = {
    "h": "c",
}

primary_domain = "c"
highlight_language = "c"

suppress_warnings = [
    "duplicate_declaration.c",
]


def _render_tls_ledger(app, exception):
    """Write the standalone audit page after Sphinx has built its HTML tree."""
    if exception is None and app.builder.format == "html":
        render_tls_specifications(
            ROOT / "tls-specifications.xml",
            Path(app.outdir) / "tls-specifications.html",
        )


def setup(app):
    app.connect("build-finished", _render_tls_ledger)
