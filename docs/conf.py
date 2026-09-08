from pathlib import Path

ROOT = Path(__file__).resolve().parent
REPO_ROOT = ROOT.parent

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
