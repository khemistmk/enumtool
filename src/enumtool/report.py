from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, Dict

from jinja2 import Environment, FileSystemLoader, select_autoescape
import importlib.resources as pkg_resources


def render_report(template_dir: Path | None, context: Dict[str, Any]) -> str:
    if template_dir and (template_dir / "report.html.j2").exists():
        loader = FileSystemLoader(str(template_dir))
    else:
        # Fallback to packaged resource
        with pkg_resources.as_file(pkg_resources.files("enumtool.resources")) as p:
            loader = FileSystemLoader(str(p))
    env = Environment(
        loader=loader,
        autoescape=select_autoescape(["html", "xml"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    tmpl = env.get_template("report.html.j2")
    return tmpl.render(**context)


def write_report(outdir: Path, html: str) -> Path:
    outdir.mkdir(parents=True, exist_ok=True)
    report_path = outdir / "report.html"
    report_path.write_text(html, encoding="utf-8")
    return report_path
