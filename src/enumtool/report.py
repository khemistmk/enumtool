from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, Dict

from jinja2 import Environment, FileSystemLoader, select_autoescape


def render_report(template_dir: Path, context: Dict[str, Any]) -> str:
    env = Environment(
        loader=FileSystemLoader(str(template_dir)),
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
