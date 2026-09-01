#!/usr/bin/env python3

import argparse
import shutil
import sys
from pathlib import Path

WKHTMLTOPDF_CANDIDATES = (
    "wkhtmltopdf",
    "/usr/bin/wkhtmltopdf",
    "/usr/local/bin/wkhtmltopdf",
)


class ReportError(RuntimeError):
    pass


class ReportNotFoundError(ReportError):
    pass


class ReportToolError(ReportError):
    pass


def find_wkhtmltopdf() -> Path | None:
    for candidate in WKHTMLTOPDF_CANDIDATES:
        if "/" in candidate:
            path = Path(candidate)
            if path.is_file():
                return path
            continue
        found = shutil.which(candidate)
        if found:
            return Path(found)
    return None


def wkhtmltopdf_install_hint() -> str:
    if Path("/etc/debian_version").exists():
        return "sudo apt install wkhtmltopdf"
    if Path("/etc/redhat-release").exists():
        return "sudo dnf install wkhtmltopdf"
    if Path("/etc/arch-release").exists():
        return "sudo pacman -S wkhtmltopdf"
    return "https://github.com/JazzCore/python-pdfkit/wiki/Installing-wkhtmltopdf"


def export_workspace_pdf(
    loot_dir: Path,
    output_path: Path | None = None,
    *,
    html_path: Path | None = None,
    html_content: str | None = None,
    force: bool = False,
) -> Path:
    loot_dir = loot_dir.resolve()
    if html_content is not None:
        report_html = None
    else:
        report_html = (html_path or loot_dir / "kitelon-report.html").resolve()
        if not report_html.is_file():
            raise ReportNotFoundError(
                "HTML report not found: "
                f"{report_html}. Import loot and generate the report first."
            )

    default_pdf = loot_dir / "reports" / "kitelon-report.pdf"
    if html_path and html_path.name.startswith("subset-"):
        default_pdf = html_path.with_suffix(".pdf")
    output_path = (
        output_path.resolve()
        if output_path
        else default_pdf
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if (
        html_content is None
        and not force
        and output_path.is_file()
        and report_html is not None
        and output_path.stat().st_mtime >= report_html.stat().st_mtime
    ):
        return output_path

    pdf_bytes = export_pdf_bytes(
        html_path=report_html,
        html_content=html_content,
        force=force,
    )
    output_path.write_bytes(pdf_bytes)
    return output_path


def export_pdf_bytes(
    *,
    html_path: Path | None = None,
    html_content: str | None = None,
    force: bool = False,
) -> bytes:
    if html_content is None:
        if html_path is None or not html_path.is_file():
            raise ReportNotFoundError("HTML report not found for PDF export")
    elif not force and html_path and html_path.with_suffix(".pdf").is_file():
        pdf_path = html_path.with_suffix(".pdf")
        return pdf_path.read_bytes()

    try:
        import pdfkit
    except ImportError as exc:
        raise ReportToolError(
            "Python package 'pdfkit' is not installed. Run: sudo bash install.sh force"
        ) from exc

    wkhtml = find_wkhtmltopdf()
    if wkhtml is None:
        raise ReportToolError(
            f"wkhtmltopdf not found. Install with: {wkhtmltopdf_install_hint()}"
        )

    config = pdfkit.configuration(wkhtmltopdf=str(wkhtml))
    options = {
        "enable-local-file-access": None,
        "quiet": "",
        "page-size": "A4",
        "margin-top": "14mm",
        "margin-bottom": "14mm",
        "margin-left": "12mm",
        "margin-right": "12mm",
        "print-media-type": None,
    }

    try:
        if html_content is not None:
            pdf_bytes = pdfkit.from_string(
                html_content,
                False,
                configuration=config,
                options=options,
            )
        else:
            pdf_bytes = pdfkit.from_url(
                html_path.resolve().as_uri(),
                False,
                configuration=config,
                options=options,
            )
    except OSError as exc:
        raise ReportError(f"PDF export failed: {exc}") from exc

    if not pdf_bytes:
        raise ReportError("PDF export produced no output")

    return pdf_bytes


def main() -> None:
    parser = argparse.ArgumentParser(description="Export kitelon-report.html to PDF")
    parser.add_argument(
        "--loot-dir",
        help="Workspace loot directory containing kitelon-report.html",
    )
    parser.add_argument(
        "--output",
        default="kitelon-report.pdf",
        help="Output PDF path",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Regenerate even if PDF is newer than HTML",
    )
    args = parser.parse_args()

    if not args.loot_dir:
        print(
            "Usage: report.py --loot-dir /usr/share/kitelon/loot/workspace/<alias> [--output report.pdf]",
            file=sys.stderr,
        )
        sys.exit(1)

    loot_dir = Path(args.loot_dir)
    output_path = Path(args.output)

    try:
        result = export_workspace_pdf(loot_dir, output_path, force=args.force)
    except ReportError as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(1)

    print(f"Wrote {result}")


if __name__ == "__main__":
    main()
