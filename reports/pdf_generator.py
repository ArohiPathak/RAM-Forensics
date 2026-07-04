"""
PDF Generator Module for Forensic Reports
==========================================

This module builds a professional, black-and-white digital forensics
investigation report in PDF format from the output of the memory-analysis
pipeline (processing/parser.py -> processing/risk_engine.py).

Design goals (per report requirements):
    - Plain, formal, black-and-white layout (no colors, icons, or decoration).
    - Clear numbered section headings, similar to a standard DFIR report.
    - Tables used for structured data (case info, risk summary, findings,
      recommendations) so the report is easy to scan.
    - Every piece of report content (findings, risk score, recommendation
      counts, etc.) is generated from the data that is passed in - nothing
      about the *analysis results* is hardcoded here. The only fixed text
      is boilerplate that any DFIR report would carry (section titles,
      the methodology explanation, and the confidentiality notice).

How the file is organized (top to bottom):
    1. Small helper functions (validation, risk-level parsing).
    2. "Section builder" functions - each one returns a list of ReportLab
       flowables (Paragraphs/Tables/Spacers) for one section of the report.
       Keeping each section in its own function makes the report easy to
       reorder, extend, or reuse.
    3. The PDFGenerator class, which is the low-level engine that turns
       those sections into an actual PDF file (using reportlab if it is
       installed, or a very small hand-written PDF writer if it is not).
    4. The public functions (generate_forensic_pdf, generate_report_from_scan)
       that other parts of the app are expected to call.
"""

import os
import sys
from typing import Dict, List, Optional
from datetime import datetime

# Make the sibling `processing/` package importable regardless of the
# current working directory the script is run from. Both paths are needed:
# the repo root (for `from processing.risk_engine import ...` below) and
# processing/ itself (because risk_engine.py does `from parser import ...`,
# a flat import that only resolves if processing/ is directly on sys.path).
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
sys.path.insert(0, os.path.join(_REPO_ROOT, "processing"))


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Metadata keys that every report must have. If any of these are missing,
# we fail loudly (ValueError) instead of silently producing a broken report.
REQUIRED_METADATA_KEYS = [
    "Case ID",
    "Lead Investigator",
    "Target File",
    "Profile",
    "Risk Score",
    "Report Date",
]

# Human-readable labels for the detection categories that risk_engine.py
# can produce inside its "details" dictionary. Used only to make the
# "Detection Category Breakdown" table readable - it does not invent any
# data, it just relabels the dictionary keys that are already there.
DETECTION_CATEGORY_LABELS = {
    "hidden_processes": "Hidden / Unlinked Processes",
    "unknown_dlls": "Unknown or Unsigned DLLs",
    "external_connections": "Suspicious External Network Connections",
    "powershell_activity": "Suspicious PowerShell Activity",
}

PAGE_MARGIN_INCHES = 0.7


# ---------------------------------------------------------------------------
# Small helper functions
# ---------------------------------------------------------------------------

def _validate_inputs(
    metadata: Dict[str, str],
    findings: List[str],
    recommendations: List[str],
) -> None:
    """
    Check that the data we were given is complete enough to build a report.

    This does NOT check that the data is "correct" (that's the job of
    parser.py / risk_engine.py) - it just makes sure nothing required is
    missing, so we fail with a clear error message instead of crashing
    partway through PDF generation or silently emitting blank sections.
    """
    for key in REQUIRED_METADATA_KEYS:
        if key not in metadata:
            raise ValueError(f"Missing required metadata key: {key}")

    if not isinstance(findings, list) or not findings:
        raise ValueError("Findings must be a non-empty list")

    if not isinstance(recommendations, list) or not recommendations:
        raise ValueError("Recommendations must be a non-empty list")


def _extract_risk_level(risk_score_text: str) -> str:
    """
    Pull a plain risk-level word (HIGH / MEDIUM / LOW / UNKNOWN) out of a
    risk score string such as "72/100 (HIGH LEVEL)".

    We only ever read this from the "Risk Score" value that was itself
    computed by risk_engine.py - this function never decides the risk
    level on its own, it just extracts the word that is already there so
    it can be displayed on its own line in the report.
    """
    text = (risk_score_text or "").upper()
    if "HIGH" in text or "CRITICAL" in text:
        return "HIGH"
    if "LOW" in text:
        return "LOW"
    if "MEDIUM" in text or "MODERATE" in text:
        return "MEDIUM"
    return "UNKNOWN"


def _pluralize(count: int, noun: str) -> str:
    """Small text helper: return '1 finding' or '3 findings', etc."""
    return f"{count} {noun}" if count == 1 else f"{count} {noun}s"


# ---------------------------------------------------------------------------
# ReportLab styles
# ---------------------------------------------------------------------------

def _build_report_styles():
    """
    Build the set of paragraph styles used throughout the report.

    Everything here is grayscale (black text, light-gray table headers) to
    match a plain, formal, black-and-white DFIR report - no accent colors.
    Centralizing the styles in one function means the visual look of the
    whole report can be tweaked in a single place.
    """
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY
    from reportlab.lib import colors

    styles = getSampleStyleSheet()

    styles.add(ParagraphStyle(
        name="ReportTitle", fontName="Helvetica-Bold", fontSize=18,
        leading=22, alignment=TA_CENTER, spaceAfter=4, textColor=colors.black,
    ))
    styles.add(ParagraphStyle(
        name="ReportSubtitle", fontName="Helvetica", fontSize=10,
        leading=13, alignment=TA_CENTER, spaceAfter=16,
        textColor=colors.HexColor("#404040"),
    ))
    styles.add(ParagraphStyle(
        name="SectionHeading", fontName="Helvetica-Bold", fontSize=12.5,
        leading=16, spaceBefore=16, spaceAfter=8, textColor=colors.black,
    ))
    styles.add(ParagraphStyle(
        name="SubHeading", fontName="Helvetica-Bold", fontSize=10.5,
        leading=13, spaceBefore=8, spaceAfter=4, textColor=colors.black,
    ))
    styles.add(ParagraphStyle(
        name="BodyText2", fontName="Helvetica", fontSize=10, leading=14,
        alignment=TA_JUSTIFY, spaceAfter=8, textColor=colors.black,
    ))
    styles.add(ParagraphStyle(
        name="TableCell", fontName="Helvetica", fontSize=9, leading=12,
        textColor=colors.black,
    ))
    styles.add(ParagraphStyle(
        name="TableCellBold", fontName="Helvetica-Bold", fontSize=9,
        leading=12, textColor=colors.black,
    ))
    styles.add(ParagraphStyle(
        name="DisclaimerText", fontName="Helvetica-Oblique", fontSize=8,
        leading=11, textColor=colors.HexColor("#404040"),
    ))
    return styles


def _standard_table_style(header_rows: int = 0):
    """
    Return the grayscale TableStyle used by every table in the report:
    thin gray gridlines, a light-gray header band (if header_rows > 0),
    and consistent padding. Keeping this in one function means every
    table in the PDF looks the same without repeating the style code.
    """
    from reportlab.platypus import TableStyle
    from reportlab.lib import colors

    style_commands = [
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]
    if header_rows:
        style_commands.append(
            ("BACKGROUND", (0, 0), (-1, header_rows - 1), colors.HexColor("#DDDDDD"))
        )
    return TableStyle(style_commands)


# ---------------------------------------------------------------------------
# Section builders
#
# Each function below returns a list of ReportLab "flowables" (things that
# can be laid out on a page: Paragraph, Table, Spacer...). The main PDF
# builder just concatenates these lists together, in order, to form the
# final report. This keeps each section's logic isolated and easy to test
# or reorder independently.
# ---------------------------------------------------------------------------

def _build_title_block(styles) -> list:
    """Report title + subtitle + a horizontal rule under them."""
    from reportlab.platypus import Paragraph, HRFlowable
    from reportlab.lib import colors

    title = Paragraph("DIGITAL FORENSICS INVESTIGATION REPORT", styles["ReportTitle"])
    subtitle = Paragraph(
        "Volatility 3 Memory Forensics Analysis", styles["ReportSubtitle"]
    )
    rule = HRFlowable(width="100%", thickness=1, color=colors.black, spaceAfter=14)
    return [title, subtitle, rule]


def _build_case_information_section(metadata: Dict[str, str], styles) -> list:
    """
    Section 1: a simple two-column table of case metadata (case ID,
    investigator, target file, OS profile, report date). All values come
    directly from the metadata dict that was passed in.
    """
    from reportlab.platypus import Paragraph, Table, Spacer

    heading = Paragraph("1. Case Information", styles["SectionHeading"])

    field_rows = [
        ("Case ID", metadata.get("Case ID", "N/A")),
        ("Lead Investigator", metadata.get("Lead Investigator", "N/A")),
        ("Target Memory Image", metadata.get("Target File", "N/A")),
        ("Operating System Profile", metadata.get("Profile", "N/A")),
        ("Report Generated", metadata.get("Report Date", "N/A")),
    ]
    table_data = [
        [Paragraph(label, styles["TableCellBold"]), Paragraph(str(value), styles["TableCell"])]
        for label, value in field_rows
    ]

    table = Table(table_data, colWidths=[170, 330])
    table.setStyle(_standard_table_style())

    return [heading, table, Spacer(1, 10)]


def _build_executive_summary_section(
    metadata: Dict[str, str],
    findings: List[str],
    recommendations: List[str],
    styles,
) -> list:
    """
    Section 2: a short plain-language paragraph summarizing what was
    scanned and what was found. Every number and label in this paragraph
    (finding count, risk level, recommendation count, target file, OS
    profile) is computed from the actual data passed into the report -
    none of it is fixed wording about specific results.
    """
    from reportlab.platypus import Paragraph

    heading = Paragraph("2. Executive Summary", styles["SectionHeading"])

    risk_level = _extract_risk_level(metadata.get("Risk Score", ""))
    finding_count = len(findings)
    recommendation_count = len(recommendations)

    summary_text = (
        f"This report documents the results of a memory forensics examination performed "
        f"on the target memory image <b>{metadata.get('Target File', 'N/A')}</b>, acquired "
        f"from a system running <b>{metadata.get('Profile', 'N/A')}</b>. Automated analysis "
        f"of the process list, DLL list, network connections, and command-line history "
        f"identified <b>{_pluralize(finding_count, 'finding')}</b> of forensic interest, "
        f"resulting in an overall risk classification of <b>{risk_level}</b> "
        f"(Risk Score: {metadata.get('Risk Score', 'N/A')}). Based on these findings, "
        f"<b>{_pluralize(recommendation_count, 'recommendation')}</b> "
        f"{'has' if recommendation_count == 1 else 'have'} been provided in Section 5 of "
        f"this report to guide remediation and any further investigation."
    )

    return [heading, Paragraph(summary_text, styles["BodyText2"])]


def _build_risk_assessment_section(
    metadata: Dict[str, str],
    detection_details: Optional[Dict[str, list]],
    styles,
) -> list:
    """
    Section 3: the numeric risk score/level, plus (if the caller supplied
    a `detection_details` dictionary from risk_engine.py) a breakdown table
    showing how many items were flagged in each detection category. This
    breakdown is entirely optional and entirely data-driven - if a category
    has zero hits, it is simply left out of the table.
    """
    from reportlab.platypus import Paragraph, Table, Spacer

    heading = Paragraph("3. Risk Assessment", styles["SectionHeading"])
    risk_level = _extract_risk_level(metadata.get("Risk Score", ""))

    score_rows = [
        [Paragraph("Overall Risk Score", styles["TableCellBold"]),
         Paragraph(str(metadata.get("Risk Score", "N/A")), styles["TableCell"])],
        [Paragraph("Risk Classification", styles["TableCellBold"]),
         Paragraph(risk_level, styles["TableCell"])],
    ]
    score_table = Table(score_rows, colWidths=[170, 330])
    score_table.setStyle(_standard_table_style())

    flowables = [heading, score_table, Spacer(1, 10)]

    if detection_details:
        # Build one row per category that actually has at least one hit.
        category_rows = [[
            Paragraph("Detection Category", styles["TableCellBold"]),
            Paragraph("Items Detected", styles["TableCellBold"]),
        ]]
        for key, label in DETECTION_CATEGORY_LABELS.items():
            items = detection_details.get(key) or []
            if items:
                category_rows.append([
                    Paragraph(label, styles["TableCell"]),
                    Paragraph(str(len(items)), styles["TableCell"]),
                ])

        # Only add the breakdown table if there is at least one category
        # with real hits - otherwise it would just be an empty header row.
        if len(category_rows) > 1:
            sub_heading = Paragraph("Detection Category Breakdown", styles["SubHeading"])
            category_table = Table(category_rows, colWidths=[350, 150], repeatRows=1)
            category_table.setStyle(_standard_table_style(header_rows=1))
            flowables += [sub_heading, category_table, Spacer(1, 10)]

    return flowables


def _build_findings_section(findings: List[str], styles) -> list:
    """
    Section 4: every finding produced by risk_engine.py, laid out as a
    numbered table row. The table automatically grows or shrinks with the
    number of findings, and long finding text wraps naturally because each
    cell is a Paragraph rather than plain text.
    """
    from reportlab.platypus import Paragraph, Table, Spacer

    heading = Paragraph("4. Detailed Findings", styles["SectionHeading"])
    intro = Paragraph(
        "The table below lists each forensic indicator identified during automated "
        "analysis of the memory image, in the order it was detected.",
        styles["BodyText2"],
    )

    table_data = [[
        Paragraph("#", styles["TableCellBold"]),
        Paragraph("Finding", styles["TableCellBold"]),
    ]]
    for index, finding in enumerate(findings, start=1):
        table_data.append([
            Paragraph(str(index), styles["TableCell"]),
            Paragraph(str(finding), styles["TableCell"]),
        ])

    table = Table(table_data, colWidths=[30, 470], repeatRows=1)
    table.setStyle(_standard_table_style(header_rows=1))

    return [heading, intro, table, Spacer(1, 10)]


def _build_recommendations_section(recommendations: List[str], styles) -> list:
    """
    Section 5: every recommendation, as a numbered table row. Recommendation
    *text* comes from RECOMMENDATION_MAP (see below), but *which* rows
    appear, and how many, is entirely determined by what the scan actually
    flagged - nothing here is a hardcoded "sample" recommendation list.
    """
    from reportlab.platypus import Paragraph, Table, Spacer

    heading = Paragraph("5. Recommendations", styles["SectionHeading"])
    intro = Paragraph(
        "The following mitigation and follow-up actions are recommended based on the "
        "findings above.",
        styles["BodyText2"],
    )

    table_data = [[
        Paragraph("#", styles["TableCellBold"]),
        Paragraph("Recommended Action", styles["TableCellBold"]),
    ]]
    for index, recommendation in enumerate(recommendations, start=1):
        table_data.append([
            Paragraph(str(index), styles["TableCell"]),
            Paragraph(str(recommendation), styles["TableCell"]),
        ])

    table = Table(table_data, colWidths=[30, 470], repeatRows=1)
    table.setStyle(_standard_table_style(header_rows=1))

    return [heading, intro, table, Spacer(1, 10)]


def _build_methodology_section(metadata: Dict[str, str], styles) -> list:
    """
    Section 6: a short, fixed explanation of *how* the analysis was done.
    This is standard boilerplate that belongs in any memory-forensics
    report (it describes the process, not the results), but the artifact
    list it references (Target File / Profile) is still pulled from the
    metadata dict rather than being written in as fixed text.
    """
    from reportlab.platypus import Paragraph

    heading = Paragraph("6. Scope and Methodology", styles["SectionHeading"])
    body = Paragraph(
        f"Analysis was performed on the memory image "
        f"<b>{metadata.get('Target File', 'N/A')}</b> using the Volatility 3 memory "
        f"forensics framework, with the OS profile <b>{metadata.get('Profile', 'N/A')}</b>. "
        f"The examination reviewed process listings (pslist/psscan), loaded modules "
        f"(dlllist), active and historical network connections (netscan), and process "
        f"command-line arguments (cmdline) to identify indicators of process hiding, "
        f"unsigned or unrecognized DLLs, suspicious external network activity, and "
        f"encoded or obfuscated PowerShell usage. Findings were scored and classified "
        f"by the automated risk-scoring engine described in this report's supporting "
        f"documentation.",
        styles["BodyText2"],
    )
    return [heading, body]


def _build_disclaimer_section(styles) -> list:
    """
    Section 7: the standard confidentiality notice. This is fixed
    boilerplate text (every report from this tool carries the same
    disclaimer), not analysis output, so it is safe to keep as a
    constant string.
    """
    from reportlab.platypus import Paragraph, Spacer

    heading = Paragraph("7. Report Disclaimer", styles["SectionHeading"])
    disclaimer = Paragraph(
        "This report contains confidential information derived from digital forensic "
        "analysis and is intended solely for authorized personnel involved in this "
        "investigation. Unauthorized access, use, or distribution of this document is "
        "strictly prohibited. Findings are based solely on the artifacts available at "
        "the time of memory acquisition and should be corroborated with other evidence "
        "sources where possible.",
        styles["BodyText2"],
    )
    return [Spacer(1, 6), heading, disclaimer]


# ---------------------------------------------------------------------------
# Low-level PDF engine
# ---------------------------------------------------------------------------

class PDFGenerator:
    """
    Turns a metadata/findings/recommendations bundle into an actual PDF
    file on disk.

    This class does not know anything about *where* the data came from -
    that is handled further down by generate_report_from_scan(). Its only
    job is: given the final report content, produce bytes on disk that are
    a valid, readable PDF.
    """

    def __init__(self):
        # Standard US Letter page size, in points (1 point = 1/72 inch).
        self.page_width = 595.27
        self.page_height = 841.89

    def generate(
        self,
        output_path: str,
        metadata: Dict[str, str],
        findings: List[str],
        recommendations: List[str],
        detection_details: Optional[Dict[str, list]] = None,
    ) -> str:
        """
        Build the PDF report and write it to `output_path`.

        Tries the full-featured reportlab-based builder first (which gives
        us proper tables, automatic page breaks, and text wrapping). If
        reportlab isn't installed, falls back to a minimal hand-written PDF
        writer that has no external dependencies, so report generation
        never hard-fails just because a library is missing.
        """
        _validate_inputs(metadata, findings, recommendations)

        try:
            return self._generate_with_reportlab(
                output_path, metadata, findings, recommendations, detection_details
            )
        except ImportError:
            return self._generate_with_raw_pdf(
                output_path, metadata, findings, recommendations
            )

    # -- Primary path: reportlab -------------------------------------------------

    def _generate_with_reportlab(
        self,
        output_path: str,
        metadata: Dict[str, str],
        findings: List[str],
        recommendations: List[str],
        detection_details: Optional[Dict[str, list]],
    ) -> str:
        """
        Build the report using reportlab's Platypus layout engine.

        Platypus (SimpleDocTemplate + flowables) is used instead of manual
        canvas drawing because it automatically handles page breaks and
        text wrapping for us - important here since the number of findings
        and recommendations is not known ahead of time and can span
        multiple pages.
        """
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.units import inch
        from reportlab.platypus import SimpleDocTemplate

        output_dir = os.path.dirname(output_path)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)

        styles = _build_report_styles()

        # Assemble the report by concatenating each section's flowables,
        # in the order they should appear on the page.
        story = []
        story += _build_title_block(styles)
        story += _build_case_information_section(metadata, styles)
        story += _build_executive_summary_section(metadata, findings, recommendations, styles)
        story += _build_risk_assessment_section(metadata, detection_details, styles)
        story += _build_findings_section(findings, styles)
        story += _build_recommendations_section(recommendations, styles)
        story += _build_methodology_section(metadata, styles)
        story += _build_disclaimer_section(styles)

        document = SimpleDocTemplate(
            output_path,
            pagesize=letter,
            leftMargin=PAGE_MARGIN_INCHES * inch,
            rightMargin=PAGE_MARGIN_INCHES * inch,
            topMargin=PAGE_MARGIN_INCHES * inch,
            bottomMargin=(PAGE_MARGIN_INCHES + 0.1) * inch,
            title="Digital Forensics Investigation Report",
            author="RAM Forensics Dashboard",
        )

        case_id = metadata.get("Case ID", "N/A")
        document.build(
            story,
            canvasmaker=lambda *args, **kwargs: _FooterCanvas(*args, case_id=case_id, **kwargs),
        )

        return os.path.abspath(output_path)

    # -- Fallback path: no external dependencies ---------------------------------

    def _generate_with_raw_pdf(
        self,
        output_path: str,
        metadata: Dict[str, str],
        findings: List[str],
        recommendations: List[str],
    ) -> str:
        """
        Generate a very basic, plain black-on-white PDF using nothing but
        the standard library. This only runs if reportlab is not installed;
        it has no tables or page breaks, just simple stacked lines of text,
        but it still displays all of the same dynamic data.
        """
        output_dir = os.path.dirname(output_path)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)

        stream_bytes = self._build_plain_text_content(
            metadata, findings, recommendations
        ).encode("latin1")

        pdf_objects = [
            b"<< /Type /Catalog /Pages 2 0 R >>",
            b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            b"<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R /F2 5 0 R >> >> "
            b"/MediaBox [0 0 595.27 841.89] /Contents 6 0 R >>",
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>",
            (f"<< /Length {len(stream_bytes)} >>\nstream\n".encode("latin1")
             + stream_bytes + b"\nendstream"),
        ]

        with open(output_path, "wb") as pdf_file:
            pdf_file.write(b"%PDF-1.4\n")
            object_offsets = []
            for index, pdf_object in enumerate(pdf_objects):
                object_offsets.append(pdf_file.tell())
                pdf_file.write(f"{index + 1} 0 obj\n".encode("latin1"))
                pdf_file.write(pdf_object)
                pdf_file.write(b"\nendobj\n")

            xref_offset = pdf_file.tell()
            pdf_file.write(b"xref\n")
            pdf_file.write(f"0 {len(pdf_objects) + 1}\n".encode("latin1"))
            pdf_file.write(b"0000000000 65535 f \n")
            for offset in object_offsets:
                pdf_file.write(f"{offset:010d} 00000 n \n".encode("latin1"))

            pdf_file.write(b"trailer\n")
            pdf_file.write(f"<< /Size {len(pdf_objects) + 1} /Root 1 0 R >>\n".encode("latin1"))
            pdf_file.write(b"startxref\n")
            pdf_file.write(f"{xref_offset}\n".encode("latin1"))
            pdf_file.write(b"%%EOF\n")

        return os.path.abspath(output_path)

    @staticmethod
    def _escape_pdf_text(value: str) -> str:
        """Escape parentheses/backslashes so raw text is safe inside a PDF string."""
        return str(value).replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")

    def _build_plain_text_content(
        self,
        metadata: Dict[str, str],
        findings: List[str],
        recommendations: List[str],
    ) -> str:
        """
        Build the raw PDF content stream for the no-dependency fallback path.
        Everything is plain black text on a white background (the fallback's
        page is white by default, so we don't even need a background fill).
        """
        lines = ["BT", "/F2 16 Tf", "50 790 Td",
                 f"({self._escape_pdf_text('DIGITAL FORENSICS INVESTIGATION REPORT')}) Tj"]

        lines += ["0 -24 Td", "/F2 11 Tf",
                  f"({self._escape_pdf_text('1. Case Information')}) Tj"]

        case_fields = [
            ("Case ID", metadata.get("Case ID", "N/A")),
            ("Lead Investigator", metadata.get("Lead Investigator", "N/A")),
            ("Target Memory Image", metadata.get("Target File", "N/A")),
            ("Operating System Profile", metadata.get("Profile", "N/A")),
            ("Risk Score", metadata.get("Risk Score", "N/A")),
            ("Report Generated", metadata.get("Report Date", "N/A")),
        ]
        for label, value in case_fields:
            safe_value = self._escape_pdf_text(str(value).replace("\n", " "))[:90]
            lines += ["0 -16 Td", "/F1 9 Tf", f"({label}: {safe_value}) Tj"]

        lines += ["0 -22 Td", "/F2 11 Tf",
                  f"({self._escape_pdf_text('2. Detailed Findings')}) Tj"]
        for index, finding in enumerate(findings, start=1):
            safe_finding = self._escape_pdf_text(str(finding).replace("\n", " "))[:95]
            lines += ["0 -14 Td", "/F1 9 Tf", f"({index}. {safe_finding}) Tj"]

        lines += ["0 -22 Td", "/F2 11 Tf",
                  f"({self._escape_pdf_text('3. Recommendations')}) Tj"]
        for index, recommendation in enumerate(recommendations, start=1):
            safe_recommendation = self._escape_pdf_text(str(recommendation).replace("\n", " "))[:95]
            lines += ["0 -14 Td", "/F1 9 Tf", f"({index}. {safe_recommendation}) Tj"]

        lines += ["0 -26 Td", "/F1 7 Tf",
                  f"({self._escape_pdf_text('CONFIDENTIAL - FOR AUTHORIZED PERSONNEL ONLY')}) Tj"]
        lines.append("ET")

        return "\n".join(lines)


class _FooterCanvas:
    """
    A ReportLab canvas subclass that draws the same footer - case ID on the
    left, confidentiality notice in the middle, "Page X of Y" on the right -
    on every page of the report.

    This is defined as a subclass (rather than a plain function) because
    ReportLab's `SimpleDocTemplate.build(..., canvasmaker=...)` needs a
    canvas *class* it can instantiate once per document. Using a canvas
    subclass here is the standard ReportLab pattern for adding page numbers,
    since the total page count isn't known until the whole document has
    already been laid out once.
    """

    def __new__(cls, *args, case_id: str = "N/A", **kwargs):
        # Import reportlab lazily so this module can still be imported
        # (and its plain functions/tests used) even if reportlab is not
        # installed - only PDF generation itself requires the dependency.
        from reportlab.pdfgen import canvas as reportlab_canvas

        class _BoundFooterCanvas(reportlab_canvas.Canvas):
            def __init__(self, *inner_args, **inner_kwargs):
                super().__init__(*inner_args, **inner_kwargs)
                self._case_id = case_id
                self._saved_page_states = []

            def showPage(self):
                # Instead of finishing the page immediately, remember its
                # state so we can go back and stamp "Page X of Y" once we
                # know the final page count.
                self._saved_page_states.append(dict(self.__dict__))
                self._startPage()

            def save(self):
                total_pages = len(self._saved_page_states)
                for state in self._saved_page_states:
                    self.__dict__.update(state)
                    self._draw_footer(total_pages)
                    super().showPage()
                super().save()

            def _draw_footer(self, total_pages):
                from reportlab.lib.pagesizes import letter
                from reportlab.lib import colors

                page_width, _ = letter
                self.setFont("Helvetica", 8)
                self.setFillColor(colors.black)
                self.drawString(0.6 * 72, 0.5 * 72, f"Case ID: {self._case_id}")
                self.drawCentredString(
                    page_width / 2, 0.5 * 72,
                    "CONFIDENTIAL - FOR AUTHORIZED PERSONNEL ONLY",
                )
                self.drawRightString(
                    page_width - 0.6 * 72, 0.5 * 72,
                    f"Page {self._pageNumber} of {total_pages}",
                )

        return _BoundFooterCanvas(*args, **kwargs)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_forensic_pdf(
    output_path: str,
    metadata: Dict[str, str],
    findings: List[str],
    recommendations: List[str],
    detection_details: Optional[Dict[str, list]] = None,
) -> str:
    """
    Generate a professional forensic incident report PDF.

    This is the main public function other code should call once it has
    already gathered the report content (typically via
    generate_report_from_scan, below).

    Args:
        output_path: Full path where the PDF should be written.
        metadata: Dict with keys "Case ID", "Lead Investigator",
            "Target File", "Profile", "Risk Score", "Report Date".
        findings: List of forensic finding strings.
        recommendations: List of recommended-action strings.
        detection_details: Optional dict (as produced by
            risk_engine.calculate_risk_score()["details"]) used only to
            render the optional "Detection Category Breakdown" table in
            the Risk Assessment section. Safe to omit.

    Returns:
        Absolute path to the generated PDF.

    Raises:
        ValueError: If required metadata/findings/recommendations are missing.
        IOError: If the file cannot be written.
    """
    generator = PDFGenerator()
    return generator.generate(
        output_path, metadata, findings, recommendations, detection_details
    )


# ---------------------------------------------------------------------------
# Integration with processing/parser.py + processing/risk_engine.py
#
# risk_engine.calculate_risk_score() returns:
#   {"score": int, "risk_level": str, "findings": [...], "details": {...}}
# generate_forensic_pdf() needs:
#   metadata{Case ID, Lead Investigator, Target File, Profile, Risk Score,
#   Report Date}, findings[], recommendations[]
#
# Two things risk_engine/parser CANNOT produce because they simply aren't in
# the Volatility txt output:
#   - Case ID / Lead Investigator -> supplied by the analyst
#   - Target File / OS Profile    -> supplied by whatever invoked Volatility
#     in the first place (the memory image filename and the profile string
#     used on the scan aren't present in pslist/psscan/dlllist/netscan/cmdline)
#
# Recommendations also don't exist upstream - risk_engine only proves THAT
# something was found, not what to do about it. RECOMMENDATION_MAP fills
# that gap based on which detection categories fired.
# ---------------------------------------------------------------------------

RECOMMENDATION_MAP = {
    "hidden_processes": (
        "Isolate the affected host from the network and terminate the hidden "
        "process(es) immediately; process hiding indicates likely rootkit or "
        "DKOM-based malware."
    ),
    "unknown_dlls": (
        "Extract and sandbox the flagged DLL(s) for static/dynamic analysis; "
        "verify digital signatures and hashes against known-good baselines "
        "and threat intelligence feeds."
    ),
    "external_connections": (
        "Block outbound traffic to the flagged external IP(s) at the "
        "firewall/proxy and review DNS and connection logs for the same "
        "destination across other hosts."
    ),
    "powershell_activity": (
        "Review PowerShell execution and Script Block logs for encoded or "
        "obfuscated commands; enable AMSI logging if not already active."
    ),
}

DEFAULT_RECOMMENDATION = (
    "No critical indicators were identified in this scan; continue routine "
    "monitoring."
)

BASELINE_RECOMMENDATION = (
    "Preserve the memory image and all Volatility3 output files under "
    "chain-of-custody procedures for potential further analysis."
)


def _build_recommendations(details: Dict[str, list]) -> List[str]:
    """
    Turn risk_engine's raw detection details into actionable recommendations.

    For each detection category that actually has hits (details[key] is a
    non-empty list), we add the matching fixed recommendation text from
    RECOMMENDATION_MAP. Which recommendations appear - and how many - is
    therefore driven entirely by the scan results; only the wording of each
    individual recommendation is a fixed template.
    """
    recommendations = []
    for category_key, recommendation_text in RECOMMENDATION_MAP.items():
        if details.get(category_key):
            recommendations.append(recommendation_text)

    if not recommendations:
        recommendations.append(DEFAULT_RECOMMENDATION)

    recommendations.append(BASELINE_RECOMMENDATION)
    return recommendations


def generate_report_from_scan(
    output_path: str,
    case_id: str,
    investigator: str,
    target_file: str,
    profile: str,
    base_path: str = "processing/sample_output",
) -> str:
    """
    Run the real detection pipeline (parser.py -> risk_engine.py) and
    generate a PDF report from its actual output.

    Args:
        output_path: Where to write the PDF.
        case_id: Analyst-supplied case identifier (not derivable from scan output).
        investigator: Analyst-supplied name/team (not derivable from scan output).
        target_file: The memory image filename that was scanned (not derivable
            from pslist/psscan/dlllist/netscan/cmdline - must be tracked
            separately, e.g. by whatever module invoked Volatility).
        profile: The OS profile Volatility used for the scan (same caveat as above).
        base_path: Directory containing the Volatility txt output files
            (pslist.txt, psscan.txt, dlllist.txt, netscan.txt, cmdline.txt).

    Returns:
        Absolute path to the generated PDF.
    """
    from processing.risk_engine import calculate_risk_score

    scan_result = calculate_risk_score(base_path)

    # Everything below is derived from scan_result - nothing about the
    # analysis outcome is hardcoded in this function.
    findings = scan_result["findings"] or [
        "No indicators of compromise were detected in this memory image."
    ]
    recommendations = _build_recommendations(scan_result["details"])

    metadata = {
        "Case ID": case_id,
        "Lead Investigator": investigator,
        "Target File": target_file,
        "Profile": profile,
        "Risk Score": f"{scan_result['score']}/100 ({scan_result['risk_level'].upper()} LEVEL)",
        "Report Date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }

    return generate_forensic_pdf(
        output_path, metadata, findings, recommendations,
        detection_details=scan_result["details"],
    )


if __name__ == "__main__":
    # Runs the REAL pipeline: parser.py -> risk_engine.py -> this PDF generator.
    # Case ID / Investigator / Target File / Profile still have to be supplied
    # here because nothing upstream produces them (see comment block above).
    out_path = sys.argv[1] if len(sys.argv) > 1 else "forensic_report.pdf"

    result_path = generate_report_from_scan(
        output_path=out_path,
        case_id="CASE-2026-004",
        investigator="Cyber Analyst Team 404",
        target_file="mem_dump_cybersecurity_incident.raw",
        profile="Win10x64_19041 (Windows 10 Pro)",
        base_path="processing/sample_output",
    )
    print(f"Generated: {result_path}")