"""PDF report generation from stored WAPT assessment records."""
from __future__ import annotations

import io
import hashlib
import re
from datetime import datetime, timezone

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)
from reportlab.platypus.tableofcontents import TableOfContents


SENSITIVE_NAMES = re.compile(
    r"(authorization|cookie|set-cookie|api[-_ ]?key|token|password|secret|session)",
    re.I,
)
SENSITIVE_VALUES = (
    re.compile(r"(?i)(bearer\s+[A-Za-z0-9._~+/=-]+)", re.I),
    re.compile(r"(?i)((?:password|passwd|secret|token|api[_-]?key|session)[=:]\s*[^\s,;]+)", re.I),
)


def redact_sensitive(value: object) -> str:
    text = "" if value is None else str(value)
    text = re.sub(r"(https?://)([^/\s:@]+:[^@\s]+)@", r"\1[redacted]@", text)
    for pattern in SENSITIVE_VALUES:
        text = pattern.sub("[redacted]", text)
    if SENSITIVE_NAMES.search(text):
        if ": " in text:
            name, _, remainder = text.partition(": ")
            if SENSITIVE_NAMES.search(name):
                text = f"{name}: [redacted]"
            else:
                text = f"{name}: {re.sub(r'[^\\s,;]+', '[redacted]', remainder)}"
    return text


def redact_headers(headers: dict[str, object]) -> dict[str, str]:
    return {
        str(name): redact_sensitive(value)
        for name, value in (headers or {}).items()
        if not SENSITIVE_NAMES.search(str(name))
    }


class WAPTDocTemplate(BaseDocTemplate):
    def __init__(self, filename: io.BytesIO) -> None:
        super().__init__(filename, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm,
                         topMargin=18 * mm, bottomMargin=16 * mm,
                         title="WAPT Security Assessment Report",
                         author="WAPT Security Console")
        frame = Frame(18 * mm, 16 * mm, A4[0] - 36 * mm, A4[1] - 34 * mm, id="main")
        self.addPageTemplates(PageTemplate(id="wapt", frames=[frame], onPage=self._on_page))

    def _on_page(self, canvas, _doc) -> None:
        canvas.saveState()
        canvas.setFillColor(colors.HexColor("#111827"))
        canvas.setFont("Helvetica", 8)
        canvas.drawString(18 * mm, A4[1] - 10 * mm, "WAPT Security Assessment")
        canvas.setFillColor(colors.HexColor("#6b7280"))
        canvas.drawRightString(A4[0] - 18 * mm, 9 * mm, f"Page {canvas.getPageNumber()}")
        canvas.drawString(18 * mm, 9 * mm, "Confidential - Authorized assessment")
        canvas.restoreState()

    def afterFlowable(self, flowable) -> None:
        if isinstance(flowable, Paragraph):
            style_name = flowable.style.name
            if style_name in {"Heading1", "Heading2"}:
                text = flowable.getPlainText()
                level = 0 if style_name == "Heading1" else 1
                key = f"h{level}-{hashlib.md5(text.encode('utf-8')).hexdigest()}"
                canvas = getattr(self, "canv", None)
                if canvas is not None:
                    canvas.bookmarkPage(key)
                self.notify("TOCEntry", (level, text, self.page, key))


def _finding_id(scan_id: int, finding: dict[str, object], index: int) -> str:
    fingerprint = str(finding.get("fingerprint") or "")
    suffix = fingerprint[:8].upper() if fingerprint else str(index).zfill(3)
    return f"WAPT-{scan_id}-{suffix}"


def generate_pdf(scan: dict[str, object]) -> io.BytesIO:
    output = io.BytesIO()
    doc = WAPTDocTemplate(output)
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="ReportTitle", parent=styles["Title"], fontName="Helvetica-Bold",
                              fontSize=24, leading=29, textColor=colors.HexColor("#111827"),
                              alignment=TA_CENTER, spaceAfter=12))
    styles.add(ParagraphStyle(name="Section", parent=styles["Heading1"], fontName="Helvetica-Bold",
                              fontSize=15, leading=19, textColor=colors.HexColor("#111827"),
                              spaceBefore=10, spaceAfter=8))
    styles.add(ParagraphStyle(name="Subsection", parent=styles["Heading2"], fontName="Helvetica-Bold",
                              fontSize=11, leading=14, textColor=colors.HexColor("#374151"),
                              spaceBefore=8, spaceAfter=5))
    styles.add(ParagraphStyle(name="BodyCompact", parent=styles["BodyText"], fontSize=9,
                              leading=13, textColor=colors.HexColor("#374151"),
                              spaceAfter=5))
    styles.add(ParagraphStyle(name="Small", parent=styles["BodyText"], fontSize=8, leading=11,
                              textColor=colors.HexColor("#4b5563")))

    story = []
    scan_id = int(scan["id"])
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    assessment = scan.get("assessment") or {}
    recon = assessment.get("reconnaissance") or {}
    coverage = scan.get("coverage") or {}
    findings = scan.get("findings") or []

    story.extend([
        Spacer(1, 24 * mm),
        Paragraph("WAPT Security Assessment Report", styles["ReportTitle"]),
        Spacer(1, 8 * mm),
        Paragraph(redact_sensitive(scan.get("target") or "Unknown target"), styles["Heading2"]),
        Spacer(1, 12 * mm),
        Table([
            ["Assessment ID", str(scan_id)],
            ["Target website", redact_sensitive(scan.get("target") or "—")],
            ["Assessment date", str(scan.get("created_at") or "—")],
            ["Report generated", generated],
            ["Report version", "WAPT PDF 3.0"],
            ["Scanner version", str(scan.get("scanner_version") or "1.0.0")],
        ], colWidths=[42 * mm, 118 * mm], style=[
            ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#374151")),
            ("LINEBELOW", (0, 0), (-1, -1), 0.25, colors.HexColor("#d1d5db")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]),
        Spacer(1, 18 * mm),
        Paragraph("Confidentiality notice", styles["Subsection"]),
        Paragraph("This report is confidential and intended only for the authorized target owner or assessment team. "
                  "Findings are baseline assessment observations, not evidence of exploitability or certification.",
                  styles["BodyCompact"]),
    ])

    story.append(Spacer(1, 10 * mm))
    story.append(Paragraph("Table of Contents", styles["Section"]))
    toc = TableOfContents()
    toc.levelStyles = [
        ParagraphStyle(name="TOC0", fontName="Helvetica", fontSize=9, leading=12,
                       leftIndent=0, textColor=colors.HexColor("#111827")),
        ParagraphStyle(name="TOC1", fontName="Helvetica", fontSize=8, leading=11,
                       leftIndent=12, textColor=colors.HexColor("#4b5563")),
    ]
    story.append(toc)

    story.append(Paragraph("Executive Summary", styles["Section"]))
    score = scan.get("score")
    counts = scan.get("counts") or {}
    confirmed = sum(1 for item in findings if str(item.get("observation_type", "")).startswith("confirmed") or
                    str(item.get("confidence", "")).lower() == "confirmed")
    potential = sum(1 for item in findings if str(item.get("observation_type", "")).startswith("potential") or
                    str(item.get("confidence", "")).lower() == "potential")
    executive_rows = [
        ["Metric", "Value"],
        ["Target", redact_sensitive(scan.get("target") or "—")],
        ["Security posture score", "Insufficient assessment coverage" if score is None else f"{score}/100"],
        ["Assessment coverage", f"{coverage.get('percentage', 0)}% ({coverage.get('tested', 0)} of {coverage.get('total', 0)} checks)"],
        ["Confirmed findings", str(confirmed)],
        ["Potential findings", str(potential)],
        ["Critical / High / Medium", f"{counts.get('critical', 0)} / {counts.get('high', 0)} / {counts.get('medium', 0)}"],
        ["Low / Informational", f"{counts.get('low', 0)} / {counts.get('info', 0)}"],
    ]
    story.append(Table(executive_rows, colWidths=[55 * mm, 105 * mm], repeatRows=1, style=[
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111827")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#d1d5db")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))

    story.append(Paragraph("Risk Overview", styles["Section"]))
    severity_rows = [["Severity", "Count"]]
    for severity in ("critical", "high", "medium", "low", "info"):
        severity_rows.append([severity.title(), str(counts.get(severity, 0))])
    story.append(Table(severity_rows, colWidths=[55 * mm, 105 * mm], repeatRows=1, style=[
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#374151")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#d1d5db")),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))

    important = [item for item in findings if item.get("severity") in {"critical", "high"}]
    story.append(Paragraph("Most important findings", styles["Subsection"]))
    if important:
        story.append(Paragraph("<br/>".join(
            f"<b>{redact_sensitive(item.get('title'))}</b> - "
            f"{redact_sensitive(item.get('affected_url') or scan.get('final_url') or 'Affected resource not recorded')}"
            for item in important[:8]), styles["BodyCompact"]))
    else:
        story.append(Paragraph("No Critical or High findings were recorded by this baseline assessment.", styles["BodyCompact"]))

    story.append(Paragraph("Technical Findings", styles["Section"]))
    if findings:
        severity_colors = {
            "critical": "#991b1b", "high": "#b45309", "medium": "#a16207",
            "low": "#2563eb", "info": "#4b5563",
        }
        for index, finding in enumerate(findings, 1):
            finding_id = _finding_id(scan_id, finding, index)
            severity = str(finding.get("severity", "info")).lower()
            story.append(Paragraph(f"{finding_id}: {redact_sensitive(finding.get('title') or 'Untitled finding')}",
                                   styles["Subsection"]))
            details = [
                ["Severity", severity.title()],
                ["Confidence", str(finding.get("confidence") or "Not recorded").title()],
                ["Affected URL", redact_sensitive(finding.get("affected_url") or scan.get("final_url") or "—")],
                ["Category", redact_sensitive(finding.get("category") or "—")],
                ["Observed evidence", redact_sensitive(finding.get("evidence") or "—")],
                ["Technical explanation", redact_sensitive(finding.get("description") or "—")],
                ["Security impact", redact_sensitive(finding.get("impact") or finding.get("description") or "—")],
                ["Recommended remediation", redact_sensitive(finding.get("recommendation") or "—")],
                ["Verification steps", redact_sensitive(finding.get("verification") or "—")],
            ]
            table = Table(details, colWidths=[38 * mm, 122 * mm], style=[
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#374151")),
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(severity_colors.get(severity, "#4b5563"))),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#d1d5db")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ])
            story.append(table)
            story.append(Spacer(1, 5 * mm))
    else:
        story.append(Paragraph("No findings were recorded. This does not prove the target is secure.",
                               styles["BodyCompact"]))

    story.append(Paragraph("Assessment Methodology", styles["Section"]))
    tested = coverage.get("checks") or {}
    scope_rows = [
        ["Item", "Result"],
        ["Target URL", redact_sensitive(scan.get("target") or "—")],
        ["Final URL", redact_sensitive(scan.get("final_url") or "—")],
        ["Pages assessed", str(coverage.get("pages_assessed", 0))],
        ["Checks performed", str(coverage.get("tested", 0))],
        ["Coverage percentage", f"{coverage.get('percentage', 0)}%"],
        ["Methodology version", str(scan.get("methodology_version") or "Not recorded")],
    ]
    for name, status in tested.items():
        scope_rows.append([f"Check: {name}", str(status).replace("_", " ").title()])
    story.append(Table(scope_rows, colWidths=[55 * mm, 105 * mm], repeatRows=1, style=[
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#374151")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#d1d5db")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(Paragraph(
        "The assessment is passive and baseline-only. It does not include authenticated crawling, "
        "source-code review, credential attacks, SQL injection testing, exploit verification, or "
        "a full OWASP certification assessment.",
        styles["BodyCompact"]))

    story.append(Paragraph("Remediation Roadmap", styles["Section"]))
    priority_groups = [
        ("Critical and High", {"critical", "high"}),
        ("Medium", {"medium"}),
        ("Low and Informational", {"low", "info"}),
    ]
    for label, severities in priority_groups:
        grouped = [item for item in findings if str(item.get("severity", "")).lower() in severities]
        story.append(Paragraph(label, styles["Subsection"]))
        if grouped:
            story.append(Paragraph("<br/>".join(
                f"{index + 1}. {redact_sensitive(item.get('title'))}: "
                f"{redact_sensitive(item.get('recommendation'))}"
                for index, item in enumerate(grouped[:12])), styles["BodyCompact"]))
        else:
            story.append(Paragraph("No findings in this priority group.", styles["BodyCompact"]))

    story.append(Paragraph("Technical Appendix", styles["Section"]))
    headers = redact_headers(recon.get("headers") or {})
    if headers:
        header_rows = [["Header", "Observed value"]]
        for name, value in sorted(headers.items()):
            header_rows.append([name, redact_sensitive(value)])
        story.append(Table(header_rows, colWidths=[55 * mm, 105 * mm], repeatRows=1, style=[
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#374151")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 7),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#d1d5db")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
    else:
        story.append(Paragraph("No relevant HTTP headers were stored for this assessment.", styles["BodyCompact"]))

    technologies = recon.get("technologies") or []
    story.append(Paragraph("Technology observations", styles["Subsection"]))
    if technologies:
        tech_rows = [["Technology", "Source", "Evidence", "Confidence"]]
        for tech in technologies:
            tech_rows.append([
                redact_sensitive(tech.get("name") or "Unknown"),
                redact_sensitive(tech.get("source") or tech.get("name") or "Unknown"),
                redact_sensitive(tech.get("evidence") or tech.get("value") or "—"),
                redact_sensitive(tech.get("confidence") or "unknown"),
            ])
        story.append(Table(tech_rows, colWidths=[35 * mm, 35 * mm, 64 * mm, 26 * mm], repeatRows=1, style=[
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#374151")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 7),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#d1d5db")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
    else:
        story.append(Paragraph("No reliable technology fingerprint was established.", styles["BodyCompact"]))

    doc.multiBuild(story)
    output.seek(0)
    return output
