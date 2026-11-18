"""Client-Ready Branded PDF Report Generator using ReportLab."""
from __future__ import annotations

import html
import io
from datetime import datetime
from typing import Dict, List, Optional
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from auditors.base import AuditIssue, AuditResult, Category, Severity
from crawler.spider import CrawlResult


def safe_xml(text: any) -> str:
    """Escapes XML entities so arbitrary HTML/symbols in audit evidence won't break ReportLab parser."""
    if text is None:
        return ""
    return html.escape(str(text))


class NumberedCanvas:
    """Canvas helper that adds page numbers in footer."""
    pass


class PDFReportGenerator:
    """Generates high-impact, presentation-grade client PDF reports."""

    def __init__(
        self,
        crawl_result: CrawlResult,
        audit_results: Dict[Category, AuditResult],
        all_issues: List[AuditIssue],
    ):
        self.crawl_result = crawl_result
        self.audit_results = audit_results
        self.all_issues = all_issues

    def generate(self, file_path_or_buffer: any):
        """Compiles story elements and builds PDF document."""
        doc = SimpleDocTemplate(
            file_path_or_buffer,
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=40,
            bottomMargin=40,
        )

        styles = getSampleStyleSheet()

        # Custom typography styles
        title_style = ParagraphStyle(
            "DocTitle",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=22,
            leading=26,
            textColor=colors.HexColor("#0F172A"),
        )
        subtitle_style = ParagraphStyle(
            "DocSubTitle",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=11,
            leading=15,
            textColor=colors.HexColor("#475569"),
        )
        section_style = ParagraphStyle(
            "SectionH2",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=14,
            leading=18,
            textColor=colors.HexColor("#1E293B"),
            spaceBefore=14,
            spaceAfter=8,
        )
        issue_title_style = ParagraphStyle(
            "IssueTitle",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=11,
            leading=14,
            textColor=colors.HexColor("#0F172A"),
        )
        body_style = ParagraphStyle(
            "BodyDark",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=9,
            leading=12,
            textColor=colors.HexColor("#334155"),
        )
        code_style = ParagraphStyle(
            "CodeBlock",
            parent=styles["Normal"],
            fontName="Courier",
            fontSize=8,
            leading=10,
            textColor=colors.HexColor("#0F172A"),
            backColor=colors.HexColor("#F8FAFC"),
        )

        story = []

        # 1. Header Banner
        overall_score = round(sum(r.score for r in self.audit_results.values()) / max(1, len(self.audit_results)))
        score_color = "#22C55E" if overall_score >= 80 else ("#EAB308" if overall_score >= 50 else "#EF4444")

        header_data = [
            [
                Paragraph("<b>WEBSITE AUDIT & SECURITY REPORT</b>", title_style),
                Paragraph(
                    f"<font size=20 color='{score_color}'><b>{overall_score}/100</b></font><br/>"
                    f"<font size=8 color='#64748B'>OVERALL HEALTH</font>",
                    ParagraphStyle("ScoreBox", alignment=2)
                ),
            ],
            [
                Paragraph(
                    f"Target: <b>{safe_xml(self.crawl_result.seed_url)}</b> &nbsp;|&nbsp; "
                    f"Analyzed: {datetime.now().strftime('%b %d, %Y')} &nbsp;|&nbsp; "
                    f"URLs Crawled: {len(self.crawl_result.pages)}",
                    subtitle_style
                ),
                "",
            ]
        ]
        header_table = Table(header_data, colWidths=[400, 140])
        header_table.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("SPAN", (0, 1), (1, 1)),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(header_table)
        story.append(Spacer(1, 10))
        story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#CBD5E1"), spaceAfter=15))

        # 2. Executive Scorecard Table
        story.append(Paragraph("Category Health Scorecard", section_style))

        scorecard_rows = [
            [
                Paragraph("<b>Audit Domain</b>", body_style),
                Paragraph("<b>Score</b>", body_style),
                Paragraph("<b>Rating</b>", body_style),
                Paragraph("<b>Issues</b>", body_style),
                Paragraph("<b>Passed Checks</b>", body_style),
            ]
        ]

        for cat in [Category.SEO, Category.SECURITY, Category.PERFORMANCE, Category.OFFPAGE]:
            res = self.audit_results.get(cat)
            score = res.score if res else 100
            rating = "Excellent" if score >= 90 else ("Good" if score >= 70 else ("Fair" if score >= 50 else "Poor"))
            c_color = "#16A34A" if score >= 80 else ("#CA8A04" if score >= 50 else "#DC2626")

            scorecard_rows.append([
                Paragraph(safe_xml(cat.value), body_style),
                Paragraph(f"<font color='{c_color}'><b>{score}/100</b></font>", body_style),
                Paragraph(safe_xml(rating), body_style),
                Paragraph(str(len(res.issues) if res else 0), body_style),
                Paragraph(str(len(res.passed_checks) if res else 0), body_style),
            ])

        score_table = Table(scorecard_rows, colWidths=[180, 80, 80, 80, 120])
        score_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1E293B")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("ALIGN", (1, 0), (-1, -1), "CENTER"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(score_table)
        story.append(Spacer(1, 15))

        # 3. Passed Checks
        story.append(Paragraph("Key Passed Health Checks", section_style))
        all_passed = []
        for r in self.audit_results.values():
            all_passed.extend(r.passed_checks)

        if all_passed:
            passed_items = []
            for check in all_passed[:6]:  # Highlight top 6 passed checks
                passed_items.append([
                    Paragraph("<font color='#16A34A'><b>[PASS]</b></font>", body_style),
                    Paragraph(safe_xml(check), body_style),
                ])
            passed_table = Table(passed_items, colWidths=[55, 485])
            passed_table.setStyle(TableStyle([
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]))
            story.append(passed_table)
        story.append(Spacer(1, 15))

        # 4. Actionable Remediation Roadmap
        story.append(Paragraph("Priority Remediation Roadmap", section_style))

        # Sort issues by severity weight descending
        sorted_issues = sorted(self.all_issues, key=lambda x: x.severity.weight, reverse=True)

        if not sorted_issues:
            story.append(Paragraph("Zero critical or high issues detected! Website shows excellent hygiene.", body_style))
        else:
            # Show up to top 15 priority issues
            for issue in sorted_issues[:15]:
                sev_color = {
                    Severity.CRITICAL: "#DC2626",
                    Severity.HIGH: "#EA580C",
                    Severity.MEDIUM: "#D97706",
                    Severity.LOW: "#2563EB",
                    Severity.INFO: "#4B5563",
                }.get(issue.severity, "#4B5563")

                bad_sign_str = issue.bad_sign or issue.title
                why_bad_str = issue.why_bad or issue.description

                issue_box = [
                    [
                        Paragraph(
                            f"<font color='{sev_color}'><b>[{issue.severity.value.upper()}]</b></font> "
                            f"<b>{safe_xml(issue.title)}</b> &nbsp;&nbsp;<font size=7 color='#64748B'>({safe_xml(issue.category.value)})</font>",
                            issue_title_style
                        )
                    ],
                    [Paragraph(f"<b><font color='#DC2626'>Bad Sign:</font></b> {safe_xml(bad_sign_str)}", body_style)],
                    [Paragraph(f"<b><font color='#D97706'>Why It's Bad (Security Risk):</font></b> {safe_xml(why_bad_str)}", body_style)],
                    [Paragraph(f"<b>Evidence:</b> {safe_xml(issue.evidence)}", body_style)],
                ]

                # If remediation code exists, display snippet
                sol_code = issue.solution_nginx or issue.solution_apache or issue.solution_code
                if sol_code:
                    clean_code = safe_xml(sol_code.strip())
                    code_lines = clean_code.splitlines()[:6]
                    disp_code = "<br/>".join(code_lines)
                    issue_box.append([Paragraph(f"<b>Remediation Code:</b><br/>{disp_code}", code_style)])

                issue_table = Table(issue_box, colWidths=[540])
                issue_table.setStyle(TableStyle([
                    ("BOX", (0, 0), (-1, -1), 1, colors.HexColor(sev_color)),
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#FFFFFF")),
                    ("TOPPADDING", (0, 0), (-1, -1), 5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                    ("LEFTPADDING", (0, 0), (-1, -1), 8),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ]))

                story.append(KeepTogether([issue_table, Spacer(1, 8)]))

        doc.build(story)
