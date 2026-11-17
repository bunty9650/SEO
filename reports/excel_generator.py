"""Multi-tab Excel Report Generator using openpyxl."""
from __future__ import annotations

import io
from typing import Dict, List, Optional
import openpyxl
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter

from auditors.base import AuditIssue, AuditResult, Category, Severity
from crawler.spider import CrawlResult, PageData


class ExcelReportGenerator:
    """Generates styled multi-tab .xlsx audit workbooks for client presentation."""

    # Color palette
    NAVY_FILL = PatternFill(start_color="1E293B", end_color="1E293B", fill_type="solid")
    HEADER_FONT = Font(name="Calibri", size=11, bold=True, color="FFFFFF")
    TITLE_FONT = Font(name="Calibri", size=16, bold=True, color="1E293B")
    SECTION_FONT = Font(name="Calibri", size=13, bold=True, color="0F172A")
    BOLD_FONT = Font(name="Calibri", size=10, bold=True)
    NORMAL_FONT = Font(name="Calibri", size=10)
    CODE_FONT = Font(name="Consolas", size=9)

    SEVERITY_FILLS = {
        Severity.CRITICAL: PatternFill(start_color="FEE2E2", end_color="FEE2E2", fill_type="solid"),  # Light red
        Severity.HIGH: PatternFill(start_color="FFEDD5", end_color="FFEDD5", fill_type="solid"),      # Light orange
        Severity.MEDIUM: PatternFill(start_color="FEF3C7", end_color="FEF3C7", fill_type="solid"),    # Light yellow
        Severity.LOW: PatternFill(start_color="E0E7FF", end_color="E0E7FF", fill_type="solid"),       # Light blue
        Severity.INFO: PatternFill(start_color="F1F5F9", end_color="F1F5F9", fill_type="solid"),      # Light gray
    }

    SEVERITY_FONTS = {
        Severity.CRITICAL: Font(name="Calibri", size=10, bold=True, color="991B1B"),
        Severity.HIGH: Font(name="Calibri", size=10, bold=True, color="9A3412"),
        Severity.MEDIUM: Font(name="Calibri", size=10, bold=True, color="92400E"),
        Severity.LOW: Font(name="Calibri", size=10, bold=True, color="3730A3"),
        Severity.INFO: Font(name="Calibri", size=10, bold=True, color="475569"),
    }

    THIN_BORDER = Border(
        left=Side(style="thin", color="E2E8F0"),
        right=Side(style="thin", color="E2E8F0"),
        top=Side(style="thin", color="E2E8F0"),
        bottom=Side(style="thin", color="E2E8F0"),
    )

    def __init__(
        self,
        crawl_result: CrawlResult,
        audit_results: Dict[Category, AuditResult],
        all_issues: List[AuditIssue],
    ):
        self.crawl_result = crawl_result
        self.audit_results = audit_results
        self.all_issues = all_issues
        self.wb = openpyxl.Workbook()

    def generate(self, file_path_or_buffer: any):
        """Builds all tabs and writes out the workbook."""
        # 1. Executive Summary
        ws_summary = self.wb.active
        ws_summary.title = "Executive Summary"
        self._build_summary_tab(ws_summary)

        # 2. Crawled URLs
        ws_urls = self.wb.create_sheet(title="Crawled URLs")
        self._build_crawled_urls_tab(ws_urls)

        # 3. Actionable Issues & Fixes
        ws_issues = self.wb.create_sheet(title="Actionable Issues & Fixes")
        self._build_issues_tab(ws_issues)

        # 4. Image & Asset Audit
        ws_assets = self.wb.create_sheet(title="Image Assets Audit")
        self._build_assets_tab(ws_assets)

        # Save
        if isinstance(file_path_or_buffer, (str, bytes)):
            self.wb.save(file_path_or_buffer)
        else:
            self.wb.save(file_path_or_buffer)

    def _auto_fit_columns(self, ws, max_width_limit: int = 60):
        """Auto-adjusts column widths based on contents."""
        for col in ws.columns:
            max_len = 0
            col_letter = get_column_letter(col[0].column)
            for cell in col:
                val = cell.value
                if val:
                    val_str = str(val)
                    if "\n" in val_str:
                        lines = val_str.split("\n")
                        max_len = max(max_len, max(len(l) for l in lines))
                    else:
                        max_len = max(max_len, len(val_str))
            ws.column_dimensions[col_letter].width = min(max_width_limit, max(max_len + 3, 12))

    def _build_summary_tab(self, ws):
        ws.views.sheetView[0].showGridLines = True

        # Title
        ws["A1"] = "WEBSITE AUDIT & DIAGNOSTIC EXECUTIVE REPORT"
        ws["A1"].font = self.TITLE_FONT
        ws["A2"] = f"Target Domain: {self.crawl_result.seed_url}"
        ws["A2"].font = Font(name="Calibri", size=11, bold=True, color="475569")

        # Health Scores Table
        ws["A4"] = "CATEGORY HEALTH SCORES"
        ws["A4"].font = self.SECTION_FONT

        headers = ["Audit Category", "Score (0-100)", "Health Rating", "Issues Count", "Passed Checks"]
        for col_idx, h in enumerate(headers, start=1):
            cell = ws.cell(row=5, column=col_idx, value=h)
            cell.fill = self.NAVY_FILL
            cell.font = self.HEADER_FONT
            cell.alignment = Alignment(horizontal="center", vertical="center")

        row_idx = 6
        for cat in [Category.SEO, Category.SECURITY, Category.PERFORMANCE, Category.OFFPAGE]:
            res = self.audit_results.get(cat)
            score = res.score if res else 100
            rating = "Excellent" if score >= 90 else ("Good" if score >= 70 else ("Fair" if score >= 50 else "Poor"))
            issues_cnt = len(res.issues) if res else 0
            passed_cnt = len(res.passed_checks) if res else 0

            ws.cell(row=row_idx, column=1, value=cat.value).font = self.NORMAL_FONT
            score_cell = ws.cell(row=row_idx, column=2, value=score)
            score_cell.font = self.BOLD_FONT
            score_cell.alignment = Alignment(horizontal="center")

            rate_cell = ws.cell(row=row_idx, column=3, value=rating)
            rate_cell.font = self.NORMAL_FONT
            rate_cell.alignment = Alignment(horizontal="center")

            ws.cell(row=row_idx, column=4, value=issues_cnt).alignment = Alignment(horizontal="center")
            ws.cell(row=row_idx, column=5, value=passed_cnt).alignment = Alignment(horizontal="center")

            for c in range(1, 6):
                ws.cell(row=row_idx, column=c).border = self.THIN_BORDER
            row_idx += 1

        # Issue Breakdown Table
        row_idx += 2
        ws.cell(row=row_idx, column=1, value="ISSUES BREAKDOWN BY SEVERITY").font = self.SECTION_FONT
        row_idx += 1

        sev_headers = ["Severity Level", "Issue Count", "Impact Description"]
        for col_idx, h in enumerate(sev_headers, start=1):
            cell = ws.cell(row=row_idx, column=col_idx, value=h)
            cell.fill = self.NAVY_FILL
            cell.font = self.HEADER_FONT
            cell.alignment = Alignment(horizontal="center", vertical="center")

        row_idx += 1
        sev_counts = {sev: sum(1 for i in self.all_issues if i.severity == sev) for sev in Severity}

        sev_desc = {
            Severity.CRITICAL: "Immediate security vulnerability or complete de-indexing risk",
            Severity.HIGH: "Major organic ranking penalty or user experience defect",
            Severity.MEDIUM: "Suboptimal configuration degrading crawlability or speed",
            Severity.LOW: "Minor hygiene issue or missing optional enhancement",
            Severity.INFO: "Informational note or advisory suggestion",
        }

        for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            cnt = sev_counts.get(sev, 0)
            cell_sev = ws.cell(row=row_idx, column=1, value=sev.value)
            cell_sev.fill = self.SEVERITY_FILLS[sev]
            cell_sev.font = self.SEVERITY_FONTS[sev]
            cell_sev.alignment = Alignment(horizontal="center")

            cnt_cell = ws.cell(row=row_idx, column=2, value=cnt)
            cnt_cell.font = self.BOLD_FONT
            cnt_cell.alignment = Alignment(horizontal="center")

            ws.cell(row=row_idx, column=3, value=sev_desc[sev]).font = self.NORMAL_FONT

            for c in range(1, 4):
                ws.cell(row=row_idx, column=c).border = self.THIN_BORDER
            row_idx += 1

        self._auto_fit_columns(ws)

    def _build_crawled_urls_tab(self, ws):
        ws.views.sheetView[0].showGridLines = True
        headers = [
            "URL", "Status Code", "Response Time (ms)", "Page Title", "Title Length",
            "Meta Description", "Desc Length", "H1 Headings", "Word Count", "Indexable?"
        ]

        for col_idx, h in enumerate(headers, start=1):
            cell = ws.cell(row=1, column=col_idx, value=h)
            cell.fill = self.NAVY_FILL
            cell.font = self.HEADER_FONT
            cell.alignment = Alignment(horizontal="center", vertical="center")

        for row_idx, page in enumerate(self.crawl_result.pages, start=2):
            ws.cell(row=row_idx, column=1, value=page.url).font = self.NORMAL_FONT

            status_cell = ws.cell(row=row_idx, column=2, value=page.status_code)
            status_cell.alignment = Alignment(horizontal="center")
            status_cell.font = self.BOLD_FONT

            time_cell = ws.cell(row=row_idx, column=3, value=page.response_time_ms)
            time_cell.alignment = Alignment(horizontal="center")

            ws.cell(row=row_idx, column=4, value=page.title or "N/A").font = self.NORMAL_FONT
            ws.cell(row=row_idx, column=5, value=len(page.title) if page.title else 0).alignment = Alignment(horizontal="center")

            ws.cell(row=row_idx, column=6, value=page.meta_description or "N/A").font = self.NORMAL_FONT
            ws.cell(row=row_idx, column=7, value=len(page.meta_description) if page.meta_description else 0).alignment = Alignment(horizontal="center")

            h1_text = " | ".join(page.h1_headings) if page.h1_headings else "None"
            ws.cell(row=row_idx, column=8, value=h1_text).font = self.NORMAL_FONT

            ws.cell(row=row_idx, column=9, value=page.word_count).alignment = Alignment(horizontal="center")
            ws.cell(row=row_idx, column=10, value="Yes" if page.is_indexable else "No (noindex)").alignment = Alignment(horizontal="center")

            for c in range(1, 11):
                ws.cell(row=row_idx, column=c).border = self.THIN_BORDER

        self._auto_fit_columns(ws)

    def _build_issues_tab(self, ws):
        ws.views.sheetView[0].showGridLines = True
        headers = [
            "Severity", "Category", "Issue Title", "Affected URL",
            "Evidence", "Description", "Nginx Configuration Fix",
            "Apache .htaccess Fix", "HTML / Code Fix"
        ]

        for col_idx, h in enumerate(headers, start=1):
            cell = ws.cell(row=1, column=col_idx, value=h)
            cell.fill = self.NAVY_FILL
            cell.font = self.HEADER_FONT
            cell.alignment = Alignment(horizontal="center", vertical="center")

        # Sort issues by severity weight descending
        sorted_issues = sorted(self.all_issues, key=lambda x: x.severity.weight, reverse=True)

        for row_idx, issue in enumerate(sorted_issues, start=2):
            cell_sev = ws.cell(row=row_idx, column=1, value=issue.severity.value)
            cell_sev.fill = self.SEVERITY_FILLS[issue.severity]
            cell_sev.font = self.SEVERITY_FONTS[issue.severity]
            cell_sev.alignment = Alignment(horizontal="center")

            ws.cell(row=row_idx, column=2, value=issue.category.value).font = self.NORMAL_FONT
            ws.cell(row=row_idx, column=3, value=issue.title).font = self.BOLD_FONT
            ws.cell(row=row_idx, column=4, value=issue.url or "Global / Domain").font = self.NORMAL_FONT
            ws.cell(row=row_idx, column=5, value=issue.evidence).font = self.NORMAL_FONT

            desc_cell = ws.cell(row=row_idx, column=6, value=issue.description)
            desc_cell.font = self.NORMAL_FONT
            desc_cell.alignment = Alignment(wrap_text=True)

            ng_cell = ws.cell(row=row_idx, column=7, value=issue.solution_nginx or "N/A")
            ng_cell.font = self.CODE_FONT
            ng_cell.alignment = Alignment(wrap_text=True)

            ap_cell = ws.cell(row=row_idx, column=8, value=issue.solution_apache or "N/A")
            ap_cell.font = self.CODE_FONT
            ap_cell.alignment = Alignment(wrap_text=True)

            code_cell = ws.cell(row=row_idx, column=9, value=issue.solution_code or "N/A")
            code_cell.font = self.CODE_FONT
            code_cell.alignment = Alignment(wrap_text=True)

            for c in range(1, 10):
                ws.cell(row=row_idx, column=c).border = self.THIN_BORDER

        self._auto_fit_columns(ws, max_width_limit=50)

    def _build_assets_tab(self, ws):
        ws.views.sheetView[0].showGridLines = True
        headers = ["Page URL", "Asset Type", "Image Source URL", "Alt Text", "Missing Alt?", "Insecure HTTP?"]

        for col_idx, h in enumerate(headers, start=1):
            cell = ws.cell(row=1, column=col_idx, value=h)
            cell.fill = self.NAVY_FILL
            cell.font = self.HEADER_FONT
            cell.alignment = Alignment(horizontal="center", vertical="center")

        row_idx = 2
        for page in self.crawl_result.pages:
            # Images
            for img_src in page.images_missing_alt:
                ws.cell(row=row_idx, column=1, value=page.url).font = self.NORMAL_FONT
                ws.cell(row=row_idx, column=2, value="Image").font = self.NORMAL_FONT
                ws.cell(row=row_idx, column=3, value=img_src).font = self.NORMAL_FONT
                ws.cell(row=row_idx, column=4, value="<Missing>").font = Font(name="Calibri", color="DC2626")
                ws.cell(row=row_idx, column=5, value="YES").font = self.BOLD_FONT
                ws.cell(row=row_idx, column=6, value="YES" if img_src.startswith("http://") else "No").alignment = Alignment(horizontal="center")
                for c in range(1, 7):
                    ws.cell(row=row_idx, column=c).border = self.THIN_BORDER
                row_idx += 1

            for inc in page.insecure_resources:
                ws.cell(row=row_idx, column=1, value=page.url).font = self.NORMAL_FONT
                ws.cell(row=row_idx, column=2, value=inc.get("type", "Resource").capitalize()).font = self.NORMAL_FONT
                ws.cell(row=row_idx, column=3, value=inc.get("src", "")).font = self.NORMAL_FONT
                ws.cell(row=row_idx, column=4, value="N/A").font = self.NORMAL_FONT
                ws.cell(row=row_idx, column=5, value="No").alignment = Alignment(horizontal="center")
                ws.cell(row=row_idx, column=6, value="YES (Insecure)").font = Font(name="Calibri", bold=True, color="DC2626")
                for c in range(1, 7):
                    ws.cell(row=row_idx, column=c).border = self.THIN_BORDER
                row_idx += 1

        self._auto_fit_columns(ws)
