"""Unit tests for Excel and PDF report generators."""
import io
import os
import openpyxl
from reportlab.pdfgen import canvas

from auditors.base import AuditIssue, AuditResult, Category, Severity
from crawler.spider import CrawlResult, PageData
from reports.excel_generator import ExcelReportGenerator
from reports.pdf_generator import PDFReportGenerator
from solutions.solution_database import SolutionDatabase


def get_mock_audit_data():
    page = PageData(
        url="https://example.com/",
        final_url="https://example.com/",
        status_code=200,
        response_time_ms=120.0,
        title="Example Homepage Title",
        meta_description="A good meta description between 120 and 160 characters long for testing reports.",
        h1_headings=["Welcome to Example"],
        word_count=450,
        images_total=2,
        images_missing_alt=["https://example.com/missing-alt.png"],
    )
    crawl = CrawlResult(
        seed_url="https://example.com",
        base_domain="example.com",
        pages=[page],
        total_crawled=1,
    )

    issue1 = SolutionDatabase.build_issue(
        issue_id="SEC_MISSING_HSTS",
        evidence="Missing Strict-Transport-Security header",
        url="https://example.com/",
    )
    issue2 = SolutionDatabase.build_issue(
        issue_id="SEO_IMG_MISSING_ALT",
        evidence="1 image missing alt attribute",
        url="https://example.com/",
    )

    all_issues = [issue1, issue2]
    audit_results = {
        Category.SEO: AuditResult(category=Category.SEO, score=85, issues=[issue2], passed_checks=["Title tag present"]),
        Category.SECURITY: AuditResult(category=Category.SECURITY, score=70, issues=[issue1], passed_checks=["SSL valid"]),
        Category.PERFORMANCE: AuditResult(category=Category.PERFORMANCE, score=90, issues=[], passed_checks=["Fast TTFB"]),
        Category.OFFPAGE: AuditResult(category=Category.OFFPAGE, score=75, issues=[], passed_checks=["Backlinks OK"]),
    }
    return crawl, audit_results, all_issues


def test_excel_generator_creates_valid_workbook(tmp_path):
    crawl, audit_results, all_issues = get_mock_audit_data()
    out_file = str(tmp_path / "test_report.xlsx")

    generator = ExcelReportGenerator(crawl, audit_results, all_issues)
    generator.generate(out_file)

    assert os.path.exists(out_file)
    assert os.path.getsize(out_file) > 1000

    # Verify tabs
    wb = openpyxl.load_workbook(out_file)
    assert "Executive Summary" in wb.sheetnames
    assert "Crawled URLs" in wb.sheetnames
    assert "Actionable Issues & Fixes" in wb.sheetnames
    assert "Image Assets Audit" in wb.sheetnames


def test_pdf_generator_creates_valid_pdf(tmp_path):
    crawl, audit_results, all_issues = get_mock_audit_data()
    out_file = str(tmp_path / "test_report.pdf")

    generator = PDFReportGenerator(crawl, audit_results, all_issues)
    generator.generate(out_file)

    assert os.path.exists(out_file)
    assert os.path.getsize(out_file) > 1000

    # Read PDF header
    with open(out_file, "rb") as f:
        header = f.read(5)
        assert header == b"%PDF-"
