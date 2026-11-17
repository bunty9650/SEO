"""CLI runner for All-in-One Website Audit, SEO, Security, Performance & Report Generator."""
from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

# Configure UTF-8 for Windows PowerShell / CMD
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

console = Console(force_terminal=True, legacy_windows=False)

from crawler.spider import WebSpider
from auditors.seo_auditor import SEOAuditor
from auditors.security_auditor import SecurityAuditor
from auditors.performance_auditor import PerformanceAuditor
from auditors.offpage_auditor import OffPageAuditor
from auditors.base import Category, Severity
from reports.excel_generator import ExcelReportGenerator
from reports.pdf_generator import PDFReportGenerator


def render_score_badge(score: int) -> Text:
    if score >= 90:
        return Text(f"{score}/100 [EXCELLENT]", style="bold green")
    elif score >= 70:
        return Text(f"{score}/100 [GOOD]", style="bold yellow")
    elif score >= 50:
        return Text(f"{score}/100 [FAIR]", style="bold dark_orange")
    else:
        return Text(f"{score}/100 [POOR]", style="bold red")


async def main_async(
    url: str,
    max_urls: int = 15,
    max_depth: int = 2,
    pagespeed_key: str = None,
    openpagerank_key: str = None,
    excel_path: str = None,
    pdf_path: str = None,
):
    console.print(Panel.fit(
        f"[bold cyan]All-in-One Website Audit & Diagnostic Suite[/bold cyan]\n"
        f"Target: [bold white]{url}[/bold white] | Max URLs: {max_urls} | Max Depth: {max_depth}",
        border_style="cyan"
    ))

    # 1. Run Crawler
    with console.status("[bold green]Crawling website internal pages...", spinner="dots"):
        spider = WebSpider(seed_url=url, max_urls=max_urls, max_depth=max_depth)
        crawl_result = await spider.crawl()

    console.print(
        f"[green][OK][/green] Crawl complete: [bold]{len(crawl_result.pages)}[/bold] URLs analyzed "
        f"in [bold]{crawl_result.duration_seconds}s[/bold]."
    )

    seed_page = crawl_result.pages[0] if crawl_result.pages else None
    seed_headers = seed_page.headers if seed_page else None
    insecure_assets = seed_page.insecure_resources if seed_page else None
    seed_html = seed_page.raw_html if seed_page else None
    seed_ttfb = seed_page.response_time_ms if seed_page else 150.0

    # 2. Run Module A: SEO Auditor
    with console.status("[bold green]Auditing Technical & On-Page SEO...", spinner="dots"):
        seo_auditor = SEOAuditor(crawl_result)
        seo_result = seo_auditor.run()

    # 3. Run Module B: Security Auditor
    with console.status("[bold green]Auditing SSL & Website Security...", spinner="dots"):
        sec_auditor = SecurityAuditor(url)
        sec_result = await sec_auditor.run(
            headers=seed_headers,
            insecure_resources=insecure_assets,
        )

    # 4. Run Module C: Performance Auditor
    with console.status("[bold green]Auditing UI & Performance Vitals...", spinner="dots"):
        perf_auditor = PerformanceAuditor(
            target_url=url,
            api_key=pagespeed_key,
            html_content=seed_html,
            ttfb_ms=seed_ttfb,
        )
        perf_result = await perf_auditor.run()

    # 5. Run Module D: Off-Page Auditor
    with console.status("[bold green]Auditing Off-Page & Social Signals...", spinner="dots"):
        offpage_auditor = OffPageAuditor(
            crawl_result=crawl_result,
            openpagerank_key=openpagerank_key,
        )
        offpage_result = await offpage_auditor.run()

    audit_results = {
        Category.SEO: seo_result,
        Category.SECURITY: sec_result,
        Category.PERFORMANCE: perf_result,
        Category.OFFPAGE: offpage_result,
    }

    # Display Scores
    console.print("\n")
    score_table = Table(title="Audit Scorecard Summary", expand=True)
    score_table.add_column("Category", style="cyan", no_wrap=True)
    score_table.add_column("Score", justify="center")
    score_table.add_column("Issues Found", justify="center")
    score_table.add_column("Passed Checks", justify="center")

    for cat in [Category.SEO, Category.SECURITY, Category.PERFORMANCE, Category.OFFPAGE]:
        res = audit_results[cat]
        score_table.add_row(
            res.category.value,
            render_score_badge(res.score),
            str(len(res.issues)),
            str(len(res.passed_checks)),
        )
    console.print(score_table)

    # Aggregate Issues
    all_issues = []
    for res in audit_results.values():
        all_issues.extend(res.issues)
    all_issues.sort(key=lambda x: x.severity.weight, reverse=True)

    # Display Top Issues
    if all_issues:
        console.print("\n[bold red][!] Priority Detected Issues & Remediation Roadmap:[/bold red]")
        for issue in all_issues[:10]:
            sev_color = {
                Severity.CRITICAL: "bold white on red",
                Severity.HIGH: "bold white on red",
                Severity.MEDIUM: "bold black on yellow",
                Severity.LOW: "bold white on blue",
                Severity.INFO: "bold white on black",
            }.get(issue.severity, "white")

            header_text = Text()
            header_text.append(f" [{issue.severity.value.upper()}] ", style=sev_color)
            header_text.append(f" {issue.title} ", style="bold white")

            content = (
                f"[bold]Category:[/bold] {issue.category.value}\n"
                f"[bold]Evidence:[/bold] {issue.evidence}\n"
                f"[bold]Description:[/bold] {issue.description}\n"
            )

            if issue.solution_nginx or issue.solution_apache or issue.solution_code:
                content += "\n[bold green]Automated Remediation Code:[/bold green]\n"
                if issue.solution_nginx:
                    content += f"[bold cyan]Nginx Configuration:[/bold cyan]\n```nginx\n{issue.solution_nginx}\n```\n"
                if issue.solution_apache:
                    content += f"[bold cyan]Apache .htaccess:[/bold cyan]\n```apache\n{issue.solution_apache}\n```\n"
                if issue.solution_code:
                    content += f"[bold cyan]HTML / Code Fix:[/bold cyan]\n```html\n{issue.solution_code}\n```\n"

            console.print(Panel(content, title=header_text, border_style="red" if issue.severity in [Severity.CRITICAL, Severity.HIGH] else "yellow"))
    else:
        console.print("\n[bold green]No critical issues found! Website demonstrates excellent hygiene.[/bold green]")

    # Export Reports if requested
    if excel_path:
        with console.status(f"[bold cyan]Generating Excel report ({excel_path})...", spinner="dots"):
            ex_gen = ExcelReportGenerator(crawl_result, audit_results, all_issues)
            ex_gen.generate(excel_path)
        console.print(f"[bold green][OK][/bold green] Excel report saved successfully: [bold]{excel_path}[/bold]")

    if pdf_path:
        with console.status(f"[bold cyan]Generating PDF report ({pdf_path})...", spinner="dots"):
            pdf_gen = PDFReportGenerator(crawl_result, audit_results, all_issues)
            pdf_gen.generate(pdf_path)
        console.print(f"[bold green][OK][/bold green] PDF report saved successfully: [bold]{pdf_path}[/bold]")


def main():
    parser = argparse.ArgumentParser(description="All-in-One Website Audit, SEO, Security & UI Diagnostic Suite")
    parser.add_argument("url", help="Target URL (e.g. https://example.com or http://127.0.0.1:9000)")
    parser.add_argument("--max-urls", type=int, default=15, help="Max URLs to crawl (default: 15)")
    parser.add_argument("--max-depth", type=int, default=2, help="Max crawl depth (default: 2)")
    parser.add_argument("--pagespeed-key", type=str, default=None, help="Google PageSpeed API key (optional)")
    parser.add_argument("--openpagerank-key", type=str, default=None, help="OpenPageRank API key (optional)")
    parser.add_argument("--excel", type=str, default=None, help="Output path for Excel workbook (.xlsx)")
    parser.add_argument("--pdf", type=str, default=None, help="Output path for PDF report (.pdf)")

    args = parser.parse_args()
    asyncio.run(main_async(
        url=args.url,
        max_urls=args.max_urls,
        max_depth=args.max_depth,
        pagespeed_key=args.pagespeed_key,
        openpagerank_key=args.openpagerank_key,
        excel_path=args.excel,
        pdf_path=args.pdf,
    ))


if __name__ == "__main__":
    main()
