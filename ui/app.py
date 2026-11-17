"""Streamlit Interactive Web Dashboard for All-in-One Website Audit, SEO, Security, UI & Reporting."""
from __future__ import annotations

import asyncio
from datetime import datetime
import io
import os
import streamlit as st
import pandas as pd

from crawler.spider import WebSpider, CrawlResult
from auditors.seo_auditor import SEOAuditor
from auditors.security_auditor import SecurityAuditor
from auditors.performance_auditor import PerformanceAuditor, capture_screenshots
from auditors.offpage_auditor import OffPageAuditor
from auditors.base import Severity, Category, AuditResult
from reports.excel_generator import ExcelReportGenerator
from reports.pdf_generator import PDFReportGenerator

# Page configuration
st.set_page_config(
    page_title="SEO, Security & UI Diagnostic Suite",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom CSS for modern styling
st.markdown("""
<style>
    .metric-card {
        background: #1e293b;
        border: 1px solid #334155;
        border-radius: 12px;
        padding: 18px 12px;
        text-align: center;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
    }
    .score-badge-green { color: #22c55e; font-size: 2.2rem; font-weight: 800; }
    .score-badge-yellow { color: #eab308; font-size: 2.2rem; font-weight: 800; }
    .score-badge-red { color: #ef4444; font-size: 2.2rem; font-weight: 800; }
    .stTabs [data-baseweb="tab-list"] { gap: 8px; }
    .stTabs [data-baseweb="tab"] {
        padding: 10px 18px;
        border-radius: 8px;
        font-weight: 600;
    }
    .vitals-box {
        background: #0f172a;
        border: 1px solid #1e293b;
        border-radius: 10px;
        padding: 15px;
        margin-bottom: 10px;
        text-align: center;
    }
</style>
""", unsafe_allow_html=True)


def get_score_html(score: int, label: str) -> str:
    color_cls = "score-badge-green" if score >= 80 else ("score-badge-yellow" if score >= 50 else "score-badge-red")
    return f"""
    <div class="metric-card">
        <div style="font-size: 0.85rem; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 6px;">{label}</div>
        <div class="{color_cls}">{score}<span style="font-size: 1.1rem; color: #64748b;">/100</span></div>
    </div>
    """


async def run_full_audit(
    target_url: str,
    max_urls: int,
    max_depth: int,
    pagespeed_key: str = None,
    openpagerank_key: str = None,
    take_screenshots: bool = False,
):
    # Step 1: Crawl
    spider = WebSpider(seed_url=target_url, max_urls=max_urls, max_depth=max_depth)
    crawl_result = await spider.crawl()

    seed_page = crawl_result.pages[0] if crawl_result.pages else None
    seed_headers = seed_page.headers if seed_page else None
    insecure_assets = seed_page.insecure_resources if seed_page else None
    seed_html = seed_page.raw_html if seed_page else None
    seed_ttfb = seed_page.response_time_ms if seed_page else 150.0

    # Step 2: Module A - SEO
    seo_auditor = SEOAuditor(crawl_result)
    seo_result = seo_auditor.run()

    # Step 3: Module B - Security
    sec_auditor = SecurityAuditor(target_url)
    sec_result = await sec_auditor.run(headers=seed_headers, insecure_resources=insecure_assets)

    # Step 4: Module C - Performance & Web Vitals
    perf_auditor = PerformanceAuditor(
        target_url=target_url,
        api_key=pagespeed_key,
        html_content=seed_html,
        ttfb_ms=seed_ttfb,
    )
    perf_result = await perf_auditor.run()

    # Step 5: Module D - Off-Page & Social Signals
    offpage_auditor = OffPageAuditor(crawl_result=crawl_result, openpagerank_key=openpagerank_key)
    offpage_result = await offpage_auditor.run()

    # Step 6: Optional Screenshots
    screenshots = {}
    if take_screenshots:
        screenshots = await capture_screenshots(target_url)

    audit_results = {
        Category.SEO: seo_result,
        Category.SECURITY: sec_result,
        Category.PERFORMANCE: perf_result,
        Category.OFFPAGE: offpage_result,
    }

    all_issues = []
    for res in audit_results.values():
        all_issues.extend(res.issues)
    all_issues.sort(key=lambda x: x.severity.weight, reverse=True)

    return crawl_result, audit_results, all_issues, screenshots


def main():
    st.sidebar.title("⚙️ Audit Configuration")
    max_urls = st.sidebar.slider("Max Crawled URLs", min_value=1, max_value=50, value=10, step=1)
    max_depth = st.sidebar.slider("Max Crawl Depth", min_value=1, max_value=5, value=2, step=1)

    with st.sidebar.expander("🔑 Optional API Keys (Free Tiers)"):
        pagespeed_key = st.text_input("Google PageSpeed Insights Key:", type="password")
        openpagerank_key = st.text_input("OpenPageRank API Key:", type="password")

    take_screenshots = st.sidebar.checkbox("Capture Desktop & Mobile Screenshots", value=False)

    st.sidebar.markdown("---")
    st.sidebar.subheader("💡 Quick Test Presets")
    if st.sidebar.button("Test Local Demo Site (Port 9000)"):
        st.session_state["target_input"] = "http://127.0.0.1:9000"
    if st.sidebar.button("Test https://example.com"):
        st.session_state["target_input"] = "https://example.com"

    st.title("🛡️ All-in-One Website Audit, SEO, Security & UI Suite")
    st.markdown("Multi-dimensional technical diagnostic engine with automated copy-paste remediation and multi-tab Excel & PDF reporting.")

    default_target = st.session_state.get("target_input", "https://example.com")
    col1, col2 = st.columns([4, 1])
    with col1:
        target_url = st.text_input("Enter Website URL:", value=default_target, placeholder="https://example.com")
    with col2:
        st.write("")
        st.write("")
        start_btn = st.button("🚀 Start Audit", type="primary", use_container_width=True)

    if start_btn:
        if not target_url.strip():
            st.error("Please enter a valid website URL.")
            return

        with st.spinner(f"Running multi-dimensional audit on {target_url}..."):
            try:
                crawl_res, audit_res, all_issues, screenshots = asyncio.run(
                    run_full_audit(
                        target_url=target_url,
                        max_urls=max_urls,
                        max_depth=max_depth,
                        pagespeed_key=pagespeed_key or None,
                        openpagerank_key=openpagerank_key or None,
                        take_screenshots=take_screenshots,
                    )
                )

                # Pre-generate downloadable reports in memory
                excel_buffer = io.BytesIO()
                ex_gen = ExcelReportGenerator(crawl_res, audit_res, all_issues)
                ex_gen.generate(excel_buffer)
                excel_data = excel_buffer.getvalue()

                pdf_buffer = io.BytesIO()
                pdf_gen = PDFReportGenerator(crawl_res, audit_res, all_issues)
                pdf_gen.generate(pdf_buffer)
                pdf_data = pdf_buffer.getvalue()

                st.session_state["audit_data"] = {
                    "crawl": crawl_res,
                    "audit_results": audit_res,
                    "all_issues": all_issues,
                    "screenshots": screenshots,
                    "excel_data": excel_data,
                    "pdf_data": pdf_data,
                    "url": target_url,
                    "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                }
                st.success("✅ Complete multi-dimensional audit finished successfully!")
            except Exception as e:
                st.error(f"Audit encountered an error: {str(e)}")

    # Render results if available
    if "audit_data" in st.session_state:
        data = st.session_state["audit_data"]
        crawl_res: CrawlResult = data["crawl"]
        audit_results: dict[Category, AuditResult] = data["audit_results"]
        all_issues: list = data["all_issues"]
        screenshots: dict = data.get("screenshots", {})

        seo_res = audit_results[Category.SEO]
        sec_res = audit_results[Category.SECURITY]
        perf_res = audit_results[Category.PERFORMANCE]
        off_res = audit_results[Category.OFFPAGE]

        st.markdown(
            f"**Target:** `{data['url']}` &nbsp;|&nbsp; "
            f"**Analyzed:** `{data['time']}` &nbsp;|&nbsp; "
            f"**Crawl Duration:** `{crawl_res.duration_seconds}s` &nbsp;|&nbsp; "
            f"**Total Issues:** `{len(all_issues)}`"
        )

        # 5 Health Metric Cards
        overall_score = round(sum(r.score for r in audit_results.values()) / 4)
        mcol1, mcol2, mcol3, mcol4, mcol5 = st.columns(5)
        with mcol1:
            st.markdown(get_score_html(overall_score, "Overall Health"), unsafe_allow_html=True)
        with mcol2:
            st.markdown(get_score_html(seo_res.score, "Technical SEO"), unsafe_allow_html=True)
        with mcol3:
            st.markdown(get_score_html(sec_res.score, "Security & SSL"), unsafe_allow_html=True)
        with mcol4:
            st.markdown(get_score_html(perf_res.score, "UI & Performance"), unsafe_allow_html=True)
        with mcol5:
            st.markdown(get_score_html(off_res.score, "Off-Page Trust"), unsafe_allow_html=True)

        st.markdown("---")

        # Tabbed navigation
        tab_issues, tab_seo, tab_sec, tab_perf, tab_offpage, tab_exports = st.tabs([
            "📋 Actionable Fixes",
            "🌐 Technical SEO",
            "🛡️ Security & SSL",
            "⚡ UI & Web Vitals",
            "🔗 Off-Page & Social",
            "📥 Export Reports",
        ])

        # TAB 1: Issues & Fixes
        with tab_issues:
            st.subheader(f"Actionable Remediation Roadmap ({len(all_issues)} Issues)")
            sev_filter = st.multiselect(
                "Filter Severity:",
                options=[s.value for s in Severity],
                default=[Severity.CRITICAL.value, Severity.HIGH.value, Severity.MEDIUM.value],
            )
            filtered = [i for i in all_issues if i.severity.value in sev_filter]

            if not filtered:
                st.info("No issues match the selected severity filter.")
            else:
                for idx, issue in enumerate(filtered):
                    icon = "🔴" if issue.severity == Severity.CRITICAL else ("🟠" if issue.severity == Severity.HIGH else ("🟡" if issue.severity == Severity.MEDIUM else "🔵"))
                    with st.expander(f"{icon} [{issue.severity.value.upper()}] {issue.title}", expanded=(idx < 2)):
                        st.markdown(f"**Domain:** `{issue.category.value}` &nbsp;|&nbsp; **URL:** `{issue.url or 'Global'}`")
                        st.markdown(f"**Evidence:** `{issue.evidence}`")
                        st.markdown(f"**Why it matters:** {issue.description}")

                        if issue.solution_nginx or issue.solution_apache or issue.solution_code:
                            st.markdown("#### 🛠️ Automated Copy-Paste Solution")
                            code_tabs = []
                            if issue.solution_nginx: code_tabs.append("Nginx (nginx.conf)")
                            if issue.solution_apache: code_tabs.append("Apache (.htaccess)")
                            if issue.solution_code: code_tabs.append("HTML / WordPress Code")

                            c_tabs = st.tabs(code_tabs)
                            c_idx = 0
                            if issue.solution_nginx:
                                with c_tabs[c_idx]: st.code(issue.solution_nginx, language="nginx")
                                c_idx += 1
                            if issue.solution_apache:
                                with c_tabs[c_idx]: st.code(issue.solution_apache, language="apache")
                                c_idx += 1
                            if issue.solution_code:
                                with c_tabs[c_idx]: st.code(issue.solution_code, language="html")

        # TAB 2: Technical SEO
        with tab_seo:
            st.subheader(f"Crawled Pages Explorer ({len(crawl_res.pages)} pages)")
            page_rows = []
            for p in crawl_res.pages:
                page_rows.append({
                    "URL": p.url,
                    "Status": p.status_code,
                    "Time (ms)": p.response_time_ms,
                    "Title": (p.title[:45] + "...") if p.title and len(p.title) > 45 else (p.title or "N/A"),
                    "H1 Count": len(p.h1_headings),
                    "Words": p.word_count,
                    "Indexable": "Yes" if p.is_indexable else "No (noindex)",
                })
            st.dataframe(pd.DataFrame(page_rows), use_container_width=True)

            st.markdown("#### Asset & Image Audit")
            total_imgs = sum(p.images_total for p in crawl_res.pages)
            missing_alt = sum(len(p.images_missing_alt) for p in crawl_res.pages)
            icol1, icol2 = st.columns(2)
            with icol1: st.metric("Total Images", total_imgs)
            with icol2: st.metric("Images Missing Alt", missing_alt, delta=f"-{missing_alt}" if missing_alt else "0", delta_color="inverse")

        # TAB 3: Security & SSL
        with tab_sec:
            st.subheader("SSL/TLS Certificate Status & Security Headers")
            ssl_info = sec_res.metrics.get("ssl", {})
            sc1, sc2, sc3 = st.columns(3)
            with sc1: st.metric("Cert Status", "Valid & Trusted" if ssl_info.get("valid") else "Invalid / Expired")
            with sc2: st.metric("Days Remaining", f"{ssl_info.get('days_remaining', 'N/A')} days")
            with sc3: st.metric("TLS Version", ssl_info.get("protocol", "N/A"))

            st.markdown("#### HTTP Security Headers Matrix")
            raw_headers = sec_res.metrics.get("headers", {})
            if raw_headers:
                st.dataframe(pd.DataFrame([{"Header": k, "Value": v} for k, v in raw_headers.items()]), use_container_width=True)

        # TAB 4: UI & Performance
        with tab_perf:
            st.subheader("Core Web Vitals & Load Performance")
            p_metrics = perf_res.metrics
            pv1, pv2, pv3, pv4 = st.columns(4)
            with pv1:
                lcp = p_metrics.get("lcp_seconds", 0)
                st.metric("LCP (Largest Paint)", f"{lcp}s", delta="Good" if lcp <= 2.5 else "Slow", delta_color="normal" if lcp <= 2.5 else "inverse")
            with pv2:
                cls_v = p_metrics.get("cls", 0)
                st.metric("CLS (Layout Shift)", f"{cls_v}", delta="Good" if cls_v <= 0.1 else "Poor", delta_color="normal" if cls_v <= 0.1 else "inverse")
            with pv3:
                fcp = p_metrics.get("fcp_seconds", 0)
                st.metric("FCP (First Paint)", f"{fcp}s", delta="Good" if fcp <= 1.8 else "Slow", delta_color="normal" if fcp <= 1.8 else "inverse")
            with pv4:
                tbt = p_metrics.get("tbt_ms", 0)
                st.metric("TBT (Blocking Time)", f"{tbt}ms")

            if screenshots:
                st.markdown("#### Visual UI Screenshots")
                sc_col1, sc_col2 = st.columns(2)
                if "desktop" in screenshots and os.path.exists(screenshots["desktop"]):
                    with sc_col1:
                        st.image(screenshots["desktop"], caption="Desktop Viewport (1920x1080)", use_column_width=True)
                if "mobile" in screenshots and os.path.exists(screenshots["mobile"]):
                    with sc_col2:
                        st.image(screenshots["mobile"], caption="Mobile Viewport (390x844)", use_column_width=True)

        # TAB 5: Off-Page & Social
        with tab_offpage:
            st.subheader("Brand Social Footprint & Outbound Link Profile")
            soc_profiles = off_res.metrics.get("social_profiles", {})
            if soc_profiles:
                st.markdown("#### Verified Social Handles Found:")
                for plat, u in soc_profiles.items():
                    st.markdown(f"- **{plat}:** [{u}]({u})")
            else:
                st.warning("No brand social media links (LinkedIn, X, Facebook, YouTube, GitHub) detected.")

            link_prof = off_res.metrics.get("link_profile", {})
            lcol1, lcol2, lcol3 = st.columns(3)
            with lcol1: st.metric("Internal Links", link_prof.get("total_internal_links", 0))
            with lcol2: st.metric("External Links", link_prof.get("total_external_links", 0))
            with lcol3: st.metric("Nofollow Ratio", f"{link_prof.get('nofollow_percentage', 0)}%")

        # TAB 6: Export Reports
        with tab_exports:
            st.subheader("📥 Export Client-Ready Multi-Format Audit Reports")
            st.markdown("Download full reports including all crawled URLs, health scores, and copy-paste remediation snippets.")

            down_col1, down_col2 = st.columns(2)
            with down_col1:
                st.download_button(
                    label="📊 Download Excel Report (.xlsx)",
                    data=data["excel_data"],
                    file_name=f"audit_report_{crawl_res.base_domain}.xlsx",
                    mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    use_container_width=True,
                )
            with down_col2:
                st.download_button(
                    label="📄 Download Executive PDF Report (.pdf)",
                    data=data["pdf_data"],
                    file_name=f"audit_report_{crawl_res.base_domain}.pdf",
                    mime="application/pdf",
                    use_container_width=True,
                )


if __name__ == "__main__":
    main()
