#!/usr/bin/env python3
"""
The Red Room — Autonomous Web Security Intelligence Platform
High-impact, enterprise-grade Streamlit application for automated vulnerability scanning.
"""

import sys
import os
import json
import asyncio
from datetime import datetime
from pathlib import Path
import streamlit as st
from streamlit.runtime import exists

# Auto-launch Streamlit CLI runner if executed via bare python
if not exists():
    from streamlit.web import cli as stcli
    sys.argv = ["streamlit", "run", __file__] + sys.argv[1:]
    sys.exit(stcli.main())

# Ensure 'src' directory is in Python path
REPO_ROOT = Path(__file__).resolve().parent
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from redroom.agents.scanner.web_scanner import WebScanner
from redroom.reports.pdf_generator import PDFReportGenerator

# -----------------------------------------------------------------------------
# Page Configuration
# -----------------------------------------------------------------------------
st.set_page_config(
    page_title="The Red Room — AI Security Scanner",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# -----------------------------------------------------------------------------
# Enterprise Dark Theme & Cyber Threat Styling
# -----------------------------------------------------------------------------
st.markdown("""
<style>
    /* Global Background & Typography */
    .stApp {
        background-color: #0B0E14;
        color: #E6EDF3;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    }
    
    /* Header & Branding */
    .hero-container {
        padding: 24px 32px;
        background: linear-gradient(135deg, rgba(229, 9, 20, 0.12) 0%, rgba(11, 14, 20, 0.95) 75%);
        border: 1px solid rgba(229, 9, 20, 0.3);
        border-radius: 12px;
        margin-bottom: 24px;
        box-shadow: 0 4px 24px rgba(0, 0, 0, 0.6);
    }
    .hero-title {
        font-size: 2.4rem;
        font-weight: 900;
        letter-spacing: -0.5px;
        background: linear-gradient(90deg, #FF334B 0%, #FF6B7D 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin: 0;
        display: flex;
        align-items: center;
        gap: 12px;
    }
    .hero-badge {
        display: inline-block;
        font-size: 0.72rem;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 1px;
        padding: 4px 10px;
        border-radius: 20px;
        background-color: rgba(56, 139, 253, 0.15);
        color: #58A6FF;
        border: 1px solid rgba(56, 139, 253, 0.4);
    }
    .hero-subtitle {
        color: #8B949E;
        font-size: 1.05rem;
        margin-top: 8px;
        margin-bottom: 0;
    }

    /* KPI Cards */
    .kpi-card {
        background-color: #151921;
        border: 1px solid #21262D;
        border-radius: 10px;
        padding: 18px 20px;
        text-align: left;
        box-shadow: 0 2px 8px rgba(0, 0, 0, 0.4);
        transition: transform 0.15s ease, border-color 0.15s ease;
    }
    .kpi-card:hover {
        transform: translateY(-2px);
        border-color: #30363D;
    }
    .kpi-label {
        font-size: 0.82rem;
        color: #8B949E;
        text-transform: uppercase;
        letter-spacing: 0.8px;
        font-weight: 600;
        margin-bottom: 6px;
    }
    .kpi-value {
        font-size: 2.1rem;
        font-weight: 800;
        color: #F0F6FC;
        line-height: 1.1;
    }
    .kpi-sub {
        font-size: 0.78rem;
        color: #6E7681;
        margin-top: 4px;
    }

    /* Severity Badges */
    .badge-critical { background-color: rgba(248, 81, 73, 0.2); color: #F85149; border: 1px solid #F85149; padding: 3px 8px; border-radius: 4px; font-weight: 700; font-size: 0.75rem; }
    .badge-high { background-color: rgba(240, 136, 62, 0.2); color: #F0883E; border: 1px solid #F0883E; padding: 3px 8px; border-radius: 4px; font-weight: 700; font-size: 0.75rem; }
    .badge-medium { background-color: rgba(210, 153, 34, 0.2); color: #D29922; border: 1px solid #D29922; padding: 3px 8px; border-radius: 4px; font-weight: 700; font-size: 0.75rem; }
    .badge-low { background-color: rgba(88, 166, 255, 0.2); color: #58A6FF; border: 1px solid #58A6FF; padding: 3px 8px; border-radius: 4px; font-weight: 700; font-size: 0.75rem; }
    .badge-info { background-color: rgba(139, 148, 158, 0.2); color: #8B949E; border: 1px solid #8B949E; padding: 3px 8px; border-radius: 4px; font-weight: 700; font-size: 0.75rem; }

    /* HTTP Method Badges */
    .method-get { background-color: rgba(46, 160, 67, 0.2); color: #3FB950; border: 1px solid #2EA043; padding: 2px 7px; border-radius: 4px; font-weight: 700; font-size: 0.72rem; }
    .method-post { background-color: rgba(56, 139, 253, 0.2); color: #58A6FF; border: 1px solid #388BFD; padding: 2px 7px; border-radius: 4px; font-weight: 700; font-size: 0.72rem; }
    .method-put { background-color: rgba(210, 153, 34, 0.2); color: #D29922; border: 1px solid #BB8009; padding: 2px 7px; border-radius: 4px; font-weight: 700; font-size: 0.72rem; }
    .method-delete { background-color: rgba(248, 81, 73, 0.2); color: #F85149; border: 1px solid #DA3633; padding: 2px 7px; border-radius: 4px; font-weight: 700; font-size: 0.72rem; }

    /* Live Feed Item */
    .live-alert-card {
        padding: 10px 14px;
        background-color: #161B22;
        border-radius: 6px;
        margin-bottom: 8px;
        border-left: 4px solid #F85149;
        font-size: 0.9rem;
    }

    /* Risk Bar */
    .risk-meter-container {
        background-color: #21262D;
        border-radius: 6px;
        height: 10px;
        width: 100%;
        display: flex;
        overflow: hidden;
        margin: 10px 0 16px 0;
    }
</style>
""", unsafe_allow_html=True)


# -----------------------------------------------------------------------------
# Remediation Knowledgebase
# -----------------------------------------------------------------------------
REMEDIATION_MAP = {
    "sql injection": "Use parameterized queries or ORM abstractions. Never concatenate user input directly into SQL statements.",
    "cross-site scripting (xss)": "Contextually HTML-encode user input before rendering. Enforce strict Content Security Policy (CSP) headers.",
    "race condition": "Wrap critical read-and-modify sequences inside atomic database transactions (`BEGIN IMMEDIATE` / `SELECT ... FOR UPDATE`) or distributed locks.",
    "insecure direct object reference (idor)": "Implement server-side session checks verifying the authenticated tenant/user is authorized for the target resource ID.",
    "server-side request forgery (ssrf)": "Validate and whitelist permitted destination URLs/IPs. Strictly block private internal CIDRs (10.0.0.0/8, 127.0.0.0/8, 169.254.169.254).",
    "command injection": "Avoid passing commands to shell interpreters (`subprocess.run(shell=True)` or `os.system`). Pass arguments as strict parameter arrays.",
    "broken authentication": "Enforce strong authentication mechanisms, secure HTTP cookies (`HttpOnly`, `Secure`, `SameSite=Strict`), and rate-limit login endpoints.",
    "api rate limiting": "Enforce token bucket or sliding-window rate limiting per IP or authenticated API key to prevent DoS and abuse.",
    "mass assignment": "Explicitly whitelist allowed request schema fields (e.g. using Pydantic DTOs or Strong Parameters).",
}

def get_remediation(vuln_type: str) -> str:
    vtype_lower = vuln_type.lower()
    for key, advice in REMEDIATION_MAP.items():
        if key in vtype_lower:
            return advice
    return "Enforce strict input validation, principle of least privilege, and verify defense-in-depth controls across application boundaries."


# -----------------------------------------------------------------------------
# Live Progress Callback for Streamlit
# -----------------------------------------------------------------------------
class StreamlitProgressCallback:
    """Updates Streamlit UI live with test stages, counts, and alert banners."""

    def __init__(self, progress_bar, status_text, live_alert_area, total_tests=71):
        self.progress_bar = progress_bar
        self.status_text = status_text
        self.live_alert_area = live_alert_area
        self.total_tests = total_tests
        self.current_index = 0
        self.found_vulns = []

    def update(self, test_name: str, status: str = "running", vulnerability=None):
        if status == "running":
            self.current_index += 1
            progress_ratio = min(1.0, self.current_index / self.total_tests)
            self.progress_bar.progress(progress_ratio)
            self.status_text.markdown(f"🔬 **Phase [{self.current_index}/{self.total_tests}]** &nbsp; Checking: ` {test_name} `")
        elif status == "completed" and vulnerability:
            self.found_vulns.append(vulnerability)
            sev = vulnerability.get("severity", "MEDIUM")
            vtype = vulnerability.get("type", "Vulnerability")
            endpoint = vulnerability.get("endpoint", "/")
            color = "#F85149" if sev in ("CRITICAL", "HIGH") else "#D29922"
            
            with self.live_alert_area:
                st.markdown(
                    f"<div class='live-alert-card' style='border-left-color: {color};'>"
                    f"<span class='badge-{sev.lower()}'>{sev}</span> "
                    f"<strong>{vtype}</strong> detected on <code>{endpoint}</code>"
                    f"</div>",
                    unsafe_allow_html=True
                )


# -----------------------------------------------------------------------------
# Session State Management
# -----------------------------------------------------------------------------
if "scan_results" not in st.session_state:
    st.session_state.scan_results = None
if "is_scanning" not in st.session_state:
    st.session_state.is_scanning = False
if "target_url_input" not in st.session_state:
    st.session_state.target_url_input = "http://localhost:8080"


# -----------------------------------------------------------------------------
# Hero Banner
# -----------------------------------------------------------------------------
st.markdown("""
<div class="hero-container">
    <div style="display: flex; justify-content: space-between; align-items: center;">
        <h1 class="hero-title">🔴 THE RED ROOM</h1>
        <span class="hero-badge">● Engine v0.1.0 • 71 Attack Checks</span>
    </div>
    <p class="hero-subtitle">Autonomous Web Application Vulnerability Scanner & Adversary Emulation Engine</p>
</div>
""", unsafe_allow_html=True)


# -----------------------------------------------------------------------------
# Target Input & Preset Pills
# -----------------------------------------------------------------------------
st.markdown("##### 🎯 Target Endpoint")

# Preset selection buttons
p1, p2, p3, _ = st.columns([1.8, 1.8, 1.8, 4])
with p1:
    if st.button("🏦 Fintech Demo (8080)", use_container_width=True):
        st.session_state.target_url_input = "http://localhost:8080"
        st.rerun()
with p2:
    if st.button("💻 Local API (8000)", use_container_width=True):
        st.session_state.target_url_input = "http://127.0.0.1:8000"
        st.rerun()
with p3:
    if st.button("🌐 External Test Site", use_container_width=True):
        st.session_state.target_url_input = "http://testphp.vulnweb.com"
        st.rerun()

# Input Bar Row
col_url, col_timeout, col_run, col_clear = st.columns([5.5, 1.5, 1.6, 1.2])

with col_url:
    target_url = st.text_input(
        "Target URL",
        value=st.session_state.target_url_input,
        placeholder="e.g. http://localhost:8080",
        label_visibility="collapsed"
    )

with col_timeout:
    timeout_val = st.number_input(
        "Timeout (s)",
        min_value=1,
        max_value=20,
        value=5,
        help="Per-request socket read timeout in seconds",
        label_visibility="collapsed"
    )

with col_run:
    scan_triggered = st.button("🚀 Run Security Scan", type="primary", use_container_width=True)

with col_clear:
    if st.button("Clear", use_container_width=True):
        st.session_state.scan_results = None
        st.session_state.is_scanning = False
        st.rerun()

st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)


# -----------------------------------------------------------------------------
# Scan Execution Pipeline
# -----------------------------------------------------------------------------
if scan_triggered:
    if not target_url.strip():
        st.error("Please provide a target URL.")
    else:
        clean_url = target_url.strip()
        if not clean_url.startswith("http://") and not clean_url.startswith("https://"):
            clean_url = "http://" + clean_url

        st.session_state.is_scanning = True
        st.session_state.scan_results = None

        st.markdown("### ⚡ Live Vulnerability Telemetry")
        progress_bar = st.progress(0.0)
        status_text = st.empty()
        
        live_alert_container = st.container()

        callback = StreamlitProgressCallback(
            progress_bar=progress_bar,
            status_text=status_text,
            live_alert_area=live_alert_container,
            total_tests=71
        )

        scanner = WebScanner(base_url=clean_url, timeout=int(timeout_val), progress_callback=callback)

        start_time = datetime.now()
        try:
            results = asyncio.run(scanner.scan())
            results["scan_duration"] = round((datetime.now() - start_time).total_seconds(), 1)
            st.session_state.scan_results = results
            progress_bar.progress(1.0)
            status_text.success(f"✅ Security Assessment Complete in {results['scan_duration']} seconds!")
        except Exception as e:
            st.error(f"Scan aborted due to an error: {e}")
        finally:
            st.session_state.is_scanning = False
            st.rerun()


# -----------------------------------------------------------------------------
# Results Dashboard & Interactive Analysis
# -----------------------------------------------------------------------------
if st.session_state.scan_results:
    results = st.session_state.scan_results
    vulns = results.get("vulnerabilities", [])
    endpoints = results.get("endpoints", [])
    duration = results.get("scan_duration", "N/A")

    crit_count = sum(1 for v in vulns if v.get("severity") == "CRITICAL")
    high_count = sum(1 for v in vulns if v.get("severity") == "HIGH")
    med_count = sum(1 for v in vulns if v.get("severity") == "MEDIUM")
    low_count = sum(1 for v in vulns if v.get("severity") in ("LOW", "INFO"))

    # Threat Score Formula
    threat_score = min(100, (crit_count * 25) + (high_count * 15) + (med_count * 8) + (low_count * 2))
    
    if threat_score >= 70:
        threat_color = "#F85149"
        threat_label = "CRITICAL RISK"
    elif threat_score >= 40:
        threat_color = "#F0883E"
        threat_label = "ELEVATED RISK"
    elif threat_score > 0:
        threat_color = "#D29922"
        threat_label = "MODERATE RISK"
    else:
        threat_color = "#3FB950"
        threat_label = "SECURE (LOW RISK)"

    # KPI Metrics Row
    k1, k2, k3, k4 = st.columns(4)

    with k1:
        st.markdown(f"""
        <div class="kpi-card">
            <div class="kpi-label">Threat Severity Score</div>
            <div class="kpi-value" style="color: {threat_color};">{threat_score} <span style="font-size: 1rem; color: #8B949E;">/ 100</span></div>
            <div class="kpi-sub" style="color: {threat_color}; font-weight: 700;">{threat_label}</div>
        </div>
        """, unsafe_allow_html=True)

    with k2:
        st.markdown(f"""
        <div class="kpi-card">
            <div class="kpi-label">Total Vulnerabilities</div>
            <div class="kpi-value">{len(vulns)}</div>
            <div class="kpi-sub"><span style="color:#F85149;">{crit_count} Critical</span> • <span style="color:#F0883E;">{high_count} High</span></div>
        </div>
        """, unsafe_allow_html=True)

    with k3:
        st.markdown(f"""
        <div class="kpi-card">
            <div class="kpi-label">Attack Surface Mapped</div>
            <div class="kpi-value">{len(endpoints)}</div>
            <div class="kpi-sub">Active Endpoints Discovered</div>
        </div>
        """, unsafe_allow_html=True)

    with k4:
        st.markdown(f"""
        <div class="kpi-card">
            <div class="kpi-label">Execution Time</div>
            <div class="kpi-value">{duration} <span style="font-size: 1.1rem; color: #8B949E;">sec</span></div>
            <div class="kpi-sub">71 checks completed</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<div style='height: 16px;'></div>", unsafe_allow_html=True)

    # Risk Distribution Breakdown Bar
    if len(vulns) > 0:
        p_crit = (crit_count / len(vulns)) * 100
        p_high = (high_count / len(vulns)) * 100
        p_med = (med_count / len(vulns)) * 100
        p_low = (low_count / len(vulns)) * 100
        
        st.markdown(f"""
        <div style="font-size: 0.8rem; color: #8B949E; margin-bottom: 4px;">THREAT COMPOSITION BREAKDOWN</div>
        <div class="risk-meter-container">
            <div style="width: {p_crit}%; background-color: #F85149;" title="Critical: {crit_count}"></div>
            <div style="width: {p_high}%; background-color: #F0883E;" title="High: {high_count}"></div>
            <div style="width: {p_med}%; background-color: #D29922;" title="Medium: {med_count}"></div>
            <div style="width: {p_low}%; background-color: #58A6FF;" title="Low/Info: {low_count}"></div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("---")

    # -------------------------------------------------------------------------
    # Main Tabs
    # -------------------------------------------------------------------------
    tab_vulns, tab_endpoints, tab_report, tab_pipeline = st.tabs([
        f"🚨 Vulnerabilities ({len(vulns)})",
        f"🌐 Attack Surface Map ({len(endpoints)})",
        "📄 Executive Report & PDF",
        "🛡️ Autonomous Pipeline Architecture"
    ])

    # -------------------------------------------------------------------------
    # Tab 1: Vulnerabilities Explorer
    # -------------------------------------------------------------------------
    with tab_vulns:
        if not vulns:
            st.success("🎉 No security vulnerabilities detected on the scanned target. All tests passed cleanly.")
        else:
            f1, f2 = st.columns([2.5, 3.5])
            with f1:
                filter_sev = st.multiselect(
                    "Filter Severity:",
                    options=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                    default=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                    label_visibility="collapsed"
                )
            with f2:
                search_term = st.text_input(
                    "Search Findings",
                    placeholder="Search by vulnerability type, endpoint, or payload...",
                    label_visibility="collapsed"
                )

            filtered_vulns = [
                v for v in vulns
                if v.get("severity") in filter_sev and (
                    search_term.lower() in v.get("type", "").lower() or
                    search_term.lower() in v.get("endpoint", "").lower() or
                    search_term.lower() in str(v.get("payload", "")).lower()
                )
            ]

            st.caption(f"Showing **{len(filtered_vulns)}** of **{len(vulns)}** findings")

            for idx, vuln in enumerate(filtered_vulns, 1):
                sev = vuln.get("severity", "MEDIUM")
                vtype = vuln.get("type", "Vulnerability")
                method = vuln.get("method", "GET").upper()
                endpoint = vuln.get("endpoint", "/")
                payload = vuln.get("payload", "N/A")
                evidence = vuln.get("evidence", "N/A")
                remediation = get_remediation(vtype)

                method_class = f"method-{method.lower()}" if method.lower() in ["get", "post", "put", "delete"] else "method-get"
                badge_class = f"badge-{sev.lower()}"

                with st.expander(f"#{idx} &nbsp; [{sev}] {vtype} — {method} {endpoint}", expanded=(idx <= 3)):
                    c_left, c_right = st.columns([1.2, 3.8])

                    with c_left:
                        st.markdown(f"**Severity Level**<br><span class='{badge_class}'>{sev}</span>", unsafe_allow_html=True)
                        st.markdown("<div style='height: 8px;'></div>", unsafe_allow_html=True)
                        st.markdown(f"**HTTP Method**<br><span class='{method_class}'>{method}</span>", unsafe_allow_html=True)
                        st.markdown("<div style='height: 8px;'></div>", unsafe_allow_html=True)
                        st.markdown(f"**Target Endpoint**<br><code>{endpoint}</code>", unsafe_allow_html=True)

                    with c_right:
                        st.markdown(f"#### {vtype}")
                        st.markdown(f"**Proof-of-Concept Exploit Payload:**")
                        st.code(str(payload), language="text")
                        
                        st.markdown("**Server Evidence & Response:**")
                        st.code(str(evidence), language="text")

                        st.markdown(f"**💡 Recommended Remediation:**")
                        st.info(remediation)

    # -------------------------------------------------------------------------
    # Tab 2: Attack Surface Map (Endpoints)
    # -------------------------------------------------------------------------
    with tab_endpoints:
        st.markdown(f"### Discovered Application Endpoints ({len(endpoints)})")
        st.caption("All routes discovered through automated crawling, form parsing, and heuristic endpoint detection.")

        if not endpoints:
            st.info("No sub-endpoints discovered.")
        else:
            table_data = []
            for ep in endpoints:
                if isinstance(ep, dict):
                    table_data.append({
                        "HTTP Method": ep.get("method", "GET"),
                        "Endpoint Path": ep.get("path", ep.get("endpoint", "/")),
                        "Status Code": ep.get("status_code", 200)
                    })
                else:
                    table_data.append({
                        "HTTP Method": "GET",
                        "Endpoint Path": str(ep),
                        "Status Code": 200
                    })
            st.dataframe(table_data, use_container_width=True)

    # -------------------------------------------------------------------------
    # Tab 3: Executive Security Report & PDF Download
    # -------------------------------------------------------------------------
    with tab_report:
        st.markdown("### 📄 Executive Security Audit Report")
        st.caption("Standardized vulnerability assessment documentation ready for security teams and engineering leadership.")

        scanner_instance = WebScanner(base_url=results.get("base_url", target_url))
        report_text = scanner_instance.generate_report(results)
        
        st.text_area("Audit Summary Text", value=report_text, height=280)

        # Generate PDF Artifact
        reports_dir = REPO_ROOT / "reports"
        reports_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        pdf_filename = f"redroom_scan_{timestamp}.pdf"
        pdf_path = reports_dir / pdf_filename

        try:
            pdf_gen = PDFReportGenerator()
            pdf_gen.generate_report(results, str(pdf_path))

            with open(pdf_path, "rb") as f:
                pdf_bytes = f.read()

            col_pdf_dl, col_json_dl = st.columns([1.5, 1.5])
            with col_pdf_dl:
                st.download_button(
                    label="📥 Download Official PDF Report",
                    data=pdf_bytes,
                    file_name=pdf_filename,
                    mime="application/pdf",
                    type="primary",
                    use_container_width=True
                )
            with col_json_dl:
                st.download_button(
                    label="💾 Export JSON Dossier",
                    data=json.dumps(results, indent=2),
                    file_name=f"redroom_scan_{timestamp}.json",
                    mime="application/json",
                    use_container_width=True
                )
        except Exception as e:
            st.error(f"PDF compilation error: {e}")

    # -------------------------------------------------------------------------
    # Tab 4: Autonomous Pipeline Architecture
    # -------------------------------------------------------------------------
    with tab_pipeline:
        st.markdown("### 🤖 The Red Room 3-Agent Autonomous Pipeline")
        st.markdown("""
        The Web Scanner is the tip of the spear for **The Red Room**. When running in full autonomous pipeline mode (`python -m redroom.cli fullscan`), discovered vulnerabilities trigger a multi-agent orchestration loop:
        """)

        st.code("""
┌─────────────────────────────────────────────────────────────────────────────┐
│                       THE RED ROOM ORCHESTRATION PIPELINE                   │
└─────────────────────────────────────────────────────────────────────────────┘

  [ AGENT 1: SCANNER & SABOTEUR ]
         │
         ▼  Discovers vulnerability (e.g. Race Condition / SQLi)
  [ Formulates Attack Hypothesis ]
         │
         ▼  Generates target-specific PoC exploit script
  [ AGENT 2: EXPLOIT LAB ]
         │
         ▼  Spawns isolated Shadow Container (Docker, 512MB RAM, 0.5 CPU)
  [ Autonomous Exploit Execution ]
         │
         ▼  Proves exploitability with evidence (database delta, timing logs)
  [ AGENT 3: SURGEON ]
         │
         ▼  LLM Patch Synthesis (AST validation + regression test cases)
  [ Generates Unified Diff & Pull Request ]
         │
         ▼
  [ Final PDF Intelligence Report Delivered ]
        """, language="text")

        st.markdown("""
        - **Saboteur Agent**: Analyzes code diffs, formulates attack hypotheses, and validates invariant violations.
        - **Exploit Lab**: Executes live attacks against ephemeral shadow containers with strict CPU/memory boundaries to prove exploitability.
        - **Surgeon Agent**: Analyzes verified execution traces, synthesizes regression-safe AST patches, and opens automated GitHub Pull Requests.
        """)
else:
    if not st.session_state.is_scanning:
        st.markdown("""
        <div style="text-align: center; padding: 48px 20px; border: 1px dashed #30363D; border-radius: 12px; margin-top: 16px;">
            <div style="font-size: 2.5rem; margin-bottom: 12px;">🛡️</div>
            <h3 style="color: #F0F6FC; margin-bottom: 8px;">Scanner Ready</h3>
            <p style="color: #8B949E; max-width: 500px; margin: 0 auto 20px auto;">
                Select a target preset above or type any web server URL, then click <strong>Run Security Scan</strong> to execute 71 automated vulnerability checks.
            </p>
        </div>
        """, unsafe_allow_html=True)
