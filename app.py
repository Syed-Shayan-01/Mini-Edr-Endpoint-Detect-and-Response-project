import os
import sys
import time
import functools
import logging
import ctypes
import subprocess
from datetime import datetime
import psutil
import pandas as pd
import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
import db_manager as db
from edr_engine import (
    BASE_DIR,
    DEMO_SANDBOX,
    VAULT_DIR,
    LOG_FILE,
    TRAP_FOLDER_NAME,
    get_sha256,
    calculate_entropy,
    is_file_compromised
)

st.set_page_config(
    page_title="Mini-EDR | Endpoint Security Console",
    layout="wide",
    initial_sidebar_state="collapsed"
)


def safe_render(fn):
    """Keeps a live fragment from crashing the page on a transient error."""
    @functools.wraps(fn)
    def wrapper(*a, **k):
        try:
            return fn(*a, **k)
        except Exception as e:
            logging.error(f"{fn.__name__} render error: {e}")
            st.warning(f"Live view refreshing ({type(e).__name__})...")
    return wrapper


@st.cache_resource
def _boot_once():
    db.init_db()
    return True


_boot_once()

if db.get_setting("dashboard_pid") != str(os.getpid()):
    db.set_setting("dashboard_pid", str(os.getpid()))


def get_engine_state():
    hb = float(db.get_setting("engine_heartbeat", "0") or 0)
    pid = int(db.get_setting("engine_pid", "0") or 0)
    is_admin = db.get_setting("engine_is_admin", "0") == "1"
    is_alive = (time.time() - hb) < 10 and (pid == 0 or psutil.pid_exists(pid))
    return is_alive, pid, is_admin


def start_background_engine(as_admin=False, force=False):
    alive, old_pid, old_admin = get_engine_state()
    engine_script = os.path.join(BASE_DIR, "edr_engine.py")
    launching_until = float(db.get_setting("engine_launching_until", "0") or 0)

    if as_admin and os.name == "nt":
        if alive and old_admin:
            return get_engine_state()
        if alive:
            db.send_command("SHUTDOWN_ENGINE")
            t0 = time.time()
            while time.time() - t0 < 6 and psutil.pid_exists(old_pid):
                time.sleep(0.2)
        db.set_setting("engine_launching_until", str(time.time() + 60))
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, f'"{engine_script}"', BASE_DIR, 0
        )
    elif not alive and (force or time.time() > launching_until):
        db.set_setting("engine_launching_until", str(time.time() + 30))
        subprocess.Popen(
            [sys.executable, engine_script],
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        )
    return get_engine_state()


if "engine_boot_done" not in st.session_state:
    st.session_state.engine_boot_done = True
    start_background_engine(as_admin=False)

# ---------------- THEME STATE ---------------- #
if "ui_theme" not in st.session_state:
    st.session_state.ui_theme = "Blue & White (Light)"

is_dark = st.session_state.ui_theme == "Cyber Navy (Dark)"

if is_dark:
    BG_MAIN = "#0b1120"
    BG_CARD = "#111c33"
    BG_INPUT = "#1e293b"
    TEXT_PRIMARY = "#f8fafc"
    TEXT_SECONDARY = "#cbd5e1"
    TEXT_MUTED = "#94a3b8"
    BORDER_COLOR = "#263554"
    ACCENT_BLUE = "#3b82f6"
    TABLE_HEADER_BG = "#172544"
    TABLE_ROW_HOVER = "#16223d"
    BANNER_SEC_BG = "#0f1d36"
    BANNER_SEC_TEXT = "#f1f5f9"
    BANNER_ALR_BG = "#2c1219"
    BANNER_ALR_TEXT = "#fecaca"
    BADGE_CLEAN_BG = "#0c4a6e"
    BADGE_CLEAN_TXT = "#e0f2fe"
    BADGE_DANGER_BG = "#7f1d1d"
    BADGE_DANGER_TXT = "#fee2e2"
    PLOTLY_TEMPLATE = "plotly_dark"
else:
    BG_MAIN = "#f4f7fb"
    BG_CARD = "#ffffff"
    BG_INPUT = "#ffffff"
    TEXT_PRIMARY = "#0f172a"
    TEXT_SECONDARY = "#1e293b"
    TEXT_MUTED = "#475569"
    BORDER_COLOR = "#cbd5e1"
    ACCENT_BLUE = "#0052cc"
    TABLE_HEADER_BG = "#eaf2ff"
    TABLE_ROW_HOVER = "#f8fafc"
    BANNER_SEC_BG = "#ffffff"
    BANNER_SEC_TEXT = "#0f172a"
    BANNER_ALR_BG = "#fff1f2"
    BANNER_ALR_TEXT = "#7f1d1d"
    BADGE_CLEAN_BG = "#e0f2fe"
    BADGE_CLEAN_TXT = "#0369a1"
    BADGE_DANGER_BG = "#fee2e2"
    BADGE_DANGER_TXT = "#b91c1c"
    PLOTLY_TEMPLATE = "plotly_white"


# ---------------- DUAL-THEME CSS (FIXED TOP PADDING & FULL-WIDTH HEADER) ---------------- #
st.markdown(f"""
<style>
    :root {{
        --bg-main: {BG_MAIN};
        --bg-card: {BG_CARD};
        --bg-input: {BG_INPUT};
        --text-primary: {TEXT_PRIMARY};
        --text-secondary: {TEXT_SECONDARY};
        --text-muted: {TEXT_MUTED};
        --border-color: {BORDER_COLOR};
        --accent-blue: {ACCENT_BLUE};
    }}
    .stApp, [data-testid="stAppViewContainer"], [data-testid="stHeader"] {{
        background-color: var(--bg-main) !important;
        color: var(--text-primary) !important;
        font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, sans-serif !important;
    }}
    /* Proper top padding so Streamlit's Stop/Deploy toolbar never clips our header */
    .block-container {{
        padding-top: 3.4rem !important;
        padding-bottom: 2.5rem !important;
        padding-left: 1.5rem !important;
        padding-right: 1.5rem !important;
        max-width: 100% !important;
    }}
    div[data-testid="stMarkdownContainer"] p,
    div[data-testid="stMarkdownContainer"] li,
    div[data-testid="stMarkdownContainer"] span,
    label[data-testid="stWidgetLabel"] p,
    label[data-testid="stWidgetLabel"] span,
    div[data-testid="stWidgetLabel"] p,
    div[data-testid="stCheckbox"] label span,
    div[data-testid="stCheckbox"] p {{
        color: var(--text-primary) !important;
        font-weight: 500 !important;
    }}
    div[data-testid="stCaptionContainer"],
    div[data-testid="stCaptionContainer"] p {{
        color: var(--text-muted) !important;
        font-size: 0.82rem !important;
    }}
    div[data-testid="stForm"] {{
        background-color: var(--bg-card) !important;
        border: 1px solid var(--border-color) !important;
        border-radius: 6px !important;
        padding: 16px !important;
    }}
    div[data-baseweb="input"],
    div[data-baseweb="input"] > div,
    div[data-baseweb="base-input"],
    input[type="text"],
    input[type="number"] {{
        background-color: var(--bg-input) !important;
        color: var(--text-primary) !important;
        border-color: var(--border-color) !important;
        -webkit-text-fill-color: var(--text-primary) !important;
    }}
    div[data-testid="stNumberInput"] button {{
        background-color: var(--bg-input) !important;
        color: var(--text-primary) !important;
        border-color: var(--border-color) !important;
    }}
    div[data-baseweb="select"] > div {{
        background-color: var(--bg-input) !important;
        color: var(--text-primary) !important;
        border-color: var(--border-color) !important;
    }}
    div[data-baseweb="select"] span {{
        color: var(--text-primary) !important;
    }}
    div.stButton > button,
    div[data-testid="stDownloadButton"] > button,
    div[data-testid="stFormSubmitButton"] > button {{
        border-radius: 5px !important;
        font-weight: 600 !important;
        font-size: 0.78rem !important;
        letter-spacing: 0.02em !important;
        border: 1px solid var(--border-color) !important;
        background-color: var(--bg-card) !important;
        color: var(--text-primary) !important;
        padding: 0.45rem 0.75rem !important;
        min-height: 38px !important;
    }}
    div.stButton > button p,
    div[data-testid="stDownloadButton"] > button p,
    div[data-testid="stFormSubmitButton"] > button p {{
        color: var(--text-primary) !important;
        font-weight: 600 !important;
    }}
    div.stButton > button:hover,
    div[data-testid="stDownloadButton"] > button:hover,
    div[data-testid="stFormSubmitButton"] > button:hover {{
        border-color: var(--accent-blue) !important;
        background-color: {TABLE_HEADER_BG} !important;
    }}
    div.stButton > button[kind="primary"],
    div[data-testid="stFormSubmitButton"] > button {{
        background-color: #0052cc !important;
        color: #ffffff !important;
        border: 1px solid #0043a4 !important;
    }}
    div.stButton > button[kind="primary"] p,
    div[data-testid="stFormSubmitButton"] > button p {{
        color: #ffffff !important;
    }}
    div.stButton > button[kind="primary"]:hover,
    div[data-testid="stFormSubmitButton"] > button:hover {{
        background-color: #003d99 !important;
    }}
    div[data-testid="stCodeBlock"], pre, code {{
        background-color: #0f172a !important;
        color: #e2e8f0 !important;
        border: 1px solid #334155 !important;
        border-radius: 6px !important;
    }}
    div[data-testid="stCodeBlock"] span {{
        color: #e2e8f0 !important;
    }}
    button[data-baseweb="tab"] {{
        font-weight: 700 !important;
        color: var(--text-muted) !important;
        font-size: 0.83rem !important;
        letter-spacing: 0.04em !important;
        background-color: transparent !important;
    }}
    button[data-baseweb="tab"] p {{
        color: var(--text-muted) !important;
        font-weight: 700 !important;
    }}
    button[data-baseweb="tab"][aria-selected="true"] {{
        color: var(--accent-blue) !important;
        border-bottom: 3px solid var(--accent-blue) !important;
    }}
    button[data-baseweb="tab"][aria-selected="true"] p {{
        color: var(--accent-blue) !important;
    }}
    /* Full-width responsive top header bar */
    .edr-navbar {{
        width: 100%;
        box-sizing: border-box;
        background: linear-gradient(90deg, #0a2540 0%, #0043a4 60%, #0052cc 100%);
        color: #ffffff !important;
        padding: 18px 26px;
        border-radius: 8px;
        box-shadow: 0 4px 14px rgba(0, 82, 204, 0.16);
        display: flex;
        justify-content: space-between;
        align-items: center;
        flex-wrap: wrap;
        gap: 12px;
        margin-bottom: 14px;
        border-bottom: 3px solid #38bdf8;
    }}
    .edr-brand-title {{
        font-size: 1.32rem;
        font-weight: 700;
        letter-spacing: 0.03em;
        color: #ffffff !important;
        text-transform: uppercase;
        margin: 0;
        line-height: 1.3;
    }}
    .edr-brand-sub {{
        font-size: 0.78rem;
        color: #bae6fd !important;
        letter-spacing: 0.04em;
        text-transform: uppercase;
        margin-top: 4px;
    }}
    .edr-nav-meta {{
        text-align: right;
        font-family: 'Consolas', 'Courier New', monospace;
        font-size: 0.78rem;
        color: #e0f2fe !important;
        background: rgba(255, 255, 255, 0.12);
        padding: 8px 14px;
        border-radius: 6px;
        border: 1px solid rgba(255, 255, 255, 0.22);
        white-space: nowrap;
    }}
    .edr-banner-secure {{
        background-color: {BANNER_SEC_BG};
        border: 1px solid var(--border-color);
        border-left: 6px solid #0284c7;
        padding: 12px 18px;
        border-radius: 6px;
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 14px;
        font-size: 0.85rem;
        color: {BANNER_SEC_TEXT} !important;
        flex-wrap: wrap;
        gap: 8px;
    }}
    .edr-banner-alert {{
        background-color: {BANNER_ALR_BG};
        border: 1px solid #ef4444;
        border-left: 6px solid #dc2626;
        padding: 12px 18px;
        border-radius: 6px;
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 14px;
        font-size: 0.85rem;
        color: {BANNER_ALR_TEXT} !important;
        flex-wrap: wrap;
        gap: 8px;
    }}
    .kpi-grid {{
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
        gap: 12px;
        margin-bottom: 18px;
    }}
    .kpi-card {{
        background: var(--bg-card);
        border: 1px solid var(--border-color);
        border-top: 3px solid var(--accent-blue);
        border-radius: 6px;
        padding: 14px 16px;
        box-shadow: 0 2px 6px rgba(0, 0, 0, 0.04);
    }}
    .kpi-title {{
        font-size: 0.72rem;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        color: var(--text-muted) !important;
        margin-bottom: 6px;
    }}
    .kpi-value {{
        font-size: 1.38rem;
        font-weight: 700;
        font-family: 'Consolas', monospace;
        color: var(--text-primary) !important;
        margin-bottom: 4px;
    }}
    .kpi-sub {{
        font-size: 0.74rem;
        color: var(--accent-blue) !important;
        font-weight: 500;
        white-space: normal;
        word-wrap: break-word;
    }}
    .edr-section-hdr {{
        font-size: 0.84rem;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        color: var(--text-primary) !important;
        border-left: 4px solid var(--accent-blue);
        padding-left: 10px;
        margin-top: 10px;
        margin-bottom: 12px;
    }}
    .edr-table-wrap {{
        background: var(--bg-card);
        border: 1px solid var(--border-color);
        border-radius: 6px;
        overflow-x: auto;
        margin-bottom: 14px;
    }}
    table.edr-table {{
        width: 100%;
        border-collapse: collapse;
        font-size: 0.82rem;
        color: var(--text-primary) !important;
    }}
    table.edr-table thead th {{
        background-color: {TABLE_HEADER_BG};
        color: var(--text-primary) !important;
        font-weight: 700;
        text-transform: uppercase;
        font-size: 0.73rem;
        letter-spacing: 0.04em;
        padding: 10px 14px;
        border-bottom: 2px solid var(--border-color);
        text-align: left;
        white-space: nowrap;
    }}
    table.edr-table tbody td {{
        padding: 9px 14px;
        border-bottom: 1px solid var(--border-color);
        color: var(--text-secondary) !important;
        word-break: break-word;
    }}
    table.edr-table tbody tr:hover {{
        background-color: {TABLE_ROW_HOVER};
    }}
    .mono-cell {{
        font-family: 'Consolas', monospace !important;
        font-size: 0.79rem;
        color: var(--text-primary) !important;
    }}
    .badge-clean {{
        background-color: {BADGE_CLEAN_BG};
        color: {BADGE_CLEAN_TXT} !important;
        border: 1px solid #38bdf8;
        padding: 3px 8px;
        border-radius: 4px;
        font-size: 0.71rem;
        font-weight: 700;
        font-family: monospace;
        display: inline-block;
        white-space: nowrap;
    }}
    .badge-danger {{
        background-color: {BADGE_DANGER_BG};
        color: {BADGE_DANGER_TXT} !important;
        border: 1px solid #f87171;
        padding: 3px 8px;
        border-radius: 4px;
        font-size: 0.71rem;
        font-weight: 700;
        font-family: monospace;
        display: inline-block;
        white-space: nowrap;
    }}
    .badge-killed {{
        background-color: #0052cc;
        color: #ffffff !important;
        padding: 3px 8px;
        border-radius: 4px;
        font-size: 0.71rem;
        font-weight: 700;
        font-family: monospace;
        display: inline-block;
        white-space: nowrap;
    }}
</style>
""", unsafe_allow_html=True)


# ---------------- PURE-PYTHON PDF REPORT GENERATOR ---------------- #
def build_pdf_incident_report(df_alerts: pd.DataFrame) -> bytes:
    def escape_pdf_text(text: str) -> str:
        clean = str(text).encode("ascii", "replace").decode("ascii")
        return clean.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")

    lines = [
        "DAWOOD UNIVERSITY OF ENGINEERING & TECHNOLOGY (DUET)",
        "MINI-EDR SECURITY OPERATIONS CENTER - INCIDENT AUDIT REPORT",
        f"Generated Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "-" * 92
    ]

    if df_alerts.empty:
        lines.append("No ransomware incidents recorded during the current monitoring period.")
    else:
        for idx, row in df_alerts.iterrows():
            lines.append(
                f"INCIDENT #{row.get('id', idx + 1)} | TIMESTAMP: {row.get('timestamp', 'N/A')} | "
                f"PROCESS: {row.get('process_name', 'Unknown')} (PID: {row.get('pid', 0)})"
            )
            lines.append(
                f"  Disposition      : {str(row.get('disposition', 'N/A')).upper()} | "
                f"Affected Assets: {row.get('affected_files', 0)}"
            )
            lines.append(f"  Trigger Heuristic: {row.get('reason', 'N/A')}")
            lines.append(
                f"  Recovery Tier    : {row.get('recovery_method', 'N/A')} "
                f"({row.get('recovery_details', 'N/A')})"
            )
            lines.append(
                f"  Telemetry SLA    : Detection = {row.get('detection_time_ms', 0)} ms | "
                f"Restoration = {row.get('restore_time_ms', 0)} ms"
            )
            lines.append("-" * 92)

    page_size = 48
    pages_lines = [lines[i:i + page_size] for i in range(0, max(1, len(lines)), page_size)]

    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>"
    ]

    page_obj_ids = []
    for p_lines in pages_lines:
        content_ops = ["BT", "/F1 8.5 Tf", "36 756 Td", "14 TL"]
        for line in p_lines:
            content_ops.append(f"({escape_pdf_text(line[:105])}) Tj T*")
        content_ops.append("ET")
        stream_bytes = "\n".join(content_ops).encode("latin-1")

        content_obj_id = len(objects) + 1
        objects.append(
            f"<< /Length {len(stream_bytes)} >>\nstream\n".encode("latin-1")
            + stream_bytes
            + b"\nendstream"
        )

        page_obj_id = len(objects) + 1
        page_obj_ids.append(page_obj_id)
        objects.append(
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            f"/Resources << /Font << /F1 3 0 R >> >> /Contents {content_obj_id} 0 R >>".encode("latin-1")
        )

    kids_str = " ".join(f"{pid} 0 R" for pid in page_obj_ids)
    objects[1] = f"<< /Type /Pages /Kids [{kids_str}] /Count {len(page_obj_ids)} >>".encode("latin-1")

    pdf_out = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for i, obj_body in enumerate(objects, start=1):
        offsets.append(len(pdf_out))
        pdf_out.extend(f"{i} 0 obj\n".encode("latin-1"))
        pdf_out.extend(obj_body)
        pdf_out.extend(b"\nendobj\n")

    xref_pos = len(pdf_out)
    pdf_out.extend(f"xref\n0 {len(objects) + 1}\n".encode("latin-1"))
    pdf_out.extend(b"0000000000 65535 f \n")
    for off in offsets[1:]:
        pdf_out.extend(f"{off:010d} 00000 n \n".encode("latin-1"))

    pdf_out.extend(
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF\n".encode("latin-1")
    )
    return bytes(pdf_out)


# ---------------- HUMAN-FRIENDLY EVENT HELPERS ---------------- #
def simplify_event_name(raw_type: str) -> str:
    mapping = {
        "CREATED": "File Created",
        "MODIFIED": "File Modified",
        "RENAMED": "File Renamed",
        "DELETED": "File Deleted",
        "TRAP_MODIFIED": "Trap File Modified",
        "TRAP_RENAMED": "Trap File Renamed",
        "TRAP_DELETED": "Trap File Deleted",
        "VAULT_TAMPER": "Vault Tamper Blocked",
    }
    return mapping.get(str(raw_type), str(raw_type))


def classify_event_risk(row) -> str:
    ev = str(row["event_type"])
    fname = str(row["file_path"]).lower()
    if "TRAP" in ev or "VAULT" in ev or fname.endswith((".locked", ".enc", ".crypted", ".ransom", ".hacked")):
        return "Attack Activity (Threat)"
    if float(row.get("delta_entropy", 0.0)) >= 0.8 and float(row.get("new_entropy", 0.0)) >= 6.5:
        return "Attack Activity (Threat)"
    return "Normal Activity (Safe)"


# ---------------- FULL-WIDTH TOP HEADER ---------------- #
st.markdown(f"""
<div class="edr-navbar">
    <div>
        <div class="edr-brand-title">Behavior-Based Ransomware Detector (Mini-EDR)</div>
        <div class="edr-brand-sub">Dawood University of Engineering & Technology (DUET) — Group F | Information Security Lab</div>
    </div>
    <div class="edr-nav-meta">
        MODE: ENFORCING &nbsp;|&nbsp; VAULT TAMPER GUARD: ACTIVE<br>
        CONSOLE PID: {os.getpid()} &nbsp;|&nbsp; THEME: {st.session_state.ui_theme.upper()}
    </div>
</div>
""", unsafe_allow_html=True)


# ---------------- LIVE STATUS BANNER & KPI RIBBON ---------------- #
@st.fragment(run_every=1.5)
@safe_render
def render_live_telemetry_header():
    alive, engine_pid, is_admin = get_engine_state()
    status = db.get_setting("system_status", "SECURE")
    t1_on = db.get_setting("tier1_vss_enabled", "1") == "1"
    t2_on = db.get_setting("tier2_vault_enabled", "1") == "1"
    folders = db.get_protected_folders()

    if is_admin and t1_on:
        active_tier_label = "TIER-1 VSS"
        priv_badge = "<span class='badge-killed'>ADMIN | TIER-1 VSS ON</span>"
    elif t2_on:
        active_tier_label = "TIER-2 VAULT"
        priv_badge = "<span class='badge-clean'>TIER-2 VAULT ACTIVE (VSS OFF)</span>" if is_admin else "<span class='badge-clean'>STANDARD | TIER-2 VAULT</span>"
    else:
        active_tier_label = "TIER-3 REPORT"
        priv_badge = "<span class='badge-danger'>TIER-3 REPORT ONLY</span>"

    launching = float(db.get_setting("engine_launching_until", "0") or 0) > time.time()

    if not alive:
        c_off1, c_off2 = st.columns([4, 2])
        with c_off1:
            if launching:
                st.markdown(
                    '<div class="edr-banner-secure">'
                    '<div><span class="badge-clean">STARTING</span> &nbsp;&nbsp;'
                    '<b>Sensor is initializing protected folders & folder-mirrored backups. Please wait...</b></div>'
                    '</div>',
                    unsafe_allow_html=True
                )
            else:
                st.markdown(
                    '<div class="edr-banner-alert">'
                    '<div><span class="badge-danger">SENSOR OFFLINE</span> &nbsp;&nbsp;'
                    '<b>Background behavioral monitoring service is not running.</b></div>'
                    '</div>',
                    unsafe_allow_html=True
                )
        with c_off2:
            b_sub1, b_sub2 = st.columns(2)
            with b_sub1:
                if st.button("START SENSOR", use_container_width=True):
                    start_background_engine(as_admin=False, force=True)
                    st.rerun()
            with b_sub2:
                if st.button("START AS ADMIN (VSS)", use_container_width=True, type="primary"):
                    start_background_engine(as_admin=True)
                    st.rerun()
    elif status == "SECURE":
        if not is_admin:
            c_s1, c_s2 = st.columns([4, 1])
            with c_s1:
                st.markdown(
                    f'<div class="edr-banner-secure">'
                    f'<div><span class="badge-clean">NOMINAL</span> &nbsp;&nbsp;<b>ENDPOINT STATE: SECURE</b> &nbsp;|&nbsp; '
                    f'Monitoring {len(folders)} Folder(s) + Backup Vault Guard Active</div>'
                    f'<div class="mono-cell">PID: <b>{engine_pid}</b> &nbsp;|&nbsp; {priv_badge}</div>'
                    f'</div>',
                    unsafe_allow_html=True
                )
            with c_s2:
                if st.button("ENABLE TIER-1 VSS (ADMIN)", use_container_width=True, type="primary"):
                    start_background_engine(as_admin=True)
                    st.rerun()
        else:
            st.markdown(
                f'<div class="edr-banner-secure">'
                f'<div><span class="badge-clean">NOMINAL</span> &nbsp;&nbsp;<b>ENDPOINT STATE: SECURE</b> &nbsp;|&nbsp; '
                f'Monitoring {len(folders)} Folder(s) + Backup Vault Guard Active</div>'
                f'<div class="mono-cell">PID: <b>{engine_pid}</b> &nbsp;|&nbsp; {priv_badge}</div>'
                f'</div>',
                unsafe_allow_html=True
            )
    else:
        c_inc1, c_inc2 = st.columns([5, 1])
        with c_inc1:
            st.markdown(
                f'<div class="edr-banner-alert">'
                f'<div><span class="badge-danger">LIVE ALERT</span> &nbsp;&nbsp;<b>{status}</b></div>'
                f'<div class="mono-cell">PID: <b>{engine_pid}</b> &nbsp;|&nbsp; {priv_badge}</div>'
                f'</div>',
                unsafe_allow_html=True
            )
        with c_inc2:
            if st.button("ACKNOWLEDGE ALERT", use_container_width=True, type="primary"):
                db.set_setting("system_status", "SECURE")
                st.rerun()

    unrec = db.get_setting("last_unrecovered", "")
    if unrec:
        st.error(f"LEVEL 3 REPORT — Unrecovered files requiring manual recovery: {unrec}")
        if st.button("DISMISS UNRECOVERED LIST", key="dismiss_unrec"):
            db.set_setting("last_unrecovered", "")
            st.rerun()

    monitored_cnt = db.get_setting("monitored_files_count", "0")
    vault_kb = db.get_setting("vault_size_kb", "0.0")
    savings_pct = db.get_setting("vault_savings_pct", "0.0")
    cpu_pct = db.get_setting("engine_cpu", "0.0")
    ram_mb = db.get_setting("engine_ram_mb", "0.0")

    st.markdown(f"""
    <div class="kpi-grid">
        <div class="kpi-card">
            <div class="kpi-title">Protected Assets</div>
            <div class="kpi-value">{monitored_cnt} Files</div>
            <div class="kpi-sub">Across {len(folders)} Folder(s) + Canary Traps</div>
        </div>
        <div class="kpi-card">
            <div class="kpi-title">Folder-Mirrored Vault</div>
            <div class="kpi-value">{vault_kb} KB</div>
            <div class="kpi-sub">Read-Only + Monitored ({savings_pct}% Saved)</div>
        </div>
        <div class="kpi-card">
            <div class="kpi-title">Sensor CPU Overhead</div>
            <div class="kpi-value">{cpu_pct} %</div>
            <div class="kpi-sub">Event-Driven Target: Near 0% Idle</div>
        </div>
        <div class="kpi-card">
            <div class="kpi-title">Sensor Memory Allocation</div>
            <div class="kpi-value">{ram_mb} MB</div>
            <div class="kpi-sub">Target Envelope: 60 - 100 MB</div>
        </div>
        <div class="kpi-card">
            <div class="kpi-title">Active Recovery Tier</div>
            <div class="kpi-value">{active_tier_label}</div>
            <div class="kpi-sub">Toggle Tiers Anytime in Tab 04</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

render_live_telemetry_header()


# ---------------- NAVIGATION TABS ---------------- #
tab_sandbox, tab_monitor, tab_alerts, tab_policy = st.tabs([
    "01 | LIVE DEMO & SIMULATION PANEL",
    "02 | LIVE MONITOR & SIMPLE GRAPHS",
    "03 | THREAT ALERTS & RECOVERY LOGS",
    "04 | FOLDERS, RECOVERY TIERS & SETTINGS"
])


# ==============================================================================
# TAB 1: LIVE DEMO & SIMULATION PANEL
# ==============================================================================
with tab_sandbox:
    st.markdown('<div class="edr-section-hdr">Controlled Ransomware Emulation (Safe Presentation Demo)</div>', unsafe_allow_html=True)

    folders = db.get_protected_folders()
    safe_demo_folders = [
        f for f in folders
        if os.path.normcase(f).startswith(os.path.normcase(BASE_DIR)) and os.path.isdir(f)
    ]
    if not safe_demo_folders:
        safe_demo_folders = [DEMO_SANDBOX]

    sel_col1, sel_col2 = st.columns([2, 3])
    with sel_col1:
        target_demo_folder = st.selectbox("Select Target Folder to Simulate Attack On:", safe_demo_folders)
    with sel_col2:
        hold_sec = float(db.get_setting("visual_hold_sec", "3.0") or 3.0)
        st.caption(
            f"The engine monitors ALL {len(folders)} folders plus MiniEDR_Backup_Vault. "
            f"On attack, the ransomware is killed immediately and compromised files stay visible for {hold_sec:.0f}s before auto-restore."
        )

    sim_c1, sim_c2, sim_c3, sim_c4, sim_c5, sim_c6 = st.columns(6)

    with sim_c1:
        if st.button("FULL BURST ATTACK", type="primary", use_container_width=True):
            subprocess.Popen([sys.executable, os.path.join(BASE_DIR, "fake_ransomware.py"), "normal", target_demo_folder])
            st.toast(f"Full burst attack launched on {os.path.basename(target_demo_folder)}.")

    with sim_c2:
        if st.button("CANARY TRAP PROBE", use_container_width=True):
            subprocess.Popen([sys.executable, os.path.join(BASE_DIR, "fake_ransomware.py"), "trap", target_demo_folder])
            st.toast("Canary (!000_Trap) probe launched.")

    with sim_c3:
        if st.button("HEADER CORRUPTION", use_container_width=True):
            subprocess.Popen([sys.executable, os.path.join(BASE_DIR, "fake_ransomware.py"), "partial", target_demo_folder])
            st.toast("4KB header corruption attack launched.")

    with sim_c4:
        if st.button("TRAP-EVADING BURST", use_container_width=True):
            subprocess.Popen([sys.executable, os.path.join(BASE_DIR, "fake_ransomware.py"), "notrap", target_demo_folder])
            st.toast("Trap-evading attack launched (tests speed + entropy rules).")

    with sim_c5:
        if st.button("TEST VAULT TAMPER", use_container_width=True):
            subprocess.Popen([sys.executable, os.path.join(BASE_DIR, "fake_ransomware.py"), "vault"])
            st.toast("Simulated attacker trying to corrupt MiniEDR_Backup_Vault!")

    with sim_c6:
        if st.button("RESET DEMO SANDBOX", use_container_width=True):
            db.send_command("REINIT_SANDBOX")
            st.toast("Sandbox reset command dispatched.")

    @st.fragment(run_every=1.5)
    @safe_render
    def render_sandbox_inventory():
        if db.get_setting("engine_busy", "0") == "1" and get_engine_state()[0]:
            st.info("Sensor is syncing backups. Live inventory resumes in a moment...")
            return

        df_latest = db.read_df("SELECT * FROM alerts ORDER BY id DESC LIMIT 1")
        if not df_latest.empty:
            r = df_latest.iloc[0]
            st.markdown(
                f"<div class='edr-banner-alert'>"
                f"<div><span class='badge-killed'>LATEST BLOCKED ATTACK #{r['id']}</span> &nbsp;&nbsp;"
                f"<b>Process:</b> <code>{r['process_name']} (PID: {r['pid']})</code> &rarr; <b>{str(r['disposition']).upper()}</b> &nbsp;|&nbsp; "
                f"<b>Reason:</b> {r['reason']}</div>"
                f"<div class='mono-cell'><b>Recovery:</b> {r['recovery_method']} ({r['affected_files']} files) &nbsp;|&nbsp; "
                f"<b>Detect:</b> {r['detection_time_ms']} ms &nbsp;|&nbsp; <b>Restore:</b> {r['restore_time_ms']} ms</div>"
                f"</div>",
                unsafe_allow_html=True
            )

        vault_meta_map = db.get_all_vault_meta()

        col_inv1, col_inv2 = st.columns([3, 2])

        with col_inv1:
            st.markdown(f'<div class="edr-section-hdr">Live Files in Selected Folder: {os.path.basename(target_demo_folder)}</div>', unsafe_allow_html=True)
            try:
                names = sorted(os.listdir(target_demo_folder)) if os.path.isdir(target_demo_folder) else []
            except OSError:
                names = []

            asset_html = []
            for fname in names:
                fpath = os.path.abspath(os.path.join(target_demo_folder, fname))
                try:
                    if not os.path.isfile(fpath):
                        continue
                    ent = calculate_entropy(fpath)
                    sz = os.path.getsize(fpath)
                    sha = get_sha256(fpath)
                    meta = vault_meta_map.get(fpath)
                    clean_hash = meta[2] if meta else None
                    is_comp = is_file_compromised(fpath, known_clean_hash=clean_hash)
                except OSError:
                    continue
                badge = "<span class='badge-danger'>COMPROMISED</span>" if is_comp else "<span class='badge-clean'>SAFE</span>"
                asset_html.append(
                    f"<tr>"
                    f"<td>{badge}</td>"
                    f"<td class='mono-cell'><b>{fname}</b></td>"
                    f"<td class='mono-cell'>{sz:,} B</td>"
                    f"<td class='mono-cell'>{ent:.2f}</td>"
                    f"<td class='mono-cell'>{sha[:20]}...</td>"
                    f"</tr>"
                )
            if asset_html:
                st.markdown(
                    "<div class='edr-table-wrap'><table class='edr-table'>"
                    "<thead><tr><th>Status</th><th>File Name</th><th>Size</th><th>Entropy</th><th>SHA-256 Hash</th></tr></thead>"
                    f"<tbody>{''.join(asset_html)}</tbody></table></div>",
                    unsafe_allow_html=True
                )
            else:
                st.info("This folder has no files yet. Add any .docx, .pdf, .txt, or .jpg file and the engine will back it up automatically.")

        with col_inv2:
            st.markdown('<div class="edr-section-hdr">Folder-Mirrored Backup Vault Structure</div>', unsafe_allow_html=True)
            df_vault = db.read_df("SELECT file_path, orig_size, comp_size FROM vault_metadata ORDER BY file_path ASC")
            if not df_vault.empty:
                vault_html = []
                for _, vr in df_vault.iterrows():
                    fp = str(vr["file_path"])
                    folder_lbl = os.path.basename(os.path.dirname(fp))
                    file_lbl = os.path.basename(fp)
                    orig_sz = int(vr["orig_size"] or 0)
                    comp_sz = int(vr["comp_size"] or 0)
                    saving = round((1.0 - (comp_sz / orig_sz)) * 100, 1) if orig_sz > 0 else 0.0
                    vault_html.append(
                        f"<tr>"
                        f"<td class='mono-cell'><span class='badge-clean'>{folder_lbl}</span> / <b>{file_lbl}</b></td>"
                        f"<td class='mono-cell'>{orig_sz:,} B</td>"
                        f"<td class='mono-cell'>{comp_sz:,} B</td>"
                        f"<td><span class='badge-clean'>-{saving}%</span></td>"
                        f"</tr>"
                    )
                st.markdown(
                    "<div class='edr-table-wrap'><table class='edr-table'>"
                    "<thead><tr><th>Vault Folder / File</th><th>Original</th><th>Vault</th><th>Saved</th></tr></thead>"
                    f"<tbody>{''.join(vault_html)}</tbody></table></div>",
                    unsafe_allow_html=True
                )
            else:
                st.info("No files backed up in vault yet.")

    render_sandbox_inventory()


# ==============================================================================
# TAB 2: LIVE MONITOR & SIMPLE GRAPHS (CLEAN, UNCLUTTERED, BEGINNER-FRIENDLY)
# ==============================================================================
with tab_monitor:
    @st.fragment(run_every=2.0)
    @safe_render
    def render_soc_monitor():
        df_events = db.read_df("SELECT * FROM file_events ORDER BY id DESC LIMIT 40")

        if not df_events.empty:
            df_chron = df_events.iloc[::-1].copy()
            df_chron["time_sec"] = df_chron["timestamp"].str.slice(0, 8)
            df_chron["Activity_Category"] = df_chron.apply(classify_event_risk, axis=1)

            col_chart1, col_chart2 = st.columns(2)

            # CHART 1: Simple Last 12 Active Timestamps (Blue = Safe, Red = Threat)
            with col_chart1:
                st.markdown('<div class="edr-section-hdr">Chart 1: Recent File Activity (Blue = Safe | Red = Attack)</div>', unsafe_allow_html=True)
                recent_times = df_chron["time_sec"].drop_duplicates().tail(12)
                df_c1 = df_chron[df_chron["time_sec"].isin(recent_times)]
                df_simple = (
                    df_c1.groupby(["time_sec", "Activity_Category"])
                    .size()
                    .reset_index(name="Files_Touched")
                )
                fig_activity = px.bar(
                    df_simple,
                    x="time_sec",
                    y="Files_Touched",
                    color="Activity_Category",
                    barmode="group",
                    template=PLOTLY_TEMPLATE,
                    color_discrete_map={
                        "Normal Activity (Safe)": "#0284c7",
                        "Attack Activity (Threat)": "#dc2626",
                    },
                    labels={
                        "time_sec": "Time (HH:MM:SS)",
                        "Files_Touched": "Files Changed",
                        "Activity_Category": "Status"
                    }
                )
                fig_activity.update_layout(
                    paper_bgcolor=BG_CARD,
                    plot_bgcolor=BG_CARD,
                    font=dict(color=TEXT_PRIMARY, size=11),
                    height=350,
                    margin=dict(l=20, r=20, t=48, b=50),
                    xaxis=dict(title="Time (HH:MM:SS)", tickfont=dict(color=TEXT_SECONDARY), gridcolor=BORDER_COLOR, tickangle=-25),
                    yaxis=dict(title="Files Changed", tickfont=dict(color=TEXT_SECONDARY), gridcolor=BORDER_COLOR, dtick=1),
                    legend=dict(orientation="h", y=1.15, x=0, title=None, font=dict(color=TEXT_PRIMARY))
                )
                st.plotly_chart(fig_activity, use_container_width=True, theme=None)

            # CHART 2: Last 15 Events Entropy Comparison (Clean #ID on X-axis, Full File Name on Hover)
            with col_chart2:
                st.markdown('<div class="edr-section-hdr">Chart 2: File Randomness / Entropy (Last 15 Events — Hover for File Name)</div>', unsafe_allow_html=True)
                df_c2 = df_chron.tail(15).copy()
                df_c2["short_id"] = "#" + df_c2["id"].astype(str)

                fig_entropy = go.Figure()
                fig_entropy.add_trace(go.Scatter(
                    x=df_c2["short_id"],
                    y=df_c2["old_entropy"],
                    customdata=df_c2["file_path"],
                    name="Before (Clean File)",
                    mode="lines+markers",
                    line=dict(color="#0284c7", width=2.5, shape="spline"),
                    marker=dict(size=7, color="#0284c7"),
                    fill="tozeroy",
                    fillcolor="rgba(2, 132, 199, 0.10)",
                    hovertemplate="<b>%{customdata}</b><br>Event: %{x}<br>Before Entropy: %{y:.2f}<extra></extra>"
                ))
                fig_entropy.add_trace(go.Scatter(
                    x=df_c2["short_id"],
                    y=df_c2["new_entropy"],
                    customdata=df_c2["file_path"],
                    name="After (Modified File)",
                    mode="lines+markers",
                    line=dict(color="#dc2626", width=2.8, shape="spline"),
                    marker=dict(size=8, color="#dc2626"),
                    fill="tonexty",
                    fillcolor="rgba(220, 38, 38, 0.16)",
                    hovertemplate="<b>%{customdata}</b><br>Event: %{x}<br>After Entropy: %{y:.2f}<extra></extra>"
                ))
                high_ent_limit = float(db.get_setting("absolute_high_entropy", 7.2))
                fig_entropy.add_hline(
                    y=high_ent_limit,
                    line_dash="dash",
                    line_color="#d97706",
                    annotation_text=f"Text Encryption Limit ({high_ent_limit:.2f})",
                    annotation_position="bottom right",
                    annotation_font=dict(size=10, color="#d97706")
                )
                fig_entropy.update_layout(
                    template=PLOTLY_TEMPLATE,
                    paper_bgcolor=BG_CARD,
                    plot_bgcolor=BG_CARD,
                    font=dict(color=TEXT_PRIMARY, size=11),
                    height=350,
                    margin=dict(l=20, r=20, t=48, b=50),
                    xaxis=dict(title="Event ID (Hover Dot for File Name)", tickfont=dict(color=TEXT_SECONDARY, size=11), gridcolor=BORDER_COLOR),
                    yaxis=dict(range=[0, 8.6], title="Shannon Entropy (0 - 8)", tickfont=dict(color=TEXT_SECONDARY), gridcolor=BORDER_COLOR),
                    legend=dict(orientation="h", y=1.15, x=0, font=dict(color=TEXT_PRIMARY))
                )
                st.plotly_chart(fig_entropy, use_container_width=True, theme=None)

            c_hdr1, c_hdr2 = st.columns([5, 1])
            with c_hdr1:
                st.markdown('<div class="edr-section-hdr">Recent File Activity Log (Simplified View)</div>', unsafe_allow_html=True)
            with c_hdr2:
                if st.button("CLEAR LOG", use_container_width=True):
                    db.execute_write("DELETE FROM file_events")
                    st.rerun()

            rows_html = []
            for _, r in df_events.head(25).iterrows():
                is_threat = classify_event_risk(r).startswith("Attack")
                risk_badge = "<span class='badge-danger'>THREAT</span>" if is_threat else "<span class='badge-clean'>SAFE</span>"
                action_text = simplify_event_name(r["event_type"])
                rows_html.append(
                    f"<tr>"
                    f"<td class='mono-cell'>#{r['id']}</td>"
                    f"<td class='mono-cell'>{r['timestamp']}</td>"
                    f"<td>{risk_badge}</td>"
                    f"<td><b>{action_text}</b></td>"
                    f"<td class='mono-cell'>{r['file_path']}</td>"
                    f"<td class='mono-cell'>{r['old_entropy']:.2f} &rarr; <b>{r['new_entropy']:.2f}</b></td>"
                    f"</tr>"
                )
            st.markdown(
                "<div class='edr-table-wrap'><table class='edr-table'>"
                "<thead><tr><th>ID</th><th>Time</th><th>Risk Level</th><th>Action</th><th>File Name</th><th>Entropy (Before &rarr; After)</th></tr></thead>"
                f"<tbody>{''.join(rows_html)}</tbody></table></div>",
                unsafe_allow_html=True
            )
        else:
            st.markdown('<div class="edr-section-hdr">Recent File Activity Log</div>', unsafe_allow_html=True)
            st.info("No file activity recorded yet. Use Tab 01 to run a simulated attack or add files to a protected folder.")

    render_soc_monitor()


# ==============================================================================
# TAB 3: THREAT ALERTS & RECOVERY LOGS
# ==============================================================================
with tab_alerts:
    @st.fragment(run_every=2.0)
    @safe_render
    def render_incident_history():
        st.markdown('<div class="edr-section-hdr">Blocked Ransomware Attacks & Automated Recovery History</div>', unsafe_allow_html=True)
        df_alerts = db.read_df("SELECT * FROM alerts ORDER BY id DESC")

        if not df_alerts.empty:
            inc_rows = []
            for _, row in df_alerts.iterrows():
                disp = str(row["disposition"]).upper()
                disp_badge = f"<span class='badge-killed'>{disp}</span>" if disp == "KILLED" else f"<span class='badge-danger'>{disp}</span>"
                inc_rows.append(
                    f"<tr>"
                    f"<td class='mono-cell'><b>#{row['id']}</b></td>"
                    f"<td class='mono-cell'>{row['timestamp']}</td>"
                    f"<td class='mono-cell'><b>{row['process_name']}</b> (PID: {row['pid']})</td>"
                    f"<td>{disp_badge}</td>"
                    f"<td>{row['reason']}</td>"
                    f"<td class='mono-cell'><b>{row['affected_files']}</b></td>"
                    f"<td><span class='badge-clean'>{row['recovery_method']}</span><br><small>{row['recovery_details']}</small></td>"
                    f"<td class='mono-cell'>{row['detection_time_ms']} ms / {row['restore_time_ms']} ms</td>"
                    f"</tr>"
                )
            st.markdown(
                "<div class='edr-table-wrap'><table class='edr-table'>"
                "<thead><tr><th>ID</th><th>Timestamp</th><th>Process & PID</th><th>Action</th>"
                "<th>Detection Reason</th><th>Files</th><th>Recovery Result</th><th>Detect / Restore</th></tr></thead>"
                f"<tbody>{''.join(inc_rows)}</tbody></table></div>",
                unsafe_allow_html=True
            )

            exp_c1, exp_c2, exp_c3 = st.columns(3)
            with exp_c1:
                csv_bytes = df_alerts.to_csv(index=False).encode("utf-8")
                st.download_button(
                    label="EXPORT REPORT (CSV)",
                    data=csv_bytes,
                    file_name="mini_edr_incident_report.csv",
                    mime="text/csv",
                    use_container_width=True
                )
            with exp_c2:
                pdf_bytes = build_pdf_incident_report(df_alerts)
                st.download_button(
                    label="EXPORT REPORT (PDF)",
                    data=pdf_bytes,
                    file_name="mini_edr_incident_report.pdf",
                    mime="application/pdf",
                    use_container_width=True
                )
            with exp_c3:
                if st.button("CLEAR HISTORY", use_container_width=True):
                    db.execute_write("DELETE FROM alerts")
                    db.set_setting("system_status", "SECURE")
                    st.rerun()
        else:
            st.info("No ransomware attacks recorded yet.")

    render_incident_history()


# ==============================================================================
# TAB 4: PROTECTED FOLDERS, RECOVERY TIERS, SETTINGS & WHITELIST
# ==============================================================================
with tab_policy:
    col_pol1, col_pol2 = st.columns(2)

    with col_pol1:
        st.markdown('<div class="edr-section-hdr">Protected Folders (Mirrored Inside Backup Vault)</div>', unsafe_allow_html=True)
        st.caption("Add any folder containing existing .docx, .pdf, .xlsx, .jpg files. Each folder gets its own subfolder inside MiniEDR_Backup_Vault.")

        new_folder_input = st.text_input(
            "Folder Path to Protect",
            placeholder=r"C:\IS_project\Folder_2"
        )
        if st.button("ADD PROTECTED FOLDER", use_container_width=True, type="primary"):
            cleaned_dir = os.path.abspath(new_folder_input.strip().strip('"'))
            if not new_folder_input.strip():
                st.error("Enter a folder path first.")
            elif os.path.normcase(cleaned_dir) == os.path.normcase(VAULT_DIR):
                st.error("Backup Vault is already monitored by the Vault Tamper Guard.")
            elif os.path.isdir(cleaned_dir):
                cur_folders = db.get_protected_folders()
                if os.path.normcase(cleaned_dir) not in [os.path.normcase(x) for x in cur_folders]:
                    cur_folders.append(cleaned_dir)
                    db.set_protected_folders(cur_folders)
                    db.send_command("RELOAD_WATCHES")
                    st.success(f"Added '{cleaned_dir}'. Engine is backing it up into MiniEDR_Backup_Vault\\{os.path.basename(cleaned_dir)}\\")
                    st.rerun()
                else:
                    st.info("This folder is already protected.")
            else:
                st.error("Folder does not exist on disk. Create it first or check the path.")

        monitored_folders = db.get_protected_folders()
        f_rows = []
        for idx, fpath in enumerate(monitored_folders, start=1):
            exists = os.path.isdir(fpath)
            f_badge = "<span class='badge-clean'>MONITORING</span>" if exists else "<span class='badge-danger'>NOT FOUND</span>"
            f_rows.append(
                f"<tr>"
                f"<td class='mono-cell'>#{idx}</td>"
                f"<td class='mono-cell'><b>{fpath}</b></td>"
                f"<td>{f_badge}</td>"
                f"</tr>"
            )
        st.markdown(
            "<div class='edr-table-wrap'><table class='edr-table'>"
            "<thead><tr><th>#</th><th>Protected Folder Path</th><th>State</th></tr></thead>"
            f"<tbody>{''.join(f_rows)}</tbody></table></div>",
            unsafe_allow_html=True
        )

        if len(monitored_folders) > 1:
            rem_col1, rem_col2 = st.columns([3, 1])
            with rem_col1:
                folder_to_remove = st.selectbox("Select Folder to Stop Monitoring", monitored_folders)
            with rem_col2:
                st.write("")
                if st.button("REMOVE", use_container_width=True):
                    updated = [f for f in monitored_folders if f != folder_to_remove]
                    db.set_protected_folders(updated)
                    db.send_command("RELOAD_WATCHES")
                    st.rerun()

        st.divider()

        st.markdown('<div class="edr-section-hdr">3-Tier Recovery Switches & Console Theme</div>', unsafe_allow_html=True)
        st.caption("Turn Tier-1 VSS OFF to demonstrate Tier-2 Folder Vault recovery. Turn both OFF to demonstrate Tier-3 Contain & Report.")

        t1_val = db.get_setting("tier1_vss_enabled", "1") == "1"
        t2_val = db.get_setting("tier2_vault_enabled", "1") == "1"

        new_t1 = st.checkbox("Enable Tier-1: Windows Volume Shadow Copy (VSS)", value=t1_val)
        new_t2 = st.checkbox("Enable Tier-2: Folder-Mirrored Backup Vault (.zvault)", value=t2_val)

        if new_t1 != t1_val or new_t2 != t2_val:
            db.set_settings_batch({
                "tier1_vss_enabled": "1" if new_t1 else "0",
                "tier2_vault_enabled": "1" if new_t2 else "0",
            })
            st.success("Recovery tier configuration updated live!")
            st.rerun()

        chosen_theme = st.selectbox(
            "Console Color Theme",
            ["Blue & White (Light)", "Cyber Navy (Dark)"],
            index=0 if st.session_state.ui_theme == "Blue & White (Light)" else 1
        )
        if chosen_theme != st.session_state.ui_theme:
            st.session_state.ui_theme = chosen_theme
            st.rerun()

        if db.get_setting("engine_is_admin", "0") != "1":
            if st.button("ELEVATE SENSOR AS ADMIN (ACTIVATE TIER-1 VSS)", use_container_width=True, type="primary"):
                start_background_engine(as_admin=True)
                st.rerun()

    with col_pol2:
        st.markdown('<div class="edr-section-hdr">Detection Thresholds & Live Demo Timing</div>', unsafe_allow_html=True)
        with st.form("heuristic_policy_form"):
            speed_files = st.number_input(
                "Max Modified Files in Time Window (Speed Check)",
                value=int(db.get_setting("speed_limit_files", 4)),
                min_value=2,
                max_value=50
            )
            speed_win = st.number_input(
                "Time Window (Seconds)",
                value=int(db.get_setting("speed_window_sec", 5)),
                min_value=1,
                max_value=60
            )
            ent_delta = st.slider(
                "Minimum Entropy Jump (Delta Threshold)",
                min_value=0.1,
                max_value=4.0,
                value=float(db.get_setting("entropy_delta_threshold", 0.8)),
                step=0.1
            )
            abs_ent = st.slider(
                "High Entropy Threshold for Text Files (0.0 - 8.0)",
                min_value=6.0,
                max_value=7.95,
                value=float(db.get_setting("absolute_high_entropy", 7.2)),
                step=0.05
            )
            visual_hold = st.slider(
                "Demo Visual Pause After Process Kill (Seconds Before Auto-Restore)",
                min_value=0.0,
                max_value=6.0,
                value=float(db.get_setting("visual_hold_sec", "3.0")),
                step=0.5
            )
            if st.form_submit_button("SAVE DETECTION SETTINGS", use_container_width=True):
                db.set_settings_batch({
                    "speed_limit_files": speed_files,
                    "speed_window_sec": speed_win,
                    "entropy_delta_threshold": ent_delta,
                    "absolute_high_entropy": abs_ent,
                    "visual_hold_sec": visual_hold
                })
                st.success("Detection & demo settings updated.")

        st.divider()

        st.markdown('<div class="edr-section-hdr">Trusted Program Whitelist (SHA-256 + Digital Signature)</div>', unsafe_allow_html=True)
        exe_input = st.text_input(
            "Trusted Program Path (.exe)",
            placeholder="C:\\Program Files\\WinRAR\\WinRAR.exe"
        )
        req_sig = st.checkbox("Require Valid Microsoft Authenticode Digital Signature", value=True)

        if st.button("ADD PROGRAM TO WHITELIST", use_container_width=True, type="primary"):
            cleaned_path = exe_input.strip().strip('"')
            base_exe = os.path.basename(cleaned_path).lower()
            blocked_interpreters = {"python.exe", "pythonw.exe", "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe"}

            if base_exe in blocked_interpreters:
                st.error(f"Policy Violation: Scripting interpreter '{base_exe}' cannot be whitelisted.")
            elif os.path.exists(cleaned_path) and os.path.isfile(cleaned_path) and cleaned_path.lower().endswith(".exe"):
                exe_hash = get_sha256(cleaned_path)
                db.execute_write(
                    "INSERT OR REPLACE INTO whitelist (process_name, exe_path, sha256_hash, require_signature) VALUES (?, ?, ?, ?)",
                    (os.path.basename(cleaned_path), cleaned_path, exe_hash, 1 if req_sig else 0)
                )
                st.success(f"Whitelisted '{os.path.basename(cleaned_path)}' | SHA-256: {exe_hash[:24]}...")
            else:
                st.error("Specify an existing local .exe file path.")

        df_wl = db.read_df(
            "SELECT id, process_name, exe_path, sha256_hash, require_signature FROM whitelist ORDER BY id DESC"
        )
        if not df_wl.empty:
            wl_rows = []
            for _, w in df_wl.iterrows():
                sig_badge = "<span class='badge-clean'>REQUIRED</span>" if w["require_signature"] else "<span class='badge-danger'>OPTIONAL</span>"
                wl_rows.append(
                    f"<tr>"
                    f"<td class='mono-cell'>#{w['id']}</td>"
                    f"<td class='mono-cell'><b>{w['process_name']}</b></td>"
                    f"<td class='mono-cell'>{str(w['sha256_hash'])[:22]}...</td>"
                    f"<td>{sig_badge}</td>"
                    f"</tr>"
                )
            st.markdown(
                "<div class='edr-table-wrap'><table class='edr-table'>"
                "<thead><tr><th>ID</th><th>Program</th><th>SHA-256 Hash</th><th>Signature</th></tr></thead>"
                f"<tbody>{''.join(wl_rows)}</tbody></table></div>",
                unsafe_allow_html=True
            )

            c_del1, c_del2 = st.columns([3, 1])
            with c_del1:
                del_id = st.selectbox("Select Whitelist ID to Remove", df_wl["id"].tolist())
            with c_del2:
                st.write("")
                if st.button("REVOKE", use_container_width=True):
                    db.execute_write("DELETE FROM whitelist WHERE id=?", (int(del_id),))
                    st.rerun()
        else:
            st.info("No trusted programs whitelisted yet.")
        last_wl = db.get_setting("last_whitelist_event", "")
        if last_wl:
            st.success(last_wl)