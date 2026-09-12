"""
app.py
------
Streamlit front-end for the email-forensics pipeline.

This adds NO new detection logic - it only calls main.run_pipeline()
(the exact same function the CLI uses) and renders the same result
dict as an interactive web page instead of a terminal report.

Run locally:
    pip install -r requirements.txt
    streamlit run app.py

The app then opens at http://localhost:8501
"""

import glob
import json
import os
import tempfile

import streamlit as st

from main import run_pipeline

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
SAMPLES_DIR = os.path.join(PROJECT_ROOT, "samples")
REAL_WORLD_CAMPAIGN_DIR = os.path.join(SAMPLES_DIR, "real_world_campaign")
SYNTHETIC_CAMPAIGN_DIR = os.path.join(SAMPLES_DIR, "campaign_batch")

st.set_page_config(
    page_title="Email Forensics & Phishing Detection",
    page_icon="🛡️",
    layout="wide",
)


# ----------------------------------------------------------------------
# Small helpers
# ----------------------------------------------------------------------

def _classification_alert(classification: str, message: str):
    """Route a fraud_classification string to the matching st.* alert box."""
    if classification == "Critical Risk":
        st.error(message)
    elif classification == "High Risk":
        st.error(message)
    elif classification == "Medium Risk":
        st.warning(message)
    else:
        st.success(message)


def _risk_level_badge(risk_level: str) -> str:
    color = {"high": "🔴", "medium": "🟠", "low": "🟢"}.get((risk_level or "").lower(), "⚪")
    return f"{color} {risk_level.upper() if risk_level else 'UNKNOWN'}"


def _auth_badge(verdict: str) -> str:
    verdict = (verdict or "unknown").lower()
    color = {
        "pass": "🟢", "fail": "🔴", "none": "🟠", "unsigned": "🟠",
        "unverified": "🟠", "softfail": "🟠", "neutral": "🟠",
    }.get(verdict, "⚪")
    return f"{color} {verdict.upper()}"


def _find_sample_files() -> list[str]:
    patterns = [
        os.path.join(SAMPLES_DIR, "*.eml"),
        os.path.join(REAL_WORLD_CAMPAIGN_DIR, "*.eml"),
        os.path.join(SYNTHETIC_CAMPAIGN_DIR, "*.eml"),
    ]
    files = []
    for pattern in patterns:
        files.extend(sorted(glob.glob(pattern)))
    return files


def _display_name(path: str) -> str:
    return os.path.relpath(path, SAMPLES_DIR)


# ----------------------------------------------------------------------
# Sidebar - choose what to analyze
# ----------------------------------------------------------------------

st.sidebar.title("🛡️ Email Forensics")
st.sidebar.caption("Trace an email's real origin, check SPF/DKIM/DMARC, scan attachments, and correlate it against other emails - then score the fraud risk.")

mode = st.sidebar.radio(
    "What do you want to analyze?",
    ["Bundled sample email", "Upload your own .eml file(s)"],
)

eml_path_to_analyze = None
campaign_dir = None
temp_dir_handle = None

if mode == "Bundled sample email":
    sample_files = _find_sample_files()
    if not sample_files:
        st.sidebar.error("No sample .eml files found under samples/.")
    else:
        chosen = st.sidebar.selectbox(
            "Pick a sample",
            sample_files,
            format_func=_display_name,
        )
        eml_path_to_analyze = chosen

        correlate = st.sidebar.checkbox(
            "Correlate against the rest of its batch",
            value=True,
            help="Scores this email against the other .eml files in the same "
                 "sample folder, so campaign clustering has something real to find.",
        )
        if correlate:
            campaign_dir = os.path.dirname(chosen)

else:
    uploaded_files = st.sidebar.file_uploader(
        "Upload one or more .eml files",
        type=["eml"],
        accept_multiple_files=True,
        help="Upload a single email for a standalone check, or several at once "
             "(e.g. a quarantine folder export) to also enable campaign correlation.",
    )

    if uploaded_files:
        temp_dir_handle = tempfile.TemporaryDirectory()
        saved_paths = []
        for uploaded in uploaded_files:
            dest = os.path.join(temp_dir_handle.name, uploaded.name)
            with open(dest, "wb") as f:
                f.write(uploaded.getbuffer())
            saved_paths.append(dest)

        if len(saved_paths) == 1:
            eml_path_to_analyze = saved_paths[0]
        else:
            eml_path_to_analyze = st.sidebar.selectbox(
                "Which email should the report focus on?",
                saved_paths,
                format_func=os.path.basename,
            )
            campaign_dir = temp_dir_handle.name
            st.sidebar.info(f"Correlating against all {len(saved_paths)} uploaded files.")

run_clicked = st.sidebar.button("🔍 Run analysis", type="primary", disabled=eml_path_to_analyze is None)

with st.sidebar.expander("About / limitations"):
    st.markdown(
        "- Static analysis only - no attachment is ever opened or executed.\n"
        "- SPF/DKIM/DMARC prefer the email's own Authentication-Results header "
        "and fall back to a live DNS check only when that's missing.\n"
        "- Campaign correlation needs 2+ related emails to do anything beyond "
        "single-email heuristics (subject wording + auth failures).\n"
        "- Some optional lookups (ASN ownership, live DNS) degrade gracefully "
        "if their library isn't installed - see requirements.txt."
    )


# ----------------------------------------------------------------------
# Main panel
# ----------------------------------------------------------------------

st.title("Email Forensics Report")

if not eml_path_to_analyze:
    st.info("👈 Pick a sample email or upload your own .eml file(s), then click **Run analysis**.")
    st.stop()

if not run_clicked and "last_result" not in st.session_state:
    st.info("Ready when you are - click **Run analysis** in the sidebar.")
    st.stop()

if run_clicked:
    with st.spinner("Parsing headers, tracing hops, checking SPF/DKIM/DMARC, scanning attachments..."):
        try:
            result = run_pipeline(eml_path_to_analyze, campaign_dir=campaign_dir)
            st.session_state["last_result"] = result
            st.session_state["last_eml_name"] = os.path.basename(eml_path_to_analyze)
        except Exception as exc:
            st.error(f"Pipeline failed on this file: {exc}")
            st.exception(exc)
            st.stop()

result = st.session_state["last_result"]
st.caption(f"Analyzed: `{st.session_state.get('last_eml_name', '')}`")

# --- Headline verdict ---
# fraud_classification is the single authoritative verdict. The
# indicator-based risk_level signal isn't a separate, potentially-
# disagreeing label anymore - it's folded directly into the weighted
# fraud_score as a fourth input (indicator_score, see fraud_score.py),
# so fraud_classification already reflects it. risk_level is still
# shown below as one of the contributing signals, not a rival verdict.
fraud_score = result.get("fraud_score")
fraud_classification = result.get("fraud_classification") or "Unknown"
risk_level = result.get("risk_level")

col1, col2 = st.columns(2)
col1.metric("Fraud score", f"{fraud_score:.1f} / 100" if fraud_score is not None else "N/A")
col2.metric("Fraud classification", fraud_classification)

_classification_alert(
    fraud_classification,
    f"**{fraud_classification}** - fraud score {fraud_score:.1f}/100" if fraud_score is not None else "Fraud score unavailable",
)
st.caption(f"↳ includes the indicator-based risk_level signal ({_risk_level_badge(risk_level)}) as one of four weighted inputs — see the breakdown below")

st.divider()

# --- Email metadata ---
email = result.get("email", {})
st.subheader("📧 Email")
m1, m2 = st.columns(2)
with m1:
    st.markdown(f"**Subject:** {email.get('subject') or '(none)'}")
    st.markdown(f"**From:** {email.get('from_address') or '(none)'}  \n"
                f"_domain: {email.get('from_domain') or 'unknown'}_")
with m2:
    st.markdown(f"**Date:** {email.get('date') or '(none)'}")
    st.markdown(f"**Message-ID:** `{email.get('message_id') or '(none)'}`")

st.divider()

# --- Origin trace ---
st.subheader("🌍 Origin trace")
geo = result.get("geo") or {}
location = ", ".join(v for v in (geo.get("city"), geo.get("country")) if v) or "unknown"
oc1, oc2 = st.columns(2)
oc1.markdown(f"**Sender IP:** `{result.get('sender_ip') or 'unknown'}`")
oc2.markdown(f"**Location:** {location}")

hop_trace = result.get("hop_trace", [])
if hop_trace:
    rows = []
    for hop in hop_trace:
        if "note" in hop:
            rows.append({
                "Hop": hop.get("hop"), "IP": "(internal)", "Country": "-",
                "ISP / ASN Owner": "-", "Matches claimed domain?": "-",
            })
            continue
        matches = hop.get("hostname_matches_claimed_domain")
        rows.append({
            "Hop": hop.get("hop"),
            "IP": hop.get("ip") or "unknown",
            "Country": hop.get("country") or "unknown",
            "ISP / ASN Owner": hop.get("asn_description") or hop.get("isp") or "unknown",
            "Matches claimed domain?": "✅ Yes" if matches else "❌ No",
        })
    st.dataframe(rows, use_container_width=True, hide_index=True)
else:
    st.caption("No traceable hops found in this email's headers.")

st.divider()

# --- Authentication ---
st.subheader("🔐 Authentication (SPF / DKIM / DMARC)")
a1, a2, a3 = st.columns(3)
for col, label, key in ((a1, "SPF", "spf"), (a2, "DKIM", "dkim"), (a3, "DMARC", "dmarc")):
    entry = result.get(key) or {}
    verdict = entry.get("result") or "unknown"
    source = entry.get("source", "unknown")
    with col:
        st.markdown(f"**{label}**")
        st.markdown(_auth_badge(verdict))
        st.caption(f"source: {source}")

st.divider()

# --- Attachments ---
attachments_block = result.get("attachments") or {}
attachment_count = attachments_block.get("attachment_count", 0)
st.subheader(f"📎 Attachments ({attachment_count})")

if attachment_count == 0:
    st.caption("No attachments on this message.")
else:
    summary = attachments_block.get("summary", {})
    st.caption(
        f"{summary.get('executable_attachments', 0)} executable · "
        f"{summary.get('macro_attachments', 0)} macro-bearing · "
        f"{summary.get('script_attachments', 0)} script · "
        f"{summary.get('signature_mismatches', 0)} signature mismatch"
    )
    for attachment in attachments_block.get("attachments", []):
        indicators = attachment.get("forensic_indicators", [])
        risky = bool(indicators)
        icon = "🚩" if risky else "✅"
        with st.expander(
            f"{icon} {attachment.get('filename', '(unnamed)')}  "
            f"({attachment.get('detected_mime_type', 'unknown')}, {attachment.get('size', 0)} bytes)"
        ):
            st.code(attachment.get("sha256", ""), language=None)
            if indicators:
                for finding in indicators:
                    st.markdown(f"- ⚠️ {finding}")
            else:
                st.markdown("No red flags found in static analysis.")

st.divider()

# --- Campaign correlation ---
campaign = result.get("campaign_correlation") or {}
if campaign:
    campaign_mode = campaign.get("mode", "single")
    mode_label = (
        "batch - correlated against related .eml files"
        if campaign_mode == "batch" else
        "single-email heuristics only (upload/select 2+ emails to enable batch correlation)"
    )
    st.subheader("🔗 Campaign correlation")
    st.caption(mode_label)
    for reason in campaign.get("reasons", []):
        st.markdown(f"- {reason}")

st.divider()

# --- Suspicious indicators ---
indicators = result.get("indicators", [])
st.subheader(f"⚠️ Suspicious indicators ({len(indicators)})")
if not indicators:
    st.success("None found - this email's headers look clean.")
else:
    for i, indicator in enumerate(indicators, start=1):
        st.markdown(f"{i}. {indicator}")

st.divider()

# --- Fraud score breakdown ---
breakdown = result.get("fraud_score_breakdown") or {}
if breakdown:
    st.subheader("🧮 Fraud score breakdown")
    weights = breakdown.get("weights", {})
    b1, b2, b3, b4 = st.columns(4)
    b1.metric(f"Geo/infra (×{weights.get('geo', 0):.2f})", f"{breakdown.get('geo_score', 0):.1f}")
    b2.metric(f"Attachment (×{weights.get('attachment', 0):.2f})", f"{breakdown.get('attachment_score', 0):.1f}")
    b3.metric(f"Campaign (×{weights.get('campaign', 0):.2f})", f"{breakdown.get('campaign_score', 0):.1f}")
    b4.metric(f"Indicator risk (×{weights.get('indicator', 0):.2f})", f"{breakdown.get('indicator_score', 0):.1f}")
    st.caption(
        f"fraud_score = geo×{weights.get('geo', 0):.2f} + attachment×{weights.get('attachment', 0):.2f} "
        f"+ campaign×{weights.get('campaign', 0):.2f} + indicator×{weights.get('indicator', 0):.2f}"
    )
    st.caption("indicator_score comes from risk_level (low=10, medium=50, high=90) — the same low/medium/high signal shown above, now weighted directly into the score instead of standing apart from it.")

# --- Raw JSON + download ---
with st.expander("Raw JSON result"):
    st.json(result)

st.download_button(
    "⬇️ Download full JSON report",
    data=json.dumps(result, indent=2, default=str),
    file_name=f"{os.path.splitext(st.session_state.get('last_eml_name', 'report'))[0]}_report.json",
    mime="application/json",
)
