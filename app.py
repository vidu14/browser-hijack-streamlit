# ============================================================
# Real-Time Browser Hijack Risk Predictor
# Developer: Vidit Desai
# ============================================================
import os
import re
import pickle
import urllib.parse
import warnings
import pandas as pd
import streamlit as st

warnings.filterwarnings("ignore")
st.set_page_config(
    page_title="Browser Hijack Predictor",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ── Custom CSS ───────────────────────────────────────────────
st.markdown("""
<style>
    /* Background */
    .stApp {
        background: linear-gradient(160deg, #0f0f1a, #1a1a2e, #16213e);
    }

    /* Gradient Header */
    .main-header {
        background: linear-gradient(135deg, #1e1e3f, #3b1f6e, #1e1e3f);
        padding: 30px 32px;
        border-radius: 18px;
        margin-bottom: 28px;
        text-align: center;
        border: 1px solid #7c3aed55;
        box-shadow: 0 4px 30px rgba(124, 58, 237, 0.3);
    }
    .main-header h1 {
        color: #e2e8f0;
        font-size: 2.4rem;
        font-weight: 800;
        margin: 0;
        letter-spacing: -0.5px;
    }
    .main-header p {
        color: #a78bfa;
        font-size: 1rem;
        margin: 8px 0 0;
    }

    /* Stats Cards */
    .stat-card {
        background: #1e1e2e;
        border-radius: 12px;
        padding: 16px 20px;
        text-align: center;
        border: 1px solid #2d2d4f;
        box-shadow: 0 2px 10px rgba(0,0,0,0.3);
    }
    .stat-card h2 {
        color: #a78bfa;
        font-size: 1.8rem;
        margin: 0;
        font-weight: 800;
    }
    .stat-card p {
        color: #6b7280;
        font-size: 0.8rem;
        margin: 4px 0 0;
        text-transform: uppercase;
        letter-spacing: 1px;
    }

    /* Risk Badges */
    .badge-safe {
        background: linear-gradient(135deg, #14532d, #166534);
        color: #86efac;
        padding: 14px 24px;
        border-radius: 12px;
        font-size: 1.2rem;
        font-weight: 700;
        border-left: 6px solid #22c55e;
        display: block;
        margin-top: 16px;
        box-shadow: 0 4px 15px rgba(34, 197, 94, 0.2);
    }
    .badge-suspicious {
        background: linear-gradient(135deg, #713f12, #92400e);
        color: #fde68a;
        padding: 14px 24px;
        border-radius: 12px;
        font-size: 1.2rem;
        font-weight: 700;
        border-left: 6px solid #f59e0b;
        display: block;
        margin-top: 16px;
        box-shadow: 0 4px 15px rgba(245, 158, 11, 0.2);
    }
    .badge-highrisk {
        background: linear-gradient(135deg, #7f1d1d, #991b1b);
        color: #fca5a5;
        padding: 14px 24px;
        border-radius: 12px;
        font-size: 1.2rem;
        font-weight: 700;
        border-left: 6px solid #ef4444;
        display: block;
        margin-top: 16px;
        box-shadow: 0 4px 15px rgba(239, 68, 68, 0.2);
        animation: pulse 1.5s infinite;
    }
    @keyframes pulse {
        0% { box-shadow: 0 4px 15px rgba(239,68,68,0.2); }
        50% { box-shadow: 0 4px 25px rgba(239,68,68,0.6); }
        100% { box-shadow: 0 4px 15px rgba(239,68,68,0.2); }
    }

    /* URL Result Box */
    .url-box {
        background: #1e1e2e;
        border: 1px solid #3d3d5c;
        border-radius: 10px;
        padding: 10px 16px;
        color: #a78bfa;
        font-size: 0.9rem;
        word-break: break-all;
        margin-top: 12px;
    }

    /* Tip Box */
    .tip-box {
        background: #1e1e2e;
        border-left: 4px solid #7c3aed;
        border-radius: 8px;
        padding: 12px 16px;
        color: #a0a0c0;
        font-size: 0.88rem;
        margin-top: 16px;
    }

    /* Buttons */
    div.stButton > button {
        background: linear-gradient(135deg, #7c3aed, #4f46e5);
        color: white;
        border: none;
        border-radius: 10px;
        padding: 12px 28px;
        font-size: 1rem;
        font-weight: 600;
        cursor: pointer;
        width: 100%;
        transition: all 0.3s ease;
        letter-spacing: 0.5px;
    }
    div.stButton > button:hover {
        background: linear-gradient(135deg, #6d28d9, #4338ca);
        transform: translateY(-2px);
        box-shadow: 0 6px 20px rgba(124, 58, 237, 0.4);
    }

    /* Tab Styling */
    .stTabs [data-baseweb="tab"] {
        font-size: 1rem;
        font-weight: 600;
        color: #a0a0c0;
    }
    .stTabs [aria-selected="true"] {
        color: #a78bfa !important;
        border-bottom: 3px solid #7c3aed !important;
    }

    /* Footer */
    .footer {
        text-align: center;
        color: #4b5563;
        font-size: 0.85rem;
        margin-top: 48px;
        padding: 20px;
        border-top: 1px solid #1f1f35;
    }
    .footer span {
        color: #7c3aed;
        font-weight: 700;
    }
</style>
""", unsafe_allow_html=True)

# ── Load Model ───────────────────────────────────────────────
@st.cache_resource
def load_model():
    model_path = os.path.join(os.path.dirname(__file__), "model.pkl")
    with open(model_path, "rb") as f:
        bundle = pickle.load(f)
    return bundle["model"], bundle["features"]

MODEL, FEATURES = load_model()

# ── Session State for Stats ──────────────────────────────────
if "total_scanned" not in st.session_state:
    st.session_state.total_scanned = 0
if "total_safe" not in st.session_state:
    st.session_state.total_safe = 0
if "total_risky" not in st.session_state:
    st.session_state.total_risky = 0

# ── Feature Extraction ───────────────────────────────────────
def extract_features(url):
    parsed = urllib.parse.urlparse(url)
    domain = parsed.netloc.lower()
    return {
        "URL_Length": 1 if len(url) < 54 else (0 if len(url) <= 75 else -1),
        "having_IP_Address": -1 if re.search(r"(\d{1,3}\.){3}\d{1,3}", domain) else 1,
        "SSLfinal_State": 1 if parsed.scheme == "https" else -1,
        "Prefix_Suffix": -1 if "-" in domain else 1,
        "HTTPS_token": -1 if "https" in domain else 1,
    }

# ── Predict ──────────────────────────────────────────────────
def predict_url(url):
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    features = extract_features(url)
    vector = [[features.get(f, 0) for f in FEATURES]]
    prob = MODEL.predict_proba(vector)[0][1]
    if prob > 0.7:
        label = "High Risk"
    elif prob > 0.4:
        label = "Suspicious"
    else:
        label = "Safe"
    return url, label, round(prob, 4)

# ── Render Badge ─────────────────────────────────────────────
def render_badge(label, score):
    css_class = {
        "Safe": "badge-safe",
        "Suspicious": "badge-suspicious",
        "High Risk": "badge-highrisk"
    }.get(label, "badge-safe")
    icon = {"Safe": "🟢", "Suspicious": "🟡", "High Risk": "🔴"}.get(label, "")
    tip = {
        "Safe": "✅ This URL appears safe. Always stay cautious online.",
        "Suspicious": "⚠️ This URL looks suspicious. Avoid entering personal info.",
        "High Risk": "🚨 Do NOT visit this URL. It may be a browser hijack attempt!"
    }.get(label, "")
    st.markdown(f'<div class="{css_class}">{icon} &nbsp; {label} &nbsp;&nbsp;|&nbsp;&nbsp; Risk Score: {score}</div>', unsafe_allow_html=True)
    st.progress(float(score))
    st.markdown(f'<div class="tip-box">{tip}</div>', unsafe_allow_html=True)

# ── Gradient Header ──────────────────────────────────────────
st.markdown("""
<div class="main-header">
    <h1>🛡️ Real-Time Browser Hijack Risk Predictor</h1>
    <p>Detect malicious & suspicious URLs instantly using Machine Learning</p>
</div>
""", unsafe_allow_html=True)

# ── Live Stats Row ───────────────────────────────────────────
col1, col2, col3 = st.columns(3)
with col1:
    st.markdown(f'<div class="stat-card"><h2>{st.session_state.total_scanned}</h2><p>Total Scanned</p></div>', unsafe_allow_html=True)
with col2:
    st.markdown(f'<div class="stat-card"><h2 style="color:#22c55e">{st.session_state.total_safe}</h2><p>Safe URLs</p></div>', unsafe_allow_html=True)
with col3:
    st.markdown(f'<div class="stat-card"><h2 style="color:#ef4444">{st.session_state.total_risky}</h2><p>Risky URLs</p></div>', unsafe_allow_html=True)

st.markdown("<br>", unsafe_allow_html=True)

# ── Sidebar ──────────────────────────────────────────────────
st.sidebar.markdown("""
<div style="
    background: linear-gradient(135deg, #1e1e2e, #2d1f4e);
    padding: 16px;
    border-radius: 14px;
    border-left: 5px solid #7c3aed;
    text-align: center;
    margin-top: 10px;
    box-shadow: 0 4px 15px rgba(124,58,237,0.2);
">
    <p style="margin:0; font-size:11px; color:#6b7280; letter-spacing:2px; text-transform:uppercase;">Developed by</p>
    <p style="margin:8px 0 0; font-size:18px; font-weight:800; color:#e2e8f0;">👨‍💻 Vidit Desai</p>
    <p style="margin:4px 0 0; font-size:11px; color:#7c3aed;">ML & Cybersecurity</p>
</div>
""", unsafe_allow_html=True)

st.sidebar.markdown("---")
st.sidebar.markdown("### ℹ️ How It Works")
st.sidebar.info("""
The model analyzes URL features like:
- 🔒 SSL Certificate
- 🌐 IP Address usage
- 📏 URL Length
- ➖ Prefix/Suffix patterns
- 🔗 HTTPS token in domain
""")

st.sidebar.markdown("---")
st.sidebar.markdown("### 🎯 Risk Levels")
st.sidebar.markdown("""
- 🟢 **Safe** → Score < 0.4  
- 🟡 **Suspicious** → Score 0.4–0.7  
- 🔴 **High Risk** → Score > 0.7  
""")

st.sidebar.markdown("---")
st.sidebar.warning("⚠️ Never visit URLs marked as **High Risk**.")

# ── Tabs ─────────────────────────────────────────────────────
tab1, tab2 = st.tabs(["🔍  Single URL", "📋  Bulk Scanner"])

with tab1:
    st.markdown("#### Enter a URL to check its risk level")
    url = st.text_input("", placeholder="https://example.com", label_visibility="collapsed")

    if st.button("🔍 Check Risk"):
        if url:
            with st.spinner("🔎 Analyzing URL..."):
                u, label, score = predict_url(url)

            # Update stats
            st.session_state.total_scanned += 1
            if label == "Safe":
                st.session_state.total_safe += 1
            else:
                st.session_state.total_risky += 1

            st.markdown(f'<div class="url-box">🔗 {u}</div>', unsafe_allow_html=True)
            render_badge(label, score)
        else:
            st.warning("⚠️ Please enter a URL first.")

with tab2:
    st.markdown("#### Paste multiple URLs or upload a file")
    text_input = st.text_area("", placeholder="https://example1.com\nhttps://example2.com", height=150, label_visibility="collapsed")
    uploaded_file = st.file_uploader("📂 Upload .txt or .csv file", type=["txt", "csv"])

    urls = []
    if text_input:
        urls = [u.strip() for u in text_input.split("\n") if u.strip()]
    if uploaded_file:
        content = uploaded_file.read().decode("utf-8")
        urls = [u.strip() for u in content.split("\n") if u.strip()]

    if st.button("🚀 Scan All URLs"):
        if urls:
            data = []
            progress = st.progress(0)
            status = st.empty()

            for i, u in enumerate(urls):
                status.text(f"Scanning {i+1}/{len(urls)}: {u[:50]}...")
                try:
                    url_out, label, score = predict_url(u)
                    data.append([i + 1, url_out, label, score])
                    if label == "Safe":
                        st.session_state.total_safe += 1
                    else:
                        st.session_state.total_risky += 1
                    st.session_state.total_scanned += 1
                except Exception:
                    data.append([i + 1, u, "Error", "-"])
                progress.progress((i + 1) / len(urls))

            status.success(f"✅ Scanned {len(urls)} URLs successfully!")
            df = pd.DataFrame(data, columns=["No", "URL", "Prediction", "Score"])

            def color_rows(val):
                if val == "High Risk":
                    return "background-color: #7f1d1d; color: #fca5a5"
                elif val == "Suspicious":
                    return "background-color: #713f12; color: #fde68a"
                elif val == "Safe":
                    return "background-color: #14532d; color: #86efac"
                return ""

            # ✅ FIXED: applymap → map (pandas 2.1.0+)
            st.dataframe(df.style.map(color_rows, subset=["Prediction"]), use_container_width=True)

            col_a, col_b = st.columns(2)
            with col_a:
                csv = df.to_csv(index=False).encode("utf-8")
                st.download_button("⬇️ Download CSV", csv, "results.csv", use_container_width=True)
            with col_b:
                safe_count = len(df[df["Prediction"] == "Safe"])
                risky_count = len(df[df["Prediction"] == "High Risk"])
                suspicious_count = len(df[df["Prediction"] == "Suspicious"])
                st.info(f"🟢 Safe: {safe_count} &nbsp; 🟡 Suspicious: {suspicious_count} &nbsp; 🔴 High Risk: {risky_count}")
        else:
            st.warning("⚠️ No URLs provided.")

# ── Footer ───────────────────────────────────────────────────
st.markdown("""
<div class="footer">
    🛡️ Browser Hijack Risk Predictor &nbsp;|&nbsp; Developed by <span>Vidit Desai</span> &nbsp;|&nbsp; Powered by Machine Learning
</div>
""", unsafe_allow_html=True)
