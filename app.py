# ============================================================
#  Real-Time Browser Hijack Risk Predictor  –  Streamlit App
#  Developer : Vidit Desai  |  GUCPC
#  Usage     : streamlit run app.py
# ============================================================

import os
import re
import pickle
import urllib.parse
import datetime
import warnings
import io

import pandas as pd
import numpy as np
import streamlit as st

warnings.filterwarnings("ignore", category=UserWarning)

# ── PAGE CONFIG ──────────────────────────────────────────────
st.set_page_config(
    page_title="Browser Hijack Risk Predictor",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── CUSTOM CSS ───────────────────────────────────────────────
st.markdown("""
<style>
html, body, [class*="css"] { font-family: 'Segoe UI', sans-serif; }

[data-testid="stSidebar"] {
    background: linear-gradient(160deg, #0f0c29, #302b63, #24243e);
    color: #fff;
}
[data-testid="stSidebar"] * { color: #e0e0ff !important; }
[data-testid="stSidebar"] h1,
[data-testid="stSidebar"] h2,
[data-testid="stSidebar"] h3 { color: #a78bfa !important; }

.main-title {
    font-size: 2.5rem;
    font-weight: 800;
    background: linear-gradient(90deg, #6366f1, #a855f7, #ec4899);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    margin-bottom: 0.2rem;
}
.sub-title { color: #64748b; font-size: 1rem; margin-bottom: 1.5rem; }

.result-safe {
    background: linear-gradient(135deg, #d1fae5, #a7f3d0);
    border-left: 6px solid #10b981;
    border-radius: 12px;
    padding: 1.2rem 1.5rem;
    color: #065f46;
}
.result-suspicious {
    background: linear-gradient(135deg, #fef9c3, #fde68a);
    border-left: 6px solid #f59e0b;
    border-radius: 12px;
    padding: 1.2rem 1.5rem;
    color: #78350f;
}
.result-danger {
    background: linear-gradient(135deg, #fee2e2, #fca5a5);
    border-left: 6px solid #ef4444;
    border-radius: 12px;
    padding: 1.2rem 1.5rem;
    color: #7f1d1d;
}
.result-title { font-size: 1.6rem; font-weight: 700; margin-bottom: 0.3rem; }
.result-sub   { font-size: 0.95rem; opacity: 0.85; }

.warning-banner {
    background: #7f1d1d;
    color: #fca5a5;
    border-radius: 10px;
    padding: 1rem 1.4rem;
    font-weight: 600;
    margin-top: 1rem;
    font-size: 0.95rem;
}

/* Bulk result row colours */
.bulk-safe       { color: #10b981; font-weight: 600; }
.bulk-suspicious { color: #f59e0b; font-weight: 600; }
.bulk-danger     { color: #ef4444; font-weight: 600; }

.stDataFrame { border-radius: 10px; overflow: hidden; }
.conf-label { font-size: 0.85rem; color: #64748b; margin-bottom: 0.2rem; }

/* Tab styling */
.stTabs [data-baseweb="tab-list"] {
    gap: 8px;
    background: transparent;
}
.stTabs [data-baseweb="tab"] {
    border-radius: 8px 8px 0 0;
    padding: 8px 20px;
    font-weight: 600;
}
</style>
""", unsafe_allow_html=True)


# ── LOAD MODEL ───────────────────────────────────────────────
@st.cache_resource(show_spinner="Loading ML model…")
def load_model():
    model_path = os.path.join(os.path.dirname(__file__), "model.pkl")
    with open(model_path, "rb") as f:
        bundle = pickle.load(f)
    return bundle["model"], bundle["features"]

MODEL, FEATURES = load_model()


# ── FEATURE EXTRACTION ───────────────────────────────────────
def extract_features(url: str) -> dict:
    parsed = urllib.parse.urlparse(url)
    domain = parsed.netloc.lower().replace("www.", "")
    full   = url.lower()
    features = {}

    L = len(url)
    features["URL_Length"] = 1 if L < 54 else (0 if L <= 75 else -1)
    features["Iframe"] = -1 if "iframe" in full else 1
    after_proto = url[url.find("//") + 2:] if "//" in url else url
    features["Redirect"] = 1 if "//" in after_proto else 0
    features["on_mouseover"] = -1 if "onmouseover" in full else 1
    features["popUpWidnow"] = -1 if any(k in full for k in ["popup", "pop-up", "alert("]) else 1
    features["Request_URL"] = -1 if full.count("http") > 2 else 1

    ip_pattern = r"(\d{1,3}\.){3}\d{1,3}"
    features["having_IP_Address"] = -1 if re.search(ip_pattern, domain) else 1
    features["SSLfinal_State"] = 1 if parsed.scheme == "https" else -1

    parts = [p for p in domain.split(".") if p]
    features["having_Sub_Domain"] = 1 if len(parts) <= 2 else (0 if len(parts) == 3 else -1)

    new_tlds = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".click", ".loan", ".win", ".bid"]
    features["age_of_domain"] = -1 if any(domain.endswith(t) for t in new_tlds) else 1
    features["DNSRecord"] = -1 if re.search(ip_pattern, domain) else 1

    safe_domains = ["google", "youtube", "facebook", "twitter", "instagram",
                    "linkedin", "microsoft", "apple", "amazon", "wikipedia",
                    "github", "stackoverflow", "reddit", "netflix", "yahoo"]
    features["web_traffic"] = 1 if any(s in domain for s in safe_domains) else 0
    features["Page_Rank"] = 1 if any(s in domain for s in safe_domains) else -1
    features["Google_Index"] = -1 if any(domain.endswith(t) for t in new_tlds) else 1
    features["Links_pointing_to_page"] = 1 if any(s in domain for s in safe_domains) else 0

    bad_tlds = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".click", ".loan", ".win", ".bid"]
    features["Statistical_report"] = -1 if any(domain.endswith(t) for t in bad_tlds) else 1
    features["Prefix_Suffix"] = -1 if "-" in domain else 1
    features["HTTPS_token"] = -1 if "https" in domain else 1

    return features


# ── RISK SCORE ───────────────────────────────────────────────
def compute_risk_score(features: dict) -> float:
    weights = {
        "having_IP_Address": 0.15, "SSLfinal_State": 0.15,
        "Iframe":            0.12, "Prefix_Suffix":  0.10,
        "age_of_domain":     0.10, "Statistical_report": 0.10,
        "DNSRecord":         0.08, "having_Sub_Domain":  0.08,
        "URL_Length":        0.07, "HTTPS_token":        0.05,
    }
    score = 0.0
    for feat, w in weights.items():
        v    = features.get(feat, 0)
        risk = {-1: 1.0, 0: 0.5, 1: 0.0}.get(v, 0.5)
        score += risk * w
    return round(score, 4)


# ── PREDICT ──────────────────────────────────────────────────
def predict_url(url: str):
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    features   = extract_features(url)
    risk_score = compute_risk_score(features)
    feat_vec   = [[features[f] for f in FEATURES]]
    proba      = float(MODEL.predict_proba(feat_vec)[0][1])
    blended    = round(proba * 0.6 + risk_score * 0.4, 4)

    if blended >= 0.65:
        prediction, threat = "High Risk",  "🔴 High"
    elif blended >= 0.35:
        prediction, threat = "Suspicious", "🟡 Medium"
    else:
        prediction, threat = "Safe",       "🟢 Low"

    return {
        "url":         url,
        "blended":     blended,
        "probability": round(proba, 4),
        "risk_score":  risk_score,
        "prediction":  prediction,
        "threat":      threat,
        "features":    features,
    }


# ── URL LOGGING ───────────────────────────────────────────────
LOG_FILE = os.path.join(os.path.dirname(__file__), "url_log.csv")

def log_result(res: dict):
    entry = {
        "timestamp":  datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "url":        res["url"],
        "prediction": res["prediction"],
        "confidence": f"{res['blended']*100:.1f}%",
    }
    df = pd.DataFrame([entry])
    df.to_csv(LOG_FILE, mode="a", index=False, header=not os.path.exists(LOG_FILE))


# ── FEATURE TABLE ─────────────────────────────────────────────
FEATURE_DESCRIPTIONS = {
    "URL_Length":             "URL character length",
    "Iframe":                 "Hidden iframe detected",
    "Redirect":               "Double-slash redirect",
    "on_mouseover":           "onmouseover JS event",
    "popUpWidnow":            "Pop-up / alert in URL",
    "Request_URL":            "Multiple embedded http refs",
    "having_IP_Address":      "IP address used as domain",
    "SSLfinal_State":         "HTTPS / SSL certificate",
    "having_Sub_Domain":      "Number of sub-domains",
    "age_of_domain":          "Domain uses new/free TLD",
    "DNSRecord":              "DNS record available",
    "web_traffic":            "Known high-traffic domain",
    "Page_Rank":              "High page rank (popular site)",
    "Google_Index":           "Indexed by Google",
    "Links_pointing_to_page": "Inbound link count (proxy)",
    "Statistical_report":     "Listed on phishing report",
    "Prefix_Suffix":          "Dash (-) in domain name",
    "HTTPS_token":            "'https' keyword inside domain",
}

def make_feature_df(features: dict) -> pd.DataFrame:
    label_map = {1: "✅ Legitimate", 0: "⚠️ Neutral", -1: "🚨 Suspicious"}
    rows = []
    for feat, val in features.items():
        rows.append({
            "Feature":     feat,
            "Description": FEATURE_DESCRIPTIONS.get(feat, ""),
            "Value":       val,
            "Signal":      label_map.get(val, str(val)),
        })
    return pd.DataFrame(rows)


# ════════════════════════════════════════════════════════════
#  SIDEBAR
# ════════════════════════════════════════════════════════════
with st.sidebar:
    st.markdown("## 🛡️ About This Project")
    st.markdown("""
**Real-Time Browser Hijack Risk Predictor** uses a machine-learning model trained on the
[UCI Phishing Websites Dataset](https://archive.ics.uci.edu/ml/datasets/phishing+websites)
(11 055 URLs, 18 features) to detect phishing and browser-hijack attempts.
""")
    st.markdown("---")
    st.markdown("### 🤖 Model Info")
    st.markdown("""
| Property | Value |
|---|---|
| Algorithm | Random Forest |
| Trees | 200 |
| Accuracy | ~91.7% |
| Features | 18 |
""")
    st.markdown("---")
    st.markdown("### 🎨 Risk Colour Guide")
    st.markdown("""
- 🟢 **Green** → Safe URL  
- 🟡 **Yellow** → Suspicious  
- 🔴 **Red** → High Risk / Hijack Possible  
""")
    st.markdown("---")
    st.markdown("### 👨‍💻 Developer")
    st.markdown("**Vidit Desai**  \nGUCPC  \n\n📁 `browser-hijack-predictor`")
    st.markdown("---")

    st.markdown("### 📋 Checked URLs Log")
    if os.path.exists(LOG_FILE):
        log_df = pd.read_csv(LOG_FILE)
        st.dataframe(log_df.tail(10), use_container_width=True, height=220)
        with open(LOG_FILE, "rb") as f:
            st.download_button("⬇️ Download Full Log", f,
                               file_name="url_log.csv", mime="text/csv")
    else:
        st.info("No URLs checked yet.")


# ════════════════════════════════════════════════════════════
#  MAIN PAGE
# ════════════════════════════════════════════════════════════
st.markdown('<p class="main-title">🛡️ Real-Time Browser Hijack Risk Predictor</p>',
            unsafe_allow_html=True)
st.markdown('<p class="sub-title">Enter any URL below to instantly check whether it is Safe, Suspicious, or a High-Risk phishing/hijack attempt.</p>',
            unsafe_allow_html=True)

st.markdown("---")

# ── TABS ─────────────────────────────────────────────────────
tab_single, tab_bulk = st.tabs(["🔍 Single URL Scanner", "📋 Bulk URL Scanner"])


# ════════════════════════════════════════════════════════════
#  TAB 1 — SINGLE URL SCANNER  (original functionality)
# ════════════════════════════════════════════════════════════
with tab_single:
    col_input, col_btn = st.columns([5, 1])

    with col_input:
        url_input = st.text_input(
            label="🔗 Enter URL",
            placeholder="e.g. https://google.com  or  http://paypal-secure.tk/login",
            label_visibility="collapsed",
        )

    with col_btn:
        check_clicked = st.button("🔍 Check Risk", use_container_width=True, type="primary")

    if "last_checked" not in st.session_state:
        st.session_state.last_checked = ""

    should_run = check_clicked or (
        url_input.strip() != "" and url_input.strip() != st.session_state.last_checked
    )

    if should_run and url_input.strip():
        raw_url = url_input.strip()
        st.session_state.last_checked = raw_url

        try:
            with st.spinner("Analysing URL…"):
                result = predict_url(raw_url)
                log_result(result)

            pred       = result["prediction"]
            ml_prob    = result["probability"] * 100

            st.markdown("")

            if pred == "Safe":
                css_class = "result-safe"
                icon      = "✅"
                headline  = "This URL appears SAFE"
            elif pred == "Suspicious":
                css_class = "result-suspicious"
                icon      = "⚠️"
                headline  = "This URL is SUSPICIOUS – proceed with caution"
            else:
                css_class = "result-danger"
                icon      = "🚨"
                headline  = "HIGH RISK – Possible Browser Hijack Detected!"

            st.markdown(f"""
<div class="{css_class}">
  <div class="result-title">{icon} {headline}</div>
  <div class="result-sub">
      Threat Level: <strong>{result['threat']}</strong> &nbsp;|&nbsp;
      Overall Risk Score: <strong>{result['blended']:.4f}</strong> &nbsp;|&nbsp;
      ML Model Confidence: <strong>{ml_prob:.1f}%</strong>
  </div>
</div>
""", unsafe_allow_html=True)

            if pred == "High Risk":
                st.markdown("""
<div class="warning-banner">
⛔ WARNING: This URL shows multiple indicators of a phishing or browser-hijack
attack. Do <strong>NOT</strong> enter any credentials or personal information.
Close this page immediately and run a malware scan.
</div>
""", unsafe_allow_html=True)

            st.markdown("")

            col_a, col_b, col_c = st.columns(3)
            with col_a:
                st.metric("🎯 Blended Risk Score", f"{result['blended']:.4f}",
                          help="Weighted blend of ML probability (60%) + heuristic score (40%)")
            with col_b:
                st.metric("🤖 ML Model Probability", f"{ml_prob:.1f}%",
                          help="Random Forest classifier output (probability of being malicious)")
            with col_c:
                st.metric("📐 Heuristic Score", f"{result['risk_score']:.4f}",
                          help="Rule-based weighted score derived from URL features")

            st.markdown('<p class="conf-label">Overall Risk Confidence</p>', unsafe_allow_html=True)
            st.progress(min(result["blended"], 1.0))

            st.markdown("---")
            st.markdown("#### 📊 Extracted URL Features")
            feat_df = make_feature_df(result["features"])
            st.dataframe(
                feat_df,
                use_container_width=True,
                height=430,
                hide_index=True,
                column_config={
                    "Feature":     st.column_config.TextColumn("Feature", width="medium"),
                    "Description": st.column_config.TextColumn("Description", width="large"),
                    "Value":       st.column_config.NumberColumn("Encoded Value", width="small"),
                    "Signal":      st.column_config.TextColumn("Signal", width="medium"),
                },
            )
            st.markdown("""
> **Encoding key:** `1` = Legitimate indicator &nbsp; `0` = Neutral &nbsp; `-1` = Phishing/Suspicious indicator
""")

        except Exception as e:
            st.error(f"❌ Error analysing URL: {e}\n\nPlease check that the URL is valid (e.g. `https://example.com`).")

    elif url_input.strip() == "" and check_clicked:
        st.warning("⚠️ Please enter a URL before clicking **Check Risk**.")


# ════════════════════════════════════════════════════════════
#  TAB 2 — BULK URL SCANNER
# ════════════════════════════════════════════════════════════
with tab_bulk:
    st.markdown("### 📋 Bulk URL Scanner")
    st.markdown(
        "Scan multiple URLs at once. **Paste URLs** (one per line) or **upload a `.txt` / `.csv` file**. "
        "Results can be downloaded as a CSV report."
    )

    st.markdown("---")

    # ── Input method ─────────────────────────────────────────
    input_method = st.radio(
        "Choose input method:",
        ["✏️ Paste URLs", "📁 Upload File"],
        horizontal=True,
        label_visibility="collapsed",
    )

    bulk_urls = []

    if input_method == "✏️ Paste URLs":
        pasted = st.text_area(
            "Paste URLs here (one per line):",
            placeholder="https://google.com\nhttp://paypal-secure.tk/login\nhttps://github.com",
            height=180,
        )
        if pasted.strip():
            bulk_urls = [u.strip() for u in pasted.strip().splitlines() if u.strip()]

    else:  # Upload file
        uploaded_file = st.file_uploader(
            "Upload a .txt or .csv file with one URL per line / row:",
            type=["txt", "csv"],
        )
        if uploaded_file is not None:
            content = uploaded_file.read().decode("utf-8", errors="ignore")
            if uploaded_file.name.endswith(".csv"):
                # Try to read first column as URLs
                try:
                    df_upload = pd.read_csv(io.StringIO(content), header=None)
                    bulk_urls = df_upload.iloc[:, 0].dropna().astype(str).tolist()
                    bulk_urls = [u.strip() for u in bulk_urls if u.strip()]
                except Exception:
                    bulk_urls = [u.strip() for u in content.splitlines() if u.strip()]
            else:
                bulk_urls = [u.strip() for u in content.splitlines() if u.strip()]

    # ── Preview count ─────────────────────────────────────────
    if bulk_urls:
        st.info(f"📌 **{len(bulk_urls)} URL(s)** loaded and ready to scan.")

        # Optional: cap at 500 to avoid timeout
        MAX_BULK = 500
        if len(bulk_urls) > MAX_BULK:
            st.warning(f"⚠️ Only the first {MAX_BULK} URLs will be scanned to avoid timeout.")
            bulk_urls = bulk_urls[:MAX_BULK]

    # ── Scan button ───────────────────────────────────────────
    scan_bulk = st.button("🚀 Scan All URLs", type="primary", disabled=len(bulk_urls) == 0)

    if scan_bulk and bulk_urls:
        results_list = []
        progress_bar = st.progress(0, text="Scanning URLs…")
        status_text  = st.empty()

        for i, url in enumerate(bulk_urls):
            try:
                res = predict_url(url)
                log_result(res)
                results_list.append({
                    "No.":          i + 1,
                    "URL":          res["url"],
                    "Prediction":   res["prediction"],
                    "Threat Level": res["threat"],
                    "Risk Score":   f"{res['blended']:.4f}",
                    "ML Prob (%)":  f"{res['probability']*100:.1f}",
                    "Heuristic":    f"{res['risk_score']:.4f}",
                })
            except Exception as e:
                results_list.append({
                    "No.":          i + 1,
                    "URL":          url,
                    "Prediction":   "Error",
                    "Threat Level": "—",
                    "Risk Score":   "—",
                    "ML Prob (%)":  "—",
                    "Heuristic":    str(e)[:60],
                })

            pct = int((i + 1) / len(bulk_urls) * 100)
            progress_bar.progress((i + 1) / len(bulk_urls), text=f"Scanning… {pct}% ({i+1}/{len(bulk_urls)})")
            status_text.caption(f"⏳ Checking: `{url[:80]}`")

        progress_bar.empty()
        status_text.empty()

        bulk_df = pd.DataFrame(results_list)

        # ── Summary metrics ───────────────────────────────────
        st.markdown("---")
        st.markdown("#### 📊 Scan Summary")

        total     = len(bulk_df)
        safe_n    = (bulk_df["Prediction"] == "Safe").sum()
        sus_n     = (bulk_df["Prediction"] == "Suspicious").sum()
        danger_n  = (bulk_df["Prediction"] == "High Risk").sum()
        error_n   = (bulk_df["Prediction"] == "Error").sum()

        c1, c2, c3, c4, c5 = st.columns(5)
        c1.metric("🔢 Total Scanned", total)
        c2.metric("🟢 Safe",          safe_n)
        c3.metric("🟡 Suspicious",    sus_n)
        c4.metric("🔴 High Risk",     danger_n)
        c5.metric("❌ Errors",        error_n)

        # Risk distribution bar
        if total > 0:
            st.markdown("**Risk Distribution**")
            col_bar, _ = st.columns([3, 1])
            with col_bar:
                dist_df = pd.DataFrame({
                    "Category": ["Safe", "Suspicious", "High Risk"],
                    "Count":    [safe_n, sus_n, danger_n],
                })
                st.bar_chart(dist_df.set_index("Category"))

        # ── Full results table ────────────────────────────────
        st.markdown("---")
        st.markdown("#### 📋 Detailed Results")

        # Colour-code Prediction column via display trick
        def highlight_prediction(val):
            color_map = {
                "Safe":       "color: #10b981; font-weight: 600;",
                "Suspicious": "color: #f59e0b; font-weight: 600;",
                "High Risk":  "color: #ef4444; font-weight: 600;",
                "Error":      "color: #94a3b8;",
            }
            return color_map.get(val, "")

        styled_df = bulk_df.style.applymap(highlight_prediction, subset=["Prediction"])
        st.dataframe(styled_df, use_container_width=True, hide_index=True, height=400)

        # ── Download button ───────────────────────────────────
        csv_bytes = bulk_df.to_csv(index=False).encode("utf-8")
        st.download_button(
            label="⬇️ Download Results as CSV",
            data=csv_bytes,
            file_name=f"bulk_scan_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv",
            type="primary",
        )

        # ── High-risk warning list ────────────────────────────
        high_risk_df = bulk_df[bulk_df["Prediction"] == "High Risk"]
        if not high_risk_df.empty:
            st.markdown("---")
            st.markdown(f"#### ⛔ {len(high_risk_df)} High-Risk URL(s) Detected")
            st.markdown('<div class="warning-banner">The following URLs are flagged as HIGH RISK. '
                        'Do NOT visit these links.</div>', unsafe_allow_html=True)
            st.dataframe(
                high_risk_df[["No.", "URL", "Risk Score", "ML Prob (%)"]],
                use_container_width=True,
                hide_index=True,
            )

    elif not bulk_urls:
        st.markdown("""
<div style="text-align:center; padding: 3rem 0; color: #94a3b8;">
    <div style="font-size:3rem;">📋</div>
    <div style="font-size:1.1rem; margin-top:0.5rem;">
        Paste URLs above or upload a file to get started
    </div>
</div>
""", unsafe_allow_html=True)


# ── FOOTER ────────────────────────────────────────────────────
st.markdown("---")
st.markdown(
    "<center style='color:#94a3b8;font-size:0.8rem;'>"
    "🛡️ Browser Hijack Risk Predictor &nbsp;|&nbsp; "
    "Vidit Desai · GUCPC &nbsp;|&nbsp; "
    "Powered by Random Forest + Heuristic Analysis"
    "</center>",
    unsafe_allow_html=True,
)

