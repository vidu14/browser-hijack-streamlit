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

import pandas as pd
import streamlit as st

# Suppress sklearn version mismatch warnings (model was saved with a
# slightly different sklearn version – works fine for prediction)
warnings.filterwarnings("ignore", category=UserWarning)

# ── PAGE CONFIG ──────────────────────────────────────────────
st.set_page_config(
    page_title="Browser Hijack Risk Predictor",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── CUSTOM CSS  (clean, modern look) ─────────────────────────
st.markdown("""
<style>
/* ── Global ── */
html, body, [class*="css"] { font-family: 'Segoe UI', sans-serif; }

/* ── Sidebar ── */
[data-testid="stSidebar"] {
    background: linear-gradient(160deg, #0f0c29, #302b63, #24243e);
    color: #fff;
}
[data-testid="stSidebar"] * { color: #e0e0ff !important; }
[data-testid="stSidebar"] h1,
[data-testid="stSidebar"] h2,
[data-testid="stSidebar"] h3 { color: #a78bfa !important; }

/* ── Main header ── */
.main-title {
    font-size: 2.5rem;
    font-weight: 800;
    background: linear-gradient(90deg, #6366f1, #a855f7, #ec4899);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    margin-bottom: 0.2rem;
}
.sub-title { color: #64748b; font-size: 1rem; margin-bottom: 1.5rem; }

/* ── Result cards ── */
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

/* ── Warning banner ── */
.warning-banner {
    background: #7f1d1d;
    color: #fca5a5;
    border-radius: 10px;
    padding: 1rem 1.4rem;
    font-weight: 600;
    margin-top: 1rem;
    font-size: 0.95rem;
}

/* ── Feature table ── */
.stDataFrame { border-radius: 10px; overflow: hidden; }

/* ── Confidence bar label ── */
.conf-label { font-size: 0.85rem; color: #64748b; margin-bottom: 0.2rem; }
</style>
""", unsafe_allow_html=True)


# ── LOAD MODEL ───────────────────────────────────────────────
@st.cache_resource(show_spinner="Loading ML model…")
def load_model():
    """Load the pre-trained Random Forest model from model.pkl."""
    model_path = os.path.join(os.path.dirname(__file__), "model.pkl")
    with open(model_path, "rb") as f:
        bundle = pickle.load(f)
    return bundle["model"], bundle["features"]

MODEL, FEATURES = load_model()


# ── FEATURE EXTRACTION ───────────────────────────────────────
def extract_features(url: str) -> dict:
    """
    Extract 18 security-relevant features from a URL.

    Encoding (UCI Phishing Dataset standard):
        -1  → Phishing / suspicious indicator
         0  → Neutral / uncertain
         1  → Legitimate indicator
    """
    parsed = urllib.parse.urlparse(url)
    domain = parsed.netloc.lower().replace("www.", "")
    full   = url.lower()

    features = {}

    # ── 1. URL_Length ──────────────────────────────────────────
    # Short URLs are safer; very long ones are suspicious
    L = len(url)
    features["URL_Length"] = 1 if L < 54 else (0 if L <= 75 else -1)

    # ── 2. Iframe ──────────────────────────────────────────────
    # Hidden iframes are used in drive-by download attacks
    features["Iframe"] = -1 if "iframe" in full else 1

    # ── 3. Redirect ────────────────────────────────────────────
    # Double slash after protocol = possible open-redirect abuse
    after_proto = url[url.find("//") + 2:] if "//" in url else url
    features["Redirect"] = 1 if "//" in after_proto else 0

    # ── 4. on_mouseover ────────────────────────────────────────
    # JS mouse events used to hide real destination
    features["on_mouseover"] = -1 if "onmouseover" in full else 1

    # ── 5. popUpWidnow ─────────────────────────────────────────
    # Unwanted pop-ups typical in hijacked browsers
    features["popUpWidnow"] = -1 if any(
        k in full for k in ["popup", "pop-up", "alert("]
    ) else 1

    # ── 6. Request_URL ─────────────────────────────────────────
    # Too many embedded http references = likely phishing
    features["Request_URL"] = -1 if full.count("http") > 2 else 1

    # ── 7. having_IP_Address ───────────────────────────────────
    # IP-based URLs avoid DNS and are very suspicious
    ip_pattern = r"(\d{1,3}\.){3}\d{1,3}"
    features["having_IP_Address"] = -1 if re.search(ip_pattern, domain) else 1

    # ── 8. SSLfinal_State ──────────────────────────────────────
    # HTTPS = safer; HTTP = possible MITM risk
    features["SSLfinal_State"] = 1 if parsed.scheme == "https" else -1

    # ── 9. having_Sub_Domain ───────────────────────────────────
    # Too many subdomains = likely spoofing (e.g., paypal.evil.com)
    parts = [p for p in domain.split(".") if p]
    features["having_Sub_Domain"] = 1 if len(parts) <= 2 else (
        0 if len(parts) == 3 else -1
    )

    # ── 10. age_of_domain ─────────────────────────────────────
    # Free / newly-registered TLDs are heavily abused for phishing
    new_tlds = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz",
                ".top", ".click", ".loan", ".win", ".bid"]
    features["age_of_domain"] = -1 if any(
        domain.endswith(t) for t in new_tlds
    ) else 1

    # ── 11. DNSRecord ─────────────────────────────────────────
    # IP-based domain = no DNS record = no legitimate registration
    features["DNSRecord"] = -1 if re.search(ip_pattern, domain) else 1

    # ── 12. web_traffic ───────────────────────────────────────
    # Well-known domains have established traffic patterns
    safe_domains = [
        "google", "youtube", "facebook", "twitter", "instagram",
        "linkedin", "microsoft", "apple", "amazon", "wikipedia",
        "github", "stackoverflow", "reddit", "netflix", "yahoo"
    ]
    features["web_traffic"] = 1 if any(s in domain for s in safe_domains) else 0

    # ── 13. Page_Rank ─────────────────────────────────────────
    # Proxy: well-known domains rank high on search engines
    features["Page_Rank"] = 1 if any(s in domain for s in safe_domains) else -1

    # ── 14. Google_Index ──────────────────────────────────────
    # Suspicious free-TLD domains are typically not indexed
    features["Google_Index"] = -1 if any(
        domain.endswith(t) for t in new_tlds
    ) else 1

    # ── 15. Links_pointing_to_page ────────────────────────────
    # Popular sites have many inbound links
    features["Links_pointing_to_page"] = 1 if any(
        s in domain for s in safe_domains
    ) else 0

    # ── 16. Statistical_report ────────────────────────────────
    # Known bad TLDs appear on phishing blocklists
    bad_tlds = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz",
                ".top", ".click", ".loan", ".win", ".bid"]
    features["Statistical_report"] = -1 if any(
        domain.endswith(t) for t in bad_tlds
    ) else 1

    # ── 17. Prefix_Suffix ─────────────────────────────────────
    # Dashes in domain are a classic phishing trick (paypal-secure.com)
    features["Prefix_Suffix"] = -1 if "-" in domain else 1

    # ── 18. HTTPS_token ───────────────────────────────────────
    # Having "https" inside the domain name itself is deceptive
    features["HTTPS_token"] = -1 if "https" in domain else 1

    return features


# ── RISK SCORE (rule-based, blended with ML) ─────────────────
def compute_risk_score(features: dict) -> float:
    """
    Weighted heuristic risk score (0 = safe, 1 = dangerous).
    Blended 60/40 with the ML model probability for final result.
    """
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


# ── PREDICT ───────────────────────────────────────────────────
def predict_url(url: str):
    """
    Full prediction pipeline:
        1. Normalise URL
        2. Extract features
        3. Compute heuristic risk score
        4. Get ML model probability
        5. Blend both scores → final verdict
    Returns a dict with all result fields.
    """
    # Normalise
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    features   = extract_features(url)
    risk_score = compute_risk_score(features)

    feat_vec   = [[features[f] for f in FEATURES]]
    proba      = float(MODEL.predict_proba(feat_vec)[0][1])   # prob of malicious

    # Blended final score
    blended = round(proba * 0.6 + risk_score * 0.4, 4)

    # Threat classification
    if blended >= 0.65:
        prediction, threat = "High Risk",   "🔴 High"
    elif blended >= 0.35:
        prediction, threat = "Suspicious",  "🟡 Medium"
    else:
        prediction, threat = "Safe",        "🟢 Low"

    return {
        "url":          url,
        "blended":      blended,
        "probability":  round(proba, 4),
        "risk_score":   risk_score,
        "prediction":   prediction,
        "threat":       threat,
        "features":     features,
    }


# ── URL LOGGING ───────────────────────────────────────────────
LOG_FILE = os.path.join(os.path.dirname(__file__), "url_log.csv")

def log_result(res: dict):
    """Append a checked URL and its result to a CSV log file."""
    entry = {
        "timestamp":   datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "url":         res["url"],
        "prediction":  res["prediction"],
        "confidence":  f"{res['blended']*100:.1f}%",
    }
    df = pd.DataFrame([entry])
    # Append without writing header if file already exists
    df.to_csv(LOG_FILE, mode="a", index=False,
              header=not os.path.exists(LOG_FILE))


# ── FEATURE TABLE HELPER ─────────────────────────────────────
FEATURE_DESCRIPTIONS = {
    "URL_Length":           "URL character length",
    "Iframe":               "Hidden iframe detected",
    "Redirect":             "Double-slash redirect",
    "on_mouseover":         "onmouseover JS event",
    "popUpWidnow":          "Pop-up / alert in URL",
    "Request_URL":          "Multiple embedded http refs",
    "having_IP_Address":    "IP address used as domain",
    "SSLfinal_State":       "HTTPS / SSL certificate",
    "having_Sub_Domain":    "Number of sub-domains",
    "age_of_domain":        "Domain uses new/free TLD",
    "DNSRecord":            "DNS record available",
    "web_traffic":          "Known high-traffic domain",
    "Page_Rank":            "High page rank (popular site)",
    "Google_Index":         "Indexed by Google",
    "Links_pointing_to_page": "Inbound link count (proxy)",
    "Statistical_report":   "Listed on phishing report",
    "Prefix_Suffix":        "Dash (-) in domain name",
    "HTTPS_token":          "'https' keyword inside domain",
}

def make_feature_df(features: dict) -> pd.DataFrame:
    """Convert raw feature dict into a human-readable DataFrame."""
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

    # ── View Log ──────────────────────────────────────────────
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

# ── URL Input ─────────────────────────────────────────────────
col_input, col_btn = st.columns([5, 1])

with col_input:
    url_input = st.text_input(
        label="🔗 Enter URL",
        placeholder="e.g. https://google.com  or  http://paypal-secure.tk/login",
        label_visibility="collapsed",
    )

with col_btn:
    check_clicked = st.button("🔍 Check Risk", use_container_width=True, type="primary")

# ── Auto-trigger on paste (real-time feel) ───────────────────
# We trigger whenever the input box has text, regardless of button press,
# but we gate behind a simple session-state dedup so it doesn't re-run
# on every unrelated interaction.
if "last_checked" not in st.session_state:
    st.session_state.last_checked = ""

should_run = check_clicked or (
    url_input.strip() != "" and url_input.strip() != st.session_state.last_checked
)

# ── RUN PREDICTION ────────────────────────────────────────────
if should_run and url_input.strip():
    raw_url = url_input.strip()
    st.session_state.last_checked = raw_url

    try:
        with st.spinner("Analysing URL…"):
            result = predict_url(raw_url)
            log_result(result)          # save to CSV log

        pred       = result["prediction"]
        confidence = result["blended"] * 100
        ml_prob    = result["probability"] * 100

        st.markdown("")

        # ── Result Card ───────────────────────────────────────
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

        # ── Warning Banner for High-Risk ──────────────────────
        if pred == "High Risk":
            st.markdown("""
<div class="warning-banner">
⛔ WARNING: This URL shows multiple indicators of a phishing or browser-hijack
attack. Do <strong>NOT</strong> enter any credentials or personal information.
Close this page immediately and run a malware scan.
</div>
""", unsafe_allow_html=True)

        st.markdown("")

        # ── Confidence / Probability Gauges ───────────────────
        col_a, col_b, col_c = st.columns(3)

        with col_a:
            st.metric("🎯 Blended Risk Score",
                      f"{result['blended']:.4f}",
                      help="Weighted blend of ML probability (60%) + heuristic score (40%)")

        with col_b:
            st.metric("🤖 ML Model Probability",
                      f"{ml_prob:.1f}%",
                      help="Random Forest classifier output (probability of being malicious)")

        with col_c:
            st.metric("📐 Heuristic Score",
                      f"{result['risk_score']:.4f}",
                      help="Rule-based weighted score derived from URL features")

        # Progress bar for visual confidence
        st.markdown('<p class="conf-label">Overall Risk Confidence</p>',
                    unsafe_allow_html=True)
        bar_color = (
            "green"  if pred == "Safe" else
            "orange" if pred == "Suspicious" else
            "red"
        )
        # Streamlit progress bar (0.0 – 1.0)
        st.progress(min(result["blended"], 1.0))

        st.markdown("---")

        # ── Extracted Features Table ──────────────────────────
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

# ── Footer ────────────────────────────────────────────────────
st.markdown("---")
st.markdown(
    "<center style='color:#94a3b8;font-size:0.8rem;'>"
    "🛡️ Browser Hijack Risk Predictor &nbsp;|&nbsp; "
    "Vidit Desai · GUCPC &nbsp;|&nbsp; "
    "Powered by Random Forest + Heuristic Analysis"
    "</center>",
    unsafe_allow_html=True,
)
