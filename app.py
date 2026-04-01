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
st.set_page_config(page_title="Browser Hijack Predictor", layout="wide")

@st.cache_resource
def load_model():
    model_path = os.path.join(os.path.dirname(__file__), "model.pkl")
    with open(model_path, "rb") as f:
        bundle = pickle.load(f)
    return bundle["model"], bundle["features"]

MODEL, FEATURES = load_model()

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

# ── UI ──────────────────────────────────────────────────────
st.title("🛡️ Real-Time Browser Hijack Risk Predictor")

# ── Styled Sidebar Developer Card ───────────────────────────
st.sidebar.markdown("---")
st.sidebar.markdown(
    """
    <div style="
        background-color: #1e1e2e;
        padding: 12px 16px;
        border-radius: 10px;
        border-left: 4px solid #7c3aed;
        text-align: center;
    ">
        <p style="margin:0; font-size:13px; color:#a0a0b0;">Developed by</p>
        <p style="margin:4px 0 0; font-size:16px; font-weight:700; color:#e2e8f0;">
            👨‍💻 Vidit Desai
        </p>
    </div>
    """,
    unsafe_allow_html=True,
)

# ── Tabs ─────────────────────────────────────────────────────
tab1, tab2 = st.tabs(["Single URL", "Bulk Scanner"])

with tab1:
    url = st.text_input("Enter URL")

    if st.button("Check Risk"):
        if url:
            u, label, score = predict_url(url)
            st.success(f"{label} (Score: {score})")
        else:
            st.warning("Enter a URL first.")

with tab2:
    text_input = st.text_area("Paste URLs (one per line)")
    uploaded_file = st.file_uploader("Upload file", type=["txt", "csv"])

    urls = []
    if text_input:
        urls = [u.strip() for u in text_input.split("\n") if u.strip()]
    if uploaded_file:
        content = uploaded_file.read().decode("utf-8")
        urls = [u.strip() for u in content.split("\n") if u.strip()]

    if st.button("Scan All"):
        if urls:
            data = []
            for i, u in enumerate(urls):
                try:
                    url_out, label, score = predict_url(u)
                    data.append([i + 1, url_out, label, score])
                except Exception:
                    data.append([i + 1, u, "Error", "-"])

            df = pd.DataFrame(data, columns=["No", "URL", "Prediction", "Score"])
            st.dataframe(df)

            csv = df.to_csv(index=False).encode("utf-8")
            st.download_button("Download CSV", csv, "results.csv")
        else:
            st.warning("No URLs provided.")

# ── Footer ───────────────────────────────────────────────────
st.markdown("---")
st.markdown("Developed by **Vidit Desai**")
