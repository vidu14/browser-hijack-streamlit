# ============================================================
#  Real-Time Browser Hijack Risk Predictor  –  Streamlit App
#  Developer : Vidit Desai
# ============================================================

import os
import re
import pickle
import urllib.parse
import datetime
import warnings
import io

import pandas as pd
import streamlit as st

warnings.filterwarnings("ignore")

# ── PAGE CONFIG ─────────────────────────────────────────────
st.set_page_config(page_title="Browser Hijack Predictor", layout="wide")


# ── LOAD MODEL ──────────────────────────────────────────────
@st.cache_resource
def load_model():
    model_path = "model.pkl"
    with open(model_path, "rb") as f:
        bundle = pickle.load(f)
    return bundle["model"], bundle["features"]

MODEL, FEATURES = load_model()


# ── FEATURE EXTRACTION ──────────────────────────────────────
def extract_features(url):
    parsed = urllib.parse.urlparse(url)
    domain = parsed.netloc.lower()

    features = {
        "URL_Length": 1 if len(url) < 54 else (0 if len(url) <= 75 else -1),
        "having_IP_Address": -1 if re.search(r"(\d{1,3}\.){3}\d{1,3}", domain) else 1,
        "SSLfinal_State": 1 if parsed.scheme == "https" else -1,
        "Prefix_Suffix": -1 if "-" in domain else 1,
        "HTTPS_token": -1 if "https" in domain else 1,
    }

    return features


# ── PREDICT ─────────────────────────────────────────────────
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

    return {
        "url": url,
        "prediction": label,
        "score": round(prob, 4)
    }


# ── UI ──────────────────────────────────────────────────────
st.title("🛡️ Browser Hijack Risk Predictor")

tab1, tab2 = st.tabs(["🔍 Single URL Scanner", "📋 Bulk Scanner"])


# ── SINGLE URL ──────────────────────────────────────────────
with tab1:
    url = st.text_input("Enter URL")

    if st.button("Check Risk"):
        if url:
            result = predict_url(url)
            st.success(f"Prediction: {result['prediction']}")
            st.write(f"Risk Score: {result['score']}")
        else:
            st.warning("Please enter a URL")


# ── BULK SCANNER ────────────────────────────────────────────
with tab2:
    st.markdown("### Bulk URL Scanner")

    text_input = st.text_area("Paste URLs (one per line)")
    file = st.file_uploader("Upload file (.txt or .csv)", type=["txt", "csv"])

    urls = []

    if text_input:
        urls = [u.strip() for u in text_input.split("\n") if u.strip()]

    if file:
        content = file.read().decode("utf-8")
        urls = [u.strip() for u in content.split("\n") if u.strip()]

    if st.button("Scan All URLs"):
        if urls:
            results = []

            for i, u in enumerate(urls):
                try:
                    res = predict_url(u)
                    results.append({
                        "No": i + 1,
                        "URL": res["url"],
                        "Prediction": res["prediction"],
                        "Score": res["score"]
                    })
                except Exception:
                    results.append({
                        "No": i + 1,
                        "URL": u,
                        "Prediction": "Error",
                        "Score": "-"
                    })

            df = pd.DataFrame(results)

            st.subheader("Results")
            st.dataframe(df)

            csv = df.to_csv(index=False).encode("utf-8")
            st.download_button("Download CSV", csv, "results.csv")

        else:
            st.warning("No URLs provided")


# ── FOOTER ──────────────────────────────────────────────────
st.markdown("---")
st.markdown("Built with ❤️ using Streamlit")
