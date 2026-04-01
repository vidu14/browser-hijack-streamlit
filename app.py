# ============================================================

# Real-Time Browser Hijack Risk Predictor – Streamlit App

# Developer : Vidit Desai

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

st.set_page_config(page_title="Browser Hijack Risk Predictor", layout="wide")

# ── LOAD MODEL ─────────────────────────────

@st.cache_resource
def load_model():
with open("model.pkl", "rb") as f:
bundle = pickle.load(f)
return bundle["model"], bundle["features"]

MODEL, FEATURES = load_model()

# ── FEATURE EXTRACTION ─────────────────────

def extract_features(url):
parsed = urllib.parse.urlparse(url)
domain = parsed.netloc.lower()
features = {}

```
features["URL_Length"] = 1 if len(url) < 54 else (0 if len(url) <= 75 else -1)
features["having_IP_Address"] = -1 if re.search(r"(\d{1,3}\.){3}\d{1,3}", domain) else 1
features["SSLfinal_State"] = 1 if parsed.scheme == "https" else -1
features["Prefix_Suffix"] = -1 if "-" in domain else 1
features["HTTPS_token"] = -1 if "https" in domain else 1

return features
```

# ── PREDICT ────────────────────────────────

def predict_url(url):
if not url.startswith(("http://", "https://")):
url = "http://" + url

```
features = extract_features(url)
feat_vec = [[features.get(f, 0) for f in FEATURES]]

proba = MODEL.predict_proba(feat_vec)[0][1]

if proba > 0.7:
    prediction = "High Risk"
elif proba > 0.4:
    prediction = "Suspicious"
else:
    prediction = "Safe"

return {
    "url": url,
    "prediction": prediction,
    "score": round(proba, 4)
}
```

# ── UI ────────────────────────────────────

st.title("🛡️ Browser Hijack Risk Predictor")

tab1, tab2 = st.tabs(["🔍 Single URL", "📋 Bulk Scanner"])

# ==============================

# SINGLE URL

# ==============================

with tab1:
url = st.text_input("Enter URL")

```
if st.button("Check Risk"):
    if url:
        res = predict_url(url)
        st.success(f"Prediction: {res['prediction']}")
    else:
        st.warning("Enter a URL")
```

# ==============================

# BULK SCANNER

# ==============================

with tab2:
st.markdown("### Bulk URL Scanner")

```
text_urls = st.text_area("Paste URLs (one per line)")
uploaded = st.file_uploader("Upload file", type=["txt", "csv"])

urls = []

if text_urls:
    urls = text_urls.split("\n")

if uploaded:
    content = uploaded.read().decode("utf-8")
    urls = content.split("\n")

if st.button("Scan All URLs"):
    if urls:
        results = []

        for i, u in enumerate(urls):
            if u.strip():
                res = predict_url(u.strip())
                results.append({
                    "No": i+1,
                    "URL": res["url"],
                    "Prediction": res["prediction"],
                    "Score": res["score"]
                })

        df = pd.DataFrame(results)

        st.markdown("### Results")

        # ✅ FIXED TABLE (NO ERROR)
        st.dataframe(df)

        # Download
        csv = df.to_csv(index=False).encode("utf-8")
        st.download_button("Download CSV", csv, "results.csv")

    else:
        st.warning("No URLs provided")
```


