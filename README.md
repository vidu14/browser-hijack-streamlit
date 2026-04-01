# 🛡️ Real-Time Browser Hijack Risk Predictor — Streamlit App

**Developer:** Vidit Desai | GUCPC  
**Framework:** Streamlit + scikit-learn (Random Forest)

---

## 📁 Files

```
streamlit_app/
├── app.py           ← Main Streamlit application
├── model.pkl        ← Pre-trained Random Forest model (18 features)
├── requirements.txt ← Python dependencies
└── README.md        ← This file
```

---

## ⚙️ How to Run

### Step 1 — Install dependencies
```bash
pip install -r requirements.txt
```

### Step 2 — Run the app
```bash
streamlit run app.py
```

The app will open automatically at **http://localhost:8501**

---

## 🖥️ Features

| Feature | Detail |
|---|---|
| URL Input | Text box with auto-trigger on paste |
| Risk Prediction | Safe / Suspicious / High Risk |
| Colour Indicators | 🟢 Green · 🟡 Yellow · 🔴 Red |
| Feature Table | 18 extracted features with descriptions |
| Confidence Score | Blended ML + heuristic score |
| Warning Banner | Shown for High Risk URLs |
| URL Logging | Auto-saved to `url_log.csv` |
| Sidebar | Project info, model details, log viewer |

---

## 🤖 Model Details

| Property | Value |
|---|---|
| Algorithm | Random Forest |
| Trees | 200 |
| Dataset | UCI Phishing Websites (11,055 URLs) |
| Accuracy | ~91.7% |
| Features | 18 security attributes |

### Feature Encoding (UCI standard)
- `1`  → Legitimate indicator
- `0`  → Neutral / uncertain
- `-1` → Phishing / suspicious indicator

---

## 🔍 How the Score is Calculated

```
Final Score = (ML Probability × 0.6) + (Heuristic Score × 0.4)

Risk Level:
  ≥ 0.65  →  🔴 High Risk
  ≥ 0.35  →  🟡 Suspicious
  < 0.35  →  🟢 Safe
```
