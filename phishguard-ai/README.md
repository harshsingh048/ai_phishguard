# 🛡️ PhishGuard AI

**AI-Powered Phishing & Scam Detection System**

Real-time detection of phishing URLs, spam messages, and fraudulent emails using ML + Rules + BERT.

---

## 🚀 Quick Start (5 Steps)

### Step 1 — Install Dependencies
```bash
cd phishguard-ai
pip install -r requirements.txt
```

Minimal install (no BERT, no PDF — fastest):
```bash
pip install flask flask-cors flask-sqlalchemy flask-jwt-extended werkzeug scikit-learn numpy requests python-whois
```

### Step 2 — Train Models
```bash
python train_models.py
```
Trains URL (GradientBoosting) and Text (TF-IDF + LogisticRegression) models.
Takes ~30-60 seconds. Creates `models/` directory with 4 .pkl files.

### Step 3 — Run Backend
```bash
python app.py
```
Server starts at: **http://localhost:5000**

### Step 4 — Open Frontend
Open browser → **http://localhost:5000**

### Step 5 — Load Chrome Extension (Optional)
1. Open Chrome → `chrome://extensions/`
2. Enable "Developer Mode"
3. Click "Load unpacked"
4. Select `chrome_extension/` folder

---

## 📁 Project Structure

```
phishguard-ai/
├── app.py                   # Flask app entry point
├── config.py                # All configuration
├── requirements.txt         # Dependencies
├── train_models.py          # Model training pipeline
├── bert_model.py            # DistilBERT deep mode
│
├── models/                  # Trained model files (.pkl)
│   ├── url_model.pkl
│   ├── url_scaler.pkl
│   ├── text_model.pkl
│   └── text_vectorizer.pkl
│
├── database/
│   └── db.py               # SQLAlchemy models (User, Scan, ThreatFeed)
│
├── auth/
│   └── auth_service.py     # JWT auth, register, login
│
├── services/
│   ├── cache.py            # LRU cache (instant repeated lookups)
│   ├── model_service.py    # ML model loader + predictor
│   ├── scan_service.py     # Main scan orchestrator
│   ├── domain_intel.py     # WHOIS + DNS + threat feed
│   └── report_service.py  # JSON + PDF export
│
├── routes/
│   ├── scan_routes.py      # POST /scan, /batch, /report
│   ├── auth_routes.py      # POST /login, /register, /me
│   └── dashboard_routes.py # GET /dashboard, /history
│
├── utils/
│   ├── url_features.py     # 20 URL features + rule scoring
│   └── text_features.py    # Text analysis + pattern detection
│
├── templates/
│   ├── index.html          # Main scanner UI
│   ├── dashboard.html      # Stats dashboard
│   └── login.html          # Auth page
│
├── static/
│   ├── css/main.css        # Dark cyberpunk theme
│   └── js/
│       ├── main.js         # Scanner frontend logic
│       ├── dashboard.js    # Charts & dashboard
│       └── auth.js         # Login/register forms
│
├── chrome_extension/        # Browser extension
│   ├── manifest.json
│   ├── popup.html/js       # Extension popup
│   ├── background.js       # Auto-scan service worker
│   └── content.js          # Page link scanner
│
└── reports/                 # Generated PDF/JSON reports
```

---

## 🔌 API Reference

### POST /api/scan
Scan a URL or message.
```json
{
  "input": "http://paypa1-verify.com/login",
  "mode": "fast"
}
```
Response includes: `risk_score`, `classification`, `triggered_rules`, `suggestions`, `explanation`

### POST /api/auth/login
```json
{ "username": "user", "password": "pass" }
```

### POST /api/auth/register
```json
{ "username": "user", "email": "user@email.com", "password": "pass" }
```

### GET /api/dashboard
Returns scan stats, trend data, recent scans.

### POST /api/batch (requires auth)
```json
{ "inputs": ["url1", "msg1", "url2"], "mode": "fast" }
```

---

## 🧪 Test Inputs

**Phishing URLs:**
- `http://paypa1-verify.com/login?redirect=evil.com`
- `http://192.168.1.1/secure-banking/verify?token=abc`

**Safe URLs:**
- `https://www.github.com/features`
- `https://www.stackoverflow.com/questions`

**Spam Messages:**
- `URGENT: Your PayPal account has been suspended! Verify NOW at paypa1.xyz`
- `Congratulations! You've won $1,000,000. Claim your prize: free-winner.tk`

**Normal Messages:**
- `Hi team, meeting moved to 3pm Thursday. Please update your calendars.`
- `Your order #12345 has shipped. Track at ups.com. Expected delivery: March 15.`

---

## 🎯 Two Scan Modes

| Feature | Fast Mode | Deep Mode |
|---------|-----------|-----------|
| ML Model | ✅ | ✅ |
| Rule Engine | ✅ | ✅ |
| BERT | ❌ | ✅ (text only) |
| WHOIS Lookup | ❌ | ✅ |
| Threat Intel | ❌ | ✅ |
| Response Time | <1s | 3-8s |
| Works Offline | ✅ | Partial |

---

## 🧠 ML Models

**URL Model (GradientBoosting):**
20 features including: URL length, entropy, subdomains, suspicious TLDs, homoglyphs, brand impersonation, redirect patterns.

**Text Model (TF-IDF + LogisticRegression):**
5000 features, ngram(1,3). Trained on augmented spam/legit dataset.

**Ensemble Scoring:**
- Fast Mode: `0.55 * ML + 0.45 * Rules`
- Deep Mode (text): `0.40 * Rules + 0.35 * BERT + 0.25 * Rules`
- Deep Mode (URL): ML score + WHOIS boost

---

## 🔐 Security

- JWT tokens (24h expiry)
- Bcrypt password hashing
- Rate limiting (30 req/min per IP)
- Input validation + length limits
- SQL injection protection via SQLAlchemy ORM
- CORS configured

---

## 🏆 Hackathon Demo Script

**Problem:** 3.4 billion phishing emails sent daily. 80% of breaches involve phishing.

**Solution:** PhishGuard AI — real-time detection in <1 second using ensemble ML.

**Innovations:**
1. Dual-mode: Fast (<1s offline) + Deep (BERT + WHOIS)
2. Explainable AI — tells you exactly WHY it flagged something
3. Auto-detects URL vs message automatically
4. Chrome extension with live page scanning
5. Beautiful, production-quality cybersecurity dashboard

**Demo Flow:**
1. Paste `http://paypa1-verify.com/login` → show dangerous 🚨
2. Paste legitimate `https://github.com` → show safe ✅
3. Paste spam email → show message analysis with highlights
4. Switch to Deep Mode → show WHOIS + BERT results
5. Open dashboard → show threat intelligence charts
6. Show Chrome extension → auto-badge on browser tabs
