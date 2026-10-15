# PhishX: Multi-Vector Phishing Detection System

**PhishX** is an end-to-end multi-vector phishing detection and threat intelligence platform powered by Python machine learning models, heuristic indicators, and string-matching algorithms. It analyzes and flags malicious threats across **URLs**, **Emails**, and **QR Codes (Quishing)**.

---

## 🎯 Key Capabilities & Technical Highlights

- **Multi-Vector Threat Detection**: Analyzes and flags malicious URLs, email headers/bodies, and QR code payloads based on heuristic indicators and ML models.
- **Typosquatting & Impersonation Engine**: Implements string-matching algorithms (Damerau-Levenshtein edit distance, homoglyph visual substitution, and combo-squatting regular expressions) to detect brand mimicry and suspicious domain permutations.
- **Email Header Parsing & Spoofing Defense**: Inspects RFC 822 email headers to detect display name deception, sender vs. `Return-Path` divergence, `Reply-To` redirection mismatches, and SPF/DKIM authentication anomalies.
- **Machine Learning Classifiers**:
  - **URL Random Forest Classifier**: Extracts 18+ lexical, statistical, and structural features (Shannon entropy, digit ratios, token counts, path depth, TLD risk, and typosquatting distance) to predict phishing probability with calibrated confidence.
  - **Email NLP Classifier**: Uses TF-IDF vectorization and a calibrated Naive Bayes pipeline to detect social engineering lures, urgency triggers, and credential harvesting patterns.
- **QR Code (Quishing) Analyzer**: Decodes QR codes with image pre-processing (contrast enhancement, thresholding) and automatically unpacks embedded URLs into the deep inspection pipeline.

---

## 🛠️ Architecture

```
                  ┌────────────────────────┐
                  │ Next.js 16 Dark-Mode UI│
                  │   (React 19 / Tailwind) │
                  └───────────┬────────────┘
                              │
               ┌──────────────┴──────────────┐
               ▼                             ▼
    Next.js Route Handlers           FastAPI REST API
    (/api/url, /api/email, /api/qr)    (main.py / /docs)
               │                             │
               └──────────────┬──────────────┘
                              ▼
        ┌───────────────────────────────────────────┐
        │       PhishX Detection Core (Python)       │
        ├─────────────────────┬─────────────────────┤
        │ 1. Heuristic Engine │ 2. Typosquatting    │
        │    • TLD Abuse      │    • Damerau-       │
        │    • IP Detection   │      Levenshtein    │
        │    • Keyword Flags  │    • Homoglyph Map  │
        │    • Protocol Check │    • Brand DB       │
        ├─────────────────────┼─────────────────────┤
        │ 3. Email Module     │ 4. ML Engine        │
        │    • Header Parsing │    • Random Forest  │
        │    • Spoofing Check │    • TF-IDF NLP     │
        │    • Link Unpacking │    • Entropy Metric │
        └─────────────────────┴─────────────────────┘
```

---

## 🚀 Getting Started

### 1. Prerequisites
- **Node.js** (v18+)
- **Python** (v3.10+ / v3.12 recommended)

### 2. Python Environment Setup
```bash
# Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate       # On Linux/macOS
.venv\Scripts\activate          # On Windows

# Install required dependencies
pip install -r requirements.txt
```

### 3. Frontend Setup
```bash
npm install
npm run dev
```
Open [http://localhost:3000](http://localhost:3000) in your browser.

### 4. Running the Python FastAPI Backend (Optional Standalone)
```bash
uvicorn main:app --reload --port 8000
```
Interactive Swagger API documentation is available at [http://localhost:8000/docs](http://localhost:8000/docs).

---

## 🧪 Automated Testing

Run the full test suite covering all detection vectors, machine learning models, and string algorithms:

```bash
python -m unittest tests/test_detection.py
```

---

## 📡 API Reference

### `POST /api/url`
Analyzes a URL against heuristics, typosquatting databases, and the Random Forest ML model.
```json
{
  "url": "http://paypal.com.verify-login.xyz/account/login.php"
}
```

### `POST /api/email`
Inspects email headers and content for spoofing, urgency indicators, and embedded phishing links.
```json
{
  "from": "\"PayPal Security\" <alerts@paypa1-security.xyz>",
  "reply_to": "attacker@gmail.com",
  "subject": "URGENT: Your account has been suspended",
  "body": "Click here to verify: http://paypal.com.verify-login.xyz"
}
```

### `POST /api/qr`
Decodes QR codes from base64 images or multipart file uploads and inspects the payload.
```json
{
  "image": "data:image/png;base64,..."
}
```

---

## 📄 License
MIT License.
