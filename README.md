# MailGuard – Spam & Phishing Detection (VS Code)

## Features
- Spam and phishing detection using TF-IDF character n-grams + Multinomial Naive Bayes, combined with transparent rule-based checks.
- Email risk score (0–100) and Low / Medium / High level.
- Explainable AI: shows the phrases and URL/sender signals that contributed to the risk score.
- URL inspection: HTTP, IP-based links, punycode, long URLs, unusual TLDs and subdomain patterns.
- Sender address format and domain checks.
- Bulk CSV scanning (`message` column required; `sender` and `subject` optional).
- Script-based multilingual language hints (Telugu, Hindi, Tamil, Bengali, Chinese, Japanese, Latin).
- Threat analytics for the most recent scan batch.
- Downloadable CSV and PDF reports.

## Setup in VS Code (Windows)
1. Extract this folder and open it in VS Code: **File → Open Folder**.
2. Open **Terminal → New Terminal**.
3. Create a virtual environment:
   ```powershell
   python -m venv .venv
   ```
4. Activate it:
   ```powershell
   .venv\Scripts\Activate.ps1
   ```
   If PowerShell blocks activation, run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` and activate again.
5. Install packages:
   ```powershell
   python -m pip install --upgrade pip
   pip install -r requirements.txt
   ```
6. Start the app:
   ```powershell
   python app.py
   ```
7. Open http://127.0.0.1:5000 in your browser.

## macOS / Linux
```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
python app.py
```

## Bulk CSV format
Use a CSV with these columns (only `message` is required):
```csv
sender,subject,message
security@example.com,Account notice,Please verify your password immediately
friend@gmail.com,Meeting,Are we meeting tomorrow?
```
A starter file is included at `data/bulk_sample.csv`.

## Important limitations
- The included training data is a small demonstration dataset. It is not enough for production-grade accuracy. Replace `data/spam.csv` with a properly licensed, larger, representative dataset before making accuracy claims.
- Multilingual support currently detects common writing scripts and uses character n-gram features, but the included training examples are English. For reliable Telugu/Hindi/etc. classification, add labelled multilingual spam and ham examples to `data/spam.csv`.
- URL checks are heuristic only. This project does not query live threat-intelligence feeds, resolve domains, inspect certificates, or verify sender authentication (SPF/DKIM/DMARC).
- Risk score is a heuristic indicator, not a calibrated probability. "Likely Safe" does not guarantee safety. Do not open suspicious links or enter credentials based on this tool's result.
- This app processes uploaded content locally; do not upload real confidential emails unless you are permitted to do so.
