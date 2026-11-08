"""Rule-assisted email security scanner with a lightweight ML classifier."""
from pathlib import Path
from urllib.parse import urlparse
import re
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline

BASE = Path(__file__).resolve().parent
DATA = BASE / "data" / "spam.csv"
MODEL = None

URL_RE = re.compile(r"https?://[^\s<>'\"]+|www\.[^\s<>'\"]+", re.I)
EMAIL_RE = re.compile(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.I)
URGENT = ["urgent", "immediately", "act now", "final warning", "account suspended",
          "verify your account", "unusual activity", "limited time", "expires today"]
MONEY = ["won", "winner", "cash prize", "free gift", "claim your prize",
         "guaranteed income", "lottery", "bank details", "send money"]
CREDENTIALS = ["password", "pin", "otp", "cvv", "social security", "credit card",
               "login details", "verify your identity"]
SUSPICIOUS_TLDS = {".xyz", ".top", ".click", ".work", ".zip", ".country", ".gq", ".tk"}
TRUSTED_HINTS = {"gmail.com", "outlook.com", "yahoo.com", "hotmail.com"}

def get_model():
    global MODEL
    if MODEL is not None:
        return MODEL
    df = pd.read_csv(DATA)
    df = df.dropna(subset=["label", "message"])
    pipe = Pipeline([
        ("tfidf", TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 5), max_features=18000,
                                  min_df=1, sublinear_tf=True)),
        ("clf", MultinomialNB(alpha=0.35))
    ])
    pipe.fit(df["message"].astype(str), df["label"].astype(str).str.lower())
    MODEL = pipe
    return MODEL

def get_urls(text):
    return [u.rstrip(".,);]") for u in URL_RE.findall(text)]

def inspect_url(raw):
    candidate = raw if raw.lower().startswith(("http://", "https://")) else "http://" + raw
    parsed = urlparse(candidate)
    host = (parsed.hostname or "").lower()
    flags = []
    if not host:
        return {"url": raw, "domain": "Unknown", "flags": ["Could not parse URL"]}
    if parsed.scheme == "http":
        flags.append("Unencrypted HTTP")
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
        flags.append("IP address used instead of a domain")
    if "xn--" in host:
        flags.append("Punycode domain (possible lookalike)")
    if host.count(".") >= 4:
        flags.append("Unusually many subdomains")
    if any(host.endswith(tld) for tld in SUSPICIOUS_TLDS):
        flags.append("Uncommon high-risk TLD")
    if "@" in parsed.netloc:
        flags.append("URL contains user-info / @ character")
    if len(raw) > 100:
        flags.append("Very long URL")
    return {"url": raw, "domain": host, "flags": flags}

def detect_language(text):
    # Lightweight script-based language hint; not a full language identification model.
    if re.search(r"[\u0C00-\u0C7F]", text): return "Telugu (script detected)"
    if re.search(r"[\u0900-\u097F]", text): return "Hindi (script detected)"
    if re.search(r"[\u0B80-\u0BFF]", text): return "Tamil (script detected)"
    if re.search(r"[\u0980-\u09FF]", text): return "Bengali (script detected)"
    if re.search(r"[\u4E00-\u9FFF]", text): return "Chinese (script detected)"
    if re.search(r"[\u3040-\u30FF]", text): return "Japanese (script detected)"
    if re.search(r"[A-Za-z]", text): return "English / Latin"
    return "Unknown"

def scan_message(message, sender="", subject=""):
    text = " ".join([str(subject or ""), str(message or "")]).strip()
    low = text.lower()
    reasons, points = [], 0
    urls = get_urls(text)
    url_details = [inspect_url(u) for u in urls]
    for phrase in URGENT:
        if phrase in low:
            points += 9
            reasons.append(f"Urgency tactic detected: '{phrase}'")
    for phrase in MONEY:
        if phrase in low:
            points += 12
            reasons.append(f"Prize / money lure detected: '{phrase}'")
    for phrase in CREDENTIALS:
        if phrase in low:
            points += 14
            reasons.append(f"Sensitive information term detected: '{phrase}'")
    if text.count("!") >= 3:
        points += 5; reasons.append("Excessive exclamation marks")
    if len(urls) >= 2:
        points += 8; reasons.append("Multiple links in one message")
    elif len(urls) == 1:
        points += 3; reasons.append("Message contains a clickable link")
    for item in url_details:
        for flag in item["flags"]:
            points += 10
            reasons.append(f"URL risk: {flag}")
    sender = str(sender or "").strip()
    if sender:
        match = EMAIL_RE.search(sender)
        if not match:
            points += 8; reasons.append("Sender address has an unusual format")
        else:
            domain = match.group(0).split("@")[-1].lower()
            if domain.startswith("xn--") or "xn--" in domain:
                points += 15; reasons.append("Sender uses a punycode domain")
            if domain.endswith(tuple(SUSPICIOUS_TLDS)):
                points += 12; reasons.append("Sender uses an uncommon high-risk TLD")
            if domain in TRUSTED_HINTS:
                reasons.append("Sender uses a common email provider (not proof of safety)")
    # ML signal: trained on included sample set. It is a supporting signal, not a verdict.
    try:
        model = get_model()
        prediction = model.predict([text])[0]
        probabilities = model.predict_proba([text])[0]
        classes = list(model.classes_)
        spam_prob = float(probabilities[classes.index("spam")]) if "spam" in classes else 0.0
        if prediction == "spam":
            points += round(spam_prob * 25)
            reasons.append(f"Text model considers this spam-like (score {spam_prob:.0%})")
    except Exception:
        spam_prob = 0.0
    score = min(100, max(0, int(points)))
    verdict = "Phishing" if score >= 55 and any(x in low for x in CREDENTIALS + ["verify", "login"]) else ("Spam" if score >= 35 or spam_prob >= .72 else "Likely Safe")
    level = "High" if score >= 60 else ("Medium" if score >= 30 else "Low")
    if not reasons:
        reasons.append("No strong indicators were detected by the configured checks.")
    return {
        "verdict": verdict, "risk_score": score, "risk_level": level,
        "language": detect_language(text), "sender": sender,
        "urls": urls, "url_details": url_details, "reasons": reasons,
        "message": str(message or "")[:1200], "ml_spam_probability": round(spam_prob * 100, 1)
    }

def scan_dataframe(df):
    results = []
    for _, row in df.fillna("").iterrows():
        results.append(scan_message(row.get("message", ""), row.get("sender", ""), row.get("subject", "")))
    return results
