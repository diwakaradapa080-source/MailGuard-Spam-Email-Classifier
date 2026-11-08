from pathlib import Path
from datetime import datetime
from io import BytesIO, StringIO
from urllib.parse import urlparse
import csv
import re
import pandas as pd
from flask import Flask, render_template, request, send_file, flash, redirect, url_for
from scanner import scan_message, scan_dataframe

BASE = Path(__file__).resolve().parent
app = Flask(__name__)
app.secret_key = "change-this-local-demo-secret"

latest_results = []

@app.route("/", methods=["GET", "POST"])
def dashboard():
    global latest_results
    single_result = None
    message = ""
    if request.method == "POST":
        message = request.form.get("message", "").strip()
        if message:
            single_result = scan_message(message)
            latest_results = [single_result]
        else:
            flash("Please enter an email or message to scan.", "error")
    stats = {
        "scanned": len(latest_results),
        "high": sum(r["risk_level"] == "High" for r in latest_results),
        "medium": sum(r["risk_level"] == "Medium" for r in latest_results),
        "low": sum(r["risk_level"] == "Low" for r in latest_results),
        "spam": sum(r["verdict"] in ("Spam", "Phishing") for r in latest_results),
    }
    return render_template("index.html", result=single_result, message=message,
                           stats=stats, recent=latest_results[-8:][::-1])

@app.route("/bulk", methods=["GET", "POST"])
def bulk():
    global latest_results
    results = []
    if request.method == "POST":
        uploaded = request.files.get("file")
        if not uploaded or not uploaded.filename:
            flash("Choose a CSV file first.", "error")
        elif not uploaded.filename.lower().endswith(".csv"):
            flash("Please upload a .csv file.", "error")
        else:
            try:
                df = pd.read_csv(uploaded)
                if "message" not in df.columns:
                    flash("CSV must contain a 'message' column. Optional columns: sender, subject.", "error")
                else:
                    results = scan_dataframe(df)
                    latest_results = results
                    flash(f"Scanned {len(results)} rows successfully.", "success")
            except Exception as exc:
                flash(f"Could not read CSV: {exc}", "error")
    return render_template("bulk.html", results=results)

@app.route("/sample-csv")
def sample_csv():
    return send_file(BASE / "data" / "bulk_sample.csv", as_attachment=True,
                     download_name="bulk_sample.csv", mimetype="text/csv")

@app.route("/analytics")
def analytics():
    rows = latest_results
    return render_template("analytics.html",
        total=len(rows),
        spam=sum(r["verdict"] in ("Spam", "Phishing") for r in rows),
        phishing=sum(r["verdict"] == "Phishing" for r in rows),
        high=sum(r["risk_level"] == "High" for r in rows),
        medium=sum(r["risk_level"] == "Medium" for r in rows),
        low=sum(r["risk_level"] == "Low" for r in rows),
        rows=rows[-20:][::-1])

@app.route("/download/csv")
def download_csv():
    if not latest_results:
        flash("Scan at least one message before downloading a report.", "error")
        return redirect(url_for("dashboard"))
    output = StringIO()
    fields = ["verdict", "risk_score", "risk_level", "language", "sender", "urls", "reasons", "message"]
    writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    for item in latest_results:
        row = dict(item)
        row["urls"] = "; ".join(item.get("urls", []))
        row["reasons"] = "; ".join(item.get("reasons", []))
        writer.writerow(row)
    data = BytesIO(output.getvalue().encode("utf-8-sig"))
    return send_file(data, mimetype="text/csv", as_attachment=True,
                     download_name="mailguard_security_report.csv")

@app.route("/download/pdf")
def download_pdf():
    if not latest_results:
        flash("Scan at least one message before downloading a report.", "error")
        return redirect(url_for("dashboard"))
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.lib.units import mm
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=15*mm, leftMargin=15*mm)
        styles = getSampleStyleSheet()
        story = [Paragraph("MailGuard - Email Security Report", styles["Title"]),
                 Paragraph("Generated: " + datetime.now().strftime("%Y-%m-%d %H:%M"), styles["Normal"]),
                 Spacer(1, 12)]
        data = [["Verdict", "Risk", "Level", "Language", "Sender"]]
        for r in latest_results[:100]:
            data.append([r["verdict"], str(r["risk_score"]), r["risk_level"],
                         r["language"], r["sender"] or "-"])
        table = Table(data, repeatRows=1)
        table.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#172554")),
            ("TEXTCOLOR", (0,0), (-1,0), colors.white),
            ("GRID", (0,0), (-1,-1), .4, colors.HexColor("#cbd5e1")),
            ("FONTSIZE", (0,0), (-1,-1), 8), ("PADDING", (0,0), (-1,-1), 6),
        ]))
        story += [table, Spacer(1, 12), Paragraph("Explainability / reasons", styles["Heading2"])]
        for i, r in enumerate(latest_results[:30], 1):
            reasons = "; ".join(r["reasons"]) or "No strong risk indicators found."
            story.append(Paragraph(f"{i}. {r['verdict']} ({r['risk_score']}/100): {reasons}", styles["BodyText"]))
            story.append(Spacer(1, 5))
        doc.build(story)
        buffer.seek(0)
        return send_file(buffer, mimetype="application/pdf", as_attachment=True,
                         download_name="mailguard_security_report.pdf")
    except ImportError:
        flash("Install reportlab with: pip install reportlab", "error")
        return redirect(url_for("dashboard"))

@app.route("/health")
def health():
    return {"status": "ok", "application": "MailGuard"}

if __name__ == "__main__":
    app.run(debug=True, port=5000)
