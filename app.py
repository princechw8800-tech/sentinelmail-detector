from flask import Flask, Response, jsonify, render_template, request
from detector import analyze_email
from io import BytesIO
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

app = Flask(__name__)


@app.route("/")
def home():
    return render_template("index.html")


@app.post("/analyze")
def analyze():
    uploaded_file = request.files.get("email_file")
    if uploaded_file is None or not uploaded_file.filename:
        return jsonify({"error": "Please select an .eml email file."}), 400

    if not uploaded_file.filename.lower().endswith(".eml"):
        return jsonify({"error": "Only .eml files can be analyzed."}), 400

    try:
        result = analyze_email(uploaded_file.read())
    except ValueError as error:
        return jsonify({"error": str(error)}), 400
    except Exception:
        app.logger.exception("Email analysis failed")
        return jsonify({"error": "The email file could not be analyzed."}), 500

    return jsonify(result)


@app.post("/report")
def report():
    data = request.get_json(silent=True) or {}
    if not data.get("classification"):
        return jsonify({"error": "Run an email scan before downloading a report."}), 400

    output = BytesIO()
    document = SimpleDocTemplate(output, pagesize=A4, leftMargin=42, rightMargin=42, topMargin=42)
    styles = getSampleStyleSheet()
    story = [Paragraph("SentinelMail Email Spoofing Report", styles["Title"]), Spacer(1, 14)]
    story.append(Paragraph(f"Verdict: <b>{data.get('classification')}</b> | Threat score: <b>{data.get('risk_score', 0)}%</b>", styles["Heading2"]))
    rows = [["Field", "Value"], ["Sender", data.get("sender", "-")], ["Domain", data.get("domain", "-")], ["Subject", data.get("subject", "-")]]
    table = Table(rows, colWidths=[115, 390])
    table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#073b35")), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white), ("GRID", (0, 0), (-1, -1), .3, colors.HexColor("#aaaaaa")), ("VALIGN", (0, 0), (-1, -1), "TOP"), ("PADDING", (0, 0), (-1, -1), 7)]))
    story += [table, Spacer(1, 16), Paragraph("Detection Signals", styles["Heading2"])]
    for reason in data.get("reasons", []):
        story.append(Paragraph(f"- {reason}", styles["BodyText"]))
    story += [Spacer(1, 14), Paragraph("Authentication", styles["Heading2"])]
    story.append(Paragraph(data.get("authentication", "No authentication information available.").replace("&", "&amp;"), styles["BodyText"]))
    document.build(story)
    return Response(output.getvalue(), mimetype="application/pdf", headers={"Content-Disposition": "attachment; filename=sentinelmail-threat-report.pdf"})


if __name__ == "__main__":
    app.run(debug=True)

