
from flask import Flask, render_template_string, request
from collections import Counter
from datetime import datetime
import csv
import io
import re

app = Flask(__name__)

HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Agentic Autonomous SOC Platform</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body {
            font-family: Arial, sans-serif;
            background: #101827;
            color: white;
            margin: 0;
            padding: 20px;
        }
        h1 { color: #38bdf8; }
        .card {
            background: #1e293b;
            padding: 18px;
            margin: 12px 0;
            border-radius: 12px;
        }
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit,minmax(140px,1fr));
            gap: 12px;
        }
        .number { font-size: 28px; color: #38bdf8; }
        input, button {
            padding: 12px;
            margin-top: 10px;
            border-radius: 6px;
        }
        button {
            background: #0284c7;
            color: white;
            border: none;
        }
        table { width: 100%; border-collapse: collapse; }
        th, td {
            text-align: left;
            padding: 10px;
            border-bottom: 1px solid #475569;
        }
        .alert { color: #f87171; }
        .safe { color: #4ade80; }
    </style>
</head>
<body>
    <h1>Agentic Autonomous SOC</h1>
    <p>Threat Intelligence & Incident Response Platform</p>

    <div class="stats">
        <div class="card">Total Logs
            <div class="number">{{ total }}</div>
        </div>
        <div class="card">Failed Logins
            <div class="number">{{ failed }}</div>
        </div>
        <div class="card">Successful Logins
            <div class="number">{{ successful }}</div>
        </div>
        <div class="card">Suspicious IPs
            <div class="number">{{ suspicious }}</div>
        </div>
    </div>

    <div class="card">
        <h2>Upload Security Logs</h2>
        <p>Upload a CSV containing IP addresses and login statuses.</p>
        <form method="POST" enctype="multipart/form-data">
            <input type="file" name="logfile" accept=".csv" required>
            <button type="submit">Analyze Logs</button>
        </form>
        <p>{{ message }}</p>
    </div>

    <div class="card">
        <h2>Security Alerts</h2>
        {% if alerts %}
        <table>
            <tr><th>IP Address</th><th>Failed Attempts</th><th>Severity</th></tr>
            {% for alert in alerts %}
            <tr>
                <td>{{ alert.ip }}</td>
                <td>{{ alert.count }}</td>
                <td class="alert">{{ alert.severity }}</td>
            </tr>
            {% endfor %}
        </table>
        {% else %}
        <p class="safe">No suspicious login activity detected.</p>
        {% endif %}
    </div>

    <div class="card">
        <h2>Platform Modules</h2>
        <p>Security Log Analysis</p>
        <p>Rule-Based Threat Detection</p>
        <p>Incident Alert Generation</p>
        <p>Threat Intelligence: future extension</p>
        <p>AI Agent Response: future extension</p>
    </div>
</body>
</html>
"""

def analyze_logs(file_content):
    rows = csv.DictReader(io.StringIO(file_content))
    failed_ips = Counter()
    total = failed = successful = 0

    for row in rows:
        total += 1
        status = str(row.get("status", "")).strip().upper()
        ip = str(row.get("ip", "")).strip()

        if status == "FAILED":
            failed += 1
            if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", ip):
                parts = [int(x) for x in ip.split(".")]
                if all(0 <= x <= 255 for x in parts):
                    failed_ips[ip] += 1
        elif status == "SUCCESS":
            successful += 1

    alerts = []
    for ip, count in failed_ips.items():
        if count >= 3:
            alerts.append({
                "ip": ip,
                "count": count,
                "severity": "HIGH" if count >= 5 else "MEDIUM"
            })

    return total, failed, successful, alerts

@app.route("/", methods=["GET", "POST"])
def dashboard():
    total = failed = successful = 0
    alerts = []
    message = "Upload a CSV file to begin analysis."

    if request.method == "POST":
        uploaded = request.files.get("logfile")

        if not uploaded or not uploaded.filename.lower().endswith(".csv"):
            message = "Please upload a valid CSV file."
        else:
            try:
                content = uploaded.read().decode("utf-8-sig")
                total, failed, successful, alerts = analyze_logs(content)
                message = "Analysis completed at " + datetime.now().strftime("%H:%M:%S")
            except (UnicodeDecodeError, csv.Error):
                message = "Could not read the file. Please check your CSV format."

    return render_template_string(
        HTML,
        total=total,
        failed=failed,
        successful=successful,
        suspicious=len(alerts),
        alerts=alerts,
        message=message
    )

if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000)
