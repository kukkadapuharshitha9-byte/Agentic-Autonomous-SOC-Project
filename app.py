from flask import Flask, render_template_string, request
from collections import Counter, defaultdict
from datetime import datetime, timedelta
import csv
import io
import os
import re

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024  # reject uploads over 2 MB

# Simulated incident response: blocked IPs are written to this file.
BLOCKLIST_FILE = os.environ.get(
    "BLOCKLIST_FILE",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "blocklist.txt"),
)

# Time-window detection: this many failures inside this window = rapid attack.
BURST_ATTEMPTS = 3
BURST_WINDOW = timedelta(minutes=5)

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
        .medium { color: #fbbf24; }
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
        <p>Upload a CSV with <b>ip</b> and <b>status</b> columns.
           An optional <b>timestamp</b> column (e.g. 2026-10-12 10:00:01)
           enables rapid-attack detection.</p>
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
            <tr>
                <th>IP Address</th><th>Failed Attempts</th><th>Severity</th>
                <th>Reason</th><th>Response</th>
            </tr>
            {% for alert in alerts %}
            <tr>
                <td>{{ alert.ip }}</td>
                <td>{{ alert.count }}</td>
                <td class="{{ 'alert' if alert.severity == 'HIGH' else 'medium' }}">{{ alert.severity }}</td>
                <td>{{ alert.reason }}</td>
                <td>{{ alert.action }}</td>
            </tr>
            {% endfor %}
        </table>
        {% else %}
        <p class="safe">No suspicious login activity detected.</p>
        {% endif %}
    </div>

    <div class="card">
        <h2>Blocklist (simulated response)</h2>
        {% if blocklist %}
        {% for blocked_ip in blocklist %}
        <p class="alert">{{ blocked_ip }}</p>
        {% endfor %}
        {% else %}
        <p class="safe">No IPs blocked yet.</p>
        {% endif %}
    </div>

    <div class="card">
        <h2>Platform Modules</h2>
        <p>Security Log Analysis</p>
        <p>Rule-Based Threat Detection</p>
        <p>Time-Window (Rapid Attack) Detection</p>
        <p>Incident Alert Generation</p>
        <p>Automated Response: simulated IP blocklist</p>
        <p>Threat Intelligence: future extension</p>
        <p>AI Agent Response: future extension</p>
    </div>
</body>
</html>
"""


def parse_time(value):
    """Return a naive datetime, or None if the value is missing/unreadable."""
    try:
        return datetime.fromisoformat(str(value or "").strip()).replace(tzinfo=None)
    except ValueError:
        return None


def has_burst(times):
    """True if BURST_ATTEMPTS failures happen within BURST_WINDOW."""
    times = sorted(times)
    return any(
        times[i + BURST_ATTEMPTS - 1] - times[i] <= BURST_WINDOW
        for i in range(len(times) - BURST_ATTEMPTS + 1)
    )


def analyze_logs(file_content):
    # strip() tolerates blank lines or spaces at the start/end of the file
    rows = csv.DictReader(io.StringIO(file_content.strip()))
    columns = {(name or "").strip().lower() for name in (rows.fieldnames or [])}
    if not {"ip", "status"} <= columns:
        raise ValueError("CSV must have 'ip' and 'status' columns in the header row.")

    failed_ips = Counter()
    fail_times = defaultdict(list)
    total = failed = successful = 0

    for row in rows:
        total += 1
        # normalise header names so " IP" / "Status" also work
        row = {(k or "").strip().lower(): v for k, v in row.items()}
        status = str(row.get("status") or "").strip().upper()
        ip = str(row.get("ip") or "").strip()

        if status == "FAILED":
            failed += 1
            if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", ip):
                parts = [int(x) for x in ip.split(".")]
                if all(0 <= x <= 255 for x in parts):
                    failed_ips[ip] += 1
                    when = parse_time(row.get("timestamp"))
                    if when:
                        fail_times[ip].append(when)
        elif status == "SUCCESS":
            successful += 1

    alerts = []
    minutes = int(BURST_WINDOW.total_seconds() // 60)
    for ip, count in failed_ips.items():
        if count < 3:
            continue
        burst = has_burst(fail_times[ip])
        high = count >= 5 or burst
        alerts.append({
            "ip": ip,
            "count": count,
            "severity": "HIGH" if high else "MEDIUM",
            "reason": (f"{BURST_ATTEMPTS}+ failures within {minutes} minutes"
                       if burst else f"{count} failed attempts"),
            "action": "Block IP and investigate" if high else "Monitor closely",
        })

    alerts.sort(key=lambda a: a["count"], reverse=True)
    return total, failed, successful, alerts


def read_blocklist():
    try:
        with open(BLOCKLIST_FILE, encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip()]
    except OSError:
        return []


def block_ips(ips):
    """Simulated response: append new IPs to the blocklist file (no duplicates)."""
    existing = set(read_blocklist())
    new = [ip for ip in ips if ip not in existing]
    if new:
        with open(BLOCKLIST_FILE, "a", encoding="utf-8") as f:
            for ip in new:
                f.write(ip + "\n")
    return new


def render_page(total=0, failed=0, successful=0, alerts=(), message=""):
    return render_template_string(
        HTML,
        total=total,
        failed=failed,
        successful=successful,
        suspicious=len(alerts),
        alerts=alerts,
        blocklist=read_blocklist(),
        message=message,
    )


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

                # Automated response (simulation): block every HIGH-severity IP
                high_ips = [a["ip"] for a in alerts if a["severity"] == "HIGH"]
                try:
                    block_ips(high_ips)
                    for a in alerts:
                        if a["severity"] == "HIGH":
                            a["action"] = "Blocked (simulated)"
                except OSError:
                    message += " (Could not update blocklist.txt)"
            except (UnicodeDecodeError, csv.Error):
                message = "Could not read the file. Please check your CSV format."
            except ValueError as exc:
                message = str(exc)

    return render_page(total, failed, successful, alerts, message)


@app.errorhandler(413)
def file_too_large(_error):
    return render_page(message="File too large. The maximum upload size is 2 MB."), 413


if __name__ == "__main__":
    # 127.0.0.1 = only this computer can open the dashboard
    app.run(debug=False, host="127.0.0.1", port=5000)
