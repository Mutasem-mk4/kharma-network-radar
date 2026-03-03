import io
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image
from reportlab.lib.units import inch

class ReportGenerator:
    def __init__(self, forensics_db):
        self.db = forensics_db

    def generate_html_report(self):
        """Generates a standalone, premium-styled HTML security report."""
        events = self.db.get_events(limit=1000)
        stats = self.db.get_stats()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Kharma Sentinel - Incident Report</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&display=swap');
        body {{
            font-family: 'JetBrains Mono', monospace;
            background: #f8fafc;
            color: #1e293b;
            padding: 40px;
            line-height: 1.6;
        }}
        .header {{
            border-bottom: 2px solid #10b981;
            padding-bottom: 20px;
            margin-bottom: 40px;
            display: flex;
            justify-content: space-between;
            align-items: flex-end;
        }}
        .brand {{
            font-size: 24px;
            font-weight: bold;
            letter-spacing: 2px;
        }}
        .brand span {{ color: #10b981; }}
        .meta {{ font-size: 12px; color: #64748b; }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 20px;
            margin-bottom: 40px;
        }}
        .stat-card {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            border-top: 4px solid #10b981;
        }}
        .stat-label {{ font-size: 10px; text-transform: uppercase; color: #64748b; }}
        .stat-value {{ font-size: 20px; font-weight: bold; margin-top: 5px; }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            background: white;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }}
        th {{
            background: #1e293b;
            color: white;
            text-align: left;
            padding: 12px 15px;
            font-size: 12px;
            text-transform: uppercase;
        }}
        td {{
            padding: 12px 15px;
            border-bottom: 1px solid #e2e8f0;
            font-size: 11px;
        }}
        .severity-critical {{ color: #ef4444; font-weight: bold; }}
        .severity-high {{ color: #f59e0b; font-weight: bold; }}
        .severity-medium {{ color: #3b82f6; }}
    </style>
</head>
<body>
    <div class="header">
        <div class="brand">KHARMA<span>_SENTINEL</span></div>
        <div class="meta">REPORT GENERATED: {timestamp}</div>
    </div>

    <h1>Security Incident Summary</h1>
    
    <div class="stats-grid">
        <div class="stat-card">
            <div class="stat-label">Total Events</div>
            <div class="stat-value">{stats.get('total', 0)}</div>
        </div>
        <div class="stat-card" style="border-top-color: #ef4444;">
            <div class="stat-label">Critical Threats</div>
            <div class="stat-value" style="color: #ef4444;">{stats.get('critical', 0)}</div>
        </div>
        <div class="stat-card" style="border-top-color: #6366f1;">
            <div class="stat-label">Blocked IPs</div>
            <div class="stat-value" style="color: #6366f1;">{stats.get('blocked', 0)}</div>
        </div>
        <div class="stat-card" style="border-top-color: #f59e0b;">
            <div class="stat-label">Community Flags</div>
            <div class="stat-value" style="color: #f59e0b;">{stats.get('community', 0)}</div>
        </div>
    </div>

    <table>
        <thead>
            <tr>
                <th>Timestamp</th>
                <th>Type</th>
                <th>IP Address</th>
                <th>Process</th>
                <th>Location</th>
                <th>Severity</th>
                <th>Details</th>
            </tr>
        </thead>
        <tbody>
"""
        for ev in events:
            sev_class = f"severity-{ev['severity']}" if ev['severity'] in ['critical', 'high', 'medium'] else ""
            html += f"""
            <tr>
                <td>{ev['timestamp']}</td>
                <td>{ev['event_type']}</td>
                <td>{ev['ip']}</td>
                <td>{ev['process']}</td>
                <td>{ev['location']}</td>
                <td class="{sev_class}">{ev['severity'].upper()}</td>
                <td>{ev['detail']}</td>
            </tr>"""

        html += """
        </tbody>
    </table>
</body>
</html>
"""
        return html

    def export_report_file(self, output_path):
        """Saves the report to a file."""
        report_content = self.generate_html_report()
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(report_content)
        return output_path
