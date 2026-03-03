import io
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.units import inch

class PDFEngine:
    """
    Kharma Elite PDF Engine.
    Handles professional-grade PDF security reports independently of HTML views.
    Includes robust data handling for missing or malformed forensic data.
    """
    def __init__(self, forensics_db):
        self.db = forensics_db

    def generate(self):
        """Generates a professional PDF security report with robust data protection."""
        try:
            events = self.db.get_events(limit=1000)
            stats = self.db.get_stats()
        except Exception as e:
            print(f"[PDF_ENGINE] Database error: {e}")
            events = []
            stats = {}

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        buffer = io.BytesIO()
        
        # Create Document Template
        doc = SimpleDocTemplate(
            buffer, 
            pagesize=A4, 
            rightMargin=30, 
            leftMargin=30, 
            topMargin=30, 
            bottomMargin=30,
            title="Kharma Sentinel - Security Report"
        )
        elements = []

        # Define Styles
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            'TitleStyle',
            parent=styles['Heading1'],
            fontSize=22,
            textColor=colors.HexColor("#10b981"),
            spaceAfter=15,
            fontName='Helvetica-Bold'
        )
        subtitle_style = ParagraphStyle(
            'SubtitleStyle',
            parent=styles['Normal'],
            fontSize=9,
            textColor=colors.grey,
            spaceAfter=40,
            fontName='Helvetica'
        )
        header_style = ParagraphStyle(
            'HeaderStyle',
            parent=styles['Heading2'],
            fontSize=14,
            textColor=colors.HexColor("#1e293b"),
            spaceBefore=15,
            spaceAfter=15
        )

        # 1. Header Section
        elements.append(Paragraph("KHARMA SENTINEL ELITE REPORT", title_style))
        elements.append(Paragraph(f"CONFIDENTIAL SECURITY AUDIT | GENERATED: {timestamp}", subtitle_style))
        elements.append(Spacer(1, 0.1 * inch))

        # 2. Executive Summary (Stats)
        elements.append(Paragraph("EXECUTIVE SUMMARY", header_style))
        
        # Calculate totals safely
        total_val = stats.get('total', sum(v for v in stats.values() if isinstance(v, (int, float))) if stats else 0)
        
        stats_data = [
            ["METRIC", "VALUE"],
            ["Total Security Events", str(total_val)],
            ["Critical Threats Detected", str(stats.get('critical', 0))],
            ["Active Blocks Applied", str(stats.get('blocked', 0))],
            ["Community Intelligence Flags", str(stats.get('community', 0))]
        ]
        
        stats_table = Table(stats_data, colWidths=[2.5 * inch, 1.5 * inch])
        stats_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#1e293b")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('TOPPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.whitesmoke),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1"))
        ]))
        elements.append(stats_table)
        elements.append(Spacer(1, 0.5 * inch))

        # 3. Incident Details Table
        elements.append(Paragraph("DEEP INVESTIGATION LOG", header_style))
        
        # Table Header
        table_data = [["TIMESTAMP", "TYPE", "ENDPOINT", "PROCESS", "SEVERITY"]]
        
        # Process Events safely
        for ev in events:
            # Defensive check for timestamp
            ts = str(ev.get('timestamp', 'N/A'))
            if len(ts) > 10:
                ts = ts[5:] # Trim date for space
            
            # Defensive check for process name
            proc = str(ev.get('process', 'Unknown'))
            if len(proc) > 18:
                proc = proc[:15] + "..."
                
            # Defensive check for IP
            ip = str(ev.get('ip', 'Local'))
            
            # Defensive check for severity
            sev = str(ev.get('severity', 'MEDIUM')).upper()

            table_data.append([
                ts,
                ev.get('event_type', 'GENERAL'),
                ip,
                proc,
                sev
            ])

        # Define column widths
        w = [1.1*inch, 1*inch, 1.4*inch, 1.7*inch, 1*inch]
        t = Table(table_data, colWidths=w, repeatRows=1)
        
        # Main Table Style
        t_style = [
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#1e293b")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
            ('TOPPADDING', (0, 0), (-1, 0), 10),
            ('GRID', (0, 0), (-1, -1), 0.2, colors.HexColor("#e2e8f0")),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")])
        ]

        # Add severity coloring
        for i, row in enumerate(table_data[1:], start=1):
            severity = row[4]
            if severity == 'CRITICAL':
                t_style.append(('TEXTCOLOR', (4, i), (4, i), colors.red))
                t_style.append(('FONTNAME', (4, i), (4, i), 'Helvetica-Bold'))
            elif severity == 'HIGH':
                t_style.append(('TEXTCOLOR', (4, i), (4, i), colors.orange))
                t_style.append(('FONTNAME', (4, i), (4, i), 'Helvetica-Bold'))

        t.setStyle(TableStyle(t_style))
        elements.append(t)

        # Build PDF
        try:
            doc.build(elements)
            pdf = buffer.getvalue()
        except Exception as e:
            print(f"[PDF_ENGINE] Build failed: {e}")
            # Fallback simple document in case of layout error
            buffer = io.BytesIO()
            fallback_doc = SimpleDocTemplate(buffer, pagesize=A4)
            fallback_doc.build([Paragraph(f"Error generating detailed report: {e}", styles['Normal'])])
            pdf = buffer.getvalue()
            
        buffer.close()
        return pdf
