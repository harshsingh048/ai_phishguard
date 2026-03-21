"""
PhishGuard AI - Report Generation Service
Generates JSON and PDF reports for scan results.
"""
import os
import json
import logging
from datetime import datetime

from config import Config

logger = logging.getLogger(__name__)

# Try importing PDF library
try:
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.colors import HexColor, black, white
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.units import inch
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False
    logger.warning("reportlab not installed. PDF reports disabled.")


def generate_json_report(scan_result: dict) -> dict:
    """Generate structured JSON report from scan result."""
    os.makedirs(Config.REPORTS_DIR, exist_ok=True)

    report = {
        "report_type": "PhishGuard AI Scan Report",
        "generated_at": datetime.utcnow().isoformat(),
        "version": "1.0",
        "scan_summary": {
            "input": scan_result.get('input', ''),
            "input_type": scan_result.get('input_type', ''),
            "risk_score": scan_result.get('risk_score', 0),
            "classification": scan_result.get('classification', {}).get('label', 'Unknown'),
            "scan_mode": scan_result.get('mode', 'fast'),
            "response_time_ms": scan_result.get('response_time_ms', 0)
        },
        "threat_analysis": {
            "triggered_rules": scan_result.get('triggered_rules', []),
            "explanation": scan_result.get('explanation', ''),
            "ml_scores": scan_result.get('ml_scores', {})
        },
        "recommendations": scan_result.get('suggestions', []),
        "domain_intelligence": scan_result.get('domain_info', {}),
        "raw_result": scan_result
    }

    # Save to file
    timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    filename = f"report_{timestamp}.json"
    filepath = os.path.join(Config.REPORTS_DIR, filename)

    try:
        with open(filepath, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        return {"success": True, "filename": filename, "path": filepath, "report": report}
    except Exception as e:
        logger.error(f"JSON report save failed: {e}")
        return {"success": False, "error": str(e), "report": report}


def generate_pdf_report(scan_result: dict) -> dict:
    """Generate PDF report from scan result."""
    if not PDF_AVAILABLE:
        return {"success": False, "error": "PDF library (reportlab) not installed"}

    os.makedirs(Config.REPORTS_DIR, exist_ok=True)

    timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    filename = f"report_{timestamp}.pdf"
    filepath = os.path.join(Config.REPORTS_DIR, filename)

    try:
        doc = SimpleDocTemplate(filepath, pagesize=letter,
                                leftMargin=0.75*inch, rightMargin=0.75*inch,
                                topMargin=0.75*inch, bottomMargin=0.75*inch)

        styles = getSampleStyleSheet()
        story = []

        # Color scheme
        DARK_BG = HexColor('#0d1117')
        GREEN = HexColor('#00ff88')
        RED = HexColor('#ff4444')
        YELLOW = HexColor('#ffd700')
        BLUE = HexColor('#4da6ff')

        # Title
        title_style = ParagraphStyle('Title', parent=styles['Heading1'],
                                     fontSize=24, textColor=BLUE, spaceAfter=12)
        story.append(Paragraph("🛡️ PhishGuard AI - Scan Report", title_style))
        story.append(Paragraph(f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}", styles['Normal']))
        story.append(Spacer(1, 0.2*inch))

        # Risk score
        score = scan_result.get('risk_score', 0)
        classification = scan_result.get('classification', {}).get('label', 'Unknown')
        score_color = GREEN if score < 30 else (YELLOW if score < 60 else RED)
        score_style = ParagraphStyle('Score', parent=styles['Heading2'],
                                     fontSize=18, textColor=score_color)
        story.append(Paragraph(f"Risk Score: {score}/100 — {classification}", score_style))
        story.append(Spacer(1, 0.1*inch))

        # Input info
        heading_style = ParagraphStyle('Heading', parent=styles['Heading2'],
                                       fontSize=14, textColor=BLUE)
        story.append(Paragraph("Scanned Input", heading_style))
        story.append(Paragraph(f"Type: {scan_result.get('input_type', 'unknown').upper()}", styles['Normal']))
        story.append(Paragraph(f"Value: {scan_result.get('input', '')[:200]}", styles['Normal']))
        story.append(Spacer(1, 0.15*inch))

        # Explanation
        story.append(Paragraph("Analysis", heading_style))
        story.append(Paragraph(scan_result.get('explanation', 'No explanation available.'), styles['Normal']))
        story.append(Spacer(1, 0.15*inch))

        # Triggered rules
        rules = scan_result.get('triggered_rules', [])
        if rules:
            story.append(Paragraph("Detected Threats", heading_style))
            for rule in rules[:10]:
                story.append(Paragraph(f"• {rule}", styles['Normal']))
            story.append(Spacer(1, 0.15*inch))

        # Suggestions
        suggestions = scan_result.get('suggestions', [])
        if suggestions:
            story.append(Paragraph("Safety Recommendations", heading_style))
            for sug in suggestions:
                story.append(Paragraph(f"{sug.get('icon', '•')} {sug.get('action', '')}", styles['Normal']))

        doc.build(story)
        return {"success": True, "filename": filename, "path": filepath}

    except Exception as e:
        logger.error(f"PDF report generation failed: {e}")
        return {"success": False, "error": str(e)}
