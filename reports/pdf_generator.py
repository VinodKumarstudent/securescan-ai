import io
from datetime import datetime, timezone
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, KeepTogether
from database.db import get_db_connection

def generate_pdf_report(scan_id):
    """
    Builds a professional executive PDF penetration testing report with ReportLab.
    Includes target authorization details, summary metrics, and categorized findings.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    # Fetch scan details
    cursor.execute("""
        SELECT s.*, t.domain, t.target_type, t.in_scope_paths, t.out_of_scope_paths, t.verification_method, t.verified_at
        FROM scans s
        JOIN targets t ON s.target_id = t.id
        WHERE s.id = ?
    """, (scan_id,))
    scan = cursor.fetchone()

    if not scan:
        conn.close()
        return None

    # Fetch authorization details if available
    cursor.execute("SELECT * FROM authorizations WHERE target_id = ? ORDER BY id DESC LIMIT 1", (scan["target_id"],))
    auth = cursor.fetchone()

    # Fetch findings
    cursor.execute("SELECT * FROM findings WHERE scan_id = ? ORDER BY cvss_score DESC", (scan_id,))
    findings = cursor.fetchall()

    conn.close()

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )

    styles = getSampleStyleSheet()
    
    # Custom palette
    primary_color = colors.HexColor("#0f172a")
    accent_color = colors.HexColor("#0284c7")
    text_dark = colors.HexColor("#1e293b")
    text_muted = colors.HexColor("#64748b")
    border_color = colors.HexColor("#cbd5e1")

    # Typography styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=24,
        leading=28,
        textColor=primary_color,
        spaceAfter=6
    )

    subtitle_style = ParagraphStyle(
        'DocSubTitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=11,
        leading=15,
        textColor=text_muted,
        spaceAfter=15
    )

    h2_style = ParagraphStyle(
        'Heading2Custom',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=15,
        leading=18,
        textColor=primary_color,
        spaceBefore=14,
        spaceAfter=8
    )

    h3_style = ParagraphStyle(
        'Heading3Custom',
        parent=styles['Heading3'],
        fontName='Helvetica-Bold',
        fontSize=12,
        leading=15,
        textColor=accent_color,
        spaceBefore=10,
        spaceAfter=4
    )

    body_style = ParagraphStyle(
        'BodyCustom',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9.5,
        leading=13.5,
        textColor=text_dark
    )

    body_bold = ParagraphStyle(
        'BodyBold',
        parent=body_style,
        fontName='Helvetica-Bold'
    )

    story = []

    # 1. Header Banner
    story.append(Paragraph("SecureScan AI — Security Audit Report", title_style))
    story.append(Paragraph(f"Authorized Vulnerability Assessment Report | Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=1.5, color=accent_color, spaceBefore=4, spaceAfter=15))

    # 2. Executive Summary & Assessment Overview
    story.append(Paragraph("1. Executive Summary", h2_style))
    exec_summary_text = (
        f"This automated security evaluation was conducted for authorized target <b>{scan['domain']}</b> "
        f"under formal authorization. The scan scanned <b>{scan['pages_crawled']}</b> in-scope pages/endpoints in "
        f"<b>{scan['duration_seconds']}s</b> with an overall evaluated risk score of <b>{scan['risk_score']} / 10.0</b>. "
        f"A total of <b>{len(findings)}</b> potential findings were identified across analyzed modules."
    )
    story.append(Paragraph(exec_summary_text, body_style))
    story.append(Spacer(1, 12))

    # Summary Metrics Table
    crit_count = sum(1 for f in findings if f["severity"] == "Critical")
    high_count = sum(1 for f in findings if f["severity"] == "High")
    med_count = sum(1 for f in findings if f["severity"] == "Medium")
    low_count = sum(1 for f in findings if f["severity"] == "Low")
    info_count = sum(1 for f in findings if f["severity"] == "Info")

    summary_data = [
        [Paragraph("Target URL", body_bold), Paragraph(scan['target_url'], body_style),
         Paragraph("Overall Risk Score", body_bold), Paragraph(f"<b>{scan['risk_score']} / 10.0</b>", body_style)],
        [Paragraph("Scan ID / Type", body_bold), Paragraph(f"#{scan['id']} ({scan['scan_type'].title()} / {scan['intensity']})", body_style),
         Paragraph("Critical / High", body_bold), Paragraph(f"<font color='#dc2626'><b>{crit_count}</b></font> Critical, <font color='#ea580c'><b>{high_count}</b></font> High", body_style)],
        [Paragraph("Duration", body_bold), Paragraph(f"{scan['duration_seconds']} seconds", body_style),
         Paragraph("Medium / Low / Info", body_bold), Paragraph(f"{med_count} Med, {low_count} Low, {info_count} Info", body_style)],
    ]
    summary_table = Table(summary_data, colWidths=[100, 165, 110, 155])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#f8fafc")),
        ('GRID', (0,0), (-1,-1), 0.5, border_color),
        ('PADDING', (0,0), (-1,-1), 6),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 15))

    # 3. Authorization & Scope Details Section (Mandatory compliance section)
    story.append(Paragraph("2. Authorization & Verification Compliance", h2_style))
    auth_org = auth["authorizer_org"] if auth else "Educational Lab / Self-Verified"
    auth_name = f"{auth['authorizer_name']} ({auth['authorizer_designation']})" if auth else "Authorized Operator"
    auth_email = auth["authorizer_email"] if auth else "N/A"
    testing_window = f"{auth['testing_window_start']} to {auth['testing_window_end']}" if auth else "Permanent (Pre-Approved Lab)"

    auth_data = [
        [Paragraph("Target Domain", body_bold), Paragraph(scan['domain'], body_style)],
        [Paragraph("Target Type", body_bold), Paragraph(scan['target_type'].upper(), body_style)],
        [Paragraph("Verification Method", body_bold), Paragraph(scan['verification_method'] or "Pre-approved", body_style)],
        [Paragraph("Authorized Contact / Org", body_bold), Paragraph(f"{auth_name} — {auth_org} ({auth_email})", body_style)],
        [Paragraph("Testing Window", body_bold), Paragraph(testing_window, body_style)],
        [Paragraph("Authorized In-Scope Paths", body_bold), Paragraph(scan['in_scope_paths'] or "/*", body_style)],
        [Paragraph("Excluded Out-of-Scope Paths", body_bold), Paragraph(scan['out_of_scope_paths'] or "None", body_style)],
    ]
    auth_table = Table(auth_data, colWidths=[160, 370])
    auth_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (0,-1), colors.HexColor("#f1f5f9")),
        ('GRID', (0,0), (-1,-1), 0.5, border_color),
        ('PADDING', (0,0), (-1,-1), 5),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
    ]))
    story.append(auth_table)
    story.append(Spacer(1, 15))

    # 4. Detailed Findings Section
    story.append(Paragraph("3. Detailed Vulnerability Findings", h2_style))

    if not findings:
        story.append(Paragraph("No vulnerabilities or security defects were identified within the configured scope.", body_style))
    else:
        for idx, f in enumerate(findings, 1):
            sev = f["severity"]
            sev_color = "#dc2626" if sev == "Critical" else "#ea580c" if sev == "High" else "#ca8a04" if sev == "Medium" else "#2563eb" if sev == "Low" else "#64748b"

            finding_header = [
                [
                    Paragraph(f"<b>#{idx}. {f['title']}</b>", h3_style),
                    Paragraph(f"<font color='{sev_color}'><b>{sev.upper()} (CVSS {f['cvss_score']})</b></font>", body_bold)
                ]
            ]
            f_table_hdr = Table(finding_header, colWidths=[400, 130])
            f_table_hdr.setStyle(TableStyle([
                ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
                ('ALIGN', (1,0), (1,0), 'RIGHT'),
                ('BOTTOMPADDING', (0,0), (-1,-1), 2),
            ]))

            f_body_data = [
                [Paragraph("Affected URL", body_bold), Paragraph(f['affected_url'], body_style)],
                [Paragraph("Parameter / Component", body_bold), Paragraph(f['parameter'] or "N/A", body_style)],
                [Paragraph("OWASP Category", body_bold), Paragraph(f['owasp_category'] or "N/A", body_style)],
                [Paragraph("Observed Evidence", body_bold), Paragraph(f['evidence'] or "N/A", body_style)],
                [Paragraph("Remediation", body_bold), Paragraph(f['remediation'] or "N/A", body_style)],
            ]
            f_table = Table(f_body_data, colWidths=[130, 400])
            f_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (0,-1), colors.HexColor("#f8fafc")),
                ('GRID', (0,0), (-1,-1), 0.5, border_color),
                ('PADDING', (0,0), (-1,-1), 5),
                ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ]))

            finding_block = [
                f_table_hdr,
                Spacer(1, 2),
                f_table,
                Spacer(1, 10)
            ]
            story.append(KeepTogether(finding_block))

    # 5. Legal & Ethical Disclaimer
    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", thickness=1, color=border_color, spaceBefore=4, spaceAfter=8))
    disclaimer_text = (
        "<b>LEGAL & COMPLIANCE NOTICE:</b> This report was compiled by SecureScan AI under authorized testing conditions. "
        "The information contained herein is privileged and confidential. The security mechanisms tested were strictly non-destructive. "
        "Distribution or testing without authorized consent violates computer crime laws."
    )
    story.append(Paragraph(disclaimer_text, ParagraphStyle('Disclaimer', parent=body_style, fontSize=8, leading=11, textColor=text_muted)))

    doc.build(story)
    buffer.seek(0)
    return buffer.getvalue()
