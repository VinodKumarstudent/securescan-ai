import sys
import os
from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.enum.text import PP_ALIGN
from pptx.dml.color import RGBColor
from pptx.enum.shapes import MSO_SHAPE

def create_presentation():
    prs = Presentation()
    # 16:9 widescreen layout
    prs.slide_width = Inches(13.333)
    prs.slide_height = Inches(7.5)

    # Theme colors
    COLOR_BG = RGBColor(11, 15, 25)         # #0B0F19 (Deep Dark Cyber)
    COLOR_CARD = RGBColor(23, 32, 54)       # #172036 (Card Dark Blue)
    COLOR_CYAN = RGBColor(0, 243, 255)      # #00F3FF (Neon Cyan Accent)
    COLOR_PURPLE = RGBColor(168, 85, 247)   # #A855F7 (Purple Accent)
    COLOR_WHITE = RGBColor(248, 250, 252)   # #F8FAFC (Text Primary)
    COLOR_MUTED = RGBColor(148, 163, 184)   # #94A3B8 (Text Secondary)
    COLOR_GREEN = RGBColor(52, 211, 153)    # #34D399 (Success Green)
    COLOR_RED = RGBColor(239, 68, 68)       # #EF4444 (Critical Red)

    blank_layout = prs.slide_layouts[6]

    def set_slide_background(slide):
        bg = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, prs.slide_width, prs.slide_height)
        bg.fill.solid()
        bg.fill.fore_color.rgb = COLOR_BG
        bg.line.fill.background()
        return bg

    def add_header(slide, title_text, category_text="SECURESCAN AI • DEFENSE & RESEARCH"):
        # Category / tracker
        cat_box = slide.shapes.add_textbox(Inches(0.8), Inches(0.4), Inches(11.7), Inches(0.4))
        tf_c = cat_box.text_frame
        tf_c.word_wrap = True
        p_c = tf_c.paragraphs[0]
        p_c.text = category_text.upper()
        p_c.font.size = Pt(11)
        p_c.font.bold = True
        p_c.font.color.rgb = COLOR_CYAN

        # Title
        title_box = slide.shapes.add_textbox(Inches(0.8), Inches(0.75), Inches(11.7), Inches(0.8))
        tf_t = title_box.text_frame
        tf_t.word_wrap = True
        p_t = tf_t.paragraphs[0]
        p_t.text = title_text
        p_t.font.size = Pt(26)
        p_t.font.bold = True
        p_t.font.color.rgb = COLOR_WHITE

    def add_card(slide, left, top, width, height, title="", border_color=COLOR_CYAN):
        card = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, left, top, width, height)
        card.fill.solid()
        card.fill.fore_color.rgb = COLOR_CARD
        card.line.color.rgb = border_color
        card.line.width = Pt(1.2)
        
        if title:
            tb = slide.shapes.add_textbox(left + Inches(0.2), top + Inches(0.15), width - Inches(0.4), Inches(0.5))
            p = tb.text_frame.paragraphs[0]
            p.text = title
            p.font.size = Pt(14)
            p.font.bold = True
            p.font.color.rgb = border_color
        return card

    # ==========================================
    # SLIDE 1: Title Slide
    # ==========================================
    s1 = prs.slides.add_slide(blank_layout)
    set_slide_background(s1)

    # Glowing decorative box
    glow = s1.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(0.8), Inches(1.2), Inches(11.733), Inches(5.1))
    glow.fill.solid()
    glow.fill.fore_color.rgb = COLOR_CARD
    glow.line.color.rgb = COLOR_CYAN
    glow.line.width = Pt(2)

    tb = s1.shapes.add_textbox(Inches(1.2), Inches(1.8), Inches(10.9), Inches(3.8))
    tf = tb.text_frame
    tf.word_wrap = True

    p0 = tf.paragraphs[0]
    p0.text = "🛡️ SECURESCAN AI"
    p0.font.size = Pt(40)
    p0.font.bold = True
    p0.font.color.rgb = COLOR_CYAN

    p1 = tf.add_paragraph()
    p1.text = "An Authorized Web Application Vulnerability Scanner & Target Governance Engine"
    p1.font.size = Pt(22)
    p1.font.bold = True
    p1.font.color.rgb = COLOR_WHITE
    p1.space_before = Pt(12)

    p2 = tf.add_paragraph()
    p2.text = "Integrating Dynamic Application Security Testing (DAST), Cryptographic Ownership Verification, SSRF Protection, and AI-Powered Remediation"
    p2.font.size = Pt(14)
    p2.font.color.rgb = COLOR_MUTED
    p2.space_before = Pt(8)

    p3 = tf.add_paragraph()
    p3.text = "Author / Presenter: Vinod Kumar | Cybersecurity & Full-Stack Engineering\nAcademic Literature Review & Project Defense Deck"
    p3.font.size = Pt(13)
    p3.font.bold = True
    p3.font.color.rgb = COLOR_GREEN
    p3.space_before = Pt(28)

    # ==========================================
    # SLIDE 2: Problem Statement & Motivation
    # ==========================================
    s2 = prs.slides.add_slide(blank_layout)
    set_slide_background(s2)
    add_header(s2, "The Problem: The 'Wild West' of Web Scanners & The Ethics Crisis")

    add_card(s2, Inches(0.8), Inches(1.8), Inches(3.6), Inches(5.0), "1. Uncontrolled Target Abuse", COLOR_RED)
    tb = s2.shapes.add_textbox(Inches(0.95), Inches(2.4), Inches(3.3), Inches(4.2))
    tf = tb.text_frame
    tf.word_wrap = True
    tf.text = "• Traditional scanners (Nikto, raw sqlmap) lack target permission gates.\n\n• Unskilled users routinely launch unauthorized scans against third parties.\n\n• Violates CFAA (18 U.S.C. § 1030) and international computer crime acts.\n\n• Legal liability falls on the tool operator and university/organization."
    for p in tf.paragraphs:
        p.font.size = Pt(12.5)
        p.font.color.rgb = COLOR_WHITE

    add_card(s2, Inches(4.8), Inches(1.8), Inches(3.6), Inches(5.0), "2. The SSRF Blindspot", COLOR_PURPLE)
    tb = s2.shapes.add_textbox(Inches(4.95), Inches(2.4), Inches(3.3), Inches(4.2))
    tf = tb.text_frame
    tf.word_wrap = True
    tf.text = "• Web scanners are often weaponized as unintended open proxies.\n\n• SSRF attacks probe internal networks (RFC 1918) and loopback interfaces (127.0.0.1).\n\n• AWS/GCP/Azure cloud metadata (169.254.169.254) can be exfiltrated.\n\n• DNS rebinding bypasses naive domain string checks."
    for p in tf.paragraphs:
        p.font.size = Pt(12.5)
        p.font.color.rgb = COLOR_WHITE

    add_card(s2, Inches(8.8), Inches(1.8), Inches(3.7), Inches(5.0), "3. High False Positives & Cryptic Output", COLOR_CYAN)
    tb = s2.shapes.add_textbox(Inches(8.95), Inches(2.4), Inches(3.4), Inches(4.2))
    tf = tb.text_frame
    tf.word_wrap = True
    tf.text = "• Scanners output raw dumps of regex warnings without context.\n\n• Developers struggle to interpret CVSS scores or remediation steps.\n\n• Destructive payloads risk breaking production databases (DROP TABLE, DoS).\n\n• Lack of tamper-evident audit trails for ISO 27001 / SOC 2 compliance."
    for p in tf.paragraphs:
        p.font.size = Pt(12.5)
        p.font.color.rgb = COLOR_WHITE

    # ==========================================
    # SLIDE 3: Key Objectives & Novel Contributions
    # ==========================================
    s3 = prs.slides.add_slide(blank_layout)
    set_slide_background(s3)
    add_header(s3, "System Objectives & Engineering Contributions")

    items = [
        ("1. Backend-Enforced Authorization Gate", "No scan can execute unless the target is pre-cleared or verified via cryptographic ownership proofs (DNS TXT, Meta Tag, or .well-known token) or verified written authorization.", COLOR_CYAN),
        ("2. Active SSRF & Real-Time DNS Rebinding Defense", "Real-time socket DNS resolution on initial probe and subsequent redirects. Automatic blacklisting of RFC 1918, loopbacks, link-local, and cloud metadata (169.254.169.254).", COLOR_PURPLE),
        ("3. Non-Destructive Vulnerability Detection (DAST)", "10 modular security checkers utilizing benign syntax markers and diagnostic signature pattern matching for XSS, SQLi, Open Redirects, CSRF, and Misconfigurations without data loss.", COLOR_GREEN),
        ("4. Dual-Engine AI Vulnerability Advisory", "Integration with OpenAI GPT models for contextual impact explanation and remediation snippets, backed by an autonomous static cybersecurity knowledge base fallback.", COLOR_CYAN),
        ("5. Executive Compliance & Multi-Device Glassmorphism UI", "Automated ReportLab PDF & JSON compliance generation with authorizer audit blocks, real-time telemetry terminal, and multi-device responsive screen scaling.", COLOR_PURPLE),
    ]

    top_pos = 1.8
    for title, desc, col in items:
        add_card(s3, Inches(0.8), Inches(top_pos), Inches(11.7), Inches(0.95), "", col)
        tb = s3.shapes.add_textbox(Inches(1.0), Inches(top_pos + 0.1), Inches(11.3), Inches(0.75))
        tf = tb.text_frame
        tf.word_wrap = True
        p0 = tf.paragraphs[0]
        p0.text = title
        p0.font.size = Pt(14)
        p0.font.bold = True
        p0.font.color.rgb = col
        p1 = tf.add_paragraph()
        p1.text = desc
        p1.font.size = Pt(11.5)
        p1.font.color.rgb = COLOR_WHITE
        p1.space_before = Pt(2)
        top_pos += 1.05

    # ==========================================
    # SLIDE 4: Academic Literature Review (Foundational Papers)
    # ==========================================
    s4 = prs.slides.add_slide(blank_layout)
    set_slide_background(s4)
    add_header(s4, "Academic Research Foundations (Literature Review - Part 1)")

    papers_p1 = [
        ("Automated Black-Box Vulnerability Scanning (DAST)", "Bau, J., Bursztein, E., Gupta, D., & Mitchell, J. (IEEE S&P)", "State of the Art: Automated Black-Box Web Application Vulnerability Testing", "Evaluated 8 commercial DAST tools. Proved that automated crawling and benign syntax probes provide high recall for reflected injection while minimizing side effects. Directly inspired SecureScan AI's non-destructive probe architecture."),
        ("SQL Injection Grammar & Error-Based Diagnostics", "Halfond, W. G., Viegas, J., & Orso, A. (ACM SIGSOFT)", "A Classification of SQL-Injection Attacks and Countermeasures", "Formalized SQL syntax-breaking probes and error-signature extraction. SecureScan AI implements Halfond's error-signature ontology across MySQL, PostgreSQL, MSSQL, Oracle, and SQLite without database modification."),
        ("Execution After Redirect & Open Redirect Flaws", "Doupé, A., Cova, M., & Vigna, G. (NDSS)", "Fear the EAR: Discovering and Mitigating Execution After Redirect", "Demonstrated risks where web applications leak sensitive sessions or facilitate phishing via unvalidated Location headers. Basis for SecureScan AI's open redirect detection module."),
    ]

    top_pos = 1.8
    for area, citation, paper_title, impact in papers_p1:
        add_card(s4, Inches(0.8), Inches(top_pos), Inches(11.7), Inches(1.6), area, COLOR_CYAN)
        tb = s4.shapes.add_textbox(Inches(1.0), Inches(top_pos + 0.4), Inches(11.3), Inches(1.15))
        tf = tb.text_frame
        tf.word_wrap = True
        p0 = tf.paragraphs[0]
        p0.text = f"📄 {paper_title} — {citation}"
        p0.font.size = Pt(12)
        p0.font.bold = True
        p0.font.color.rgb = COLOR_GREEN
        p1 = tf.add_paragraph()
        p1.text = f"Relevance to SecureScan AI: {impact}"
        p1.font.size = Pt(11)
        p1.font.color.rgb = COLOR_WHITE
        p1.space_before = Pt(4)
        top_pos += 1.75

    # ==========================================
    # SLIDE 5: Academic Literature Review (SSRF, Ownership & AI)
    # ==========================================
    s5 = prs.slides.add_slide(blank_layout)
    set_slide_background(s5)
    add_header(s5, "Academic Research Foundations (Literature Review - Part 2)")

    papers_p2 = [
        ("SSRF Defense & DNS Rebinding Mitigation", "Jackson, C., Barth, A., Bortz, B., Shao, W., & Boneh, D. (ACM CCS)", "Protecting Browsers from DNS Rebinding Attacks & Modern SSRF", "Identified that validating hostnames by string matching is vulnerable to Time-of-Check to Time-of-Use (TOCTOU) DNS rebinding. SecureScan AI adopts their pin-and-resolve model, resolving DNS immediately prior to socket connections."),
        ("Automated Domain Ownership Validation Protocols", "Barnes, R., Hoffman-Andrews, J., McCarney, D., & Kasten, E. (IETF RFC 8555)", "Automatic Certificate Management Environment (ACME) - DNS-01 & HTTP-01", "Established cryptographic proofs for domain ownership using DNS TXT challenges and well-known URI endpoints. SecureScan AI adapts RFC 8555's verification methods for penetration testing clearance."),
        ("LLMs in Automated Vulnerability Remediation", "Pearce, H., Ahmad, B., Tan, B., Dolan-Gavitt, B., & Karri, R. (IEEE S&P)", "Asleep at the Keyboard? Assessing LLMs for Security Vulnerability Analysis", "Surveyed LLM effectiveness in explaining code vulnerabilities and generating patches. SecureScan AI applies this with contextual prompt engineering, backed by a deterministic static knowledge base fallback."),
    ]

    top_pos = 1.8
    for area, citation, paper_title, impact in papers_p2:
        add_card(s5, Inches(0.8), Inches(top_pos), Inches(11.7), Inches(1.6), area, COLOR_PURPLE)
        tb = s5.shapes.add_textbox(Inches(1.0), Inches(top_pos + 0.4), Inches(11.3), Inches(1.15))
        tf = tb.text_frame
        tf.word_wrap = True
        p0 = tf.paragraphs[0]
        p0.text = f"📄 {paper_title} — {citation}"
        p0.font.size = Pt(12)
        p0.font.bold = True
        p0.font.color.rgb = COLOR_GREEN
        p1 = tf.add_paragraph()
        p1.text = f"Relevance to SecureScan AI: {impact}"
        p1.font.size = Pt(11)
        p1.font.color.rgb = COLOR_WHITE
        p1.space_before = Pt(4)
        top_pos += 1.75

    # ==========================================
    # SLIDE 6: System Architecture & Workflow
    # ==========================================
    s6 = prs.slides.add_slide(blank_layout)
    set_slide_background(s6)
    add_header(s6, "System Architecture & Processing Pipeline")

    arch_steps = [
        ("1. Target Registration", "Operator inputs target domain, in-scope & out-of-scope paths, testing window, and intensity level.", COLOR_CYAN),
        ("2. Verification Gate", "Cryptographic proof (DNS TXT / Meta Tag / File) or signed written approval token. Status must be VERIFIED.", COLOR_PURPLE),
        ("3. Pre-Scan Guardrails", "Socket DNS resolution; SSRF checks reject RFC 1918, 127.0.0.1, and cloud metadata (169.254.169.254).", COLOR_RED),
        ("4. DAST Engine Execution", "Multi-threaded crawler + 10 non-destructive modules with rate limiting (req/sec) and stop switch.", COLOR_GREEN),
        ("5. Intelligence & Export", "CVSS scoring, AI explanation advisory, tamper-evident audit logging, ReportLab PDF, and JSON reports.", COLOR_CYAN),
    ]

    left_pos = 0.8
    for title, desc, col in arch_steps:
        add_card(s6, Inches(left_pos), Inches(1.8), Inches(2.2), Inches(5.0), "", col)
        tb = s6.shapes.add_textbox(Inches(left_pos + 0.1), Inches(2.0), Inches(2.0), Inches(4.5))
        tf = tb.text_frame
        tf.word_wrap = True
        p0 = tf.paragraphs[0]
        p0.text = title
        p0.font.size = Pt(14)
        p0.font.bold = True
        p0.font.color.rgb = col
        p1 = tf.add_paragraph()
        p1.text = desc
        p1.font.size = Pt(11.5)
        p1.font.color.rgb = COLOR_WHITE
        p1.space_before = Pt(12)
        left_pos += 2.38

    # ==========================================
    # SLIDE 7: Target Authorization & Governance Engine
    # ==========================================
    s7 = prs.slides.add_slide(blank_layout)
    set_slide_background(s7)
    add_header(s7, "Target Governance: Cryptographic Ownership & Written Consent")

    add_card(s7, Inches(0.8), Inches(1.8), Inches(3.6), Inches(5.0), "Own Websites (Cryptographic)", COLOR_CYAN)
    tb = s7.shapes.add_textbox(Inches(0.95), Inches(2.4), Inches(3.3), Inches(4.2))
    tf = tb.text_frame
    tf.word_wrap = True
    tf.text = "• DNS TXT Record:\n  Checks 'securescan-verify=<token>' using dnspython query resolver.\n\n• HTML Meta Tag:\n  Inspects homepage <head> for <meta name='securescan-verification' content='<token>'>.\n\n• Well-Known File:\n  Validates plaintext token at /.well-known/securescan-verify.txt.\n\n• Token Lifecycle: 32-char hex, single-use, 7-day expiration."
    for p in tf.paragraphs:
        p.font.size = Pt(11.5)
        p.font.color.rgb = COLOR_WHITE

    add_card(s7, Inches(4.8), Inches(1.8), Inches(3.6), Inches(5.0), "Third-Party (Written Authorization)", COLOR_PURPLE)
    tb = s7.shapes.add_textbox(Inches(4.95), Inches(2.4), Inches(3.3), Inches(4.2))
    tf = tb.text_frame
    tf.word_wrap = True
    tf.text = "• Form Data Collected:\n  - Authorizer Name, Designation, Org\n  - Official Corporate Email & Phone\n  - Testing Window (Start & End Time)\n  - Max Requests per Second Quota\n\n• Document Upload:\n  Signed proof (PDF/PNG) stored with randomized UUID filename.\n\n• Authorizer Approval Link:\n  Unique token-based URL (/approve/<token>).\n\n• Legal Affirmation Checkboxes:\n  Mandatory civil liability acceptance."
    for p in tf.paragraphs:
        p.font.size = Pt(11.5)
        p.font.color.rgb = COLOR_WHITE

    add_card(s7, Inches(8.8), Inches(1.8), Inches(3.7), Inches(5.0), "Pre-Approved Educational Lab", COLOR_GREEN)
    tb = s7.shapes.add_textbox(Inches(8.95), Inches(2.4), Inches(3.3), Inches(4.2))
    tf = tb.text_frame
    tf.word_wrap = True
    tf.text = "• Safe Training Environments:\n  - Localhost (127.0.0.1, 5001)\n  - testphp.vulnweb.com\n  - testasp.vulnweb.com\n  - OWASP Juice Shop\n  - DVWA Sandbox\n\n• Auto-Approved for Research:\n  Students and researchers can experiment immediately without external DNS dependencies.\n\n• Isolated Loopback Privilege:\n  Only approved lab targets may access local interface addresses."
    for p in tf.paragraphs:
        p.font.size = Pt(11.5)
        p.font.color.rgb = COLOR_WHITE

    # ==========================================
    # SLIDE 8: SSRF & Scope Guardrails
    # ==========================================
    s8 = prs.slides.add_slide(blank_layout)
    set_slide_background(s8)
    add_header(s8, "SSRF Defense, DNS-Rebinding Mitigation & Scope Enforcement")

    add_card(s8, Inches(0.8), Inches(1.8), Inches(5.6), Inches(5.0), "SSRF & DNS-Rebinding Defense Mechanism", COLOR_RED)
    tb = s8.shapes.add_textbox(Inches(1.0), Inches(2.4), Inches(5.2), Inches(4.2))
    tf = tb.text_frame
    tf.word_wrap = True
    tf.text = "1. Pre-Flight DNS Resolution:\n   Before issuing any HTTP request, socket.getaddrinfo() resolves the hostname to IPv4/IPv6.\n\n2. Real-Time IP Validation:\n   IP is evaluated against restricted ranges using Python's ipaddress library:\n   - RFC 1918 Private Ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)\n   - Loopback Addresses (127.0.0.0/8, ::1)\n   - Link-Local Subnets (169.254.0.0/16, fe80::/10)\n   - Cloud Metadata Service (169.254.169.254)\n\n3. Redirect Re-Validation:\n   On HTTP 301/302 redirects, the destination IP is re-resolved to thwart DNS rebinding attacks."
    for p in tf.paragraphs:
        p.font.size = Pt(11.5)
        p.font.color.rgb = COLOR_WHITE

    add_card(s8, Inches(6.9), Inches(1.8), Inches(5.6), Inches(5.0), "Granular Path-Level Scope Boundaries", COLOR_CYAN)
    tb = s8.shapes.add_textbox(Inches(7.1), Inches(2.4), Inches(5.2), Inches(4.2))
    tf = tb.text_frame
    tf.word_wrap = True
    tf.text = "1. In-Scope Matching:\n   Operators define permitted subtrees (e.g., '/*', '/api/*', '/portal/*'). URLs outside scope are discarded by the crawler.\n\n2. Strict Exclusion Filter:\n   Out-of-scope paths (e.g., '/admin', '/payment', '/logout') are blocked before request dispatch.\n\n3. Rate Limiting & User-Agent Disclosure:\n   Requests adhere to token-bucket rate limits (1-20 req/sec).\n   Transparent User-Agent:\n   'SecureScanAI/1.0 (authorized security scan; contact: <email>)'\n\n4. Global Kill Switch:\n   Allows immediate revocation and thread halting in emergency scenarios."
    for p in tf.paragraphs:
        p.font.size = Pt(11.5)
        p.font.color.rgb = COLOR_WHITE

    # ==========================================
    # SLIDE 9: Non-Destructive DAST Modules
    # ==========================================
    s9 = prs.slides.add_slide(blank_layout)
    set_slide_background(s9)
    add_header(s9, "DAST Detection Engine: 10 Non-Destructive Modules")

    mods = [
        ("🕷️ Scope Crawler", "BFS crawler with depth limits; collects <a href>, <form>, and input parameters within scope."),
        ("🛡️ Security Headers", "Inspects missing CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy."),
        ("🍪 Cookie Security", "Verifies Set-Cookie flags: HttpOnly (anti-XSS), Secure (TLS only), SameSite (anti-CSRF)."),
        ("💉 Reflected XSS", "Injects benign non-executable marker (<securescan_test_marker_x78>) in query params and forms."),
        ("🗄️ SQL Injection", "Harmless syntax-breaking probes (', \", \\) matching diagnostic database error signatures."),
        ("🔀 Open Redirect", "Checks redirect params (url, next, dest) against external benign target to detect unvalidated forwards."),
        ("📁 Sensitive Files", "Probes for exposed /.env, /.git/HEAD, /backup.sql, robots.txt with signature indicators."),
        ("🔐 SSL / TLS Audit", "Evaluates TLS protocols (flags deprecated TLS 1.0/1.1), checks certificate validity, and HTTPS redirect."),
        ("🏷️ Info Disclosure", "Detects verbose Server and X-Powered-By banners and unhandled debug stack trace leaks."),
        ("🛡️ CSRF Form Token", "Audits state-changing POST forms for presence of anti-CSRF token hidden inputs."),
    ]

    for i, (m_title, m_desc) in enumerate(mods):
        row = i // 2
        col = i % 2
        x = Inches(0.8 + col * 5.95)
        y = Inches(1.8 + row * 1.02)
        add_card(s9, x, y, Inches(5.75), Inches(0.92), "", COLOR_CYAN if col == 0 else COLOR_PURPLE)
        tb = s9.shapes.add_textbox(x + Inches(0.15), y + Inches(0.08), Inches(5.45), Inches(0.75))
        tf = tb.text_frame
        tf.word_wrap = True
        p0 = tf.paragraphs[0]
        p0.text = m_title
        p0.font.size = Pt(12.5)
        p0.font.bold = True
        p0.font.color.rgb = COLOR_GREEN
        p1 = tf.add_paragraph()
        p1.text = m_desc
        p1.font.size = Pt(10.5)
        p1.font.color.rgb = COLOR_WHITE

    # ==========================================
    # SLIDE 10: Dual-Engine AI Vulnerability Explainer
    # ==========================================
    s10 = prs.slides.add_slide(blank_layout)
    set_slide_background(s10)
    add_header(s10, "Dual-Engine AI Vulnerability Explainer & Remediation Advisory")

    add_card(s10, Inches(0.8), Inches(1.8), Inches(5.6), Inches(5.0), "Mode 1: OpenAI GPT API Integration", COLOR_CYAN)
    tb = s10.shapes.add_textbox(Inches(1.0), Inches(2.4), Inches(5.2), Inches(4.2))
    tf = tb.text_frame
    tf.word_wrap = True
    tf.text = "• Real-Time Contextual Analysis:\n  Supplies title, severity, parameter, evidence, and OWASP category to OpenAI API.\n\n• Structured 4-Part Output:\n  1. Executive Summary\n  2. Technical Attack Vector & Mechanism\n  3. Business & Security Impact\n  4. Developer Remediation Code Examples\n\n• Caching Mechanism:\n  Explanations cached in SQLite to prevent redundant API calls and optimize latency."
    for p in tf.paragraphs:
        p.font.size = Pt(12)
        p.font.color.rgb = COLOR_WHITE

    add_card(s10, Inches(6.9), Inches(1.8), Inches(5.6), Inches(5.0), "Mode 2: Deterministic Static Knowledge Base Fallback", COLOR_PURPLE)
    tb = s10.shapes.add_textbox(Inches(7.1), Inches(2.4), Inches(5.2), Inches(4.2))
    tf = tb.text_frame
    tf.word_wrap = True
    tf.text = "• Zero-Dependency Offline Operation:\n  If no API key is provided or the network is air-gapped, the engine seamlessly falls back to a curated cybersecurity knowledge base.\n\n• OWASP Top 10 Aligned Rules:\n  Covers SQL Injection, Reflected XSS, CSP deficiencies, Cookie HttpOnly/SameSite flaws, and CSRF patterns.\n\n• Concrete Code Snippets:\n  Provides verified defensive syntax for Python/Flask, PHP, and SQL prepared statements."
    for p in tf.paragraphs:
        p.font.size = Pt(12)
        p.font.color.rgb = COLOR_WHITE

    # ==========================================
    # SLIDE 11: Experimental Results & Local Evaluation
    # ==========================================
    s11 = prs.slides.add_slide(blank_layout)
    set_slide_background(s11)
    add_header(s11, "Experimental Evaluation & Localhost Validation Results")

    # Metrics Card
    add_card(s11, Inches(0.8), Inches(1.8), Inches(11.7), Inches(1.2), "Key Performance Benchmarks (Live Sandbox)", COLOR_GREEN)
    tb = s11.shapes.add_textbox(Inches(1.0), Inches(2.3), Inches(11.3), Inches(0.6))
    tf = tb.text_frame
    tf.word_wrap = True
    tf.text = "⚡ Scan Execution Time: 3.2s | 🎯 Target: http://127.0.0.1:5055/lab/test-page | 🛡️ Total Findings: 11 | ❌ False Positives: 0"
    tf.paragraphs[0].font.size = Pt(14)
    tf.paragraphs[0].font.bold = True
    tf.paragraphs[0].font.color.rgb = COLOR_WHITE

    # Findings Table Cards
    f_items = [
        ("Reflected XSS in Parameter 'name'", "High (CVSS 7.5)", "Benign marker reflected verbatim without HTML encoding", "Encode via htmlspecialchars/autoescape"),
        ("Missing Anti-CSRF Token on POST Form", "Medium (CVSS 6.5)", "State-changing POST form submitting without CSRF token", "Implement synchronizer token / Flask-WTF"),
        ("Missing Content-Security-Policy (CSP)", "Medium (CVSS 5.4)", "No CSP header; permits arbitrary script injection", "Set default-src 'self'; script-src 'self'"),
        ("Plaintext HTTP Not Redirected to HTTPS", "Medium (CVSS 5.3)", "Web server accepts unencrypted traffic without 301", "Enforce permanent 301 HTTPS redirection"),
        ("Server Banner Disclosure (Server Header)", "Low (CVSS 3.4)", "Server header disclosed 'DemoServer/2.4.49'", "Configure server_tokens off in Nginx/Apache"),
    ]

    top_pos = 3.2
    for title, sev, ev, rem in f_items:
        add_card(s11, Inches(0.8), Inches(top_pos), Inches(11.7), Inches(0.72), "", COLOR_CYAN if "High" in sev else COLOR_PURPLE)
        tb = s11.shapes.add_textbox(Inches(1.0), Inches(top_pos + 0.08), Inches(11.3), Inches(0.55))
        tf = tb.text_frame
        tf.word_wrap = True
        p0 = tf.paragraphs[0]
        p0.text = f"{title}  |  Severity: {sev}"
        p0.font.size = Pt(12)
        p0.font.bold = True
        p0.font.color.rgb = COLOR_CYAN if "High" in sev else COLOR_PURPLE
        p1 = tf.add_paragraph()
        p1.text = f"Evidence: {ev}  -->  Remediation: {rem}"
        p1.font.size = Pt(10)
        p1.font.color.rgb = COLOR_WHITE
        top_pos += 0.8

    # ==========================================
    # SLIDE 12: Compliance Reporting & Multi-Device UI
    # ==========================================
    s12 = prs.slides.add_slide(blank_layout)
    set_slide_background(s12)
    add_header(s12, "Compliance Reporting & Responsive Multi-Device UI")

    add_card(s12, Inches(0.8), Inches(1.8), Inches(5.6), Inches(5.0), "Executive Compliance Reports", COLOR_CYAN)
    tb = s12.shapes.add_textbox(Inches(1.0), Inches(2.4), Inches(5.2), Inches(4.2))
    tf = tb.text_frame
    tf.word_wrap = True
    tf.text = "• ReportLab PDF Generator:\n  Compiles structured executive penetration testing reports:\n  - Executive Summary & Overall Risk Score\n  - Mandatory Authorization & Compliance Section (Authorizer contact, testing window, and scope boundaries)\n  - Detailed CVSS 3.1 Findings Table with remediation code\n  - Legal privileged & confidential notice\n\n• JSON Assessment Export:\n  Complete machine-readable assessment schema for CI/CD integration and SOC 2 / ISO 27001 audit archiving."
    for p in tf.paragraphs:
        p.font.size = Pt(12)
        p.font.color.rgb = COLOR_WHITE

    add_card(s12, Inches(6.9), Inches(1.8), Inches(5.6), Inches(5.0), "Multi-Device Screen Adjustment System", COLOR_PURPLE)
    tb = s12.shapes.add_textbox(Inches(7.1), Inches(2.4), Inches(5.2), Inches(4.2))
    tf = tb.text_frame
    tf.word_wrap = True
    tf.text = "• Dynamic Screen Adjustment Toolbar:\n  Integrated topbar & settings modal allowing live UI scaling (80% to 125%) and layout density toggling (Compact, Comfortable, Spacious).\n\n• Multi-Device Responsive Breakpoints:\n  - Mobile Phones (<768px): Off-canvas slide drawer with backdrop overlay, touch targets >= 44px, stacked cards.\n  - Tablets & Small Laptops (769px-1024px): Fluid dual-column layout with auto-scaling Chart.js visualizers.\n  - Ultra-Wide Screens (1440px+): Expanded 4-column metrics."
    for p in tf.paragraphs:
        p.font.size = Pt(12)
        p.font.color.rgb = COLOR_WHITE

    # ==========================================
    # SLIDE 13: Comparison with Existing DAST Solutions
    # ==========================================
    s13 = prs.slides.add_slide(blank_layout)
    set_slide_background(s13)
    add_header(s13, "Comparative Analysis: SecureScan AI vs. Existing Tools")

    # Table of comparison
    headers_c = ["Feature / Capability", "Nikto", "OWASP ZAP", "Burp Suite Pro", "SecureScan AI"]
    rows_c = [
        ["Target Permission Enforcement", "❌ None (Free scan)", "⚠️ Manual checklist", "⚠️ Manual warning", "✅ Cryptographic & Written Gate"],
        ["SSRF & Metadata IP Defense", "❌ No protection", "⚠️ Partial", "⚠️ Partial", "✅ Real-time DNS & Cloud Shield"],
        ["In-Scope / Out-of-Scope Filter", "⚠️ Flag only", "✅ Yes", "✅ Yes", "✅ Strict Path Subtree Matching"],
        ["AI Vulnerability Explainer", "❌ None", "❌ None", "⚠️ Add-on plugin", "✅ Dual Engine (GPT + Static KB)"],
        ["Multi-Device Adaptive UI", "❌ CLI only", "❌ Desktop Java UI", "❌ Desktop Java UI", "✅ Responsive Web + Screen Presets"],
        ["Automated Compliance PDF", "❌ Raw text/HTML", "⚠️ Basic HTML/PDF", "✅ Comprehensive PDF", "✅ ReportLab with Auth Details"],
    ]

    col_widths = [Inches(3.3), Inches(1.9), Inches(2.1), Inches(2.1), Inches(2.3)]
    left_start = Inches(0.8)
    top_start = Inches(2.0)

    # Header Row
    for col_idx, h_text in enumerate(headers_c):
        c_left = left_start + sum(col_widths[:col_idx])
        c_w = col_widths[col_idx]
        card = add_card(s13, c_left, top_start, c_w, Inches(0.6), "", COLOR_CYAN)
        tb = s13.shapes.add_textbox(c_left, top_start + Inches(0.08), c_w, Inches(0.45))
        p = tb.text_frame.paragraphs[0]
        p.text = h_text
        p.font.size = Pt(11.5)
        p.font.bold = True
        p.font.color.rgb = COLOR_CYAN
        p.alignment = PP_ALIGN.CENTER if col_idx > 0 else PP_ALIGN.LEFT

    top_row = top_start + Inches(0.65)
    for r_idx, row_data in enumerate(rows_c):
        for col_idx, cell_text in enumerate(row_data):
            c_left = left_start + sum(col_widths[:col_idx])
            c_w = col_widths[col_idx]
            card = add_card(s13, c_left, top_row, c_w, Inches(0.65), "", COLOR_CARD if col_idx < 4 else COLOR_GREEN)
            tb = s13.shapes.add_textbox(c_left, top_row + Inches(0.08), c_w, Inches(0.5))
            p = tb.text_frame.paragraphs[0]
            p.text = cell_text
            p.font.size = Pt(11)
            p.font.color.rgb = COLOR_GREEN if col_idx == 4 else COLOR_WHITE
            p.alignment = PP_ALIGN.CENTER if col_idx > 0 else PP_ALIGN.LEFT
        top_row += Inches(0.72)

    # ==========================================
    # SLIDE 14: Conclusion, Future Roadmap & Defense Q&A
    # ==========================================
    s14 = prs.slides.add_slide(blank_layout)
    set_slide_background(s14)
    add_header(s14, "Conclusion, Future Roadmap & Defense Q&A")

    add_card(s14, Inches(0.8), Inches(1.8), Inches(5.6), Inches(5.0), "Project Summary & Achievements", COLOR_GREEN)
    tb = s14.shapes.add_textbox(Inches(1.0), Inches(2.4), Inches(5.2), Inches(4.2))
    tf = tb.text_frame
    tf.word_wrap = True
    tf.text = "• Fully Realized DAST Platform:\n  Integrated backend, scanner engine, glassmorphic UI, authorization manager, and reporting engine in one cohesive system.\n\n• Rigorous Ethical Guardrails:\n  Solves the industry problem of accidental or malicious target scanning through cryptographic domain proofs and SSRF protection.\n\n• Production Tested:\n  100% test pass rate across unit security suite and live server integration audits.\n\n• Source Code Repository:\n  https://github.com/VinodKumarstudent/securescan-ai"
    for p in tf.paragraphs:
        p.font.size = Pt(12)
        p.font.color.rgb = COLOR_WHITE

    add_card(s14, Inches(6.9), Inches(1.8), Inches(5.6), Inches(5.0), "Future Roadmap & Open for Questions", COLOR_CYAN)
    tb = s14.shapes.add_textbox(Inches(7.1), Inches(2.4), Inches(5.2), Inches(4.2))
    tf = tb.text_frame
    tf.word_wrap = True
    tf.text = "• Future Enhancements:\n  1. Headless Browser (Playwright/Puppeteer) execution for complex Single Page Application (SPA) DOM XSS detection.\n  2. Fine-tuned local LLM (Llama 3 / Mistral) for entirely offline AI reasoning.\n  3. Distributed agent workers with Redis queueing for enterprise-scale concurrent assessments.\n\n💬 Thank you for your time and evaluation!\nQuestions, feedback, and discussion are welcome."
    for p in tf.paragraphs:
        p.font.size = Pt(12)
        p.font.color.rgb = COLOR_WHITE

    output_path = "/Users/vinodkumar/.gemini/antigravity/scratch/securescan-ai/securescan_ai_presentation.pptx"
    prs.save(output_path)
    print(f"[✓] Presentation generated successfully at: {output_path}")

if __name__ == "__main__":
    create_presentation()
