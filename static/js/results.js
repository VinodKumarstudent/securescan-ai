/**
 * SecureScan AI - Results Presentation & AI Explainer
 */
const ResultsManager = {
  currentScan: null,
  cachedFindings: [],

  async viewScan(scanId) {
    try {
      const resp = await fetch(`/api/scan/${scanId}`);
      if (!resp.ok) {
        App.showToast('Failed to load scan results', 'error');
        return;
      }
      const data = await resp.json();
      this.currentScan = data.scan;
      this.cachedFindings = this.currentScan.findings || [];

      // Reveal Results tab
      document.getElementById('nav-results').style.display = 'flex';
      App.navigate('scan-results');

      this.renderScanOverview(this.currentScan);
      this.renderFindings(this.cachedFindings);
    } catch (e) {
      App.showToast('Error loading results', 'error');
    }
  },

  renderScanOverview(scan) {
    document.getElementById('results-target-title').innerText = `Assessment Results: ${scan.domain}`;
    document.getElementById('results-meta-subtitle').innerText = 
      `Scan ID #${scan.id} | Target URL: ${scan.target_url} | Duration: ${scan.duration_seconds}s | Pages Analyzed: ${scan.pages_crawled}`;

    // Risk score
    const riskElem = document.getElementById('results-risk-score');
    riskElem.innerText = scan.risk_score;
    if (scan.risk_score >= 8.0) {
      riskElem.style.color = 'var(--severity-critical)';
    } else if (scan.risk_score >= 5.0) {
      riskElem.style.color = 'var(--severity-high)';
    } else {
      riskElem.style.color = 'var(--accent-cyan)';
    }

    // Severity chips
    const counts = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
    this.cachedFindings.forEach(f => {
      if (counts[f.severity] !== undefined) counts[f.severity]++;
    });

    const chipsContainer = document.getElementById('results-sev-chips');
    chipsContainer.innerHTML = `
      <span class="badge badge-critical">${counts.Critical} Critical</span>
      <span class="badge badge-high">${counts.High} High</span>
      <span class="badge badge-medium">${counts.Medium} Medium</span>
      <span class="badge badge-low">${counts.Low} Low</span>
      <span class="badge badge-info">${counts.Info} Info</span>
    `;

    // Download buttons
    document.getElementById('btn-download-pdf').href = `/api/scan/${scan.id}/report.pdf`;
    document.getElementById('btn-download-json').href = `/api/scan/${scan.id}/report.json`;
  },

  renderFindings(findings) {
    const container = document.getElementById('findings-container');
    if (!container) return;

    if (!findings || findings.length === 0) {
      container.innerHTML = `
        <div style="text-align: center; padding: 3rem 1rem; color: var(--text-muted);">
          No vulnerabilities found matching current filters.
        </div>
      `;
      return;
    }

    container.innerHTML = findings.map((f, idx) => {
      const sevClass = f.severity.toLowerCase();
      return `
        <div class="card" style="margin-bottom: 1rem; border-left: 4px solid var(--severity-${sevClass}); background: rgba(15, 23, 42, 0.45);">
          <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 0.6rem;">
            <div>
              <div style="font-size: 1.05rem; font-weight: 700; color: var(--text-primary); margin-bottom: 0.25rem;">
                #${idx + 1}. ${f.title}
              </div>
              <div style="font-size: 0.82rem; color: var(--text-muted); font-family: var(--font-mono);">
                ${f.affected_url}
              </div>
            </div>
            <div style="display: flex; gap: 0.5rem; align-items: center;">
              <span class="badge badge-${sevClass}">${f.severity} (CVSS ${f.cvss_score})</span>
              <button class="btn btn-secondary btn-sm" onclick="ResultsManager.explainFinding(${f.id})" style="border-color: var(--accent-purple);">
                🤖 Explain with AI
              </button>
            </div>
          </div>

          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 0.75rem; margin-top: 0.75rem; font-size: 0.84rem;">
            <div>
              <span style="color: var(--text-muted);">Affected Component:</span>
              <code style="color: var(--text-primary);">${f.parameter || 'N/A'}</code>
            </div>
            <div>
              <span style="color: var(--text-muted);">OWASP Category:</span>
              <span style="color: var(--accent-cyan); font-weight: 500;">${f.owasp_category || 'N/A'}</span>
            </div>
          </div>

          <div style="margin-top: 0.75rem; font-size: 0.84rem;">
            <div style="color: var(--text-muted); margin-bottom: 0.2rem;">Observed Technical Evidence:</div>
            <div style="background: rgba(0, 0, 0, 0.4); padding: 0.6rem; border-radius: 4px; font-family: var(--font-mono); font-size: 0.8rem; color: #cbd5e1; word-break: break-all;">
              ${this.escapeHtml(f.evidence || 'N/A')}
            </div>
          </div>

          <div style="margin-top: 0.75rem; font-size: 0.84rem; background: rgba(0, 243, 255, 0.04); border: 1px solid rgba(0, 243, 255, 0.15); padding: 0.75rem; border-radius: 4px;">
            <div style="color: var(--accent-cyan); font-weight: 600; margin-bottom: 0.2rem;">Remediation Recommendation:</div>
            <div style="color: var(--text-primary);">${f.remediation || 'Follow defensive engineering standards.'}</div>
          </div>
        </div>
      `;
    }).join('');
  },

  filterFindings() {
    const search = (document.getElementById('findings-search').value || '').toLowerCase();
    const sev = document.getElementById('findings-sev-filter').value;

    const filtered = this.cachedFindings.filter(f => {
      const matchSearch = !search || f.title.toLowerCase().includes(search) || f.affected_url.toLowerCase().includes(search) || (f.parameter && f.parameter.toLowerCase().includes(search));
      const matchSev = !sev || f.severity === sev;
      return matchSearch && matchSev;
    });

    this.renderFindings(filtered);
  },

  async explainFinding(findingId) {
    const modal = document.getElementById('modal-ai-explain');
    const body = document.getElementById('modal-explain-body');
    modal.classList.add('active');
    body.innerHTML = `
      <div style="text-align: center; padding: 2rem;">
        <div style="color: var(--accent-cyan); margin-bottom: 0.5rem;">Generating comprehensive AI vulnerability advisory...</div>
        <div style="font-size: 0.8rem; color: var(--text-muted);">Consulting cybersecurity engine and threat models...</div>
      </div>
    `;

    try {
      const resp = await fetch('/api/explain', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ finding_id: findingId })
      });
      const data = await resp.json();
      
      // Simple markdown parser for rendering
      let html = this.renderMarkdown(data.explanation);
      body.innerHTML = html;
    } catch (e) {
      body.innerHTML = `<div style="color: var(--severity-critical);">Failed to generate explanation: ${e.message}</div>`;
    }
  },

  closeExplainModal() {
    document.getElementById('modal-ai-explain').classList.remove('active');
  },

  renderMarkdown(text) {
    if (!text) return '';
    let out = text
      .replace(/### (.*)/g, '<h3 style="color: var(--accent-cyan); margin: 1rem 0 0.5rem 0;">$1</h3>')
      .replace(/#### (.*)/g, '<h4 style="color: var(--text-primary); margin: 0.8rem 0 0.4rem 0;">$1</h4>')
      .replace(/\*\*(.*?)\*\*/g, '<b>$1</b>')
      .replace(/`([^`]+)`/g, '<code style="background: rgba(255,255,255,0.1); padding: 2px 4px; border-radius: 3px; font-family: var(--font-mono);">$1</code>')
      .replace(/```([\s\S]*?)```/g, '<pre style="background: #05070e; border: 1px solid var(--glass-border); padding: 0.8rem; border-radius: 4px; font-family: var(--font-mono); overflow-x: auto; color: #38bdf8; margin: 0.6rem 0;">$1</pre>')
      .replace(/> (.*)/g, '<blockquote style="border-left: 3px solid var(--accent-purple); padding-left: 0.75rem; margin: 0.5rem 0; color: var(--text-muted);">$1</blockquote>')
      .replace(/\n\n/g, '<p style="margin-bottom: 0.75rem;"></p>');
    return out;
  },

  escapeHtml(str) {
    return (str || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }
};
