/**
 * SecureScan AI - Historical Scans & Comparative Analysis
 */
const HistoryManager = {
  cachedScans: [],
  selectedScanIds: new Set(),

  async loadHistory() {
    try {
      const resp = await fetch('/api/scans');
      const data = await resp.json();
      this.cachedScans = data.scans || [];
      this.selectedScanIds.clear();
      this.updateCompareButton();
      this.renderHistoryTable(this.cachedScans);
    } catch (e) {
      App.showToast('Failed to load history', 'error');
    }
  },

  renderHistoryTable(scans) {
    const tbody = document.getElementById('history-table-body');
    if (!tbody) return;

    if (!scans || scans.length === 0) {
      tbody.innerHTML = `<tr><td colspan="10" style="text-align: center; color: var(--text-muted); padding: 2rem;">No historical scans on record.</td></tr>`;
      return;
    }

    tbody.innerHTML = scans.map(s => {
      const isChecked = this.selectedScanIds.has(s.id) ? 'checked' : '';
      const statusBadge = `<span class="badge badge-${s.status === 'completed' ? 'verified' : s.status === 'running' ? 'pending' : 'failed'}">${s.status}</span>`;

      return `
        <tr>
          <td>
            <input type="checkbox" onchange="HistoryManager.toggleSelectScan(${s.id}, this.checked)" ${isChecked}>
          </td>
          <td style="font-family: var(--font-mono); font-weight: 700;">#${s.id}</td>
          <td><b>${s.domain}</b></td>
          <td>${s.scan_type} / ${s.intensity}</td>
          <td>${statusBadge}</td>
          <td><b>${s.findings_count}</b> issues</td>
          <td style="font-family: var(--font-mono); font-weight: 700; color: ${s.risk_score >= 7.0 ? 'var(--severity-critical)' : 'var(--accent-cyan)'};">${s.risk_score}</td>
          <td style="color: var(--text-muted);">${s.duration_seconds}s</td>
          <td style="color: var(--text-muted); font-size: 0.8rem;">${s.created_at}</td>
          <td>
            <button class="btn btn-primary btn-sm" onclick="ResultsManager.viewScan(${s.id})" style="margin-right: 0.3rem;">View</button>
            <button class="btn btn-secondary btn-sm" onclick="HistoryManager.rescan(${s.id})" title="Re-scan Target" style="margin-right: 0.3rem;">↻</button>
            <button class="btn btn-danger btn-sm" onclick="HistoryManager.deleteScan(${s.id})">🗑</button>
          </td>
        </tr>
      `;
    }).join('');
  },

  toggleSelectScan(scanId, isSelected) {
    if (isSelected) {
      if (this.selectedScanIds.size >= 2) {
        App.showToast('You can compare a maximum of 2 scans at a time.', 'warning');
        this.renderHistoryTable(this.cachedScans);
        return;
      }
      this.selectedScanIds.add(scanId);
    } else {
      this.selectedScanIds.delete(scanId);
    }
    this.updateCompareButton();
  },

  updateCompareButton() {
    const btn = document.getElementById('btn-compare-scans');
    if (!btn) return;
    const count = this.selectedScanIds.size;
    btn.innerText = `⚖️ Compare Selected (${count})`;
    btn.disabled = count !== 2;
  },

  async compareSelectedScans() {
    const ids = Array.from(this.selectedScanIds);
    if (ids.length !== 2) return;

    try {
      const [r1, r2] = await Promise.all([
        fetch(`/api/scan/${ids[0]}`).then(r => r.json()),
        fetch(`/api/scan/${ids[1]}`).then(r => r.json())
      ]);

      const s1 = r1.scan;
      const s2 = r2.scan;

      const modal = document.getElementById('modal-compare');
      const content = document.getElementById('compare-modal-content');

      const f1Titles = new Set((s1.findings || []).map(f => f.title));
      const f2Titles = new Set((s2.findings || []).map(f => f.title));

      const newInS2 = (s2.findings || []).filter(f => !f1Titles.has(f.title));
      const resolvedInS2 = (s1.findings || []).filter(f => !f2Titles.has(f.title));

      content.innerHTML = `
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 1.5rem;">
          <div class="card" style="background: rgba(15, 23, 42, 0.4);">
            <div style="font-size: 0.82rem; color: var(--text-muted);">Baseline Scan</div>
            <div style="font-size: 1.1rem; font-weight: 700; color: var(--accent-cyan); margin: 0.2rem 0;">Scan #${s1.id} — ${s1.domain}</div>
            <div style="font-size: 0.85rem; color: var(--text-secondary);">Risk Score: <b>${s1.risk_score}</b> | Total Issues: <b>${s1.findings.length}</b></div>
            <div style="font-size: 0.78rem; color: var(--text-muted); margin-top: 0.3rem;">${s1.created_at}</div>
          </div>

          <div class="card" style="background: rgba(15, 23, 42, 0.4);">
            <div style="font-size: 0.82rem; color: var(--text-muted);">Comparison Scan</div>
            <div style="font-size: 1.1rem; font-weight: 700; color: var(--accent-purple); margin: 0.2rem 0;">Scan #${s2.id} — ${s2.domain}</div>
            <div style="font-size: 0.85rem; color: var(--text-secondary);">Risk Score: <b>${s2.risk_score}</b> | Total Issues: <b>${s2.findings.length}</b></div>
            <div style="font-size: 0.78rem; color: var(--text-muted); margin-top: 0.3rem;">${s2.created_at}</div>
          </div>
        </div>

        <div style="margin-bottom: 1.25rem;">
          <h3 style="font-size: 0.95rem; color: #f87171; margin-bottom: 0.5rem;">🚨 New Vulnerabilities Introduced (${newInS2.length}):</h3>
          ${newInS2.length === 0 ? '<div style="font-size: 0.85rem; color: var(--text-muted);">None identified.</div>' : 
            newInS2.map(f => `<div style="font-size: 0.85rem; padding: 0.35rem 0; border-bottom: 1px solid var(--glass-border); color: var(--text-primary);"><span class="badge badge-${f.severity.toLowerCase()}">${f.severity}</span> <b>${f.title}</b> (${f.affected_url})</div>`).join('')}
        </div>

        <div>
          <h3 style="font-size: 0.95rem; color: #34d399; margin-bottom: 0.5rem;">✅ Resolved / Closed Findings (${resolvedInS2.length}):</h3>
          ${resolvedInS2.length === 0 ? '<div style="font-size: 0.85rem; color: var(--text-muted);">None resolved.</div>' : 
            resolvedInS2.map(f => `<div style="font-size: 0.85rem; padding: 0.35rem 0; border-bottom: 1px solid var(--glass-border); color: var(--text-secondary);"><span class="badge badge-low">${f.severity}</span> ${f.title}</div>`).join('')}
        </div>
      `;

      modal.classList.add('active');
    } catch (e) {
      App.showToast('Error comparing scans', 'error');
    }
  },

  closeCompareModal() {
    document.getElementById('modal-compare').classList.remove('active');
  },

  rescan(scanId) {
    const s = this.cachedScans.find(x => x.id === scanId);
    if (!s) return;
    App.navigate('new-scan');
    setTimeout(() => {
      const select = document.getElementById('scan-target-select');
      if (select) {
        select.value = s.target_id;
        ScanManager.handleTargetSelected(s.target_id);
      }
      document.getElementById('scan-target-url').value = s.target_url;
      document.getElementById('scan-intensity').value = s.intensity || 'Standard';
    }, 150);
  },

  async deleteScan(scanId) {
    if (!confirm(`Are you sure you want to delete Scan #${scanId}?`)) return;
    try {
      await fetch(`/api/scan/${scanId}`, { method: 'DELETE' });
      App.showToast(`Scan #${scanId} deleted`, 'info');
      this.loadHistory();
    } catch (e) {
      App.showToast('Failed to delete scan', 'error');
    }
  }
};
