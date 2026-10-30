/**
 * SecureScan AI - Compliance Audit Trail & Forensics
 */
const ComplianceManager = {
  async loadAuditLogs() {
    const action = document.getElementById('audit-filter-action')?.value.trim() || '';
    const domain = document.getElementById('audit-filter-domain')?.value.trim() || '';

    try {
      const url = `/api/audit-logs?action=${encodeURIComponent(action)}&domain=${encodeURIComponent(domain)}`;
      const resp = await fetch(url);
      const data = await resp.json();
      this.renderAuditTable(data.logs || []);
    } catch (e) {
      console.error('Failed to load audit logs:', e);
    }
  },

  renderAuditTable(logs) {
    const tbody = document.getElementById('audit-logs-table-body');
    if (!tbody) return;

    if (!logs || logs.length === 0) {
      tbody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: var(--text-muted); padding: 2rem;">No audit logs match criteria.</td></tr>`;
      return;
    }

    tbody.innerHTML = logs.map(l => {
      const isBlocked = l.status === 'BLOCKED' || l.status === 'FAILED';
      const statusBadge = `<span class="badge badge-${isBlocked ? 'failed' : 'verified'}">${l.status}</span>`;

      return `
        <tr>
          <td style="font-family: var(--font-mono); color: var(--text-muted);">#${l.id}</td>
          <td><code style="color: var(--accent-cyan); font-weight: 600;">${l.action}</code></td>
          <td><b>${l.target_domain || 'System'}</b></td>
          <td style="font-size: 0.84rem; color: var(--text-secondary); max-width: 320px; word-break: break-all;">${l.details || ''}</td>
          <td style="font-family: var(--font-mono); font-size: 0.8rem; color: var(--text-muted);">${l.ip_address}</td>
          <td><span style="font-size: 0.82rem;">${l.user_identifier}</span></td>
          <td>${statusBadge}</td>
          <td style="color: var(--text-muted); font-size: 0.8rem; white-space: nowrap;">${l.created_at}</td>
        </tr>
      `;
    }).join('');
  }
};
