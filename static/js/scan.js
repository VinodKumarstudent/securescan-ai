/**
 * SecureScan AI - Scan Orchestration & Live Telemetry Poller
 */
const ScanManager = {
  activeScanId: null,
  pollTimer: null,
  verifiedTargets: [],

  async loadVerifiedTargets() {
    try {
      const resp = await fetch('/api/targets');
      const data = await resp.json();
      const allTargets = data.targets || [];
      
      // Filter for verified or approved targets ONLY
      this.verifiedTargets = allTargets.filter(t => t.status === 'verified' || t.status === 'approved');

      const select = document.getElementById('scan-target-select');
      if (!select) return;

      if (this.verifiedTargets.length === 0) {
        select.innerHTML = '<option value="">No verified targets available. Add & verify one first.</option>';
        return;
      }

      select.innerHTML = '<option value="">-- Choose an authorized target --</option>' + 
        this.verifiedTargets.map(t => `<option value="${t.id}">${t.domain} (${t.target_type.toUpperCase()} - ${t.status.toUpperCase()})</option>`).join('');

      // If a target was pre-selected, update summary
      if (select.value) {
        this.handleTargetSelected(select.value);
      }
    } catch (e) {
      console.error('Failed to load verified targets:', e);
    }
  },

  extractDomainFromUrl(url) {
    if (!url) return '';
    try {
      let testUrl = url.trim();
      if (!testUrl.startsWith('http://') && !testUrl.startsWith('https://')) {
        testUrl = 'http://' + testUrl;
      }
      const parsed = new URL(testUrl);
      return parsed.hostname.toLowerCase();
    } catch (e) {
      return '';
    }
  },

  handleUrlInput() {
    const urlInput = document.getElementById('scan-target-url');
    const select = document.getElementById('scan-target-select');
    const alertBox = document.getElementById('scan-scope-mismatch-alert');
    if (!urlInput || !select) return;

    const typedDomain = this.extractDomainFromUrl(urlInput.value);
    if (!typedDomain) {
      if (alertBox) alertBox.style.display = 'none';
      return;
    }

    const currentTarget = this.verifiedTargets.find(x => x.id == select.value);

    // Check if typed domain directly matches another authorized target
    const matchingTarget = this.verifiedTargets.find(t => {
      const cleanDom = t.domain.split(':')[0].toLowerCase();
      return cleanDom === typedDomain || typedDomain.endsWith('.' + cleanDom);
    });

    // Auto-switch target dropdown if user typed/pasted a different authorized target URL
    if (matchingTarget && (!currentTarget || matchingTarget.id != currentTarget.id)) {
      select.value = matchingTarget.id;
      this.handleTargetSelected(matchingTarget.id, false); // false = keep typed URL
      if (alertBox) {
        alertBox.style.display = 'block';
        alertBox.style.backgroundColor = 'rgba(56, 189, 248, 0.12)';
        alertBox.style.border = '1px solid rgba(56, 189, 248, 0.4)';
        alertBox.style.color = '#38bdf8';
        alertBox.style.padding = '0.5rem 0.75rem';
        alertBox.style.borderRadius = '6px';
        alertBox.style.fontSize = '0.82rem';
        alertBox.innerHTML = `🎯 <b>Auto-selected authorized target:</b> ${matchingTarget.domain}`;
        setTimeout(() => { if (alertBox) alertBox.style.display = 'none'; }, 4000);
      }
      return;
    }

    // If current target doesn't match typed domain
    if (currentTarget) {
      const currentDomain = currentTarget.domain.split(':')[0].toLowerCase();
      if (currentDomain !== typedDomain && !typedDomain.endsWith('.' + currentDomain)) {
        if (alertBox) {
          alertBox.style.display = 'block';
          alertBox.style.backgroundColor = 'rgba(239, 68, 68, 0.12)';
          alertBox.style.border = '1px solid rgba(239, 68, 68, 0.4)';
          alertBox.style.color = '#fca5a5';
          alertBox.style.padding = '0.5rem 0.75rem';
          alertBox.style.borderRadius = '6px';
          alertBox.style.fontSize = '0.82rem';
          alertBox.innerHTML = `⚠️ <b>Target Mismatch:</b> You selected <b>${currentTarget.domain}</b> above, but entered a URL for <b>${typedDomain}</b>.<br>To fix: select <b>${typedDomain}</b> from the dropdown above, or add it in <a href="#targets" onclick="App.navigate('targets')" style="color: #67e8f9; text-decoration: underline;">Authorized Targets</a>.`;
        }
        return;
      }
    }

    if (alertBox) alertBox.style.display = 'none';
  },

  handleTargetSelected(targetId, updateUrl = true) {
    const summaryBox = document.getElementById('target-scope-details');
    const urlInput = document.getElementById('scan-target-url');
    const alertBox = document.getElementById('scan-scope-mismatch-alert');
    if (!targetId) {
      summaryBox.innerHTML = '<div style="text-align: center; padding: 2rem 1rem; color: var(--text-muted);">Select an authorized target from the dropdown to review scope limits, allowed testing windows, and rate quotas.</div>';
      return;
    }

    const t = this.verifiedTargets.find(x => x.id == targetId);
    if (!t) return;

    // Automatically synchronize URL field with selected target
    if (urlInput && updateUrl) {
      const isLocal = t.domain.includes('localhost') || t.domain.includes('127.0.0.1');
      const proto = isLocal ? 'http://' : (t.domain.includes('vulnweb') ? 'http://' : 'https://');
      const defaultPath = isLocal ? '/lab/test-page' : '/';
      urlInput.value = `${proto}${t.domain}${defaultPath}`;
      if (alertBox) alertBox.style.display = 'none';
    }

    // Render scope summary
    summaryBox.innerHTML = `
      <div style="display: flex; flex-direction: column; gap: 0.75rem;">
        <div style="display: flex; justify-content: space-between; border-bottom: 1px solid var(--glass-border); padding-bottom: 0.5rem;">
          <span style="color: var(--text-muted);">Target Domain:</span>
          <span style="font-weight: 700; color: var(--accent-cyan);">${t.domain}</span>
        </div>
        <div style="display: flex; justify-content: space-between; border-bottom: 1px solid var(--glass-border); padding-bottom: 0.5rem;">
          <span style="color: var(--text-muted);">Target Status:</span>
          <span class="badge badge-${t.status}">${t.status}</span>
        </div>
        <div style="border-bottom: 1px solid var(--glass-border); padding-bottom: 0.5rem;">
          <span style="color: var(--text-muted); display: block; margin-bottom: 0.2rem;">Authorized In-Scope Paths:</span>
          <code style="color: #34d399; font-size: 0.82rem;">${t.in_scope_paths || '/*'}</code>
        </div>
        <div style="border-bottom: 1px solid var(--glass-border); padding-bottom: 0.5rem;">
          <span style="color: var(--text-muted); display: block; margin-bottom: 0.2rem;">Excluded Out-of-Scope Paths:</span>
          <code style="color: #f87171; font-size: 0.82rem;">${t.out_of_scope_paths || 'None'}</code>
        </div>
        <div style="display: flex; justify-content: space-between; border-bottom: 1px solid var(--glass-border); padding-bottom: 0.5rem;">
          <span style="color: var(--text-muted);">Max Intensity:</span>
          <span><b>${t.allowed_intensity || 'Standard'}</b></span>
        </div>
        <div style="display: flex; justify-content: space-between;">
          <span style="color: var(--text-muted);">Testing Authorization Expiry:</span>
          <span style="font-size: 0.82rem; color: var(--text-primary);">${t.expiry_countdown}</span>
        </div>
      </div>
    `;

    // Cap intensity dropdown if target specifies Passive or Light
    const intensitySelect = document.getElementById('scan-intensity');
    if (intensitySelect && t.allowed_intensity) {
      if (t.allowed_intensity === 'Passive') {
        intensitySelect.value = 'Passive';
      } else if (t.allowed_intensity === 'Light' && intensitySelect.value === 'Standard') {
        intensitySelect.value = 'Light';
      }
    }
  },

  async handleScanSubmit(e) {
    e.preventDefault();
    const targetId = document.getElementById('scan-target-select').value;
    const targetUrl = document.getElementById('scan-target-url').value.trim();
    const scanType = document.getElementById('scan-profile').value;
    const intensity = document.getElementById('scan-intensity').value;
    const authChecked = document.getElementById('scan-auth-checkbox').checked;

    if (!targetId) {
      App.showToast('Please select a verified target.', 'error');
      return;
    }
    if (!authChecked) {
      App.showToast('You must check the authorization affirmation.', 'error');
      return;
    }

    // Client-side domain match check
    const targetObj = this.verifiedTargets.find(x => x.id == targetId);
    const typedDomain = this.extractDomainFromUrl(targetUrl);
    if (targetObj && typedDomain) {
      const authDomain = targetObj.domain.split(':')[0].toLowerCase();
      if (typedDomain !== authDomain && !typedDomain.endsWith('.' + authDomain)) {
        App.showToast(`Domain Mismatch: Target selected is '${targetObj.domain}', but URL is for '${typedDomain}'. Please select '${typedDomain}' in the dropdown.`, 'error');
        return;
      }
    }

    try {
      const resp = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target_id: parseInt(targetId),
          target_url: targetUrl,
          scan_type: scanType,
          intensity: intensity,
          authorized_declaration: true
        })
      });

      const data = await resp.json();
      if (!resp.ok) {
        App.showToast(`Scan Blocked (HTTP ${resp.status}): ${data.error}`, 'error');
        return;
      }

      App.showToast('Scan launched successfully!', 'success');
      this.activeScanId = data.scan_id;

      // Reveal Live Scan tab and navigate
      document.getElementById('nav-live-scan').style.display = 'flex';
      App.navigate('live-scan');

      this.startLiveMonitoring(this.activeScanId);
    } catch (e) {
      App.showToast('Error initiating scan: ' + e.message, 'error');
    }
  },

  startLiveMonitoring(scanId) {
    if (this.pollTimer) {
      clearInterval(this.pollTimer);
    }

    document.getElementById('live-scan-title').innerText = `Scan #${scanId} in Progress`;
    document.getElementById('btn-stop-scan').style.display = 'inline-flex';
    document.getElementById('btn-view-results').style.display = 'none';

    // Reset progress
    document.getElementById('live-progress-bar').style.width = '0%';
    document.getElementById('live-progress-pct').innerText = '0%';
    document.getElementById('live-terminal-logs').innerHTML = '';
    document.getElementById('live-findings-list').innerHTML = '';

    const poll = async () => {
      try {
        const resp = await fetch(`/api/scan/${scanId}/status`);
        if (!resp.ok) return;
        const data = await resp.json();

        // Update progress bar
        const pct = Math.min(100, Math.max(0, data.progress || 0));
        document.getElementById('live-progress-bar').style.width = `${pct}%`;
        document.getElementById('live-progress-pct').innerText = `${pct}%`;
        document.getElementById('live-active-module').innerText = data.current_module || 'Analyzing...';

        // Update logs
        if (data.logs && data.logs.length > 0) {
          const logHtml = data.logs.map(l => {
            const timeStr = l.timestamp.split(' ')[1] || l.timestamp;
            return `<div class="terminal-line"><span class="time">[${timeStr}]</span> <span class="level-${l.level}">[${l.level}]</span> ${l.message}</div>`;
          }).join('');
          const term = document.getElementById('live-terminal-logs');
          term.innerHTML = logHtml;
          term.scrollTop = term.scrollHeight;
        }

        // Update live findings list
        document.getElementById('live-findings-count').innerText = data.findings_count || 0;
        if (data.findings && data.findings.length > 0) {
          document.getElementById('live-findings-list').innerHTML = data.findings.map(f => {
            const sevClass = f.severity.toLowerCase();
            return `
              <div style="background: rgba(15, 23, 42, 0.5); border: 1px solid var(--glass-border); border-left: 3px solid var(--severity-${sevClass}); padding: 0.6rem 0.8rem; border-radius: 4px; margin-bottom: 0.5rem; display: flex; justify-content: space-between; align-items: center;">
                <div>
                  <div style="font-weight: 600; font-size: 0.86rem; color: var(--text-primary);">${f.title}</div>
                  <div style="font-size: 0.78rem; color: var(--text-muted);">${f.affected_url}</div>
                </div>
                <span class="badge badge-${sevClass}">${f.severity}</span>
              </div>
            `;
          }).join('');
        }

        // Check if finished
        if (data.status === 'completed' || data.status === 'stopped' || data.status === 'failed') {
          clearInterval(this.pollTimer);
          this.pollTimer = null;
          document.getElementById('btn-stop-scan').style.display = 'none';
          document.getElementById('btn-view-results').style.display = 'inline-flex';
          document.getElementById('live-scan-title').innerText = `Scan #${scanId} ${data.status.toUpperCase()}`;
          App.showToast(`Scan #${scanId} finished with status: ${data.status}`, data.status === 'completed' ? 'success' : 'warning');
        }
      } catch (e) {
        console.error('Polling error:', e);
      }
    };

    // Immediate first poll then interval
    poll();
    this.pollTimer = setInterval(poll, 1000);
  },

  async stopActiveScan() {
    if (!this.activeScanId) return;
    try {
      await fetch(`/api/scan/${this.activeScanId}/stop`, { method: 'POST' });
      App.showToast('Stop signal transmitted.', 'warning');
    } catch (e) {
      App.showToast('Failed to stop scan', 'error');
    }
  },

  viewActiveResults() {
    if (this.activeScanId) {
      ResultsManager.viewScan(this.activeScanId);
    }
  }
};
