/**
 * SecureScan AI - Authorized Target Management System
 */
const TargetsManager = {
  currentStep: 1,
  activeTargetType: 'own',
  activeOwnMethod: 'dns_txt',
  cachedTargets: [],

  async loadTargets() {
    try {
      const resp = await fetch('/api/targets');
      const data = await resp.json();
      this.cachedTargets = data.targets || [];
      this.renderTargetsTable(this.cachedTargets);
    } catch (e) {
      App.showToast('Failed to load targets', 'error');
    }
  },

  renderTargetsTable(targets) {
    const tbody = document.getElementById('targets-table-body');
    if (!tbody) return;

    if (!targets || targets.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: var(--text-muted); padding: 2rem;">No authorized targets registered. Click '+ Add New Target' to verify a website.</td></tr>`;
      return;
    }

    tbody.innerHTML = targets.map(t => {
      const typeLabel = t.target_type === 'lab' ? 'Lab Target' : t.target_type === 'third_party' ? 'Third-Party' : 'Own Website';
      const badgeClass = t.status === 'verified' ? 'verified' : t.status === 'approved' ? 'approved' : t.status === 'pending' ? 'pending' : 'failed';
      
      let actionButtons = '';
      if (t.status === 'pending' && t.target_type === 'own') {
        actionButtons += `<button class="btn btn-primary btn-sm" onclick="TargetsManager.triggerVerify(${t.id})" style="margin-right: 0.4rem;">Verify Now</button>`;
      } else if (t.status === 'pending' && t.target_type === 'third_party') {
        actionButtons += `<button class="btn btn-primary btn-sm" onclick="TargetsManager.quickApproveThirdParty(${t.id})" title="Simulate authorizer link approval" style="margin-right: 0.4rem;">Approve (Demo)</button>`;
      }
      
      if (t.status === 'verified' || t.status === 'approved') {
        actionButtons += `<button class="btn btn-primary btn-sm" onclick="TargetsManager.launchScanForTarget(${t.id})" style="margin-right: 0.4rem;">Scan ⚡</button>`;
      }

      actionButtons += `<button class="btn btn-secondary btn-sm" onclick="TargetsManager.showTargetDetails(${t.id})" style="margin-right: 0.4rem;">Scope</button>`;
      actionButtons += `<button class="btn btn-danger btn-sm" onclick="TargetsManager.deleteTarget(${t.id})">🗑</button>`;

      return `
        <tr>
          <td><strong style="color: var(--accent-cyan);">${t.domain}</strong></td>
          <td><span style="font-size: 0.82rem; color: var(--text-secondary);">${typeLabel}</span></td>
          <td><span class="badge badge-${badgeClass}">${t.status}</span></td>
          <td><code>${t.verification_method || 'N/A'}</code></td>
          <td style="font-size: 0.8rem; max-width: 200px; word-break: break-all;">
            <div><span style="color: #34d399;">In:</span> ${t.in_scope_paths || '/*'}</div>
            ${t.out_of_scope_paths ? `<div><span style="color: #f87171;">Out:</span> ${t.out_of_scope_paths}</div>` : ''}
          </td>
          <td style="font-size: 0.82rem; color: ${t.is_expired ? 'var(--severity-critical)' : 'var(--text-muted)'};">
            ${t.expiry_countdown}
          </td>
          <td>${actionButtons}</td>
        </tr>
      `;
    }).join('');
  },

  openAddTargetModal() {
    this.currentStep = 1;
    this.goToStep(1);
    document.getElementById('modal-add-target').classList.add('active');
    this.updateOwnInstructions();
  },

  closeAddTargetModal() {
    document.getElementById('modal-add-target').classList.remove('active');
  },

  goToStep(stepNumber) {
    this.currentStep = stepNumber;

    // Update wizard step indicators
    for (let i = 1; i <= 3; i++) {
      const dot = document.getElementById(`step-dot-${i}`);
      const content = document.getElementById(`wizard-step-${i}`);
      if (i < stepNumber) {
        dot.className = 'step-item completed';
        content.classList.remove('active');
      } else if (i === stepNumber) {
        dot.className = 'step-item active';
        content.classList.add('active');
      } else {
        dot.className = 'step-item';
        content.classList.remove('active');
      }
    }

    if (stepNumber === 2) {
      this.handleTypeChange(document.getElementById('target-type-select').value);
    }
  },

  handleTypeChange(type) {
    this.activeTargetType = type;
    document.getElementById('subpanel-own').style.display = type === 'own' ? 'block' : 'none';
    document.getElementById('subpanel-third-party').style.display = type === 'third_party' ? 'block' : 'none';
    document.getElementById('subpanel-lab').style.display = type === 'lab' ? 'block' : 'none';
    if (type === 'own') {
      this.updateOwnInstructions();
    }
  },

  toggleOwnMethod(method) {
    this.activeOwnMethod = method;
    this.updateOwnInstructions();
  },

  updateOwnInstructions() {
    const box = document.getElementById('own-instructions-box');
    const domain = document.getElementById('target-domain-input').value.trim() || 'yourdomain.com';
    const sampleToken = 'sscan_verify_token_sample';

    if (this.activeOwnMethod === 'dns_txt') {
      box.innerHTML = `
        <div style="font-size: 0.86rem; margin-bottom: 0.5rem;"><b>DNS TXT Verification Instructions:</b></div>
        <div style="font-size: 0.82rem; color: var(--text-secondary); margin-bottom: 0.6rem;">
          Add a TXT record to <code>${domain}</code> with the following verification token:
        </div>
        <div style="background: rgba(0,0,0,0.4); padding: 0.5rem; border-radius: 4px; font-family: var(--font-mono); font-size: 0.82rem; color: var(--accent-cyan); display: flex; justify-content: space-between; align-items: center;">
          <span>securescan-verify=&lt;system-token&gt;</span>
          <span style="font-size: 0.72rem; color: var(--text-muted);">(Generated upon saving)</span>
        </div>
      `;
    } else if (this.activeOwnMethod === 'html_meta') {
      box.innerHTML = `
        <div style="font-size: 0.86rem; margin-bottom: 0.5rem;"><b>HTML Meta Tag Instructions:</b></div>
        <div style="font-size: 0.82rem; color: var(--text-secondary); margin-bottom: 0.6rem;">
          Place this HTML meta tag inside the <code>&lt;head&gt;</code> section of your homepage (<code>https://${domain}/</code>):
        </div>
        <div style="background: rgba(0,0,0,0.4); padding: 0.5rem; border-radius: 4px; font-family: var(--font-mono); font-size: 0.8rem; color: var(--accent-cyan);">
          &lt;meta name="securescan-verification" content="&lt;system-token&gt;"&gt;
        </div>
      `;
    } else {
      box.innerHTML = `
        <div style="font-size: 0.86rem; margin-bottom: 0.5rem;"><b>File Upload Verification:</b></div>
        <div style="font-size: 0.82rem; color: var(--text-secondary); margin-bottom: 0.6rem;">
          Create a plaintext file hosted publicly at:
        </div>
        <div style="background: rgba(0,0,0,0.4); padding: 0.5rem; border-radius: 4px; font-family: var(--font-mono); font-size: 0.8rem; color: var(--accent-cyan); margin-bottom: 0.4rem;">
          https://${domain}/.well-known/securescan-verify.txt
        </div>
        <div style="font-size: 0.8rem; color: var(--text-muted);">The file must contain your generated verification token.</div>
      `;
    }
  },

  async submitNewTarget() {
    const domain = document.getElementById('target-domain-input').value.trim();
    const targetType = document.getElementById('target-type-select').value;
    const inScope = document.getElementById('target-in-scope').value.trim() || '/*';
    const outScope = document.getElementById('target-out-scope').value.trim() || '/admin,/payment,/logout';
    const intensity = document.getElementById('target-intensity').value;
    const maxReq = document.getElementById('target-max-req').value;

    if (!domain) {
      App.showToast('Target domain is required', 'error');
      this.goToStep(1);
      return;
    }

    try {
      // 1. Create target record
      const resp = await fetch('/api/targets', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          domain: domain,
          target_type: targetType,
          verification_method: targetType === 'own' ? this.activeOwnMethod : targetType === 'lab' ? 'preapproved' : 'written_auth',
          in_scope_paths: inScope,
          out_of_scope_paths: outScope,
          allowed_intensity: intensity,
          max_requests_per_sec: maxReq
        })
      });

      const resData = await resp.json();
      if (!resp.ok) {
        App.showToast(resData.error || 'Failed to add target', 'error');
        return;
      }

      const targetId = resData.target_id;

      // 2. If Third-Party, submit written authorization form
      if (targetType === 'third_party') {
        const formData = new FormData();
        formData.append('authorizer_name', document.getElementById('auth-name').value);
        formData.append('authorizer_designation', document.getElementById('auth-designation').value);
        formData.append('authorizer_org', document.getElementById('auth-org').value);
        formData.append('authorizer_email', document.getElementById('auth-email').value);
        formData.append('testing_window_start', document.getElementById('auth-win-start').value || new Date().toISOString().slice(0, 19).replace('T', ' '));
        
        // Default 30 days window if not selected
        const d30 = new Date();
        d30.setDate(d30.getDate() + 30);
        formData.append('testing_window_end', document.getElementById('auth-win-end').value || d30.toISOString().slice(0, 19).replace('T', ' '));
        
        formData.append('in_scope_paths', inScope);
        formData.append('out_of_scope_paths', outScope);
        formData.append('allowed_intensity', intensity);
        formData.append('max_requests_per_sec', maxReq);
        formData.append('decl_written_permission', document.getElementById('auth-decl-1').checked ? '1' : '');
        formData.append('decl_legal_responsibility', document.getElementById('auth-decl-2').checked ? '1' : '');
        formData.append('decl_no_exploitation', document.getElementById('auth-decl-3').checked ? '1' : '');

        const fileInput = document.getElementById('auth-proof-file');
        if (fileInput.files.length > 0) {
          formData.append('proof_document', fileInput.files[0]);
        }

        const authResp = await fetch(`/api/targets/${targetId}/authorization`, {
          method: 'POST',
          body: formData
        });
        const authData = await authResp.json();
        if (!authResp.ok) {
          App.showToast(`Target created, but authorization form had error: ${authData.error}`, 'warning');
        } else {
          App.showToast('Written authorization submitted! Approval link generated.', 'success');
        }
      } else if (targetType === 'own') {
        App.showToast(`Target registered. Your verification token is: ${resData.verification_token}`, 'info');
      } else {
        App.showToast('Educational lab target registered and verified!', 'success');
      }

      this.closeAddTargetModal();
      this.loadTargets();
    } catch (e) {
      App.showToast('Network error while creating target: ' + e.message, 'error');
    }
  },

  async triggerVerify(targetId) {
    App.showToast('Executing ownership verification check...', 'info');
    try {
      const resp = await fetch(`/api/targets/${targetId}/verify`, { method: 'POST' });
      const data = await resp.json();
      if (resp.ok) {
        App.showToast('Ownership verified successfully!', 'success');
      } else {
        App.showToast(`Verification failed: ${data.message}`, 'error');
      }
      this.loadTargets();
    } catch (e) {
      App.showToast('Verification request error', 'error');
    }
  },

  async quickApproveThirdParty(targetId) {
    try {
      const resp = await fetch(`/api/targets/${targetId}/manual-approve`, { method: 'POST' });
      const data = await resp.json();
      App.showToast(data.message || 'Target approved', 'success');
      this.loadTargets();
    } catch (e) {
      App.showToast('Failed to approve target', 'error');
    }
  },

  async deleteTarget(targetId) {
    if (!confirm('Are you sure you want to delete this target and all associated scans?')) return;
    try {
      await fetch(`/api/targets/${targetId}`, { method: 'DELETE' });
      App.showToast('Target deleted', 'info');
      this.loadTargets();
    } catch (e) {
      App.showToast('Delete error', 'error');
    }
  },

  showTargetDetails(targetId) {
    const t = this.cachedTargets.find(x => x.id === targetId);
    if (!t) return;
    alert(`Target Scope & Authorization:\n\nDomain: ${t.domain}\nType: ${t.target_type}\nStatus: ${t.status}\nIn-Scope: ${t.in_scope_paths}\nOut-of-Scope: ${t.out_of_scope_paths}\nMax Intensity: ${t.allowed_intensity}\nRate Limit: ${t.max_requests_per_sec} req/s`);
  },

  launchScanForTarget(targetId) {
    App.navigate('new-scan');
    setTimeout(() => {
      const select = document.getElementById('scan-target-select');
      if (select) {
        select.value = targetId;
        ScanManager.handleTargetSelected(targetId);
      }
    }, 150);
  }
};
