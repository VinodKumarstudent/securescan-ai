/**
 * SecureScan AI - Dashboard Metrics & Interactive Visualizations
 */
const DashboardManager = {
  charts: {},

  async loadStats() {
    try {
      const resp = await fetch('/api/stats');
      const data = await resp.json();

      // Animate stat counters
      this.animateCounter('stat-total-scans', data.total_scans);
      this.animateCounter('stat-total-vulns', data.total_vulnerabilities);
      this.animateCounter('stat-critical-vulns', data.critical_issues);
      this.animateCounter('stat-avg-risk', data.avg_risk_score, true);

      // Render Charts
      this.renderSeverityChart(data.severity_distribution);
      this.renderTimelineChart(data.timeline);
      this.renderOwaspChart(data.owasp_distribution);

      // Render Recent Scans
      this.renderRecentScans(data.recent_scans);
    } catch (e) {
      console.error('Error loading dashboard stats:', e);
    }
  },

  animateCounter(elemId, targetVal, isDecimal = false) {
    const elem = document.getElementById(elemId);
    if (!elem) return;
    const start = 0;
    const duration = 800;
    const startTime = performance.now();

    function update(now) {
      const elapsed = now - startTime;
      const progress = Math.min(elapsed / duration, 1);
      const current = start + (targetVal - start) * progress;
      elem.innerText = isDecimal ? current.toFixed(1) : Math.floor(current);
      if (progress < 1) {
        requestAnimationFrame(update);
      } else {
        elem.innerText = isDecimal ? targetVal.toFixed(1) : targetVal;
      }
    }
    requestAnimationFrame(update);
  },

  renderSeverityChart(dist) {
    const ctx = document.getElementById('chart-severity');
    if (!ctx) return;

    if (this.charts.severity) {
      this.charts.severity.destroy();
    }

    this.charts.severity = new Chart(ctx, {
      type: 'doughnut',
      data: {
        labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
        datasets: [{
          data: [
            dist.Critical || 0,
            dist.High || 0,
            dist.Medium || 0,
            dist.Low || 0,
            dist.Info || 0
          ],
          backgroundColor: [
            '#ef4444',
            '#f97316',
            '#eab308',
            '#3b82f6',
            '#64748b'
          ],
          borderWidth: 2,
          borderColor: '#111827'
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: 'right',
            labels: { color: '#94a3b8', font: { size: 11 } }
          }
        },
        cutout: '70%'
      }
    });
  },

  renderTimelineChart(timeline) {
    const ctx = document.getElementById('chart-timeline');
    if (!ctx) return;

    if (this.charts.timeline) {
      this.charts.timeline.destroy();
    }

    this.charts.timeline = new Chart(ctx, {
      type: 'line',
      data: {
        labels: timeline.labels && timeline.labels.length ? timeline.labels : ['No Scans'],
        datasets: [{
          label: 'Vulnerabilities Identified',
          data: timeline.counts && timeline.counts.length ? timeline.counts : [0],
          borderColor: '#00f3ff',
          backgroundColor: 'rgba(0, 243, 255, 0.1)',
          fill: true,
          tension: 0.35,
          pointBackgroundColor: '#00f3ff',
          pointBorderColor: '#fff',
          pointRadius: 4
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false }
        },
        scales: {
          x: {
            grid: { color: 'rgba(255, 255, 255, 0.05)' },
            ticks: { color: '#94a3b8' }
          },
          y: {
            beginAtZero: true,
            grid: { color: 'rgba(255, 255, 255, 0.05)' },
            ticks: { color: '#94a3b8', stepSize: 1 }
          }
        }
      }
    });
  },

  renderOwaspChart(owasp) {
    const ctx = document.getElementById('chart-owasp');
    if (!ctx) return;

    if (this.charts.owasp) {
      this.charts.owasp.destroy();
    }

    this.charts.owasp = new Chart(ctx, {
      type: 'bar',
      data: {
        labels: owasp.labels && owasp.labels.length ? owasp.labels : ['No Findings'],
        datasets: [{
          data: owasp.counts && owasp.counts.length ? owasp.counts : [0],
          backgroundColor: '#9333ea',
          borderRadius: 4
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false }
        },
        scales: {
          x: {
            grid: { display: false },
            ticks: { color: '#94a3b8', font: { size: 10 } }
          },
          y: {
            beginAtZero: true,
            grid: { color: 'rgba(255, 255, 255, 0.05)' },
            ticks: { color: '#94a3b8', stepSize: 1 }
          }
        }
      }
    });
  },

  renderRecentScans(scans) {
    const tbody = document.getElementById('dashboard-recent-scans-body');
    if (!tbody) return;

    if (!scans || scans.length === 0) {
      tbody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">No recent scans found.</td></tr>`;
      return;
    }

    tbody.innerHTML = scans.map(s => {
      const statusBadge = `<span class="badge badge-${s.status === 'completed' ? 'verified' : s.status === 'running' ? 'pending' : 'failed'}">${s.status}</span>`;
      return `
        <tr>
          <td style="font-family: var(--font-mono); font-weight: 600;">#${s.id}</td>
          <td><b>${s.domain}</b></td>
          <td>${s.scan_type} / ${s.intensity}</td>
          <td>${statusBadge}</td>
          <td><span style="font-weight: 700;">${s.findings_count}</span> issues</td>
          <td style="font-family: var(--font-mono); font-weight: 700; color: ${s.risk_score >= 7.0 ? 'var(--severity-critical)' : 'var(--accent-cyan)'};">${s.risk_score}</td>
          <td style="color: var(--text-muted); font-size: 0.8rem;">${s.completed_at || s.created_at}</td>
          <td>
            <button class="btn btn-secondary btn-sm" onclick="ResultsManager.viewScan(${s.id})">Results →</button>
          </td>
        </tr>
      `;
    }).join('');
  }
};
