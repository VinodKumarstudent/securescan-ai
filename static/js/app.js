/**
 * SecureScan AI - Main Core Application & Router
 */
const App = {
  currentPage: 'dashboard',

  init() {
    this.bindEvents();
    this.handleRoute();
    ScreenManager.init();
    // Load initial dashboard stats
    DashboardManager.loadStats();
  },

  bindEvents() {
    // Navigation items
    document.querySelectorAll('.nav-item').forEach(item => {
      item.addEventListener('click', (e) => {
        const page = item.getAttribute('data-page');
        if (page) {
          this.navigate(page);
        }
      });
    });

    // Sidebar toggle (handles desktop collapse & mobile drawer)
    const sidebarToggle = document.getElementById('sidebar-toggle');
    const sidebar = document.getElementById('sidebar');
    const backdrop = document.getElementById('sidebar-backdrop');
    if (sidebarToggle && sidebar) {
      sidebarToggle.addEventListener('click', () => {
        if (window.innerWidth <= 768) {
          sidebar.classList.toggle('open');
          if (backdrop) backdrop.classList.toggle('active');
        } else {
          sidebar.classList.toggle('collapsed');
        }
      });
    }

    if (backdrop && sidebar) {
      backdrop.addEventListener('click', () => {
        sidebar.classList.remove('open');
        backdrop.classList.remove('active');
      });
    }

    // Auto-close sidebar drawer on mobile upon page click
    document.querySelectorAll('.nav-item').forEach(item => {
      item.addEventListener('click', () => {
        if (window.innerWidth <= 768 && sidebar) {
          sidebar.classList.remove('open');
          if (backdrop) backdrop.classList.remove('active');
        }
      });
    });

    // Theme toggle
    const themeToggle = document.getElementById('theme-toggle');
    if (themeToggle) {
      themeToggle.addEventListener('click', () => {
        const html = document.documentElement;
        const currentTheme = html.getAttribute('data-theme') || 'dark';
        const nextTheme = currentTheme === 'dark' ? 'light' : 'dark';
        html.setAttribute('data-theme', nextTheme);
      });
    }

    // Handle browser back/forward buttons
    window.addEventListener('hashchange', () => this.handleRoute());
  },

  navigate(pageId) {
    window.location.hash = pageId;
    this.showPage(pageId);
  },

  handleRoute() {
    const hash = window.location.hash.replace('#', '') || 'dashboard';
    this.showPage(hash);
  },

  showPage(pageId) {
    this.currentPage = pageId;

    // Update active nav item
    document.querySelectorAll('.nav-item').forEach(item => {
      if (item.getAttribute('data-page') === pageId) {
        item.classList.add('active');
      } else {
        item.classList.remove('active');
      }
    });

    // Update active page view
    document.querySelectorAll('.page-view').forEach(view => {
      view.classList.remove('active');
    });

    const targetView = document.getElementById(`page-${pageId}`);
    if (targetView) {
      targetView.classList.add('active');
    }

    // Update Topbar title
    const titles = {
      'dashboard': 'Dashboard Overview',
      'targets': 'Authorized Target Management',
      'new-scan': 'Launch Authorized Scan',
      'live-scan': 'Live Scan Execution & Telemetry',
      'scan-results': 'Vulnerability Assessment Results',
      'history': 'Scan Assessment History',
      'compliance': 'Compliance & Audit Trail',
      'settings': 'System Settings & Kill Switch',
      'about': 'About & Legal Compliance'
    };
    const titleElem = document.getElementById('current-page-title');
    if (titleElem) {
      titleElem.innerText = titles[pageId] || 'SecureScan AI';
    }

    // Page-specific initialization hooks
    if (pageId === 'dashboard') {
      DashboardManager.loadStats();
    } else if (pageId === 'targets') {
      TargetsManager.loadTargets();
    } else if (pageId === 'new-scan') {
      ScanManager.loadVerifiedTargets();
    } else if (pageId === 'history') {
      HistoryManager.loadHistory();
    } else if (pageId === 'compliance') {
      ComplianceManager.loadAuditLogs();
    } else if (pageId === 'settings') {
      SettingsManager.loadSettings();
    }
  },

  showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    const icon = type === 'success' ? '✓' : type === 'error' ? '⚠' : 'ℹ';
    toast.innerHTML = `<span>${icon}</span> <span>${message}</span>`;
    container.appendChild(toast);

    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateX(100%)';
      setTimeout(() => toast.remove(), 300);
    }, 4000);
  }
};

// Global Settings Manager
const SettingsManager = {
  async loadSettings() {
    try {
      const resp = await fetch('/api/settings');
      const data = await resp.json();
      document.getElementById('setting-contact-email').value = data.contact_email || '';
      
      const killBtn = document.getElementById('kill-switch-toggle');
      if (data.kill_switch) {
        killBtn.innerText = 'Kill Switch: ACTIVE (All Scans Blocked)';
        killBtn.className = 'btn btn-danger';
        killBtn.style.boxShadow = '0 0 15px #ef4444';
      } else {
        killBtn.innerText = 'Kill Switch: OFF';
        killBtn.className = 'btn btn-secondary';
        killBtn.style.boxShadow = 'none';
      }
    } catch (e) {
      App.showToast('Failed to load settings', 'error');
    }
  },

  async toggleKillSwitch() {
    try {
      const resp = await fetch('/api/settings');
      const data = await resp.json();
      const newState = !data.kill_switch;

      await fetch('/api/settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ kill_switch: newState })
      });

      this.loadSettings();
      App.showToast(newState ? 'Emergency Kill Switch ACTIVATED.' : 'Kill Switch deactivated.', newState ? 'error' : 'success');
    } catch (e) {
      App.showToast('Error toggling kill switch', 'error');
    }
  },

  async saveSettings(e) {
    e.preventDefault();
    const email = document.getElementById('setting-contact-email').value.trim();
    const key = document.getElementById('setting-openai-key').value.trim();

    try {
      const resp = await fetch('/api/settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ contact_email: email, openai_api_key: key })
      });
      if (resp.ok) {
        App.showToast('Settings saved successfully.', 'success');
      }
    } catch (e) {
      App.showToast('Failed to save settings', 'error');
    }
  }
};

/**
 * Screen & Multi-Device Adaptation Manager
 * Handles live responsive detection, density, zoom scaling, and device presets.
 */
const ScreenManager = {
  currentPreset: 'auto',
  currentZoom: 100,
  currentDensity: 'comfortable',

  init() {
    // 1. Restore persisted zoom and density from localStorage
    const savedZoom = localStorage.getItem('securescan_ui_zoom');
    if (savedZoom) {
      this.setZoom(parseInt(savedZoom, 10), false);
    }

    const savedDensity = localStorage.getItem('securescan_ui_density');
    if (savedDensity) {
      this.setDensity(savedDensity, false);
    }

    const savedPreset = localStorage.getItem('securescan_ui_preset') || 'auto';
    this.setPreset(savedPreset, false);

    // 2. Initial resolution and device detection
    this.updateDetection();

    // 3. Listen to window resize and orientation events
    window.addEventListener('resize', () => {
      this.updateDetection();
      if (this.currentPreset === 'auto') {
        this.applyAutoAdaptation();
      }
    });

    window.addEventListener('orientationchange', () => {
      setTimeout(() => this.updateDetection(), 200);
    });

    // 4. Listen to HTML5 Fullscreen state changes
    document.addEventListener('fullscreenchange', () => {
      const isFs = !!document.fullscreenElement;
      const fsIcon = document.getElementById('fullscreen-icon');
      const fsText = document.getElementById('fullscreen-text');
      if (fsIcon) fsIcon.textContent = isFs ? '🗗' : '⛶';
      if (fsText) fsText.textContent = isFs ? 'Exit Fullscreen' : 'Fullscreen';
    });
  },

  updateDetection() {
    const w = window.innerWidth;
    const h = window.innerHeight;
    const dpr = window.devicePixelRatio || 1;
    const pill = document.getElementById('topbar-device-pill');
    const resText = document.getElementById('screen-detected-resolution');
    const typeBadge = document.getElementById('screen-detected-type');

    let devType = 'Desktop';
    if (w <= 480) devType = 'Phone';
    else if (w <= 768) devType = 'Mobile';
    else if (w <= 1024) devType = 'Tablet';
    else if (w <= 1440) devType = 'Laptop';
    else devType = 'Widescreen';

    if (pill) {
      pill.textContent = `${devType} (${w}px)`;
    }
    if (resText) {
      resText.textContent = `${w} × ${h} px @ ${dpr.toFixed(1)}x DPR`;
    }
    if (typeBadge) {
      typeBadge.textContent = devType;
    }
  },

  applyAutoAdaptation() {
    const w = window.innerWidth;
    const root = document.documentElement;
    root.classList.remove('preset-force-mobile', 'preset-force-tablet', 'preset-force-laptop', 'preset-force-desktop');

    if (w <= 600) {
      this.setDensity('compact', false);
    } else if (w >= 1600) {
      this.setDensity('spacious', false);
    } else {
      this.setDensity('comfortable', false);
    }
  },

  openModal() {
    this.updateDetection();
    const modal = document.getElementById('modal-screen-adjust');
    if (modal) modal.classList.add('active');
  },

  closeModal() {
    const modal = document.getElementById('modal-screen-adjust');
    if (modal) modal.classList.remove('active');
  },

  setPreset(preset, save = true) {
    this.currentPreset = preset;
    if (save) localStorage.setItem('securescan_ui_preset', preset);

    document.querySelectorAll('.preset-btn').forEach(b => b.classList.remove('active'));
    const btn = document.getElementById(`preset-${preset}`);
    if (btn) btn.classList.add('active');

    const root = document.documentElement;
    root.classList.remove('preset-force-mobile', 'preset-force-tablet', 'preset-force-laptop', 'preset-force-desktop');

    if (preset === 'auto') {
      this.applyAutoAdaptation();
      if (save) App.showToast('Display set to Auto-Detect mode.', 'info');
    } else if (preset === 'mobile') {
      root.classList.add('preset-force-mobile');
      this.setDensity('compact', false);
      if (save) App.showToast('Applied Mobile Phone display preset.', 'info');
    } else if (preset === 'tablet') {
      root.classList.add('preset-force-tablet');
      this.setDensity('comfortable', false);
      if (save) App.showToast('Applied Tablet display preset.', 'info');
    } else if (preset === 'laptop') {
      root.classList.add('preset-force-laptop');
      this.setDensity('comfortable', false);
      if (save) App.showToast('Applied Standard Laptop display preset.', 'info');
    } else if (preset === 'desktop') {
      root.classList.add('preset-force-desktop');
      this.setDensity('spacious', false);
      if (save) App.showToast('Applied Widescreen Desktop display preset.', 'info');
    }
  },

  handleZoomInput(val) {
    this.setZoom(parseInt(val, 10));
  },

  setZoom(val, save = true) {
    val = Math.max(70, Math.min(140, val));
    this.currentZoom = val;
    if (save) localStorage.setItem('securescan_ui_zoom', val);

    const slider = document.getElementById('screen-zoom-slider');
    const badge = document.getElementById('screen-zoom-value');
    if (slider) slider.value = val;
    if (badge) badge.textContent = `${val}%`;

    const root = document.documentElement;
    root.style.setProperty('--ui-zoom', `${val}%`);
    document.body.style.zoom = `${val}%`;
  },

  setDensity(density, save = true) {
    this.currentDensity = density;
    if (save) localStorage.setItem('securescan_ui_density', density);

    const root = document.documentElement;
    root.setAttribute('data-density', density);

    ['compact', 'comfortable', 'spacious'].forEach(d => {
      const b = document.getElementById(`density-${d}`);
      if (b) {
        if (d === density) {
          b.classList.remove('btn-secondary');
          b.classList.add('btn-primary');
        } else {
          b.classList.remove('btn-primary');
          b.classList.add('btn-secondary');
        }
      }
    });
  },

  toggleFullscreen() {
    if (!document.fullscreenElement) {
      document.documentElement.requestFullscreen().catch(err => {
        App.showToast(`Fullscreen request: ${err.message}`, 'error');
      });
    } else {
      if (document.exitFullscreen) {
        document.exitFullscreen();
      }
    }
  },

  resetDefaults() {
    this.setZoom(100);
    this.setPreset('auto');
    this.setDensity('comfortable');
    App.showToast('Display settings reset to default.', 'success');
  }
};

document.addEventListener('DOMContentLoaded', () => {
  App.init();
});
