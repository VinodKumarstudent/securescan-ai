/**
 * SecureScan AI - Main Core Application & Router
 */
const App = {
  currentPage: 'dashboard',

  init() {
    this.bindEvents();
    this.handleRoute();
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

    // Sidebar collapse toggle
    const sidebarToggle = document.getElementById('sidebar-toggle');
    if (sidebarToggle) {
      sidebarToggle.addEventListener('click', () => {
        document.getElementById('sidebar').classList.toggle('collapsed');
      });
    }

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

document.addEventListener('DOMContentLoaded', () => {
  App.init();
});
