/* app.js — Core Alpine.js application for ar.io Content Scanner Admin */

document.addEventListener('alpine:init', () => {
  Alpine.store('auth', {
    key: localStorage.getItem('scanner_admin_key') || '',
    authenticated: false,
    error: '',

    async login(key) {
      this.error = '';
      try {
        const resp = await fetch('/api/admin/stats', {
          headers: { 'Authorization': `Bearer ${key}` }
        });
        if (resp.status === 401) {
          this.error = 'Invalid API key';
          return false;
        }
        if (!resp.ok) {
          this.error = 'Connection error';
          return false;
        }
        this.key = key;
        this.authenticated = true;
        localStorage.setItem('scanner_admin_key', key);
        return true;
      } catch (e) {
        this.error = 'Cannot connect to scanner';
        return false;
      }
    },

    logout() {
      this.key = '';
      this.authenticated = false;
      localStorage.removeItem('scanner_admin_key');
    }
  });

  // Auto-login if key exists
  const stored = localStorage.getItem('scanner_admin_key');
  if (stored) {
    Alpine.store('auth').login(stored);
  }
});

/* Shared API helper */
async function api(path, options = {}) {
  const key = Alpine.store('auth').key;
  const resp = await fetch(path, {
    ...options,
    headers: {
      'Authorization': `Bearer ${key}`,
      ...(options.headers || {})
    }
  });
  if (resp.status === 401) {
    Alpine.store('auth').logout();
    throw new Error('Unauthorized');
  }
  return resp;
}

async function apiJson(path, options = {}) {
  const resp = await api(path, options);
  if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
  return resp.json();
}

/* Utility functions */
function formatUptime(seconds) {
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const mins = Math.floor((seconds % 3600) / 60);
  if (days > 0) return `${days}d ${hours}h`;
  if (hours > 0) return `${hours}h ${mins}m`;
  return `${mins}m`;
}

function formatTimestamp(unix) {
  if (!unix) return '—';
  return new Date(unix * 1000).toLocaleString();
}

function formatBytes(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / 1048576).toFixed(1) + ' MB';
}

function badgeClass(verdict) {
  return 'badge badge-' + (verdict || 'clean');
}

function scoreColor(score) {
  if (score === null || score === undefined) return 'var(--color-gray)';
  if (score >= 0.95) return 'var(--color-red)';
  if (score >= 0.5) return 'var(--color-amber)';
  return 'var(--color-green)';
}

function truncateId(id, len = 16) {
  if (!id || id.length <= len) return id || '—';
  return id.substring(0, len) + '...';
}

async function downloadCsv(path, filename) {
  const resp = await api(path);
  const blob = await resp.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}
