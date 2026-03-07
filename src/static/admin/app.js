/* app.js — Core Alpine.js application for ar.io Content Scanner Admin */

document.addEventListener('alpine:init', function () {
  // --- Auth Store ---
  Alpine.store('auth', {
    key: localStorage.getItem('scanner_admin_key') || '',
    authenticated: false,
    error: '',

    async login(key) {
      this.error = '';
      try {
        var resp = await fetch('/api/admin/stats', {
          headers: { 'Authorization': 'Bearer ' + key }
        });
        if (resp.status === 401) {
          this.error = 'Invalid admin key';
          return false;
        }
        if (!resp.ok) {
          this.error = 'Unable to connect to scanner';
          return false;
        }
        this.key = key;
        this.authenticated = true;
        localStorage.setItem('scanner_admin_key', key);
        Alpine.store('health').check();
        return true;
      } catch (e) {
        this.error = 'Cannot connect to scanner service';
        return false;
      }
    },

    logout() {
      this.key = '';
      this.authenticated = false;
      localStorage.removeItem('scanner_admin_key');
    }
  });

  // --- Health Store (for header mode/version) ---
  Alpine.store('health', {
    mode: '',
    version: '',
    loaded: false,
    async check() {
      try {
        var resp = await fetch('/health');
        if (!resp.ok) return;
        var data = await resp.json();
        this.mode = data.mode || '';
        this.version = data.version || '';
        this.loaded = true;
      } catch (e) { /* silently fail */ }
    }
  });

  // --- Toast Store ---
  Alpine.store('toast', {
    items: [],
    show: function (message, type) {
      type = type || 'success';
      var id = Date.now() + Math.random();
      this.items.push({ id: id, message: message, type: type });
      var self = this;
      setTimeout(function () {
        self.items = self.items.filter(function (t) { return t.id !== id; });
      }, 4000);
    }
  });

  // Auto-login if key exists
  var stored = localStorage.getItem('scanner_admin_key');
  if (stored) {
    Alpine.store('auth').login(stored);
  }
});

/* Shared API helper */
async function api(path, options) {
  options = options || {};
  var key = Alpine.store('auth').key;
  var headers = Object.assign(
    {},
    { 'Authorization': 'Bearer ' + key },
    options.headers || {}
  );
  var resp = await fetch(path, Object.assign({}, options, { headers: headers }));
  if (resp.status === 401) {
    Alpine.store('auth').logout();
    throw new Error('Session expired. Please log in again.');
  }
  return resp;
}

async function apiJson(path, options) {
  var resp = await api(path, options);
  if (!resp.ok) throw new Error('Request failed (HTTP ' + resp.status + ')');
  return resp.json();
}

/* Utility functions */
function formatUptime(seconds) {
  var days = Math.floor(seconds / 86400);
  var hours = Math.floor((seconds % 86400) / 3600);
  var mins = Math.floor((seconds % 3600) / 60);
  if (days > 0) return days + 'd ' + hours + 'h';
  if (hours > 0) return hours + 'h ' + mins + 'm';
  return mins + 'm';
}

function formatTimestamp(unix) {
  if (!unix) return '\u2014';
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

function truncateId(id, len) {
  len = len || 16;
  if (!id || id.length <= len) return id || '\u2014';
  return id.substring(0, len) + '...';
}

function parseRules(rulesStr) {
  try { return JSON.parse(rulesStr || '[]'); }
  catch (e) { return []; }
}

async function downloadCsv(path, filename) {
  var resp = await api(path);
  var blob = await resp.blob();
  var url = URL.createObjectURL(blob);
  var a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}
