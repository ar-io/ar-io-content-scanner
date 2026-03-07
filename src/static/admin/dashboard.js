/* dashboard.js — Dashboard tab logic */

document.addEventListener('alpine:init', () => {
  Alpine.data('dashboardTab', () => ({
    stats: null,
    loading: true,
    error: '',
    lastUpdated: null,
    autoRefresh: true,
    _interval: null,

    async init() {
      await this.load();
      this._interval = setInterval(() => {
        if (this.autoRefresh) this.load();
      }, 30000);
    },

    destroy() {
      if (this._interval) clearInterval(this._interval);
    },

    async load() {
      try {
        this.stats = await apiJson('/api/admin/stats');
        this.lastUpdated = new Date();
        this.error = '';
        this.loading = false;
      } catch (e) {
        this.error = 'Failed to load stats';
        this.loading = false;
      }
    },

    get uptimeFormatted() {
      return this.stats ? formatUptime(this.stats.uptime_seconds) : '—';
    },

    get lastUpdatedAgo() {
      if (!this.lastUpdated) return '';
      const secs = Math.floor((Date.now() - this.lastUpdated.getTime()) / 1000);
      return secs < 5 ? 'just now' : `${secs}s ago`;
    },

    get cacheHitRate() {
      if (!this.stats) return '0%';
      const m = this.stats.metrics;
      const total = m.cache_hits + m.cache_misses;
      if (total === 0) return '—';
      return Math.round((m.cache_hits / total) * 100) + '%';
    }
  }));
});
