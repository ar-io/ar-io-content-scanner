/* dashboard.js — Dashboard tab logic */

document.addEventListener('alpine:init', function () {
  Alpine.data('dashboardTab', function () {
    return {
      stats: null,
      loading: true,
      error: '',
      lastUpdated: null,
      autoRefresh: true,
      _interval: null,
      _tickInterval: null,
      _tickCount: 0,

      async init() {
        await this.load();
        var self = this;
        this._interval = setInterval(function () {
          if (self.autoRefresh) self.load();
        }, 30000);
        this._tickInterval = setInterval(function () {
          self._tickCount++;
        }, 1000);
      },

      destroy() {
        if (this._interval) clearInterval(this._interval);
        if (this._tickInterval) clearInterval(this._tickInterval);
      },

      async load() {
        try {
          this.stats = await apiJson('/api/admin/stats');
          this.lastUpdated = new Date();
          this._tickCount = 0;
          this.error = '';
          this.loading = false;
        } catch (e) {
          this.error = 'Failed to load dashboard data. Check your connection and try again.';
          this.loading = false;
        }
      },

      get uptimeFormatted() {
        return this.stats ? formatUptime(this.stats.uptime_seconds) : '\u2014';
      },

      get lastUpdatedAgo() {
        // Reference _tickCount to trigger Alpine reactivity
        void this._tickCount;
        if (!this.lastUpdated) return '';
        var secs = Math.floor((Date.now() - this.lastUpdated.getTime()) / 1000);
        if (secs < 5) return 'just now';
        if (secs < 60) return secs + 's ago';
        return Math.floor(secs / 60) + 'm ago';
      },

      get cacheHitRate() {
        if (!this.stats) return '0%';
        var m = this.stats.metrics;
        var total = m.cache_hits + m.cache_misses;
        if (total === 0) return '\u2014';
        return Math.round((m.cache_hits / total) * 100) + '%';
      },

      get cacheHitPercent() {
        if (!this.stats) return 0;
        var m = this.stats.metrics;
        var total = m.cache_hits + m.cache_misses;
        if (total === 0) return 0;
        return Math.round((m.cache_hits / total) * 100);
      },

      get cacheBarColor() {
        var p = this.cacheHitPercent;
        if (p >= 80) return 'var(--color-green)';
        if (p >= 50) return 'var(--color-amber)';
        return 'var(--color-red)';
      },

      get threatRate() {
        if (!this.stats || !this.stats.counts.scans_total) return '';
        var rate = this.stats.counts.malicious / this.stats.counts.scans_total * 100;
        if (rate < 0.01 && this.stats.counts.malicious > 0) return '<0.01%';
        return rate.toFixed(2) + '%';
      },

      get verdictBar() {
        if (!this.stats || !this.stats.counts.scans_total) {
          return { clean: 100, suspicious: 0, malicious: 0 };
        }
        var c = this.stats.counts;
        var total = c.scans_total;
        var mal = c.malicious / total * 100;
        var sus = c.suspicious / total * 100;
        var clean = 100 - mal - sus;
        return {
          clean: Math.max(0, clean),
          suspicious: sus,
          malicious: mal,
          cleanCount: total - c.malicious - c.suspicious,
          suspiciousCount: c.suspicious,
          maliciousCount: c.malicious
        };
      },

      get lastWebhookFormatted() {
        if (!this.stats || !this.stats.last_webhook_at) return 'No webhooks received';
        // Reference _tickCount for reactivity
        void this._tickCount;
        var secs = Math.floor(Date.now() / 1000 - this.stats.last_webhook_at);
        if (secs < 5) return 'just now';
        if (secs < 60) return secs + 's ago';
        if (secs < 3600) return Math.floor(secs / 60) + 'm ago';
        return Math.floor(secs / 3600) + 'h ago';
      },

      get webhookStale() {
        if (!this.stats || !this.stats.last_webhook_at) return true;
        void this._tickCount;
        var secs = Math.floor(Date.now() / 1000 - this.stats.last_webhook_at);
        return secs > 300;
      }
    };
  });
});
