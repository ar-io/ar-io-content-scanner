/* settings.js — Settings tab logic */

document.addEventListener('alpine:init', () => {
  Alpine.data('settingsTab', () => ({
    config: null,
    loading: true,
    error: '',

    async init() {
      await this.load();
    },

    async load() {
      this.loading = true;
      try {
        this.config = await apiJson('/api/admin/settings');
        this.error = '';
      } catch (e) {
        this.error = 'Failed to load settings';
      }
      this.loading = false;
    },

    async exportTraining() {
      await downloadCsv('/api/admin/training-export', 'training_data.csv');
    },

    formatScanBytes() {
      if (!this.config) return '—';
      return formatBytes(this.config.max_scan_bytes);
    },

    formatTimeout() {
      if (!this.config) return '—';
      return (this.config.scan_timeout_ms / 1000).toFixed(0) + 's';
    }
  }));
});
