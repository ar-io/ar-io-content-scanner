/* settings.js — Settings tab logic */

document.addEventListener('alpine:init', function () {
  Alpine.data('settingsTab', function () {
    return {
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
          this.error = 'Failed to load settings. ' + (e.message || '');
        }
        this.loading = false;
      },

      async exportTraining() {
        await downloadCsv('/api/admin/training-export', 'training_data.csv');
        Alpine.store('toast').show('Training data exported', 'info');
      },

      formatScanBytes() {
        if (!this.config) return '\u2014';
        return formatBytes(this.config.max_scan_bytes);
      },

      formatTimeout() {
        if (!this.config) return '\u2014';
        return (this.config.scan_timeout_ms / 1000).toFixed(0) + 's';
      }
    };
  });
});
