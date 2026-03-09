/* history.js — Scan history tab logic */

document.addEventListener('alpine:init', function () {
  Alpine.data('historyTab', function () {
    return {
      items: [],
      total: 0,
      page: 1,
      pages: 1,
      perPage: 25,
      query: '',
      verdictFilter: 'all',
      sourceFilter: 'all',
      period: 'all',
      sort: 'newest',
      loading: true,
      error: '',
      _debounce: null,

      async init() {
        await this.load();
      },

      async load() {
        this.loading = true;
        try {
          var params = new URLSearchParams({
            q: this.query,
            verdict: this.verdictFilter,
            source: this.sourceFilter,
            period: this.period,
            sort: this.sort,
            page: this.page,
            per_page: this.perPage
          });
          var data = await apiJson('/api/admin/history?' + params);
          this.items = data.items;
          this.total = data.total;
          this.pages = data.pages;
          this.error = '';
        } catch (e) {
          this.error = 'Failed to load scan history. ' + (e.message || '');
        }
        this.loading = false;
      },

      onSearch() {
        var self = this;
        clearTimeout(this._debounce);
        this._debounce = setTimeout(function () {
          self.page = 1;
          self.load();
        }, 300);
      },

      async setFilter(type, value) {
        this[type] = value;
        this.page = 1;
        await this.load();
      },

      async setPage(n) {
        this.page = Math.max(1, Math.min(n, this.pages));
        await this.load();
      },

      async setPerPage(n) {
        this.perPage = n;
        this.page = 1;
        await this.load();
      },

      async exportCsv() {
        var params = new URLSearchParams({
          q: this.query,
          verdict: this.verdictFilter,
          source: this.sourceFilter,
          period: this.period
        });
        await downloadCsv('/api/admin/history/export?' + params, 'scan_history.csv');
        Alpine.store('toast').show('CSV export downloaded', 'info');
      },

      getSource(item) {
        if (item.source && item.source !== 'local') return 'feed';
        if (item.tx_id === 'backfill') return 'backfill';
        return 'webhook';
      }
    };
  });
});
