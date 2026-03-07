/* history.js — Scan history tab logic */

document.addEventListener('alpine:init', () => {
  Alpine.data('historyTab', () => ({
    items: [],
    total: 0,
    page: 1,
    pages: 1,
    perPage: 25,
    query: '',
    verdictFilter: 'all',
    sourceFilter: 'all',
    period: 'all',
    loading: true,
    error: '',
    _debounce: null,

    async init() {
      await this.load();
    },

    async load() {
      this.loading = true;
      try {
        const params = new URLSearchParams({
          q: this.query,
          verdict: this.verdictFilter,
          source: this.sourceFilter,
          period: this.period,
          page: this.page,
          per_page: this.perPage,
        });
        const data = await apiJson(`/api/admin/history?${params}`);
        this.items = data.items;
        this.total = data.total;
        this.pages = data.pages;
        this.error = '';
      } catch (e) {
        this.error = 'Failed to load history';
      }
      this.loading = false;
    },

    onSearch() {
      clearTimeout(this._debounce);
      this._debounce = setTimeout(() => {
        this.page = 1;
        this.load();
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
      const params = new URLSearchParams({
        q: this.query,
        verdict: this.verdictFilter,
        source: this.sourceFilter,
        period: this.period,
      });
      await downloadCsv(`/api/admin/history/export?${params}`, 'scan_history.csv');
    },

    parseRules(rulesStr) {
      try { return JSON.parse(rulesStr || '[]'); }
      catch { return []; }
    },

    getSource(txId) {
      return txId === 'backfill' ? 'backfill' : 'webhook';
    }
  }));
});
