/* review.js — Review queue tab logic */

document.addEventListener('alpine:init', () => {
  Alpine.data('reviewTab', () => ({
    items: [],
    total: 0,
    page: 1,
    pages: 1,
    perPage: 25,
    verdictFilter: 'all',
    statusFilter: 'pending',
    sort: 'newest',
    loading: true,
    error: '',
    actionLoading: {},
    // Detail modal
    showModal: false,
    detail: null,
    detailSource: '',
    detailLoading: false,

    async init() {
      await this.load();
    },

    async load() {
      this.loading = true;
      try {
        const params = new URLSearchParams({
          verdict: this.verdictFilter,
          status: this.statusFilter,
          sort: this.sort,
          page: this.page,
          per_page: this.perPage,
        });
        const data = await apiJson(`/api/admin/review?${params}`);
        this.items = data.items;
        this.total = data.total;
        this.pages = data.pages;
        this.error = '';
      } catch (e) {
        this.error = 'Failed to load review queue';
      }
      this.loading = false;
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

    async confirmItem(hash) {
      this.actionLoading[hash] = 'confirm';
      try {
        await api(`/api/admin/review/${hash}/confirm`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ notes: '' }),
        });
        await this.load();
      } catch (e) {
        this.error = 'Failed to confirm';
      }
      delete this.actionLoading[hash];
    },

    async dismissItem(hash) {
      this.actionLoading[hash] = 'dismiss';
      try {
        await api(`/api/admin/review/${hash}/dismiss`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ notes: '' }),
        });
        await this.load();
      } catch (e) {
        this.error = 'Failed to dismiss';
      }
      delete this.actionLoading[hash];
    },

    async openDetail(hash) {
      this.detailLoading = true;
      this.showModal = true;
      this.detailSource = '';
      try {
        this.detail = await apiJson(`/api/admin/review/${hash}`);
        // Fetch source preview
        const resp = await api(`/api/admin/preview/${this.detail.tx_id}`);
        const text = await resp.text();
        this.detailSource = text.substring(0, 5000);
      } catch (e) {
        this.detail = null;
        this.error = 'Failed to load details';
      }
      this.detailLoading = false;
    },

    closeModal() {
      this.showModal = false;
      this.detail = null;
      this.detailSource = '';
    },

    parseRules(rulesStr) {
      try { return JSON.parse(rulesStr || '[]'); }
      catch { return []; }
    }
  }));
});
