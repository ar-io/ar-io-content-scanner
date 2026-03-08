/* review.js — Review queue tab logic */

document.addEventListener('alpine:init', function () {
  Alpine.data('reviewTab', function () {
    return {
      items: [],
      total: 0,
      page: 1,
      pages: 1,
      perPage: 25,
      verdictFilter: 'all',
      statusFilter: 'pending',
      sort: 'newest',
      searchQuery: '',
      loading: true,
      error: '',
      _debounce: null,

      // Confirmation dialog
      confirmDialog: {
        show: false,
        hash: '',
        action: '',
        notes: '',
        loading: false
      },

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
          var params = new URLSearchParams({
            q: this.searchQuery,
            verdict: this.verdictFilter,
            status: this.statusFilter,
            sort: this.sort,
            page: this.page,
            per_page: this.perPage
          });
          var data = await apiJson('/api/admin/review?' + params);
          this.items = data.items;
          this.total = data.total;
          this.pages = data.pages;
          this.error = '';
        } catch (e) {
          this.error = 'Failed to load review queue. ' + (e.message || '');
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

      onSearch() {
        var self = this;
        clearTimeout(this._debounce);
        this._debounce = setTimeout(function () {
          self.page = 1;
          self.load();
        }, 300);
      },

      // --- Confirmation flow ---
      promptConfirm(hash) {
        this.confirmDialog = {
          show: true,
          hash: hash,
          action: 'confirm',
          notes: '',
          loading: false
        };
      },

      promptDismiss(hash) {
        this.confirmDialog = {
          show: true,
          hash: hash,
          action: 'dismiss',
          notes: '',
          loading: false
        };
      },

      async executeAction() {
        var dialog = this.confirmDialog;
        dialog.loading = true;
        var endpoint = dialog.action === 'confirm' ? 'confirm' : 'dismiss';
        try {
          await api('/api/admin/review/' + dialog.hash + '/' + endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ notes: dialog.notes })
          });
          dialog.show = false;
          if (dialog.action === 'confirm') {
            Alpine.store('toast').show('Content confirmed as malicious', 'success');
          } else {
            Alpine.store('toast').show('Content dismissed as false positive', 'success');
          }
          await this.load();
        } catch (e) {
          Alpine.store('toast').show('Action failed: ' + (e.message || 'Unknown error'), 'error');
        }
        dialog.loading = false;
      },

      async revertOverride(hash) {
        try {
          await api('/api/admin/review/' + hash + '/revert', { method: 'POST' });
          Alpine.store('toast').show('Override reverted — item returned to pending review', 'success');
          await this.load();
        } catch (e) {
          Alpine.store('toast').show('Revert failed: ' + (e.message || 'Unknown error'), 'error');
        }
      },

      // --- Detail modal ---
      async openDetail(hash) {
        this.detailLoading = true;
        this.showModal = true;
        this.detailSource = '';
        try {
          this.detail = await apiJson('/api/admin/review/' + hash);
          var resp = await api('/api/admin/preview/' + this.detail.tx_id);
          var text = await resp.text();
          this.detailSource = text.substring(0, 5000);
        } catch (e) {
          this.detail = null;
          this.error = 'Failed to load scan details';
        }
        this.detailLoading = false;
      },

      closeModal() {
        this.showModal = false;
        this.detail = null;
        this.detailSource = '';
      }
    };
  });
});
