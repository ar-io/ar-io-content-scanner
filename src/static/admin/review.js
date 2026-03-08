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

      // Screenshots
      screenshotUrls: {},

      // Detail modal
      showModal: false,
      detail: null,
      detailSource: '',
      detailMeta: null,
      detailScreenshotUrl: '',
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
          this.loadScreenshots(data.items);
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

      async setPerPage(n) {
        this.perPage = n;
        this.page = 1;
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

      // --- Screenshot loading ---
      loadScreenshots(items) {
        // Revoke old blob URLs to prevent memory leak
        var oldUrls = this.screenshotUrls;
        Object.keys(oldUrls).forEach(function (k) {
          if (oldUrls[k]) URL.revokeObjectURL(oldUrls[k]);
        });
        this.screenshotUrls = {};

        var self = this;
        items.forEach(function (item) {
          var hash = item.content_hash;
          api('/api/admin/screenshot/' + hash).then(function (resp) {
            if (resp.ok) {
              return resp.blob().then(function (blob) {
                // Reassign entire object to trigger Alpine reactivity
                var updated = Object.assign({}, self.screenshotUrls);
                updated[hash] = URL.createObjectURL(blob);
                self.screenshotUrls = updated;
              });
            }
          }).catch(function () {
            // No screenshot available — that's fine
          });
        });
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
        try {
          if (dialog.action === 'revert') {
            await api('/api/admin/review/' + dialog.hash + '/revert', { method: 'POST' });
            dialog.show = false;
            Alpine.store('toast').show('Override reverted — item returned to pending review', 'success');
          } else {
            var endpoint = dialog.action === 'confirm' ? 'confirm' : 'dismiss';
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
          }
          await this.load();
        } catch (e) {
          Alpine.store('toast').show('Action failed: ' + (e.message || 'Unknown error'), 'error');
        }
        dialog.loading = false;
      },

      promptRevert(hash) {
        this.confirmDialog = {
          show: true,
          hash: hash,
          action: 'revert',
          notes: '',
          loading: false
        };
      },

      // --- Detail modal ---
      parseHtmlMeta(html) {
        try {
          var doc = new DOMParser().parseFromString(html, 'text/html');
          var meta = {};

          // Title
          var title = doc.querySelector('title');
          if (title && title.textContent.trim()) meta.title = title.textContent.trim();

          // Meta tags
          var descEl = doc.querySelector('meta[name="description"]') || doc.querySelector('meta[property="og:description"]');
          if (descEl) meta.description = descEl.getAttribute('content');

          var ogTitle = doc.querySelector('meta[property="og:title"]');
          if (ogTitle) meta.ogTitle = ogTitle.getAttribute('content');

          var ogImage = doc.querySelector('meta[property="og:image"]');
          if (ogImage) meta.ogImage = ogImage.getAttribute('content');

          var keywords = doc.querySelector('meta[name="keywords"]');
          if (keywords) meta.keywords = keywords.getAttribute('content');

          var canonical = doc.querySelector('link[rel="canonical"]');
          if (canonical) meta.canonical = canonical.getAttribute('href');

          var favicon = doc.querySelector('link[rel="icon"]') || doc.querySelector('link[rel="shortcut icon"]');
          if (favicon) meta.favicon = favicon.getAttribute('href');

          // Form actions — key phishing signal
          var forms = doc.querySelectorAll('form[action]');
          var actions = [];
          forms.forEach(function (f) {
            var action = f.getAttribute('action');
            if (action && action !== '#' && action !== '') actions.push(action);
          });
          if (actions.length) meta.formActions = actions;

          // External script sources
          var scripts = doc.querySelectorAll('script[src]');
          var extScripts = [];
          scripts.forEach(function (s) {
            var src = s.getAttribute('src');
            if (src && /^https?:\/\//.test(src)) extScripts.push(src);
          });
          if (extScripts.length) meta.externalScripts = extScripts;

          // Input field counts — useful context
          var passwordInputs = doc.querySelectorAll('input[type="password"]').length;
          var textInputs = doc.querySelectorAll('input[type="text"], input:not([type])').length;
          if (passwordInputs || textInputs) {
            meta.inputs = {};
            if (textInputs) meta.inputs.text = textInputs;
            if (passwordInputs) meta.inputs.password = passwordInputs;
          }

          // Check if anything was found
          if (Object.keys(meta).length === 0) return null;
          return meta;
        } catch (e) {
          return null;
        }
      },

      async openDetail(hash) {
        this.detailLoading = true;
        this.showModal = true;
        this.detailSource = '';
        this.detailMeta = null;
        this.detailScreenshotUrl = '';
        try {
          this.detail = await apiJson('/api/admin/review/' + hash);
          // Load screenshot and source preview in parallel
          var promises = [];
          var self = this;
          promises.push(
            api('/api/admin/preview/' + this.detail.tx_id).then(function (resp) {
              return resp.text();
            }).then(function (text) {
              self.detailMeta = self.parseHtmlMeta(text);
              self.detailSource = text.substring(0, 5000);
            }).catch(function () {})
          );
          if (this.detail.has_screenshot) {
            promises.push(
              api('/api/admin/screenshot/' + hash).then(function (resp) {
                if (resp.ok) return resp.blob();
              }).then(function (blob) {
                if (blob) self.detailScreenshotUrl = URL.createObjectURL(blob);
              }).catch(function () {})
            );
          }
          await Promise.all(promises);
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
        this.detailMeta = null;
        if (this.detailScreenshotUrl) {
          URL.revokeObjectURL(this.detailScreenshotUrl);
          this.detailScreenshotUrl = '';
        }
      }
    };
  });
});
