/* block.js — Manual block tab logic */

document.addEventListener('alpine:init', function () {
  var ARWEAVE_ID_RE = /^[A-Za-z0-9_-]{43}$/;

  // Accepts either an Arweave TX ID or an IPFS CID (CIDv0 / CIDv1).
  // isIpfsCid is defined in app.js.
  function isValidContentId(s) {
    return ARWEAVE_ID_RE.test(s) || isIpfsCid(s);
  }

  // --- Sandbox subdomain -> Arweave TX ID -------------------------------
  // Arweave gateways serve each tx on a "sandbox" subdomain that is the
  // RFC-4648 base32 (lowercase, unpadded) of the tx's raw 32 bytes. Google
  // Safe Browsing and the scanner report offending content by that hostname,
  // so accept it here and decode it back to the 43-char base64url TX ID.
  var B32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

  function base32ToBytes(s) {
    s = s.toUpperCase().replace(/=+$/, '');
    var bits = 0, value = 0, out = [];
    for (var i = 0; i < s.length; i++) {
      var idx = B32_ALPHABET.indexOf(s.charAt(i));
      if (idx < 0) return null;
      value = (value << 5) | idx;
      bits += 5;
      if (bits >= 8) {
        out.push((value >>> (bits - 8)) & 0xff);
        bits -= 8;
      }
    }
    return out;
  }

  function bytesToB64url(bytes) {
    var bin = '';
    for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  // Returns the 43-char TX ID for a sandbox subdomain (bare label or full
  // hostname like "<label>.arweave.net"), or null if it isn't one.
  function sandboxToTxId(input) {
    var label = String(input).trim().toLowerCase().split('.')[0];
    // CIDv1 also uses base32 and starts with "baf" — leave those to isIpfsCid.
    if (label.indexOf('baf') === 0) return null;
    if (!/^[a-z2-7]{52}$/.test(label)) return null;
    var bytes = base32ToBytes(label);
    if (!bytes || bytes.length !== 32) return null;
    return bytesToB64url(bytes);
  }

  Alpine.data('blockTab', function () {
    return {
      txInput: '',
      reason: '',
      loading: false,
      error: '',
      validationError: '',

      // History from DB
      historyItems: [],
      historyTotal: 0,
      historyPage: 1,
      historyPages: 1,
      historyLoading: false,

      confirmDialog: {
        show: false,
        txIds: [],
        reason: '',
        progressText: ''
      },

      async init() {
        await this.loadHistory();
      },

      async loadHistory() {
        this.historyLoading = true;
        try {
          var params = new URLSearchParams({
            source: 'manual',
            sort: 'newest',
            page: this.historyPage,
            per_page: 25
          });
          var data = await apiJson('/api/admin/history?' + params);
          this.historyItems = data.items;
          this.historyTotal = data.total;
          this.historyPages = data.pages;
        } catch (e) {
          // Silently fail — the form still works
        }
        this.historyLoading = false;
      },

      async setHistoryPage(n) {
        this.historyPage = Math.max(1, Math.min(n, this.historyPages));
        await this.loadHistory();
      },

      parseTxIds() {
        if (!this.txInput.trim()) return [];
        return this.txInput.split(/[\n,]+/)
          .map(function (s) { return s.trim(); })
          .filter(function (s) { return s.length > 0; })
          // Transparently resolve sandbox subdomains to their TX ID so the
          // count, preview, validation, and submitted payload all use the
          // real ID. Non-sandbox entries pass through unchanged.
          .map(function (s) { return sandboxToTxId(s) || s; });
      },

      // --- ArNS name blocking ---
      nameInput: '',
      nameReason: '',
      nameLoading: false,
      nameError: '',

      parseNames() {
        if (!this.nameInput.trim()) return [];
        return this.nameInput.split(/[\n,]+/)
          .map(function (s) { return s.trim().toLowerCase(); })
          .filter(function (s) { return s.length > 0; });
      },

      async submitNames(action) {
        this.nameError = '';
        var names = this.parseNames();
        if (names.length === 0) { this.nameError = 'At least one name is required'; return; }
        if (names.length > 100) { this.nameError = 'Maximum 100 names at once'; return; }
        var bad = names.filter(function (n) { return !/^[a-z0-9_-]{1,51}$/.test(n); });
        if (bad.length) {
          this.nameError = 'Invalid name' + (bad.length > 1 ? 's' : '') + ' (1-51 chars, a-z 0-9 _ -): ' + bad.slice(0, 3).join(', ');
          return;
        }
        var verb = action === 'block' ? 'Block' : 'Unblock';
        if (!window.confirm(verb + ' ' + names.length + ' ArNS name' + (names.length > 1 ? 's' : '') + '?\n\n' + names.join('\n'))) return;

        this.nameLoading = true;
        try {
          var endpoint = action === 'block' ? '/api/admin/block-name' : '/api/admin/unblock-name';
          var single = names.length === 1;
          var payload;
          if (action === 'block') {
            payload = single ? { name: names[0], reason: this.nameReason }
                             : { names: names, reason: this.nameReason };
          } else {
            payload = single ? { name: names[0] } : { names: names };
          }
          var resp = await api(endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
          });
          if (!resp.ok) {
            var errData = await resp.json().catch(function () { return {}; });
            throw new Error(errData.detail || 'Request failed (HTTP ' + resp.status + ')');
          }
          var result = await resp.json();
          var okField = action === 'block' ? 'blocked' : 'unblocked';
          var okCount = result.results
            ? result.results.filter(function (r) { return r[okField]; }).length
            : (result[okField] ? 1 : 0);
          var total = result.results ? result.results.length : 1;
          Alpine.store('toast').show(
            verb + 'ed ' + okCount + '/' + total + ' name' + (total > 1 ? 's' : ''),
            okCount === total ? 'success' : 'error'
          );
          this.nameInput = '';
          this.nameReason = '';
        } catch (e) {
          this.nameError = e.message || 'Request failed';
          Alpine.store('toast').show(verb + ' failed: ' + (e.message || 'Unknown error'), 'error');
        }
        this.nameLoading = false;
      },

      validateTxIds() {
        var ids = this.parseTxIds();
        if (ids.length === 0) {
          this.validationError = 'At least one ID is required';
          return null;
        }
        if (ids.length > 100) {
          this.validationError = 'Maximum 100 IDs at once';
          return null;
        }
        var invalid = [];
        for (var i = 0; i < ids.length; i++) {
          if (!isValidContentId(ids[i])) {
            invalid.push(ids[i].substring(0, 20) + (ids[i].length > 20 ? '...' : ''));
          }
        }
        if (invalid.length > 0) {
          this.validationError = 'Invalid ID' + (invalid.length > 1 ? 's' : '') + ' (expected Arweave TX ID or IPFS CID): ' + invalid.slice(0, 3).join(', ') + (invalid.length > 3 ? ' (+' + (invalid.length - 3) + ' more)' : '');
          return null;
        }
        // Deduplicate
        var seen = {};
        var unique = [];
        for (var j = 0; j < ids.length; j++) {
          if (!seen[ids[j]]) {
            seen[ids[j]] = true;
            unique.push(ids[j]);
          }
        }
        this.validationError = '';
        return unique;
      },

      promptBlock() {
        var ids = this.validateTxIds();
        if (!ids) return;
        this.confirmDialog = {
          show: true,
          txIds: ids,
          reason: this.reason.trim(),
          progressText: ''
        };
      },

      async executeBlock() {
        this.loading = true;
        this.error = '';
        var dialog = this.confirmDialog;
        var isSingle = dialog.txIds.length === 1;

        if (!isSingle) {
          dialog.progressText = 'Processing ' + dialog.txIds.length + ' transactions...';
        }

        try {
          var payload = isSingle
            ? { tx_id: dialog.txIds[0], reason: dialog.reason }
            : { tx_ids: dialog.txIds, reason: dialog.reason };

          var resp = await api('/api/admin/block', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
          });
          if (!resp.ok) {
            var errData = await resp.json().catch(function () { return {}; });
            throw new Error(errData.detail || 'Request failed (HTTP ' + resp.status + ')');
          }
          var result = await resp.json();
          dialog.show = false;

          if (isSingle) {
            var msg = result.blocked
              ? 'Content blocked successfully'
              : 'Verdict saved but gateway block failed';
            if (result.already_existed) msg += ' (overwrote existing verdict)';
            Alpine.store('toast').show(msg, result.blocked ? 'success' : 'error');
          } else {
            this._showBulkToast(result);
          }

          this.txInput = '';
          this.reason = '';

          // Refresh the history table to show the new blocks
          this.historyPage = 1;
          await this.loadHistory();
        } catch (e) {
          dialog.show = false;
          this.error = e.message || 'Failed to block transactions';
          Alpine.store('toast').show('Block failed: ' + (e.message || 'Unknown error'), 'error');
        }
        this.loading = false;
      },

      async exportBlockedTxIds(source) {
        try {
          var resp = await api('/api/admin/block/export?source=' + source);
          if (!resp.ok) throw new Error('Export failed (HTTP ' + resp.status + ')');
          var text = await resp.text();
          if (!text.trim()) {
            Alpine.store('toast').show('No blocked IDs to export', 'info');
            return;
          }
          var blob = new Blob([text], { type: 'text/plain' });
          var url = URL.createObjectURL(blob);
          var a = document.createElement('a');
          a.href = url;
          a.download = source === 'manual' ? 'manual_blocked_ids.txt' : 'all_blocked_ids.txt';
          a.click();
          URL.revokeObjectURL(url);
          var count = text.trim().split('\n').length;
          Alpine.store('toast').show('Exported ' + count + ' IDs', 'success');
        } catch (e) {
          Alpine.store('toast').show('Export failed: ' + (e.message || 'Unknown error'), 'error');
        }
      },

      _showBulkToast(result) {
        var blockedCount = result.results
          ? result.results.filter(function (r) { return r.blocked; }).length
          : 0;
        var gatewayFailed = result.succeeded - blockedCount;
        var totalAttempted = result.succeeded + result.failed;
        var parts = [];

        if (blockedCount > 0) parts.push(blockedCount + ' blocked');
        if (gatewayFailed > 0) parts.push(gatewayFailed + ' saved (gateway failed)');
        if (result.failed > 0) parts.push(result.failed + ' skipped (invalid)');

        var msg = parts.join(', ');
        msg = msg.charAt(0).toUpperCase() + msg.slice(1);
        msg += ' \u2014 ' + totalAttempted + ' total';

        var type = blockedCount === totalAttempted ? 'success' : (blockedCount > 0 ? 'success' : 'error');
        Alpine.store('toast').show(msg, type);
      }
    };
  });
});
